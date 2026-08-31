//! Backend Windows complet : lecture locale, ecriture deleguee au helper.
//!
//! # Repartition des roles
//!
//! - L'inventaire des disques est fait **ici**, sans privilege : WMI y repond
//!   sans elevation.
//! - Les variables du firmware sont lues **par le helper**, qui seul detient
//!   le privilege necessaire.
//! - L'ecriture de `BootNext` est faite **par le helper**, qui verifie
//!   lui-meme le resultat avant de repondre.
//! - Le redemarrage est fait **ici** : il ne demande aucun privilege
//!   particulier.
//!
//! # Double verification
//!
//! Le helper applique le garde-fou avant de repondre, et
//! [`bootsel_core::select::commit_selection`] l'applique a nouveau du cote
//! interface, sur ses propres instantanes. Le processus qui detient le
//! privilege n'est donc jamais le seul juge de sa propre operation.

use crate::elevate::HelperChannel;
use bootsel_core::backend::{BackendError, BootBackend};
use bootsel_core::ipc::{decode_state, ErrorKind, Request, Response};
use bootsel_core::model::{BootId, FirmwareMode, FirmwareState, StorageDevice};
use std::sync::Mutex;

use super::{firmware, power, storage};

/// Backend Windows disposant d'un canal vers le helper privilegie.
#[derive(Debug)]
pub struct ElevatedWindowsBackend {
    /// Le canal est serialise : le protocole est strictement question/reponse,
    /// deux requetes simultanees melangeraient les reponses.
    channel: Mutex<HelperChannel>,
    read_only: bool,
}

impl ElevatedWindowsBackend {
    pub fn new(channel: HelperChannel) -> Self {
        ElevatedWindowsBackend {
            channel: Mutex::new(channel),
            read_only: false,
        }
    }

    /// Variante incapable d'ecrire, quoi qu'il arrive (`--dry-run`).
    pub fn read_only(channel: HelperChannel) -> Self {
        ElevatedWindowsBackend {
            channel: Mutex::new(channel),
            read_only: true,
        }
    }

    /// Version du helper connecte, pour les journaux et le diagnostic.
    pub fn helper_version(&self) -> String {
        self.channel
            .lock()
            .map(|c| c.helper_version.clone())
            .unwrap_or_default()
    }

    /// Vrai si le helper a effectivement obtenu le privilege firmware.
    pub fn helper_is_elevated(&self) -> bool {
        self.channel.lock().map(|c| c.elevated).unwrap_or(false)
    }

    fn request(&self, request: &Request) -> Result<Response, BackendError> {
        let encoded = serde_json::to_string(request)
            .map_err(|e| BackendError::Io(format!("serialisation de la requete : {e}")))?;

        let mut channel = self
            .channel
            .lock()
            .map_err(|_| BackendError::Io("canal du composant privilegie corrompu".into()))?;

        let raw = channel.exchange(&encoded)?;

        serde_json::from_str::<Response>(&raw)
            .map_err(|e| BackendError::Io(format!("reponse illisible du composant privilegie : {e}")))
    }
}

/// Traduit une erreur du protocole en erreur locale.
fn translate(kind: ErrorKind, message: String) -> BackendError {
    match kind {
        ErrorKind::PrivilegeRequired => BackendError::PrivilegeRequired,
        ErrorKind::NotUefi => BackendError::NotUefi,
        ErrorKind::EntryNotFound => BackendError::TargetVanished,
        ErrorKind::WriteRefused => BackendError::WriteRefused(message),
        // Le garde-fou du helper a detecte un changement interdit. On remonte
        // l'echec tel quel : l'interface ne doit surtout pas redemarrer.
        ErrorKind::GuardViolation => BackendError::WriteRefused(message),
        ErrorKind::BadRequest | ErrorKind::Internal => BackendError::Io(message),
    }
}

impl BootBackend for ElevatedWindowsBackend {
    fn firmware_mode(&self) -> Result<FirmwareMode, BackendError> {
        // Non privilegie : inutile de deranger le helper.
        firmware::firmware_mode()
    }

    fn read_state(&self) -> Result<FirmwareState, BackendError> {
        match self.request(&Request::ReadState)? {
            Response::State { variables } => Ok(decode_state(&variables)),
            Response::Error { kind, message } => Err(translate(kind, message)),
            other => Err(BackendError::Io(format!(
                "reponse inattendue a une lecture : {other:?}"
            ))),
        }
    }

    fn list_devices(&self) -> Result<Vec<StorageDevice>, BackendError> {
        // Non privilegie : WMI repond directement a ce processus.
        storage::list_devices()
    }

    fn set_boot_next(&self, target: BootId) -> Result<(), BackendError> {
        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }

        // L'identifiant transmis est produit par `BootId`, donc toujours
        // exactement quatre chiffres hexadecimaux. Le helper le revalide malgre
        // tout de son cote.
        let request = Request::SetBootNext {
            id: target.hex4(),
        };

        match self.request(&request)? {
            Response::Written { id } => {
                // Ultime verification de coherence : le helper doit confirmer
                // la cible exacte qui lui a ete demandee.
                if id == target.hex4() {
                    Ok(())
                } else {
                    Err(BackendError::WriteRefused(format!(
                        "le composant privilegie a confirme {id} au lieu de {}",
                        target.hex4()
                    )))
                }
            }
            Response::Error { kind, message } => Err(translate(kind, message)),
            other => Err(BackendError::Io(format!(
                "reponse inattendue a une ecriture : {other:?}"
            ))),
        }
    }

    fn reboot(&self) -> Result<(), BackendError> {
        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }
        power::reboot()
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn name(&self) -> &'static str {
        "windows-eleve"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_guard_violation_never_becomes_a_success() {
        // Le cas critique : si le helper signale que le garde-fou a saute,
        // l'interface doit recevoir une erreur, jamais un succes.
        let error = translate(
            ErrorKind::GuardViolation,
            "BootOrder a change pendant l'operation".into(),
        );
        assert!(matches!(error, BackendError::WriteRefused(_)));
        assert!(error.to_string().contains("BootOrder"));
    }

    #[test]
    fn protocol_errors_keep_their_meaning() {
        assert_eq!(
            translate(ErrorKind::PrivilegeRequired, String::new()),
            BackendError::PrivilegeRequired
        );
        assert_eq!(
            translate(ErrorKind::NotUefi, String::new()),
            BackendError::NotUefi
        );
        assert_eq!(
            translate(ErrorKind::EntryNotFound, String::new()),
            BackendError::TargetVanished
        );
    }

    #[test]
    fn errors_that_guarantee_no_write_are_marked_as_such() {
        for kind in [
            ErrorKind::PrivilegeRequired,
            ErrorKind::NotUefi,
            ErrorKind::EntryNotFound,
        ] {
            assert!(
                translate(kind, String::new()).guarantees_no_write(),
                "{kind:?} devrait garantir qu'aucune ecriture n'a eu lieu"
            );
        }

        // Une ecriture refusee ou un garde-fou viole laissent un doute : on ne
        // promet rien.
        assert!(!translate(ErrorKind::WriteRefused, String::new()).guarantees_no_write());
        assert!(!translate(ErrorKind::GuardViolation, String::new()).guarantees_no_write());
    }

    #[test]
    fn the_identifier_sent_on_the_wire_is_always_four_hex_digits() {
        for id in [0u16, 2, 0xabcd, 0xFFFF] {
            let request = Request::SetBootNext {
                id: BootId(id).hex4(),
            };
            let Request::SetBootNext { id: sent } = &request else {
                unreachable!()
            };
            assert_eq!(sent.len(), 4);
            assert!(sent.bytes().all(|b| b.is_ascii_hexdigit()));
            // Doit repasser la validation du helper.
            assert_eq!(bootsel_core::ipc::parse_target_id(sent), Some(BootId(id)));
        }
    }
}
