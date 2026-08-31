//! Acces privilegie au firmware. **Le seul module du projet qui ecrive.**
//!
//! # Perimetre
//!
//! Ce module definit exactement une fonction d'ecriture,
//! [`write_boot_next`], et elle ne peut ecrire qu'une seule variable :
//! `BootNext`. Le nom de cette variable est une constante litterale, jamais un
//! parametre. Il n'existe aucune fonction generique du genre
//! `write_variable(nom, valeur)` : ecrire `BootOrder` demanderait d'ajouter du
//! code, pas seulement de passer une autre chaine.
//!
//! # Ce qui est ecrit, exhaustivement
//!
//! Deux octets. L'identifiant de l'entree cible, en little-endian, dans la
//! variable `BootNext` de l'espace de nommage global UEFI. Rien d'autre, sous
//! aucune condition.

use bootsel_core::backend::BackendError;
use bootsel_core::model::{
    BootId, FirmwareMode, FirmwareState, VAR_BOOT_CURRENT, VAR_BOOT_NEXT, VAR_BOOT_ORDER,
};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    GetLastError, ERROR_ENVVAR_NOT_FOUND, ERROR_INVALID_FUNCTION, ERROR_PRIVILEGE_NOT_HELD,
    WIN32_ERROR,
};
use windows::Win32::Security::SE_SYSTEM_ENVIRONMENT_NAME;
use windows::Win32::System::SystemInformation::{
    FirmwareTypeUefi, GetFirmwareType, FIRMWARE_TYPE,
};
use windows::Win32::System::WindowsProgramming::{
    GetFirmwareEnvironmentVariableW, SetFirmwareEnvironmentVariableW,
};

/// Espace de nommage des variables globales UEFI.
const EFI_GLOBAL_GUID: &str = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

/// **Le seul nom de variable que ce module ecrit.** Constante litterale,
/// jamais un parametre : c'est la deuxieme des quatre barrieres du projet.
const WRITABLE_VARIABLE: &str = VAR_BOOT_NEXT;

const MAX_VARIABLE_SIZE: usize = 8192;
const PROBE_LIMIT: u16 = 0x0200;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Privilege
// ---------------------------------------------------------------------------

static PRIVILEGE: OnceLock<Result<(), BackendError>> = OnceLock::new();

/// Active `SeSystemEnvironmentPrivilege`, une seule fois par processus.
///
/// Le resultat est memorise : la lecture d'un instantane complet interroge
/// plusieurs centaines de variables, il serait absurde de reajuster le jeton a
/// chaque fois.
pub fn enable_privilege() -> Result<(), BackendError> {
    PRIVILEGE
        .get_or_init(|| crate::privilege::enable(SE_SYSTEM_ENVIRONMENT_NAME))
        .clone()
}

/// Vrai si le helper dispose reellement du privilege firmware.
pub fn is_elevated() -> bool {
    enable_privilege().is_ok()
}

// ---------------------------------------------------------------------------
// Lecture
// ---------------------------------------------------------------------------

pub fn firmware_mode() -> Result<FirmwareMode, BackendError> {
    let mut kind = FIRMWARE_TYPE::default();

    // SAFETY: `kind` est une variable locale valide qui recoit un unique
    // `FIRMWARE_TYPE`.
    match unsafe { GetFirmwareType(&mut kind) } {
        Ok(()) if kind == FirmwareTypeUefi => Ok(FirmwareMode::Uefi),
        Ok(()) => Ok(FirmwareMode::LegacyBios),
        Err(e) => Err(BackendError::FirmwareUnavailable(format!(
            "GetFirmwareType a echoue : {e}"
        ))),
    }
}

enum ReadOutcome {
    Found(Vec<u8>),
    Absent,
}

fn read_variable(name: &str) -> Result<ReadOutcome, BackendError> {
    enable_privilege()?;

    let name_w = wide(name);
    let guid_w = wide(EFI_GLOBAL_GUID);
    let mut buffer = vec![0u8; MAX_VARIABLE_SIZE];

    // SAFETY: les deux chaines sont des tampons UTF-16 termines par un nul,
    // vivants pendant tout l'appel. `buffer` fait exactement la taille
    // annoncee. L'API n'ecrit que dans ce tampon.
    let written = unsafe {
        GetFirmwareEnvironmentVariableW(
            PCWSTR(name_w.as_ptr()),
            PCWSTR(guid_w.as_ptr()),
            Some(buffer.as_mut_ptr().cast()),
            MAX_VARIABLE_SIZE as u32,
        )
    };

    if written > 0 {
        buffer.truncate(written as usize);
        return Ok(ReadOutcome::Found(buffer));
    }

    // SAFETY: appel sans argument, sans effet de bord.
    let err = unsafe { GetLastError() };
    classify(name, err)
}

fn classify(name: &str, err: WIN32_ERROR) -> Result<ReadOutcome, BackendError> {
    match err {
        ERROR_ENVVAR_NOT_FOUND => Ok(ReadOutcome::Absent),
        ERROR_PRIVILEGE_NOT_HELD => Err(BackendError::PrivilegeRequired),
        ERROR_INVALID_FUNCTION => Err(BackendError::NotUefi),
        other => Err(BackendError::FirmwareUnavailable(format!(
            "lecture de {name} : erreur Windows {}",
            other.0
        ))),
    }
}

/// Instantane complet des variables de demarrage. **Lecture seule.**
pub fn read_state() -> Result<FirmwareState, BackendError> {
    let mut variables = BTreeMap::new();

    for name in [VAR_BOOT_ORDER, VAR_BOOT_NEXT, VAR_BOOT_CURRENT] {
        if let ReadOutcome::Found(raw) = read_variable(name)? {
            variables.insert(name.to_string(), raw);
        }
    }

    let mut wanted: Vec<u16> = Vec::new();
    if let Some(raw) = variables.get(VAR_BOOT_ORDER) {
        if let Ok(ids) = bootsel_core::efi::parse_boot_id_list(raw) {
            wanted.extend(ids);
        }
    }
    wanted.extend(0..PROBE_LIMIT);
    wanted.sort_unstable();
    wanted.dedup();

    for id in wanted {
        let name = BootId(id).variable_name();
        if let ReadOutcome::Found(raw) = read_variable(&name)? {
            variables.insert(name, raw);
        }
    }

    Ok(FirmwareState::new(variables))
}

// ---------------------------------------------------------------------------
// Ecriture — l'unique operation d'ecriture du projet
// ---------------------------------------------------------------------------

/// Ecrit `BootNext` et verifie que rien d'autre n'a bouge.
///
/// # Sequence
///
/// 1. Refus immediat si la machine n'est pas en UEFI.
/// 2. Instantane complet **avant**.
/// 3. Refus si l'entree visee n'existe pas dans cet instantane.
/// 4. Ecriture de deux octets dans `BootNext`.
/// 5. Instantane complet **apres**.
/// 6. Verification que la seule difference est `BootNext`, et qu'elle vaut la
///    cible demandee.
///
/// Les etapes 2, 5 et 6 sont refaites independamment par l'appelant. Cette
/// double evaluation est deliberee : le processus qui detient le privilege ne
/// doit pas etre le seul a se controler.
///
/// # Ce qui n'est jamais fait
///
/// Aucune entree n'est creee, supprimee ni reordonnee. `BootOrder` n'est ni lu
/// pour etre reecrit, ni touche. Aucun fichier, aucune partition, aucun disque
/// n'est ouvert.
pub fn write_boot_next(target: BootId) -> Result<FirmwareState, BackendError> {
    if !firmware_mode()?.supports_boot_next() {
        return Err(BackendError::NotUefi);
    }

    let before = read_state()?;

    // On n'ecrit jamais un identifiant qui ne correspond a rien : le firmware
    // tenterait de demarrer sur une entree inexistante.
    if !before.contains_entry(target) {
        return Err(BackendError::EntryNotFound(target));
    }

    set_boot_next_variable(target)?;

    let after = read_state()?;
    bootsel_core::guard::verify_only_boot_next_changed(&before, &after, target)?;

    Ok(after)
}

/// L'appel systeme d'ecriture. Isole dans sa propre fonction pour que le
/// perimetre soit lisible d'un coup d'oeil.
fn set_boot_next_variable(target: BootId) -> Result<(), BackendError> {
    enable_privilege()?;

    // Deux octets. Pas un de plus.
    let payload: [u8; 2] = target.to_le_bytes();

    let name_w = wide(WRITABLE_VARIABLE);
    let guid_w = wide(EFI_GLOBAL_GUID);

    // SAFETY: `name_w` et `guid_w` sont des tampons UTF-16 termines par un nul,
    // vivants pendant l'appel. `payload` fait exactement deux octets, la taille
    // annoncee. L'API lit ce tampon sans le conserver.
    let ok = unsafe {
        SetFirmwareEnvironmentVariableW(
            PCWSTR(name_w.as_ptr()),
            PCWSTR(guid_w.as_ptr()),
            Some(payload.as_ptr().cast()),
            payload.len() as u32,
        )
    };

    ok.map_err(|e| {
        // SAFETY: appel sans argument, sans effet de bord.
        let code = unsafe { GetLastError() };
        match code {
            ERROR_PRIVILEGE_NOT_HELD => BackendError::PrivilegeRequired,
            ERROR_INVALID_FUNCTION => BackendError::NotUefi,
            _ => BackendError::WriteRefused(format!("{e} (erreur Windows {})", code.0)),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_one_variable_name_is_ever_writable() {
        // Garde-fou de revue : la constante d'ecriture doit rester BootNext.
        assert_eq!(WRITABLE_VARIABLE, "BootNext");
        assert_ne!(WRITABLE_VARIABLE, VAR_BOOT_ORDER);
    }

    #[test]
    fn the_payload_is_always_exactly_two_bytes() {
        for id in [0u16, 1, 2, 0x1234, 0xFFFF] {
            assert_eq!(BootId(id).to_le_bytes().len(), 2);
        }
        assert_eq!(BootId(2).to_le_bytes(), [0x02, 0x00]);
        assert_eq!(BootId(0x1234).to_le_bytes(), [0x34, 0x12]);
    }

    #[test]
    fn the_namespace_guid_matches_the_uefi_specification() {
        assert_eq!(
            EFI_GLOBAL_GUID,
            bootsel_core::efi::Guid::EFI_GLOBAL_VARIABLE.to_braced()
        );
    }

    #[test]
    fn error_classification_never_invents_a_success() {
        assert!(matches!(
            classify("BootNext", ERROR_ENVVAR_NOT_FOUND),
            Ok(ReadOutcome::Absent)
        ));
        assert_eq!(
            classify("BootOrder", ERROR_PRIVILEGE_NOT_HELD).err(),
            Some(BackendError::PrivilegeRequired)
        );
        assert_eq!(
            classify("BootOrder", ERROR_INVALID_FUNCTION).err(),
            Some(BackendError::NotUefi)
        );
    }

    #[test]
    fn reading_is_possible_or_fails_cleanly_but_never_panics() {
        match read_state() {
            Ok(state) => assert!(state.get(VAR_BOOT_ORDER).is_some()),
            Err(BackendError::PrivilegeRequired) | Err(BackendError::NotUefi) => {}
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }

    #[test]
    fn writing_a_nonexistent_entry_is_refused_before_any_write() {
        // Si le firmware est lisible, viser une entree absente doit echouer a
        // l'etape de validation, sans jamais atteindre l'appel d'ecriture.
        let Ok(state) = read_state() else {
            return; // firmware inaccessible : rien a verifier ici
        };

        let absent = (0u16..=0xFFFF)
            .map(BootId)
            .find(|id| !state.contains_entry(*id))
            .expect("au moins un identifiant doit etre libre");

        let before = state.clone();
        let result = write_boot_next(absent);

        assert_eq!(result.err(), Some(BackendError::EntryNotFound(absent)));

        // Preuve que rien n'a ete ecrit.
        let after = read_state().expect("relecture");
        assert_eq!(
            bootsel_core::guard::diff(&before, &after),
            Vec::new(),
            "une ecriture a eu lieu alors que la cible etait invalide"
        );
    }
}
