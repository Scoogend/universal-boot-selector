//! Backend Windows. **Lecture seule dans ce processus.**
//!
//! L'ecriture de `BootNext` et le redemarrage ne sont pas implementes ici :
//! ils appartiennent au helper privilegie. Ce backend refuse explicitement ces
//! operations tant qu'aucun canal vers le helper n'a ete etabli, ce qui rend
//! structurellement impossible qu'un bug de l'interface declenche une ecriture.

pub mod firmware;
pub mod storage;

use bootsel_core::backend::{BackendError, BootBackend};
use bootsel_core::model::{BootId, FirmwareMode, FirmwareState, StorageDevice};

/// Backend Windows en lecture seule.
#[derive(Debug, Default)]
pub struct WindowsBootBackend {
    /// Interdit toute ecriture, meme lorsqu'un helper sera disponible.
    read_only: bool,
}

impl WindowsBootBackend {
    pub fn new() -> Self {
        WindowsBootBackend { read_only: false }
    }

    /// Backend incapable d'ecrire, quoi qu'il arrive. Mode `--dry-run`.
    pub fn read_only() -> Self {
        WindowsBootBackend { read_only: true }
    }

    /// Vrai si le processus courant peut deja lire le firmware, c'est-a-dire
    /// s'il est eleve. Sert a decider s'il faut demander une elevation.
    pub fn can_read_firmware(&self) -> bool {
        firmware::can_read_firmware()
    }
}

impl BootBackend for WindowsBootBackend {
    fn firmware_mode(&self) -> Result<FirmwareMode, BackendError> {
        firmware::firmware_mode()
    }

    fn read_state(&self) -> Result<FirmwareState, BackendError> {
        firmware::read_state()
    }

    fn list_devices(&self) -> Result<Vec<StorageDevice>, BackendError> {
        storage::list_devices()
    }

    fn set_boot_next(&self, _target: BootId) -> Result<(), BackendError> {
        // Aucune ecriture n'est possible depuis le processus d'interface.
        // Le helper privilegie, seul habilite, sera branche en phase 5.
        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }
        Err(BackendError::PrivilegeRequired)
    }

    fn reboot(&self) -> Result<(), BackendError> {
        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }
        Err(BackendError::PrivilegeRequired)
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn name(&self) -> &'static str {
        "windows"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_read_only_backend_refuses_writes_before_anything_else() {
        let b = WindowsBootBackend::read_only();
        assert!(b.is_read_only());
        assert_eq!(b.set_boot_next(BootId(2)), Err(BackendError::ReadOnlyMode));
        assert_eq!(b.reboot(), Err(BackendError::ReadOnlyMode));
    }

    #[test]
    fn the_default_backend_cannot_write_either_without_the_helper() {
        let b = WindowsBootBackend::new();
        assert_eq!(b.set_boot_next(BootId(2)), Err(BackendError::PrivilegeRequired));
        assert_eq!(b.reboot(), Err(BackendError::PrivilegeRequired));
    }

    #[test]
    fn detection_works_on_this_machine_without_elevation() {
        let b = WindowsBootBackend::new();

        // Non privilegie : doit toujours reussir.
        assert!(b.firmware_mode().is_ok());
        assert!(!b.list_devices().expect("inventaire disques").is_empty());

        // Privilegie : peut echouer proprement, jamais paniquer.
        match b.read_state() {
            Ok(_) | Err(BackendError::PrivilegeRequired) | Err(BackendError::NotUefi) => {}
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }
}
