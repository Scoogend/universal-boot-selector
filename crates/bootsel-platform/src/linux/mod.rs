//! Backend Linux. **Lecture seule dans ce processus.**
//!
//! # Asymetrie assumee avec Windows
//!
//! Sous Linux, `/sys/firmware/efi/efivars/` est lisible par tout utilisateur :
//! la detection complete fonctionne **sans aucun privilege**. Aucune elevation
//! n'est donc demandee au lancement, contrairement a Windows ou meme lire
//! exige des droits administrateur.
//!
//! Seule l'ecriture de `BootNext` demande une elevation, au moment precis ou
//! l'utilisateur la declenche.

pub mod firmware;
pub mod power;
pub mod storage;

use bootsel_core::backend::{BackendError, BootBackend};
use bootsel_core::model::{BootId, FirmwareMode, FirmwareState, StorageDevice};
use std::path::{Path, PathBuf};

/// Backend Linux en lecture seule.
#[derive(Debug)]
pub struct LinuxBootBackend {
    /// Racine du systeme de fichiers. `/` en production, un repertoire
    /// temporaire dans les tests.
    root: PathBuf,
    read_only: bool,
}

impl Default for LinuxBootBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxBootBackend {
    pub fn new() -> Self {
        LinuxBootBackend {
            root: PathBuf::from("/"),
            read_only: false,
        }
    }

    /// Backend incapable d'ecrire, quoi qu'il arrive. Mode `--dry-run`.
    pub fn read_only() -> Self {
        LinuxBootBackend {
            root: PathBuf::from("/"),
            read_only: true,
        }
    }

    /// Backend operant sur une arborescence simulee. Reserve aux tests.
    pub fn with_root(root: impl AsRef<Path>) -> Self {
        LinuxBootBackend {
            root: root.as_ref().to_path_buf(),
            read_only: false,
        }
    }
}

impl BootBackend for LinuxBootBackend {
    fn firmware_mode(&self) -> Result<FirmwareMode, BackendError> {
        Ok(firmware::firmware_mode(&self.root))
    }

    fn read_state(&self) -> Result<FirmwareState, BackendError> {
        firmware::read_state(&self.root)
    }

    fn list_devices(&self) -> Result<Vec<StorageDevice>, BackendError> {
        storage::list_devices(&self.root)
    }

    fn set_boot_next(&self, _target: BootId) -> Result<(), BackendError> {
        // Aucune ecriture n'est possible depuis le processus d'interface.
        // L'ecriture appartient au helper privilegie, lance via pkexec.
        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }
        Err(BackendError::PrivilegeRequired)
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
        "linux"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_read_only_backend_refuses_writes_before_anything_else() {
        let b = LinuxBootBackend::read_only();
        assert!(b.is_read_only());
        assert_eq!(b.set_boot_next(BootId(2)), Err(BackendError::ReadOnlyMode));
        assert_eq!(b.reboot(), Err(BackendError::ReadOnlyMode));
    }

    #[test]
    fn the_default_backend_cannot_write_without_the_helper() {
        let b = LinuxBootBackend::new();
        assert_eq!(
            b.set_boot_next(BootId(2)),
            Err(BackendError::PrivilegeRequired)
        );
    }

    #[test]
    fn reboot_is_refused_unless_the_application_armed_it() {
        // Meme verrou que sous Windows : le redemarrage exige un armement
        // explicite, qu aucun test n effectue.
        assert!(!power::is_reboot_armed());
        assert!(matches!(
            LinuxBootBackend::new().reboot(),
            Err(BackendError::Unsupported(_))
        ));
    }

    #[test]
    fn detection_works_against_a_simulated_root() {
        use bootsel_core::efi::testdata;

        let root = std::env::temp_dir().join("bootsel-linux-backend");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(firmware::efivars_dir(&root)).expect("efivars");
        std::fs::create_dir_all(root.join("sys/block")).expect("sys/block");

        let put = |name: &str, value: Vec<u8>| {
            let mut raw = 0x0000_0007u32.to_le_bytes().to_vec();
            raw.extend_from_slice(&value);
            std::fs::write(
                firmware::efivars_dir(&root).join(firmware::variable_file_name(name)),
                raw,
            )
            .expect("fixture");
        };
        put("BootOrder", testdata::boot_order(&[1]));
        put("Boot0001", testdata::load_option_windows());

        let backend = LinuxBootBackend::with_root(&root);
        assert_eq!(backend.firmware_mode().unwrap(), FirmwareMode::Uefi);
        assert_eq!(backend.name(), "linux");

        let state = backend.read_state().expect("lecture");
        assert_eq!(state.boot_order(), Some(vec![BootId(1)]));
        assert!(backend.list_devices().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }
}
