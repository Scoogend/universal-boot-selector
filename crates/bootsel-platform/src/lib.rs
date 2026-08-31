//! # bootsel-platform
//!
//! Implementations systeme du trait [`BootBackend`](bootsel_core::BootBackend).
//!
//! Ce crate **lit** le firmware et le stockage. Il ne contient aucune fonction
//! capable d'ecrire une variable UEFI : l'unique ecriture du projet vit dans
//! `bootsel-helper`, un binaire separe et eleve.
//!
//! La selection de l'implementation se fait a la compilation (`cfg(windows)` /
//! `cfg(target_os = "linux")`) et a l'execution pour le backend simule.

#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(windows)]
pub mod elevate;
#[cfg(windows)]
pub mod windows;

use bootsel_core::backend::{BackendError, BootBackend};

/// Comment construire le backend au demarrage de l'application.
#[derive(Clone, Debug, Default)]
pub struct BackendOptions {
    /// Nom d'un scenario simule (`--mock-boot <nom>`). Court-circuite le
    /// systeme reel : aucun acces au firmware ni aux disques.
    pub mock_scenario: Option<String>,
    /// Interdit toute ecriture, quelle que soit la plateforme (`--dry-run`).
    pub read_only: bool,
    /// Autorise a demander une elevation si le firmware n'est pas lisible
    /// autrement. Sous Windows, cela declenche une invite UAC.
    ///
    /// A `false`, l'application reste strictement non privilegiee : elle
    /// affiche l'inventaire materiel et signale que les entrees UEFI n'ont pas
    /// ete lues.
    pub elevate: bool,
}

/// Construit le backend adapte a la plateforme et aux options.
pub fn create_backend(options: &BackendOptions) -> Result<Box<dyn BootBackend>, BackendError> {
    if let Some(name) = &options.mock_scenario {
        return create_mock(name, options.read_only);
    }

    #[cfg(windows)]
    {
        // Sans elevation, on livre le backend en lecture locale : l'inventaire
        // materiel reste disponible, les entrees UEFI non.
        if !options.elevate {
            let backend = if options.read_only {
                windows::WindowsBootBackend::read_only()
            } else {
                windows::WindowsBootBackend::new()
            };
            return Ok(Box::new(backend));
        }

        // Le processus est deja eleve : inutile de lancer le helper, la
        // lecture directe fonctionne et n'ouvre aucun canal supplementaire.
        if windows::firmware::can_read_firmware() {
            let backend = if options.read_only {
                windows::WindowsBootBackend::read_only()
            } else {
                windows::WindowsBootBackend::new()
            };
            return Ok(Box::new(backend));
        }

        let channel = elevate::launch_helper()?;
        let backend = if options.read_only {
            windows::elevated::ElevatedWindowsBackend::read_only(channel)
        } else {
            windows::elevated::ElevatedWindowsBackend::new(channel)
        };
        return Ok(Box::new(backend));
    }

    #[cfg(not(windows))]
    {
        Err(BackendError::Unsupported(
            "aucun backend n'est encore implemente pour cette plateforme".to_string(),
        ))
    }
}

#[cfg(feature = "mock")]
fn create_mock(name: &str, read_only: bool) -> Result<Box<dyn BootBackend>, BackendError> {
    let backend = bootsel_core::mock::scenario(name).ok_or_else(|| {
        BackendError::Unsupported(format!(
            "scenario simule inconnu : {name}. Disponibles : {}",
            bootsel_core::mock::SCENARIOS.join(", ")
        ))
    })?;

    Ok(Box::new(if read_only {
        backend.read_only()
    } else {
        backend
    }))
}

#[cfg(not(feature = "mock"))]
fn create_mock(_name: &str, _read_only: bool) -> Result<Box<dyn BootBackend>, BackendError> {
    Err(BackendError::Unsupported(
        "ce binaire a ete compile sans le mode simule (activer la fonctionnalite \"mock\")"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_native_backend_by_default() {
        let backend = create_backend(&BackendOptions::default()).expect("backend natif");
        assert!(!backend.is_read_only());
        #[cfg(windows)]
        assert_eq!(backend.name(), "windows");
    }

    #[test]
    fn read_only_option_is_honoured_by_the_native_backend() {
        let backend = create_backend(&BackendOptions {
            mock_scenario: None,
            read_only: true,
            elevate: false,
        })
        .expect("backend natif");
        assert!(backend.is_read_only());
    }

    #[cfg(feature = "mock")]
    #[test]
    fn builds_every_named_mock_scenario() {
        for name in bootsel_core::mock::SCENARIOS {
            let backend = create_backend(&BackendOptions {
                mock_scenario: Some(name.to_string()),
                read_only: false,
                elevate: false,
            })
            .unwrap_or_else(|e| panic!("{name} : {e}"));
            assert_eq!(backend.name(), "mock");
        }
    }

    #[cfg(feature = "mock")]
    #[test]
    fn an_unknown_scenario_is_rejected_with_a_helpful_message() {
        let err = create_backend(&BackendOptions {
            mock_scenario: Some("inexistant".into()),
            read_only: false,
            elevate: false,
        })
        .unwrap_err();
        assert!(matches!(err, BackendError::Unsupported(_)));
        assert!(err.to_string().contains("multi-os"), "doit lister les scenarios");
    }
}
