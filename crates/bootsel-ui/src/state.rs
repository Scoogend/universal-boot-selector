//! Etat partage de l'application.
//!
//! Un seul backend et une seule configuration, derriere un verrou. Le backend
//! peut etre remplace en cours de route — c'est ce qui se produit lorsque
//! l'utilisateur accepte une elevation : on passe d'un backend en lecture
//! locale a un backend disposant d'un canal vers le helper privilegie.

use bootsel_core::alias::Config;
use bootsel_core::backend::BootBackend;
use bootsel_platform::{create_backend, BackendOptions};
use std::sync::{Mutex, MutexGuard};

/// Options de demarrage, issues de la ligne de commande.
#[derive(Clone, Debug, Default)]
pub struct Startup {
    pub mock_scenario: Option<String>,
    pub read_only: bool,
    /// Tenter une elevation au lancement. Sous Windows, une invite UAC.
    pub elevate: bool,
}

impl Startup {
    fn options(&self, elevate: bool) -> BackendOptions {
        BackendOptions {
            mock_scenario: self.mock_scenario.clone(),
            read_only: self.read_only,
            elevate,
        }
    }
}

#[derive(Debug)]
struct Inner {
    backend: Box<dyn BootBackend>,
    config: Config,
    startup: Startup,
    elevated: bool,
}

/// Etat partage, tel que Tauri le distribue aux commandes.
#[derive(Debug)]
pub struct AppState(Mutex<Inner>);

#[derive(Debug)]
pub struct StateGuard<'a>(MutexGuard<'a, Inner>);

impl StateGuard<'_> {
    pub fn backend(&self) -> &dyn BootBackend {
        self.0.backend.as_ref()
    }

    pub fn config(&self) -> &Config {
        &self.0.config
    }

    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.0.config
    }

    /// Vrai si un backend privilegie est deja en place.
    pub fn is_elevated(&self) -> bool {
        self.0.elevated
    }

    /// Remplace le backend par un backend eleve.
    ///
    /// Declenche l'invite UAC. En cas de refus, l'etat reste **inchange** :
    /// l'ancien backend continue de servir et l'application reste utilisable.
    pub fn elevate(&mut self) -> Result<(), String> {
        if self.0.elevated {
            return Ok(());
        }

        let options = self.0.startup.options(true);
        match create_backend(&options) {
            Ok(backend) => {
                self.0.backend = backend;
                self.0.elevated = true;
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

impl AppState {
    /// Construit l'etat initial.
    ///
    /// L'elevation demandee au lancement n'est pas bloquante : si elle echoue
    /// ou si l'utilisateur la refuse, on retombe sur un backend non
    /// privilegie plutot que de refuser de demarrer.
    pub fn new(startup: Startup) -> Result<AppState, String> {
        let (backend, elevated) = match create_backend(&startup.options(startup.elevate)) {
            Ok(backend) => (backend, startup.elevate),
            Err(_) if startup.elevate => {
                // Repli silencieux : l'interface signalera que les entrees
                // UEFI n'ont pas ete lues et proposera de reessayer.
                let fallback = create_backend(&startup.options(false))
                    .map_err(|e| format!("aucun backend disponible : {e}"))?;
                (fallback, false)
            }
            Err(e) => return Err(format!("aucun backend disponible : {e}")),
        };

        Ok(AppState(Mutex::new(Inner {
            backend,
            config: crate::config_store::load(),
            startup,
            elevated,
        })))
    }

    pub fn lock(&self) -> Result<StateGuard<'_>, String> {
        self.0
            .lock()
            .map(StateGuard)
            .map_err(|_| "etat de l application corrompu".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mock_backend_starts_without_any_elevation() {
        let state = AppState::new(Startup {
            mock_scenario: Some("multi-os".into()),
            read_only: false,
            elevate: false,
        })
        .expect("etat construit");

        let guard = state.lock().expect("verrou");
        assert_eq!(guard.backend().name(), "mock");
        assert!(!guard.is_elevated());
    }

    #[test]
    fn read_only_startup_produces_a_backend_that_refuses_to_write() {
        let state = AppState::new(Startup {
            mock_scenario: Some("windows-debian".into()),
            read_only: true,
            elevate: false,
        })
        .expect("etat construit");

        let guard = state.lock().expect("verrou");
        assert!(guard.backend().is_read_only());
    }

    #[test]
    fn an_unknown_scenario_is_reported_rather_than_silently_ignored() {
        let error = AppState::new(Startup {
            mock_scenario: Some("inexistant".into()),
            read_only: false,
            elevate: false,
        })
        .unwrap_err();
        assert!(error.contains("aucun backend disponible"));
    }

    #[test]
    fn the_configuration_is_loaded_at_startup() {
        let state = AppState::new(Startup {
            mock_scenario: Some("windows-only".into()),
            read_only: false,
            elevate: false,
        })
        .expect("etat construit");

        let guard = state.lock().expect("verrou");
        assert_eq!(
            guard.config().version,
            bootsel_core::alias::CONFIG_VERSION
        );
    }
}
