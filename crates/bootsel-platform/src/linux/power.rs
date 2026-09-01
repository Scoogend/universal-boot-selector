//! Redemarrage de la machine, sous Linux.
//!
//! # Verrou d'armement
//!
//! Comme sous Windows, le redemarrage refuse de s'executer tant qu'il n'a pas
//! ete arme par le point d'entree de l'application. Ce verrou existe a la
//! suite d'un incident : un test appelait la fonction de redemarrage en
//! croyant qu'elle ne faisait rien, et a redemarre la machine de
//! developpement pendant `cargo test`.
//!
//! # Methode
//!
//! On passe par `systemctl reboot`, qui delegue a `systemd-logind`. C'est la
//! voie standard sur Debian et derivees, et elle laisse le systeme arreter
//! proprement ses services et demonter ses volumes. Un appel direct a
//! `reboot(2)` serait brutal et risquerait de perdre des donnees non ecrites,
//! ce qui contredirait la regle premiere du projet.
//!
//! La commande est invoquee avec des arguments separes, sans passer par un
//! interpreteur de commandes : aucune chaine n'est construite, donc aucune
//! surface d'injection.

use bootsel_core::backend::BackendError;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(not(test))]
use std::time::Duration;

/// Verrou d'armement. Voir la documentation du module.
static REBOOT_ARMED: AtomicBool = AtomicBool::new(false);

/// Delai au-dela duquel on considere que la commande ne repondra pas.
#[cfg(not(test))]
const TIMEOUT: Duration = Duration::from_secs(10);

/// Autorise le redemarrage pour la duree du processus.
///
/// **Appele uniquement par le point d'entree de l'application reelle**, jamais
/// par une bibliotheque ni par un test.
pub fn arm_reboot() {
    REBOOT_ARMED.store(true, Ordering::SeqCst);
}

/// Vrai si le redemarrage a ete arme par l'application.
pub fn is_reboot_armed() -> bool {
    REBOOT_ARMED.load(Ordering::SeqCst)
}

/// Redemarre la machine.
///
/// Refuse si [`arm_reboot`] n'a pas ete appele, et refuse a la compilation
/// dans tout binaire de test de ce crate.
pub fn reboot() -> Result<(), BackendError> {
    if !is_reboot_armed() {
        return Err(BackendError::Unsupported(
            "le redemarrage n a pas ete arme par l application : refus".to_string(),
        ));
    }

    #[cfg(test)]
    {
        Err(BackendError::Unsupported(
            "redemarrage indisponible dans un binaire de test".to_string(),
        ))
    }

    #[cfg(not(test))]
    {
        do_reboot()
    }
}

#[cfg(not(test))]
fn do_reboot() -> Result<(), BackendError> {
    use std::process::{Command, Stdio};

    // Arguments separes, aucun interpreteur, aucune chaine construite.
    let mut child = Command::new("systemctl")
        .arg("reboot")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            BackendError::Io(format!(
                "systemctl est introuvable ou n a pas pu etre lance : {e}"
            ))
        })?;

    // La machine part normalement en redemarrage avant que l on relise le
    // code de sortie ; ce delai n existe que pour ne jamais rester bloque.
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(BackendError::Io(format!(
                    "systemctl reboot a echoue (code {})",
                    status.code().unwrap_or(-1)
                )))
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                // Le redemarrage est probablement en cours : on ne tue pas le
                // processus, on rend simplement la main.
                return Ok(());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(BackendError::Io(format!("attente de systemctl : {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portion livree du fichier : tout ce qui precede le module de test.
    ///
    /// Deux precautions, apprises d un echec de CI :
    ///
    /// - les fins de ligne sont normalisees, car git peut livrer du CRLF sous
    ///   Windows et un motif ecrit avec des LF ne correspondrait plus ;
    /// - la coupure vise le **module** de test, pas le premier `#[cfg(test)]`
    ///   venu : il en existe a l interieur de fonctions, et couper la
    ///   amputerait le code livre que l on veut justement analyser.
    fn shipped_source() -> String {
        let source = include_str!("power.rs").replace("
", "
");
        match source.find("
#[cfg(test)]
mod tests") {
            Some(end) => source[..end].to_string(),
            None => source,
        }
    }

    #[test]
    fn reboot_refuses_while_unarmed() {
        assert!(!is_reboot_armed(), "aucun test ne doit armer le redemarrage");
        assert!(matches!(reboot(), Err(BackendError::Unsupported(_))));
    }

    #[test]
    fn the_system_call_is_absent_from_test_binaries() {
        assert!(
            shipped_source().contains("#[cfg(not(test))]\nfn do_reboot()"),
            "le redemarrage reel doit etre exclu des binaires de test"
        );
    }

    #[test]
    fn the_reboot_is_delegated_to_systemd_and_never_forced() {
        let code = shipped_source();

        // Voie propre : systemd arrete les services et demonte les volumes.
        assert!(code.contains("\"systemctl\""));
        assert!(code.contains("\"reboot\""));

        // Aucune methode brutale, qui perdrait les ecritures en attente.
        for forbidden in ["reboot(RB_", "RB_AUTOBOOT", "--force", "-f\"", "sync_and_reboot"] {
            assert!(
                !code.contains(forbidden),
                "redemarrage brutal interdit : {forbidden}"
            );
        }
    }

    #[test]
    fn the_command_is_built_from_separate_arguments_without_a_shell() {
        let code = shipped_source();

        // Arguments separes : rien n est concatene, donc rien n est injectable.
        assert!(code.contains(".arg(\"reboot\")"));
        for forbidden in ["sh -c", "\"bash\"", "format!(\"systemctl"] {
            assert!(
                !code.contains(forbidden),
                "aucune commande ne doit passer par un interpreteur : {forbidden}"
            );
        }
    }
}
