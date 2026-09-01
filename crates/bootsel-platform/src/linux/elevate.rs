//! Elevation ponctuelle sous Linux, par `pkexec`.
//!
//! # Pourquoi une invocation ponctuelle et non un service
//!
//! Sous Linux, `/sys/firmware/efi/efivars` est lisible par tout utilisateur :
//! la detection complete fonctionne sans privilege. Seule l'ecriture en
//! demande. Faire vivre un processus privilegie pendant toute la session
//! n'aurait donc aucune contrepartie : le helper est lance pour une operation,
//! et meurt aussitot.
//!
//! Une requete sur l'entree standard, une reponse sur la sortie, et c'est
//! fini. La ligne de commande ne porte aucun parametre : la cible voyage dans
//! le JSON, ce qui evite toute question d'echappement d'arguments.

use bootsel_core::backend::BackendError;
use bootsel_core::ipc::{Request, Response};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Delai au-dela duquel on considere que l'utilisateur ne repondra pas a
/// l'invite d'authentification.
const TIMEOUT_SECS: u64 = 120;

/// Chemin attendu du helper : a cote de l'executable courant.
///
/// On ne cherche pas dans le `PATH` : un binaire privilegie ne doit pas
/// pouvoir etre substitue par un homonyme place dans un repertoire
/// inscriptible.
pub fn helper_path() -> Result<PathBuf, BackendError> {
    let exe = std::env::current_exe()
        .map_err(|e| BackendError::Io(format!("chemin de l'executable : {e}")))?;
    let candidate = exe
        .parent()
        .ok_or_else(|| BackendError::Io("executable sans repertoire parent".into()))?
        .join("bootsel-helper");

    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(BackendError::Io(format!(
            "le composant privilegie est introuvable : {}",
            candidate.display()
        )))
    }
}

/// Execute une requete privilegiee via `pkexec`.
///
/// Affiche une invite d'authentification. Un refus n'est pas une panne :
/// l'application revient simplement a son etat precedent.
pub fn run_privileged(request: &Request) -> Result<Response, BackendError> {
    let helper = helper_path()?;

    let encoded = serde_json::to_string(request)
        .map_err(|e| BackendError::Io(format!("serialisation de la requete : {e}")))?;

    // Arguments separes, aucun interpreteur, aucune donnee utilisateur sur la
    // ligne de commande.
    let mut child = Command::new("pkexec")
        .arg(&helper)
        .arg("--oneshot")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            BackendError::Io(format!(
                "pkexec est introuvable ou n'a pas pu etre lance : {e}"
            ))
        })?;

    child
        .stdin
        .as_mut()
        .ok_or_else(|| BackendError::Io("entree du composant privilegie indisponible".into()))?
        .write_all(format!("{encoded}\n").as_bytes())
        .map_err(|e| BackendError::Io(format!("envoi au composant privilegie : {e}")))?;

    // Fermer l'entree signale au helper que la requete est complete.
    drop(child.stdin.take());

    let output = wait_with_timeout(child)?;

    if !output.status.success() {
        // 126 et 127 sont les codes que pkexec renvoie quand l'utilisateur
        // annule l'invite ou n'est pas autorise.
        return match output.status.code() {
            Some(126) | Some(127) => Err(BackendError::PrivilegeRequired),
            _ => Err(BackendError::Io(format!(
                "le composant privilegie a echoue : {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))),
        };
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| {
            BackendError::Io("le composant privilegie n'a rien renvoye d'exploitable".into())
        })?;

    serde_json::from_str::<Response>(line)
        .map_err(|e| BackendError::Io(format!("reponse illisible : {e}")))
}

fn wait_with_timeout(
    mut child: std::process::Child,
) -> Result<std::process::Output, BackendError> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(TIMEOUT_SECS);

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| BackendError::Io(format!("lecture de la reponse : {e}")))
            }
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                return Err(BackendError::Io(
                    "aucune reponse a l'invite d'authentification".into(),
                ));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(e) => return Err(BackendError::Io(format!("attente du helper : {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portion livree du fichier, pour les controles de revue.
    fn shipped_source() -> String {
        let source = include_str!("elevate.rs").replace("\r\n", "\n");
        match source.find("\n#[cfg(test)]\nmod tests") {
            Some(end) => source[..end].to_string(),
            None => source,
        }
    }

    #[test]
    fn the_helper_is_looked_up_beside_the_executable_never_in_the_path() {
        let exe = std::env::current_exe().expect("chemin de l'executable");
        match helper_path() {
            Ok(path) => {
                assert!(path.is_absolute());
                assert_eq!(path.parent(), exe.parent());
                assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("bootsel-helper"));
            }
            // Cas normal quand le helper n'est pas a cote pendant les tests.
            Err(BackendError::Io(_)) => {}
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }

    #[test]
    fn the_command_carries_no_user_supplied_argument() {
        // Garde-fou de revue : la cible voyage dans le JSON sur l'entree
        // standard, jamais sur la ligne de commande. Aucun echappement a
        // maitriser, donc aucune injection possible.
        let code = shipped_source();
        assert!(code.contains(".arg(\"--oneshot\")"));
        for forbidden in ["format!(\"--", "sh -c", "\"bash\"", ".args(", "shell"] {
            assert!(
                !code.contains(forbidden),
                "aucun argument construit dynamiquement : {forbidden}"
            );
        }
    }

    #[test]
    fn a_cancelled_authentication_is_not_treated_as_a_crash() {
        // pkexec renvoie 126 ou 127 quand l'utilisateur annule.
        let code = shipped_source();
        assert!(code.contains("Some(126) | Some(127)"));
        assert!(code.contains("PrivilegeRequired"));
    }

    #[test]
    fn a_refused_elevation_guarantees_no_write() {
        assert!(BackendError::PrivilegeRequired.guarantees_no_write());
    }
}
