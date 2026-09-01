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

/// Vrai si l'application s'execute depuis une AppImage.
///
/// Une AppImage se monte en FUSE **sans** l'option `allow_other` :
/// `(ro,nosuid,nodev,user_id=1000,group_id=1000)`. Seul l'utilisateur qui l'a
/// lancee voit son contenu — **root en est exclu**. `pkexec` ne peut donc pas
/// executer un binaire situe a l'interieur.
fn inside_appimage(helper: &std::path::Path) -> bool {
    // `Path::starts_with` raisonne en composants entiers : « /tmp/.mount_ »
    // n'en est pas un. La comparaison doit donc se faire sur le texte.
    std::env::var_os("APPIMAGE").is_some()
        || std::env::var_os("APPDIR").is_some()
        || helper.to_string_lossy().starts_with("/tmp/.mount_")
}

/// Copie du helper placee la ou root peut la lire.
///
/// Supprimee des que l'operation est terminee.
struct StagedHelper {
    path: PathBuf,
}

impl Drop for StagedHelper {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Recopie le helper hors de l'AppImage, dans un emplacement que root peut
/// atteindre.
///
/// # Ou, et pourquoi la
///
/// Dans `$XDG_RUNTIME_DIR` — typiquement `/run/user/1000` — qui presente
/// exactement les proprietes voulues : cree par le systeme en mode `0700`,
/// appartenant a l'utilisateur, sur un systeme de fichiers ordinaire que root
/// lit sans entrave. Aucun **autre** utilisateur ne peut y ecrire, donc
/// personne d'autre ne peut substituer le binaire avant son execution.
///
/// La copie est ensuite passee en lecture et execution seules (`0500`) : meme
/// son proprietaire ne peut plus la modifier sans en changer les droits.
///
/// Reste le cas d'un processus hostile tournant sous **le meme utilisateur**.
/// Celui-la peut deja modifier l'AppImage elle-meme, ou le raccourci qui la
/// lance : ce n'est pas une frontiere de privilege que ce code puisse
/// defendre, et pretendre le contraire serait malhonnete.
fn stage_helper(source: &std::path::Path) -> Result<StagedHelper, BackendError> {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .ok_or_else(|| {
            BackendError::Io(
                "aucun repertoire d'execution utilisateur disponible pour extraire le \
                 composant privilegie ; installez plutot le paquet .deb"
                    .into(),
            )
        })?;

    // Nom imprevisible : deux instances simultanees ne se marchent pas dessus.
    let unique = format!(
        "bootsel-helper-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    );
    let path = directory.join(unique);

    std::fs::copy(source, &path).map_err(|e| {
        BackendError::Io(format!("extraction du composant privilegie : {e}"))
    })?;

    // Lecture et execution seules : plus modifiable en l'etat.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).map_err(|e| {
        let _ = std::fs::remove_file(&path);
        BackendError::Io(format!("droits du composant privilegie : {e}"))
    })?;

    Ok(StagedHelper { path })
}

/// Execute une requete privilegiee via `pkexec`.
///
/// Affiche une invite d'authentification. Un refus n'est pas une panne :
/// l'application revient simplement a son etat precedent.
pub fn run_privileged(request: &Request) -> Result<Response, BackendError> {
    let installed = helper_path()?;

    // Depuis une AppImage, root ne voit pas le contenu du montage : on lui
    // presente une copie a un endroit qu'il peut lire.
    let staged = if inside_appimage(&installed) {
        Some(stage_helper(&installed)?)
    } else {
        None
    };
    let helper = staged
        .as_ref()
        .map(|s| s.path.clone())
        .unwrap_or(installed);

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
    fn an_appimage_is_detected_from_its_mount_path() {
        // Le montage FUSE d'une AppImage vit toujours sous /tmp/.mount_.
        assert!(inside_appimage(std::path::Path::new(
            "/tmp/.mount_UniverpBkoAc/usr/bin/bootsel-helper"
        )));
    }

    #[test]
    fn a_normally_installed_helper_is_not_staged() {
        // Installe par le .deb, le helper est deja lisible par root : le
        // recopier serait inutile et elargirait la surface pour rien.
        let installed = std::path::Path::new("/usr/bin/bootsel-helper");
        let is_appimage = std::env::var_os("APPIMAGE").is_some()
            || std::env::var_os("APPDIR").is_some();
        if !is_appimage {
            assert!(!inside_appimage(installed));
        }
    }

    #[test]
    fn the_staged_copy_is_not_writable() {
        // Garde-fou de revue : la copie doit etre passee en 0500, sans quoi
        // elle pourrait etre substituee avant son execution par root.
        let code = shipped_source();
        assert!(code.contains("from_mode(0o500)"));
        assert!(code.contains("XDG_RUNTIME_DIR"));
        // Et jamais dans un repertoire partage entre utilisateurs.
        assert!(!code.contains("\"/tmp\""));
        assert!(!code.contains("temp_dir()"));
    }

    #[test]
    fn the_staged_copy_is_removed_afterwards() {
        let code = shipped_source();
        assert!(code.contains("impl Drop for StagedHelper"));
        assert!(code.contains("remove_file"));
    }

    #[test]
    fn a_refused_elevation_guarantees_no_write() {
        assert!(BackendError::PrivilegeRequired.guarantees_no_write());
    }
}
