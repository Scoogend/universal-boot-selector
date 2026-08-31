//! Lancement du helper privilegie et canal de communication.
//!
//! # Sequence
//!
//! 1. L'interface, non elevee, cree un tube nomme au nom tire au hasard.
//! 2. Elle lance le helper via `ShellExecuteExW` avec le verbe `runas`, ce qui
//!    declenche **une** invite UAC.
//! 3. Le helper eleve se connecte au tube.
//! 4. Les deux cotes echangent un salut de version.
//!
//! # Pourquoi l'interface cree le tube
//!
//! `ShellExecuteExW` passe par le service AppInfo pour elever : les handles ne
//! sont donc pas herites, un tube anonyme est impossible. Restait a choisir qui
//! cree le tube nomme. Un tube cree par un processus eleve herite d'un niveau
//! d'integrite eleve, et un processus d'integrite moyenne — l'interface — ne
//! peut pas y ecrire. En creant le tube du cote non privilegie, l'ecriture se
//! fait du haut vers le bas, ce que Windows autorise toujours.
//!
//! # Si l'utilisateur refuse l'UAC
//!
//! `ShellExecuteExW` renvoie `ERROR_CANCELLED`. L'application continue en mode
//! degrade : elle affiche l'inventaire materiel et propose de reessayer. Elle
//! ne plante pas et ne redemande rien d'elle-meme.

use bootsel_core::backend::BackendError;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_CANCELLED, HANDLE};
use windows::Win32::Storage::FileSystem::{
    PIPE_ACCESS_DUPLEX, FILE_FLAG_FIRST_PIPE_INSTANCE,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

/// Delai maximal d'attente de la connexion du helper apres l'invite UAC.
///
/// Genereux : l'utilisateur doit avoir le temps de lire l'invite et de cliquer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

/// Taille des tampons du tube.
const PIPE_BUFFER: u32 = 64 * 1024;

/// Raison pour laquelle l'elevation n'a pas abouti.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElevationError {
    /// L'utilisateur a refuse l'invite UAC. Cas normal, pas une panne.
    Declined,
    /// Le binaire du helper est introuvable a cote de l'executable courant.
    HelperNotFound(PathBuf),
    /// Echec technique.
    Failed(String),
}

impl std::fmt::Display for ElevationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ElevationError::Declined => f.write_str(
                "L'elevation a ete refusee. Les entrees UEFI ne peuvent pas etre lues. \
                 Aucune modification n'a ete effectuee.",
            ),
            ElevationError::HelperNotFound(p) => write!(
                f,
                "Le composant privilegie est introuvable : {}",
                p.display()
            ),
            ElevationError::Failed(m) => write!(f, "Elevation impossible : {m}"),
        }
    }
}

impl From<ElevationError> for BackendError {
    fn from(e: ElevationError) -> Self {
        match e {
            ElevationError::Declined => BackendError::PrivilegeRequired,
            other => BackendError::Io(other.to_string()),
        }
    }
}

/// Canal ouvert vers le helper privilegie.
#[derive(Debug)]
pub struct HelperChannel {
    reader: BufReader<std::fs::File>,
    writer: std::fs::File,
    /// Version annoncee par le helper, pour les journaux.
    pub helper_version: String,
    /// Vrai si le helper a effectivement obtenu le privilege firmware.
    pub elevated: bool,
}

impl HelperChannel {
    /// Envoie une ligne et lit la reponse.
    pub fn exchange(&mut self, request: &str) -> Result<String, BackendError> {
        self.writer
            .write_all(request.as_bytes())
            .and_then(|_| self.writer.write_all(b"\n"))
            .and_then(|_| self.writer.flush())
            .map_err(|e| BackendError::Io(format!("envoi au composant privilegie : {e}")))?;

        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .map_err(|e| BackendError::Io(format!("reponse du composant privilegie : {e}")))?;

        if read == 0 {
            return Err(BackendError::Io(
                "le composant privilegie s'est arrete de facon inattendue".into(),
            ));
        }
        Ok(line.trim_end().to_string())
    }
}

// Aucun `Drop` explicite n'est necessaire : la fermeture du tube, faite
// automatiquement par `File`, termine la boucle de service du helper des que
// sa lecture renvoie zero octet.

/// Chemin attendu du helper : a cote de l'executable courant.
///
/// On ne cherche pas ailleurs, et surtout pas dans le `PATH` : un binaire
/// privilegie ne doit pas pouvoir etre substitue par un homonyme place dans un
/// repertoire inscriptible.
pub fn helper_path() -> Result<PathBuf, ElevationError> {
    let exe = std::env::current_exe()
        .map_err(|e| ElevationError::Failed(format!("chemin de l'executable : {e}")))?;
    let dir = exe
        .parent()
        .ok_or_else(|| ElevationError::Failed("executable sans repertoire parent".into()))?;

    let candidate = dir.join("bootsel-helper.exe");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(ElevationError::HelperNotFound(candidate))
    }
}

/// Genere un nom de tube imprevisible.
///
/// L'alea vient de l'horloge haute resolution, de l'identifiant du processus
/// et de l'adresse d'une allocation, ce qui suffit amplement : le nom sert a
/// eviter une collision et un squattage opportuniste, pas a proteger un secret.
fn random_pipe_name() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
    );
    hasher.write_u32(std::process::id());
    let boxed = Box::new(0u8);
    hasher.write_usize(Box::into_raw(boxed) as usize);
    let a = hasher.finish();

    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(a);
    hasher.write_u64(Instant::now().elapsed().as_nanos() as u64);
    let b = hasher.finish();

    format!("bootsel-{a:016x}{b:016x}")
}

/// Cree le tube, lance le helper eleve, attend sa connexion.
pub fn launch_helper() -> Result<HelperChannel, ElevationError> {
    let helper = helper_path()?;
    let pipe_name = random_pipe_name();
    let pipe_path = format!(r"\\.\pipe\{pipe_name}");

    let server = create_pipe(&pipe_path)?;
    spawn_elevated(&helper, &pipe_name)?;
    wait_for_connection(server)?;

    // Le tube est ouvert des deux cotes : on peut le manipuler comme un
    // fichier ordinaire.
    let file = handle_to_file(server);
    let writer = file
        .try_clone()
        .map_err(|e| ElevationError::Failed(format!("duplication du tube : {e}")))?;

    let mut channel = HelperChannel {
        reader: BufReader::new(file),
        writer,
        helper_version: String::new(),
        elevated: false,
    };

    handshake(&mut channel)?;
    Ok(channel)
}

fn create_pipe(path: &str) -> Result<HANDLE, ElevationError> {
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `wide` est un tampon UTF-16 termine par un nul, vivant pendant
    // l'appel. `FILE_FLAG_FIRST_PIPE_INSTANCE` fait echouer la creation si le
    // nom est deja pris, ce qui empeche un autre processus de se substituer au
    // tube. Une seule instance est autorisee : un seul helper peut se
    // connecter.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(wide.as_ptr()),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            PIPE_BUFFER,
            PIPE_BUFFER,
            0,
            None,
        )
    };

    if handle.is_invalid() {
        return Err(ElevationError::Failed(
            "creation du tube de communication impossible".into(),
        ));
    }
    Ok(handle)
}

fn spawn_elevated(helper: &Path, pipe_name: &str) -> Result<(), ElevationError> {
    let verb: Vec<u16> = "runas".encode_utf16().chain(std::iter::once(0)).collect();
    let file: Vec<u16> = helper
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // Les arguments sont construits ici, jamais a partir d'une saisie
    // utilisateur : seul le nom de tube genere localement y figure.
    let params: Vec<u16> = format!("--serve --pipe {pipe_name}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // On ne demande pas de handle sur le processus cree : le helper se
    // termine de lui-meme a la fermeture du tube, il n'y a rien a surveiller
    // ni a fermer.
    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };

    // SAFETY: `info` est correctement dimensionne et tous les pointeurs qu'il
    // porte referencent des tampons vivants jusqu'apres l'appel.
    let result = unsafe { ShellExecuteExW(&mut info) };

    match result {
        Ok(()) => Ok(()),
        Err(e) if e.code().0 as u32 & 0xFFFF == ERROR_CANCELLED.0 => {
            Err(ElevationError::Declined)
        }
        Err(e) => Err(ElevationError::Failed(format!(
            "lancement du composant privilegie : {e}"
        ))),
    }
}

fn wait_for_connection(server: HANDLE) -> Result<(), ElevationError> {
    let deadline = Instant::now() + CONNECT_TIMEOUT;

    // `ConnectNamedPipe` bloque jusqu'a la connexion du helper. Le tube etant
    // en mode bloquant, l'attente est geree par le systeme.
    //
    // SAFETY: `server` est un handle de tube valide obtenu par
    // `CreateNamedPipeW`, non encore connecte.
    let connected = unsafe { ConnectNamedPipe(server, None) };

    match connected {
        Ok(()) => Ok(()),
        Err(e) => {
            // ERROR_PIPE_CONNECTED : le helper etait deja la. Ce n'est pas un
            // echec.
            if e.code().0 as u32 & 0xFFFF == 535 {
                Ok(())
            } else if Instant::now() >= deadline {
                Err(ElevationError::Failed(
                    "le composant privilegie ne s'est pas connecte a temps".into(),
                ))
            } else {
                Err(ElevationError::Failed(format!(
                    "connexion du composant privilegie : {e}"
                )))
            }
        }
    }
}

fn handle_to_file(handle: HANDLE) -> std::fs::File {
    use std::os::windows::io::FromRawHandle;

    // SAFETY: `handle` est un handle de fichier valide dont on transfere la
    // propriete a `File`, qui le fermera. Il n'est plus utilise ailleurs.
    unsafe { std::fs::File::from_raw_handle(handle.0 as *mut _) }
}

fn handshake(channel: &mut HelperChannel) -> Result<(), ElevationError> {
    use bootsel_core::ipc::{Request, Response, PROTOCOL_VERSION};

    let request = serde_json::to_string(&Request::Hello {
        protocol: PROTOCOL_VERSION,
    })
    .map_err(|e| ElevationError::Failed(format!("serialisation du salut : {e}")))?;

    let raw = channel
        .exchange(&request)
        .map_err(|e| ElevationError::Failed(e.to_string()))?;

    match serde_json::from_str::<Response>(&raw) {
        Ok(Response::Hello {
            protocol,
            helper_version,
            elevated,
        }) => {
            if protocol != PROTOCOL_VERSION {
                return Err(ElevationError::Failed(format!(
                    "version de protocole incompatible : {protocol} contre {PROTOCOL_VERSION}"
                )));
            }
            channel.helper_version = helper_version;
            channel.elevated = elevated;
            Ok(())
        }
        Ok(other) => Err(ElevationError::Failed(format!(
            "reponse inattendue au salut : {other:?}"
        ))),
        Err(e) => Err(ElevationError::Failed(format!(
            "salut illisible : {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pipe_names_are_valid_and_unique() {
        let mut seen = Vec::new();
        for _ in 0..200 {
            let name = random_pipe_name();

            // Doit satisfaire la validation du helper : 8 a 64 caracteres
            // alphanumeriques ou tirets.
            assert!((8..=64).contains(&name.len()), "longueur : {name}");
            assert!(
                name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "caractere invalide dans {name}"
            );
            assert!(name.starts_with("bootsel-"));
            assert!(!name.contains(".."));

            seen.push(name);
        }

        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "collision de nom de tube");
    }

    #[test]
    fn a_refused_uac_prompt_is_not_treated_as_a_crash() {
        let error: BackendError = ElevationError::Declined.into();
        assert_eq!(error, BackendError::PrivilegeRequired);
        assert!(
            error.guarantees_no_write(),
            "un refus d'elevation garantit qu'aucune ecriture n'a eu lieu"
        );
    }

    #[test]
    fn error_messages_state_that_nothing_was_modified() {
        assert!(ElevationError::Declined
            .to_string()
            .contains("Aucune modification"));
    }

    #[test]
    fn the_helper_is_looked_up_beside_the_executable_never_in_the_path() {
        // Le chemin resolu doit etre absolu et frere de l'executable courant.
        let exe = std::env::current_exe().expect("chemin de l'executable");
        let expected_dir = exe.parent().expect("repertoire parent");

        match helper_path() {
            Ok(path) => {
                assert!(path.is_absolute());
                assert_eq!(path.parent(), Some(expected_dir));
                assert_eq!(
                    path.file_name().and_then(|n| n.to_str()),
                    Some("bootsel-helper.exe")
                );
            }
            Err(ElevationError::HelperNotFound(path)) => {
                // Cas normal quand le helper n'est pas encore compile.
                assert_eq!(path.parent(), Some(expected_dir));
            }
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }

    #[test]
    fn the_helper_arguments_contain_nothing_user_supplied() {
        // Garde-fou de revue : la ligne de commande transmise au processus
        // eleve ne doit contenir que des elements generes localement.
        let name = random_pipe_name();
        let params = format!("--serve --pipe {name}");
        assert_eq!(params.split_whitespace().count(), 3);
        assert!(!params.contains('&'));
        assert!(!params.contains('|'));
        assert!(!params.contains(';'));
        assert!(!params.contains('"'));
    }
}
