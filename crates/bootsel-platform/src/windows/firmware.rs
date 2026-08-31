//! Acces aux variables de demarrage du firmware, sous Windows.
//!
//! # Privileges
//!
//! Sous Windows, **meme la lecture** d'une variable UEFI exige le privilege
//! `SE_SYSTEM_ENVIRONMENT_NAME`, detenu par les seuls administrateurs. Un appel
//! sans ce privilege echoue avec `ERROR_PRIVILEGE_NOT_HELD` (1314). Il n'existe
//! aucune API non privilegiee equivalente : ce module renvoie donc
//! [`BackendError::PrivilegeRequired`] plutot que de tenter un contournement.
//!
//! # Ce que ce module ne fait pas
//!
//! Il **lit** uniquement. L'ecriture de `BootNext` vit dans `bootsel-helper`,
//! le seul binaire eleve du projet. Aucune fonction d'ecriture n'est definie
//! ici, ce qui rend impossible d'en appeler une par erreur depuis le processus
//! d'interface.

use bootsel_core::backend::BackendError;
use bootsel_core::model::{
    BootId, FirmwareMode, FirmwareState, VAR_BOOT_CURRENT, VAR_BOOT_NEXT, VAR_BOOT_ORDER,
};
use std::collections::BTreeMap;
use windows::core::PCWSTR;
use std::sync::OnceLock;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ENVVAR_NOT_FOUND, ERROR_INVALID_FUNCTION,
    ERROR_NOT_ALL_ASSIGNED, ERROR_PRIVILEGE_NOT_HELD, HANDLE, LUID, WIN32_ERROR,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SYSTEM_ENVIRONMENT_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::SystemInformation::{
    FirmwareTypeUefi, GetFirmwareType, FIRMWARE_TYPE,
};
use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;

/// GUID de l'espace de nommage des variables globales UEFI, forme attendue par
/// l'API Windows (avec accolades).
const EFI_GLOBAL_GUID: &str = "{8be4df61-93ca-11d2-aa0d-00e098032b8c}";

/// Taille du tampon de lecture. Une entree `Boot####` depasse rarement 1 Kio ;
/// 8 Kio couvre tres largement les descriptions et donnees optionnelles les
/// plus verbeuses sans allouer inutilement.
const MAX_VARIABLE_SIZE: usize = 8192;

/// Borne du balayage des entrees absentes de `BootOrder`.
///
/// Les firmwares attribuent des identifiants bas et contigus. Balayer les
/// 65 536 possibilites couterait plusieurs secondes pour ne rien trouver de
/// plus ; on se limite donc a cette plage, en plus de tout ce que `BootOrder`
/// designe explicitement.
const PROBE_LIMIT: u16 = 0x0200;

/// Convertit une chaine Rust en tampon UTF-16 termine par un nul.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Mode de demarrage de la machine. **Non privilegie.**
pub fn firmware_mode() -> Result<FirmwareMode, BackendError> {
    let mut kind = FIRMWARE_TYPE::default();

    // SAFETY: `GetFirmwareType` ecrit un unique `FIRMWARE_TYPE` a l'adresse
    // fournie. `kind` est une variable locale valide et correctement alignee,
    // vivante pendant toute la duree de l'appel.
    let ok = unsafe { GetFirmwareType(&mut kind) };

    match ok {
        Ok(()) if kind == FirmwareTypeUefi => Ok(FirmwareMode::Uefi),
        Ok(()) => Ok(FirmwareMode::LegacyBios),
        // L'API n'a pas su conclure. On ne devine pas : refuser vaut mieux que
        // supposer a tort que la machine est en UEFI.
        Err(e) => Err(BackendError::FirmwareUnavailable(format!(
            "GetFirmwareType a echoue : {e}"
        ))),
    }
}

/// Resultat de la lecture d'une variable.
enum ReadOutcome {
    Found(Vec<u8>),
    /// La variable n'existe pas. Situation normale : `BootNext` est absente la
    /// plupart du temps.
    Absent,
}

/// Lit une variable du firmware. **Lecture seule, privilegiee.**
fn read_variable(name: &str) -> Result<ReadOutcome, BackendError> {
    // Etre administrateur ne suffit pas : le privilege est present dans le
    // jeton mais desactive par defaut. Il faut l'activer explicitement.
    enable_firmware_privilege()?;

    let name_w = wide(name);
    let guid_w = wide(EFI_GLOBAL_GUID);
    let mut buffer = vec![0u8; MAX_VARIABLE_SIZE];

    // SAFETY: les deux chaines sont des tampons UTF-16 termines par un nul,
    // vivants pendant tout l'appel. `buffer` est alloue avec exactement
    // `MAX_VARIABLE_SIZE` octets, la taille annoncee a l'API. La fonction
    // n'ecrit que dans ce tampon et ne conserve aucun des pointeurs.
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

    // SAFETY: appel sans argument, sans effet de bord observable.
    let err = unsafe { GetLastError() };
    classify(name, err)
}

fn classify(name: &str, err: WIN32_ERROR) -> Result<ReadOutcome, BackendError> {
    match err {
        ERROR_ENVVAR_NOT_FOUND => Ok(ReadOutcome::Absent),

        // Le point de friction principal sous Windows : sans elevation, meme
        // la lecture est refusee.
        ERROR_PRIVILEGE_NOT_HELD => Err(BackendError::PrivilegeRequired),

        // Renvoye lorsque la machine n'a pas demarre en UEFI.
        ERROR_INVALID_FUNCTION => Err(BackendError::NotUefi),

        other => Err(BackendError::FirmwareUnavailable(format!(
            "lecture de {name} : erreur Windows {}",
            other.0
        ))),
    }
}

/// Lit l'instantane complet des variables de demarrage. **Lecture seule.**
///
/// Rassemble `BootOrder`, `BootNext`, `BootCurrent` et toutes les entrees
/// `Boot####` accessibles. L'instantane obtenu sert ensuite de reference au
/// garde-fou : c'est lui qui permet d'affirmer que rien d'autre que `BootNext`
/// n'a change.
pub fn read_state() -> Result<FirmwareState, BackendError> {
    let mut variables = BTreeMap::new();

    // 1. Les variables scalaires. `BootOrder` doit etre lisible : son absence
    //    signalerait un firmware inexploitable.
    for name in [VAR_BOOT_ORDER, VAR_BOOT_NEXT, VAR_BOOT_CURRENT] {
        if let ReadOutcome::Found(raw) = read_variable(name)? {
            variables.insert(name.to_string(), raw);
        }
    }

    // 2. Les entrees designees par BootOrder, dans l'ordre.
    let mut wanted: Vec<u16> = Vec::new();
    if let Some(raw) = variables.get(VAR_BOOT_ORDER) {
        if let Ok(ids) = bootsel_core::efi::parse_boot_id_list(raw) {
            wanted.extend(ids);
        }
    }

    // 3. Plus un balayage borne, pour les entrees absentes de BootOrder
    //    (entrees masquees, ajoutees recemment, ou ordre incomplet).
    wanted.extend(0..PROBE_LIMIT);
    wanted.sort_unstable();
    wanted.dedup();

    for id in wanted {
        let name = BootId(id).variable_name();
        match read_variable(&name)? {
            ReadOutcome::Found(raw) => {
                variables.insert(name, raw);
            }
            ReadOutcome::Absent => {}
        }
    }

    Ok(FirmwareState::new(variables))
}

/// Verifie si le processus courant peut lire les variables du firmware.
///
/// Sert a decider s'il faut demander une elevation, sans faire echouer un
/// cycle de detection complet pour rien.
pub fn can_read_firmware() -> bool {
    matches!(read_variable(VAR_BOOT_ORDER), Ok(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_produces_a_nul_terminated_utf16_buffer() {
        let w = wide("Boot");
        assert_eq!(w, vec![0x42, 0x6F, 0x6F, 0x74, 0x00]);
        assert_eq!(*w.last().unwrap(), 0);
    }

    #[test]
    fn the_global_guid_is_the_one_uefi_defines() {
        // Doit correspondre exactement a la constante du coeur, sinon on lirait
        // des variables d'un autre espace de nommage.
        assert_eq!(
            EFI_GLOBAL_GUID,
            bootsel_core::efi::Guid::EFI_GLOBAL_VARIABLE.to_braced()
        );
    }

    #[test]
    fn a_missing_variable_is_not_an_error() {
        assert!(matches!(
            classify("BootNext", ERROR_ENVVAR_NOT_FOUND),
            Ok(ReadOutcome::Absent)
        ));
    }

    #[test]
    fn missing_privileges_are_reported_as_such_not_as_a_generic_failure() {
        assert_eq!(
            classify("BootOrder", ERROR_PRIVILEGE_NOT_HELD).err(),
            Some(BackendError::PrivilegeRequired)
        );
    }

    #[test]
    fn a_legacy_bios_machine_is_recognised() {
        assert_eq!(
            classify("BootOrder", ERROR_INVALID_FUNCTION).err(),
            Some(BackendError::NotUefi)
        );
    }

    #[test]
    fn detects_this_machines_firmware_mode() {
        // Non privilegie : doit fonctionner dans tous les cas.
        let mode = firmware_mode().expect("GetFirmwareType doit repondre");
        assert!(matches!(
            mode,
            FirmwareMode::Uefi | FirmwareMode::LegacyBios
        ));
    }

    #[test]
    fn reading_the_firmware_without_privileges_fails_cleanly() {
        // Ce test documente le comportement reel constate : sans elevation,
        // la lecture echoue proprement, sans panique ni contournement.
        match read_state() {
            Ok(state) => {
                // Session elevee : l'instantane doit etre coherent.
                assert!(
                    state.get(VAR_BOOT_ORDER).is_some(),
                    "un firmware lisible doit exposer BootOrder"
                );
            }
            Err(BackendError::PrivilegeRequired) => { /* cas nominal non-admin */ }
            Err(BackendError::NotUefi) => { /* machine en BIOS herite */ }
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Activation du privilege de lecture du firmware
// ---------------------------------------------------------------------------

/// Resultat memorise de l'activation du privilege : l'operation est faite une
/// seule fois par processus.
static PRIVILEGE: OnceLock<Result<(), BackendError>> = OnceLock::new();

/// Active `SeSystemEnvironmentPrivilege` dans le jeton du processus courant.
///
/// # Pourquoi c'est necessaire
///
/// Appartenir au groupe Administrateurs ne suffit pas. Le privilege est bien
/// present dans le jeton d'un processus eleve, mais **desactive** : Windows
/// exige qu'un programme demande explicitement l'activation de chaque
/// privilege sensible avant de s'en servir. Sans cette etape,
/// `GetFirmwareEnvironmentVariableW` echoue avec `ERROR_PRIVILEGE_NOT_HELD`
/// meme dans un terminal administrateur — comportement constate sur la machine
/// de developpement.
///
/// # Pourquoi c'est sans danger
///
/// Cette fonction n'**accorde** aucun droit : elle ne peut qu'activer un
/// privilege que l'utilisateur possede deja. Sur un jeton non eleve, l'appel
/// echoue avec `ERROR_NOT_ALL_ASSIGNED` et rien ne change. Elle ne modifie que
/// le jeton du processus courant, qui disparait a la sortie ; ni le systeme,
/// ni le compte utilisateur, ni aucun autre processus n'en garde trace.
///
/// Le privilege active autorise la lecture **et** l'ecriture des variables du
/// firmware. C'est precisement pour cela que ce processus ne definit aucune
/// fonction d'ecriture : la capacite existe au niveau du systeme, mais aucun
/// chemin de code ici ne permet de s'en servir.
fn enable_firmware_privilege() -> Result<(), BackendError> {
    PRIVILEGE.get_or_init(adjust_privilege).clone()
}

fn adjust_privilege() -> Result<(), BackendError> {
    let mut token = HANDLE::default();

    // SAFETY: `GetCurrentProcess` renvoie un pseudo-handle toujours valide qui
    // n'a pas a etre ferme. `token` est une variable locale valide qui recoit
    // le handle du jeton.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| {
        BackendError::FirmwareUnavailable(format!("ouverture du jeton de processus : {e}"))
    })?;

    let result = configure_privilege(token);

    // SAFETY: `token` provient d'un `OpenProcessToken` reussi et n'a pas encore
    // ete ferme. Il n'est plus utilise apres cet appel.
    let _ = unsafe { CloseHandle(token) };

    result
}

fn configure_privilege(token: HANDLE) -> Result<(), BackendError> {
    let mut luid = LUID::default();

    // SAFETY: `SE_SYSTEM_ENVIRONMENT_NAME` est une chaine large statique
    // terminee par un nul, fournie par la bibliotheque. `luid` est une variable
    // locale valide qui recoit l'identifiant du privilege.
    unsafe { LookupPrivilegeValueW(None, SE_SYSTEM_ENVIRONMENT_NAME, &mut luid) }.map_err(|e| {
        BackendError::FirmwareUnavailable(format!("privilege introuvable : {e}"))
    })?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `token` est un handle valide ouvert avec TOKEN_ADJUST_PRIVILEGES.
    // `privileges` decrit exactement un privilege, ce qu'annonce
    // `PrivilegeCount`, et sa taille est calculee a partir du type lui-meme.
    // Aucun etat precedent n'est demande, donc les deux derniers arguments sont
    // nuls, ce qui est explicitement autorise.
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(&privileges),
            std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
    };

    // Piege classique de cette API : elle renvoie un succes meme lorsqu'elle
    // n'a rien pu activer. Seul `GetLastError` dit la verite.
    //
    // SAFETY: appel sans argument, sans effet de bord observable.
    let last = unsafe { GetLastError() };

    match adjusted {
        Ok(()) if last == ERROR_NOT_ALL_ASSIGNED => Err(BackendError::PrivilegeRequired),
        Ok(()) => Ok(()),
        Err(e) => Err(BackendError::FirmwareUnavailable(format!(
            "activation du privilege refusee : {e}"
        ))),
    }
}

#[cfg(test)]
mod privilege_tests {
    use super::*;

    #[test]
    fn enabling_the_privilege_is_idempotent_and_never_panics() {
        let first = enable_firmware_privilege();
        let second = enable_firmware_privilege();
        assert_eq!(first, second, "le resultat doit etre memorise");

        // Selon l'elevation de la session, les deux issues sont legitimes.
        match first {
            Ok(()) => { /* session elevee */ }
            Err(BackendError::PrivilegeRequired) => { /* session normale */ }
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }

    #[test]
    fn the_privilege_name_is_the_one_windows_expects() {
        // Garde-fou : une faute de frappe rendrait la lecture impossible avec
        // une erreur difficile a diagnostiquer.
        let expected: Vec<u16> = "SeSystemEnvironmentPrivilege"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        // SAFETY: la constante est une chaine large statique terminee par un
        // nul ; on ne lit que jusqu'a ce terminateur.
        let actual: Vec<u16> = unsafe {
            let ptr = SE_SYSTEM_ENVIRONMENT_NAME.0;
            let mut out = Vec::new();
            let mut i = 0;
            loop {
                let c = *ptr.add(i);
                out.push(c);
                if c == 0 {
                    break;
                }
                i += 1;
            }
            out
        };

        assert_eq!(actual, expected);
    }
}
