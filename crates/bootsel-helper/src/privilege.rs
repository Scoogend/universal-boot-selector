//! Activation d'un privilege dans le jeton du processus courant.
//!
//! # Ce que cela fait, et ne fait pas
//!
//! Windows distingue *detenir* un privilege et l'avoir *active*. Le jeton d'un
//! processus eleve contient bien `SeSystemEnvironmentPrivilege`, mais
//! desactive : le systeme exige qu'un programme demande explicitement
//! l'activation de chaque privilege sensible avant de s'en servir.
//!
//! Cette fonction ne peut **qu'activer un privilege deja detenu**. Sur un jeton
//! non eleve, elle echoue avec `ERROR_NOT_ALL_ASSIGNED` et rien ne change : ce
//! n'est en aucun cas un moyen d'obtenir des droits. Elle ne modifie que le
//! jeton du processus courant, qui disparait a sa sortie.

use bootsel_core::backend::BackendError;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Active un privilege nomme dans le jeton du processus.
///
/// Renvoie [`BackendError::PrivilegeRequired`] si le processus ne le detient
/// pas — cas normal d'une session non elevee.
pub fn enable(privilege: PCWSTR) -> Result<(), BackendError> {
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
    .map_err(|e| BackendError::FirmwareUnavailable(format!("ouverture du jeton : {e}")))?;

    let result = adjust(token, privilege);

    // SAFETY: `token` provient d'un `OpenProcessToken` reussi et n'est plus
    // utilise apres cet appel.
    let _ = unsafe { CloseHandle(token) };

    result
}

fn adjust(token: HANDLE, privilege: PCWSTR) -> Result<(), BackendError> {
    let mut luid = LUID::default();

    // SAFETY: `privilege` est une chaine large statique terminee par un nul,
    // fournie par la bibliotheque. `luid` recoit l'identifiant du privilege.
    unsafe { LookupPrivilegeValueW(None, privilege, &mut luid) }
        .map_err(|e| BackendError::FirmwareUnavailable(format!("privilege introuvable : {e}")))?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `token` est valide et ouvert avec TOKEN_ADJUST_PRIVILEGES.
    // `privileges` decrit exactement un privilege, ce qu'annonce
    // `PrivilegeCount`, et la taille annoncee vient du type lui-meme. Aucun
    // etat precedent n'est demande, d'ou les deux derniers arguments nuls.
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

    // Piege de cette API : elle renvoie un succes meme lorsqu'elle n'a rien
    // active. Seul `GetLastError` dit la verite.
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
mod tests {
    use super::*;
    use windows::Win32::Security::SE_SYSTEM_ENVIRONMENT_NAME;

    #[test]
    fn enabling_a_held_privilege_succeeds_or_fails_cleanly() {
        match enable(SE_SYSTEM_ENVIRONMENT_NAME) {
            Ok(()) => { /* session elevee */ }
            Err(BackendError::PrivilegeRequired) => { /* session normale */ }
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }

    #[test]
    fn enabling_is_repeatable_without_side_effects() {
        let a = enable(SE_SYSTEM_ENVIRONMENT_NAME);
        let b = enable(SE_SYSTEM_ENVIRONMENT_NAME);
        assert_eq!(a, b);
    }

    #[test]
    fn an_unknown_privilege_name_is_reported_not_silently_ignored() {
        let bogus = windows::core::w!("SeThisPrivilegeDoesNotExist");
        assert!(matches!(
            enable(bogus),
            Err(BackendError::FirmwareUnavailable(_))
        ));
    }
}
