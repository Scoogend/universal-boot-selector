//! Redemarrage de la machine.
//!
//! # Pourquoi ce code n'est pas dans le helper privilegie
//!
//! Redemarrer ne demande aucun droit particulier : tout utilisateur local
//! detient `SeShutdownPrivilege`. Router le redemarrage par le helper aurait
//! elargi sa surface d'attaque sans rien apporter. Il reste donc ici, dans le
//! processus d'interface, non eleve.
//!
//! Le privilege doit malgre tout etre **active** explicitement : Windows le
//! detient mais le laisse desactive par defaut, comme pour l'acces au
//! firmware.
//!
//! # Garantie d'ordonnancement
//!
//! Rien ici ne verifie que `BootNext` a ete correctement ecrite. Cette
//! garantie est portee par le type : [`bootsel_core::select::reboot_after`]
//! exige un [`bootsel_core::SelectionOutcome`], qui ne peut etre construit
//! qu'apres une verification reussie du garde-fou.
//!
//! On utilise l'API systeme plutot que `shutdown.exe` : aucun processus a
//! lancer, aucune ligne de commande a construire, donc aucune surface
//! d'injection.

use bootsel_core::backend::BackendError;
use std::sync::atomic::{AtomicBool, Ordering};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
// Ces symboles ne servent qu au redemarrage reel, absent des binaires de test.
#[cfg(not(test))]
use windows::Win32::System::Shutdown::{
    ExitWindowsEx, EWX_REBOOT, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_OTHER,
    SHTDN_REASON_MINOR_OTHER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Verrou d'armement du redemarrage.
///
/// # Pourquoi ce verrou existe
///
/// Pendant le developpement, un test appelait `reboot()` sur un backend reel
/// en croyant que la fonction ne faisait rien. La session etait elevee : la
/// machine a redemarre pendant `cargo test`. Corriger ce test ne suffisait
/// pas — il fallait que l'accident devienne impossible.
///
/// Le redemarrage refuse desormais de s'executer tant qu'il n'a pas ete arme
/// explicitement par le point d'entree de l'application. Aucun test, unitaire
/// ou d'integration, n'arme ce verrou : tous obtiennent un refus, quel que
/// soit le niveau de privilege de la session.
static REBOOT_ARMED: AtomicBool = AtomicBool::new(false);

/// Autorise le redemarrage pour la duree du processus.
///
/// **Appele uniquement par le point d'entree de l'application reelle**, jamais
/// par une bibliotheque ni par un test. Un binaire qui ne l'appelle pas est
/// structurellement incapable de redemarrer la machine.
pub fn arm_reboot() {
    REBOOT_ARMED.store(true, Ordering::SeqCst);
}

/// Vrai si le redemarrage a ete arme par l'application.
pub fn is_reboot_armed() -> bool {
    REBOOT_ARMED.load(Ordering::SeqCst)
}

/// Redemarre la machine.
///
/// Refuse si [`arm_reboot`] n'a pas ete appele. Refuse egalement, a la
/// compilation, dans tout binaire de test de ce crate.
///
/// Le redemarrage n'est **pas force** : Windows previent l'utilisateur et
/// laisse les applications enregistrer leur travail. Forcer la fermeture
/// risquerait de faire perdre des donnees, ce qui contredirait la regle
/// premiere du projet.
pub fn reboot() -> Result<(), BackendError> {
    // Premiere barriere : verrou d'execution, actif dans tous les binaires.
    if !is_reboot_armed() {
        return Err(BackendError::Unsupported(
            "le redemarrage n'a pas ete arme par l'application : refus".to_string(),
        ));
    }

    // Deuxieme barriere : dans un binaire de test de ce crate, l'appel systeme
    // n'est meme pas compile.
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
    enable_shutdown_privilege()?;

    // SAFETY: appel systeme sans pointeur ni tampon ; les drapeaux sont des
    // constantes fournies par la bibliotheque.
    unsafe {
        ExitWindowsEx(
            EWX_REBOOT,
            SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED,
        )
    }
    .map_err(|e| BackendError::Io(format!("le redemarrage a ete refuse : {e}")))
}

/// Active `SeShutdownPrivilege` dans le jeton du processus courant.
///
/// Ne peut qu'activer un privilege deja detenu ; n'en accorde aucun.
fn enable_shutdown_privilege() -> Result<(), BackendError> {
    let mut token = HANDLE::default();

    // SAFETY: `GetCurrentProcess` renvoie un pseudo-handle toujours valide qui
    // n'a pas a etre ferme. `token` recoit le handle du jeton.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .map_err(|e| BackendError::Io(format!("ouverture du jeton : {e}")))?;

    let result = adjust(token, SE_SHUTDOWN_NAME);

    // SAFETY: `token` provient d'un `OpenProcessToken` reussi et n'est plus
    // utilise apres cet appel.
    let _ = unsafe { CloseHandle(token) };

    result
}

fn adjust(token: HANDLE, privilege: PCWSTR) -> Result<(), BackendError> {
    let mut luid = LUID::default();

    // SAFETY: `privilege` est une chaine large statique terminee par un nul ;
    // `luid` recoit l'identifiant du privilege.
    unsafe { LookupPrivilegeValueW(None, privilege, &mut luid) }
        .map_err(|e| BackendError::Io(format!("privilege introuvable : {e}")))?;

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // SAFETY: `token` est valide et ouvert avec TOKEN_ADJUST_PRIVILEGES.
    // `privileges` decrit exactement un privilege, ce qu'annonce
    // `PrivilegeCount`, et la taille vient du type lui-meme.
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

    // Cette API renvoie un succes meme quand elle n'a rien active.
    // SAFETY: appel sans argument, sans effet de bord observable.
    let last = unsafe { GetLastError() };

    match adjusted {
        Ok(()) if last == ERROR_NOT_ALL_ASSIGNED => Err(BackendError::PrivilegeRequired),
        Ok(()) => Ok(()),
        Err(e) => Err(BackendError::Io(format!(
            "activation du privilege de redemarrage refusee : {e}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portion livree du fichier : tout ce qui precede le module de test.
    ///
    /// Sans cette coupure, le test se signalerait lui-meme, puisque ses
    /// propres assertions citent les constantes qu'il interdit.
    fn shipped_source() -> String {
        let source = include_str!("power.rs");
        let end = source.find("#[cfg(test)]").unwrap_or(source.len());
        source[..end]
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_reboot_is_planned_and_never_forced() {
        // Garde-fou de revue : `EWX_FORCE` fermerait les applications sans
        // leur laisser enregistrer, ce qui ferait perdre du travail.
        let code = shipped_source();

        assert!(!code.contains("EWX_FORCE"), "redemarrage force interdit");
        assert!(!code.contains("EWX_POWEROFF"), "extinction interdite");
        assert!(!code.contains("EWX_SHUTDOWN"), "arret interdit");
        assert!(code.contains("EWX_REBOOT"));
    }

    #[test]
    fn reboot_refuses_while_unarmed() {
        // Le test qui a fait redemarrer la machine pendant le developpement
        // aurait echoue ici au lieu de reussir.
        assert!(!is_reboot_armed(), "aucun test ne doit armer le redemarrage");
        assert!(matches!(
            reboot(),
            Err(BackendError::Unsupported(_))
        ));
    }

    #[test]
    fn the_system_call_is_absent_from_test_binaries() {
        // Deuxieme barriere, verifiee sur le source plutot qu'en armant le
        // verrou : armer une variable globale rendrait les tests dependants de
        // leur ordre d execution.
        let source = include_str!("power.rs");
        assert!(
            source.contains("#[cfg(not(test))]
fn do_reboot()"),
            "l appel systeme de redemarrage doit etre exclu des binaires de test"
        );
    }

    #[test]
    fn the_shutdown_privilege_can_be_enabled_without_rebooting() {
        // Active le privilege sans jamais appeler `reboot` : ce test ne doit
        // evidemment pas redemarrer la machine.
        match enable_shutdown_privilege() {
            Ok(()) => { /* cas normal : tout utilisateur local le detient */ }
            Err(BackendError::PrivilegeRequired) => { /* jeton restreint */ }
            Err(e) => panic!("echec inattendu : {e}"),
        }
    }

    #[test]
    fn an_unknown_privilege_is_reported_rather_than_silently_ignored() {
        let mut token = HANDLE::default();
        // SAFETY: pseudo-handle valide, `token` est une variable locale.
        unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )
        }
        .expect("ouverture du jeton");

        let result = adjust(token, windows::core::w!("SeNotARealPrivilege"));

        // SAFETY: `token` provient d'un appel reussi et n'est plus utilise.
        let _ = unsafe { CloseHandle(token) };

        assert!(matches!(result, Err(BackendError::Io(_))));
    }
}
