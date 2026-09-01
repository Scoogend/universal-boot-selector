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

/// Autorise le redemarrage pour la duree du processus.
///
/// **Appele uniquement par le point d'entree de l'application reelle**, jamais
/// par une bibliotheque ni par un test. Ce verrou existe a la suite d'un
/// incident : un test appelait la fonction de redemarrage en croyant qu'elle
/// ne faisait rien, et a redemarre la machine de developpement pendant
/// `cargo test`.
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

/// Delai accorde a une commande qui n'attend aucune saisie.
#[cfg(not(test))]
const DELAI_COMMANDE: Duration = Duration::from_secs(5);

/// Delai accorde a une commande qui attend une **saisie humaine**.
///
/// `pkexec` affiche une demande de mot de passe. Une version precedente lui
/// laissait cinq secondes : la fenetre etait tuee avant que l'utilisateur ait
/// pu repondre, et la seule methode qui aurait fonctionne echouait ainsi
/// systematiquement.
#[cfg(not(test))]
const DELAI_SAISIE: Duration = Duration::from_secs(180);

/// Temps laisse au systeme pour s'arreter avant de conclure a un echec.
#[cfg(not(test))]
const DELAI_CONSTAT: Duration = Duration::from_secs(8);

#[cfg(not(test))]
fn do_reboot() -> Result<(), BackendError> {
    let mut refus = Vec::new();

    for methode in methodes_de_redemarrage() {
        match tenter(&methode) {
            // Une commande acceptee ne prouve rien : `shutdown` sort avec le
            // code 0 alors meme qu'il refuse faute de droits, et elogind
            // accepte l'appel D-Bus sans agir. On attend donc de *constater*
            // l'arret plutot que de le supposer.
            Ok(()) => {
                if machine_part_bien() {
                    return Ok(());
                }
                refus.push(format!("{} : accepte mais sans effet", methode.nom));
            }
            Err(raison) => refus.push(format!("{} : {raison}", methode.nom)),
        }
    }

    Err(BackendError::Io(format!(
        "aucune methode de redemarrage n a abouti ({})",
        refus.join(" ; ")
    )))
}

/// Attend de voir si la machine s'arrete reellement.
///
/// Un redemarrage reel tue ce processus bien avant la fin de l'attente : si
/// cette fonction rend la main, c'est que la methode n'a pas fonctionne.
#[cfg(not(test))]
fn machine_part_bien() -> bool {
    let echeance = std::time::Instant::now() + DELAI_CONSTAT;
    while std::time::Instant::now() < echeance {
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// Vrai si le processus tourne deja avec les droits root.
#[cfg(not(test))]
fn est_root() -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid() == 0)
        .unwrap_or(false)
}

/// Prepare une commande systeme en **assainissant l'environnement**.
///
/// # Pourquoi c'est indispensable depuis une AppImage
///
/// Une AppImage place ses propres bibliotheques en tete de `LD_LIBRARY_PATH`.
/// Un programme du systeme lance depuis ce contexte charge alors ces
/// bibliotheques-la plutot que celles de la machine, et echoue :
///
/// ```text
/// /usr/bin/dbus-send: /tmp/.mount_XXXX/usr/lib/libdbus-1.so.3:
///   version `LIBDBUS_PRIVATE_1.16.2' not found
/// ```
///
/// AppImage conserve les valeurs d'origine sous `APPIMAGE_ORIGINAL_*`. On les
/// restaure, ou on supprime la variable a defaut.
#[cfg(not(test))]
fn commande_systeme(programme: &str) -> std::process::Command {
    let mut commande = std::process::Command::new(programme);

    for nom in [
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONPATH",
        "PERLLIB",
        "XDG_DATA_DIRS",
        "GSETTINGS_SCHEMA_DIR",
        "QT_PLUGIN_PATH",
        "GST_PLUGIN_SYSTEM_PATH",
        "GST_PLUGIN_SYSTEM_PATH_1_0",
        "GTK_PATH",
    ] {
        match std::env::var_os(format!("APPIMAGE_ORIGINAL_{nom}")) {
            Some(origine) => {
                commande.env(nom, origine);
            }
            None => {
                commande.env_remove(nom);
            }
        }
    }

    commande
}

/// Methodes de redemarrage, de la plus propre a la plus rustique.
///
/// # Quatre hypotheses fausses, corrigees a l'usage
///
/// 1. `systemctl` n'est pas toujours utilisable : MX Linux tourne sous
///    SysVinit. Sa presence est verifiee, jamais supposee.
/// 2. `loginctl` non plus : sur cette meme machine il appartient au paquet
///    *systemd*. On passe par D-Bus, interface commune a systemd-logind et a
///    elogind.
/// 3. Le `PATH` d'une application graphique ne contient pas `/sbin` : tous les
///    chemins sont absolus.
/// 4. `shutdown` et `reboot` **echouent en silence** sans droits root — ils
///    affichent « you must be root » mais sortent avec le code 0. Les essayer
///    sans etre root ne fait donc que perdre du temps : ils sont ecartes.
#[cfg(not(test))]
fn methodes_de_redemarrage() -> Vec<Methode> {
    let mut methodes = Vec::new();
    let root = est_root();

    // 1. systemd, uniquement s'il est reellement PID 1. Fonctionne sans
    //    privilege grace a polkit.
    if std::path::Path::new("/run/systemd/system").is_dir() {
        if let Some(programme) = premier_existant(&["/usr/bin/systemctl", "/bin/systemctl"]) {
            methodes.push(Methode {
                nom: "systemctl",
                programme,
                arguments: &["reboot"],
                attente: DELAI_COMMANDE,
            });
        }
    }

    // 2. D-Bus : systemd-logind comme elogind.
    if let Some(programme) = premier_existant(&["/usr/bin/dbus-send", "/bin/dbus-send"]) {
        methodes.push(Methode {
            nom: "dbus-send",
            programme,
            arguments: &[
                "--system",
                "--print-reply",
                "--dest=org.freedesktop.login1",
                "/org/freedesktop/login1",
                "org.freedesktop.login1.Manager.Reboot",
                "boolean:true",
            ],
            attente: DELAI_COMMANDE,
        });
    }

    // 3. Arret direct, seulement si on a deja les droits : sinon la commande
    //    refuse tout en pretendant reussir.
    if root {
        if let Some(programme) = premier_existant(&["/sbin/shutdown", "/usr/sbin/shutdown"]) {
            methodes.push(Methode {
                nom: "shutdown",
                programme,
                arguments: &["-r", "now"],
                attente: DELAI_COMMANDE,
            });
        }
    }

    // 4. Le meme arret propre, avec les droits obtenus par pkexec. Demande une
    //    authentification, d'ou sa place en fin de liste et son delai long.
    if let (Some(pkexec), Some(_)) = (
        premier_existant(&["/usr/bin/pkexec", "/bin/pkexec"]),
        premier_existant(&["/sbin/shutdown", "/usr/sbin/shutdown"]),
    ) {
        methodes.push(Methode {
            nom: "pkexec shutdown",
            programme: pkexec,
            arguments: &["/sbin/shutdown", "-r", "now"],
            attente: DELAI_SAISIE,
        });
    }

    methodes
}

/// Une facon de redemarrer. Programme et arguments sont fixes a la
/// compilation : rien n'est construit a partir d'une donnee exterieure.
#[cfg(not(test))]
struct Methode {
    nom: &'static str,
    programme: &'static str,
    arguments: &'static [&'static str],
    attente: Duration,
}

/// Premier chemin absolu existant de la liste.
#[cfg(not(test))]
fn premier_existant(chemins: &[&'static str]) -> Option<&'static str> {
    chemins
        .iter()
        .find(|c| std::path::Path::new(c).is_file())
        .copied()
}

/// Lance une commande de redemarrage et attend son verdict.
#[cfg(not(test))]
fn tenter(methode: &Methode) -> Result<(), String> {
    use std::process::Stdio;

    let mut child = commande_systeme(methode.programme)
        .args(methode.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{e}"))?;

    let echeance = std::time::Instant::now() + methode.attente;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                let mut details = String::new();
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let mut tampon = String::new();
                    let _ = err.read_to_string(&mut tampon);
                    details = tampon.lines().next().unwrap_or("").to_string();
                }
                return Err(format!("code {} {details}", status.code().unwrap_or(-1)));
            }
            Ok(None) if std::time::Instant::now() >= echeance => {
                let _ = child.kill();
                return Err("aucune reponse".to_string());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("attente : {e}")),
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
    fn the_reboot_never_assumes_systemd() {
        // Un test ecrit apres coup : la version precedente appelait
        // `systemctl reboot` sans condition, et echouait sur MX Linux, qui
        // tourne sous SysVinit.
        let code = shipped_source();

        assert!(
            code.contains("/run/systemd/system"),
            "la presence de systemd doit etre verifiee, jamais supposee"
        );
        assert!(
            code.contains("org.freedesktop.login1.Manager.Reboot"),
            "elogind doit etre joint par D-Bus, pas par loginctl qui appartient a systemd"
        );
        assert!(code.contains("\"shutdown\""), "un repli SysVinit est necessaire");

        // Aucune methode brutale, qui perdrait les ecritures en attente.
        for forbidden in ["reboot(RB_", "RB_AUTOBOOT", "--force", "-f\"", "sync_and_reboot"] {
            assert!(
                !code.contains(forbidden),
                "redemarrage brutal interdit : {forbidden}"
            );
        }
    }

    #[test]
    fn an_accepted_command_is_not_taken_for_a_reboot() {
        // Constate sur MX Linux : dbus-send renvoie un succes, elogind
        // accepte, et rien ne se passe. L application affichait
        // « Redemarrage en cours... » indefiniment.
        let code = shipped_source();
        assert!(
            code.contains("machine_part_bien()"),
            "l arret doit etre constate, jamais suppose"
        );
        assert!(
            code.contains("accepte mais sans effet"),
            "une commande acceptee sans effet doit etre signalee comme telle"
        );
    }

    #[test]
    fn an_interactive_command_gets_time_for_a_human_to_answer() {
        // Une version precedente laissait cinq secondes a pkexec : la demande
        // de mot de passe etait tuee avant que l utilisateur puisse repondre,
        // et la seule methode qui aurait fonctionne echouait toujours.
        let code = shipped_source();
        assert!(code.contains("DELAI_SAISIE"));
        assert!(
            code.contains("attente: DELAI_SAISIE"),
            "pkexec doit disposer du delai long"
        );
    }

    #[test]
    fn spawned_programs_do_not_inherit_the_appimage_libraries() {
        // Depuis une AppImage, LD_LIBRARY_PATH pointe vers ses propres
        // bibliotheques et fait echouer les programmes du systeme.
        let code = shipped_source();
        assert!(code.contains("APPIMAGE_ORIGINAL_"));
        assert!(code.contains("LD_LIBRARY_PATH"));
        assert!(code.contains("env_remove"));
        assert!(
            !code.contains("std::process::Command::new(methode.programme)"),
            "toute commande systeme doit passer par commande_systeme"
        );
    }

    #[test]
    fn commands_that_need_root_are_skipped_when_unprivileged() {
        // `shutdown` affiche « you must be root » mais sort avec le code 0 :
        // l essayer sans droits ne fait que perdre le delai de constat.
        let code = shipped_source();
        assert!(code.contains("fn est_root()"));
        assert!(code.contains("if root {"));
    }

    #[test]
    fn every_program_is_an_absolute_path() {
        // Le PATH d'une application graphique ne contient pas /sbin :
        // `Command::new("shutdown")` echouait avec « fichier introuvable »
        // alors que le programme existait.
        let code = shipped_source();
        for chemin in ["/sbin/shutdown", "/usr/sbin/shutdown", "/usr/bin/dbus-send"] {
            assert!(code.contains(chemin), "chemin absolu attendu : {chemin}");
        }
        // Les commentaires citent nommement la forme fautive pour expliquer
        // le bug : seul le code effectif doit etre examine.
        let effectif: String = code
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !effectif.contains("Command::new(\"shutdown\")"),
            "aucun programme ne doit etre resolu par le PATH"
        );
    }

    #[test]
    fn the_command_is_built_from_separate_arguments_without_a_shell() {
        let code = shipped_source();

        // Arguments separes et constants : rien n est concatene, donc rien
        // n est injectable.
        assert!(code.contains(".args(methode.arguments)"));
        assert!(code.contains("commande_systeme(methode.programme)"));
        for forbidden in ["sh -c", "\"bash\"", "format!(\"systemctl"] {
            assert!(
                !code.contains(forbidden),
                "aucune commande ne doit passer par un interpreteur : {forbidden}"
            );
        }
    }
}
