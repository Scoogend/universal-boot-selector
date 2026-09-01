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
const TIMEOUT: Duration = Duration::from_secs(5);

/// Temps laisse au systeme pour s'arreter avant de conclure a un echec.
///
/// Genereux : un arret propre demonte les volumes et arrete les services.
#[cfg(not(test))]
const DELAI_CONSTAT: Duration = Duration::from_secs(12);

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
    let mut refus = Vec::new();

    for methode in methodes_de_redemarrage() {
        match tenter(&methode) {
            // Une commande acceptee ne prouve rien : sous SysVinit, elogind
            // accepte l'appel D-Bus et ne redemarre pas. On attend donc de
            // *constater* l'arret plutot que de le supposer.
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
/// # Pourquoi ce controle existe
///
/// Constate sur MX Linux : `dbus-send` renvoie un succes, elogind accepte la
/// demande, et **rien ne se passe**. L'application affichait alors
/// « Redemarrage en cours... » indefiniment, alors que la selection etait
/// faite depuis longtemps et qu'il suffisait de redemarrer a la main.
///
/// Un redemarrage reel tue ce processus bien avant la fin de l'attente : si
/// cette fonction rend la main, c'est que la methode n'a pas fonctionne.
#[cfg(not(test))]
fn machine_part_bien() -> bool {
    let echeance = std::time::Instant::now() + DELAI_CONSTAT;
    while std::time::Instant::now() < echeance {
        std::thread::sleep(Duration::from_millis(200));
    }
    // Toujours la : la machine n'est pas partie.
    false
}

/// Methodes de redemarrage, de la plus propre a la plus rustique.
///
/// # Trois hypotheses fausses, corrigees a l'usage
///
/// 1. **`systemctl` n'est pas toujours utilisable.** MX Linux tourne sous
///    SysVinit ; la commande refuse net. Sa presence est donc verifiee.
///
/// 2. **`loginctl` non plus.** Sur cette meme machine, `/usr/bin/loginctl`
///    appartient au paquet *systemd* et refuse pour la meme raison — alors
///    qu'`elogind` tourne bel et bien et accepterait la demande. Passer par
///    **D-Bus** contourne le probleme : `org.freedesktop.login1` est
///    l'interface commune a systemd-logind et a elogind.
///
/// 3. **Le `PATH` d'une application graphique ne contient pas `/sbin`.**
///    `Command::new("shutdown")` echouait avec « fichier introuvable » alors
///    que le programme existait. Tous les chemins sont donc absolus.
#[cfg(not(test))]
fn methodes_de_redemarrage() -> Vec<Methode> {
    let mut methodes = Vec::new();

    // 1. systemd, uniquement s'il est reellement PID 1.
    if std::path::Path::new("/run/systemd/system").is_dir() {
        if let Some(programme) = premier_existant(&["/usr/bin/systemctl", "/bin/systemctl"]) {
            methodes.push(Methode {
                nom: "systemctl",
                programme,
                arguments: &["reboot"],
            });
        }
    }

    // 2. D-Bus. Une seule interface pour systemd-logind et elogind, et elle
    //    fonctionne sans privilege pour l'utilisateur de la session locale.
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
        });
    }

    // 3. SysVinit et OpenRC. Arret propre, mais demande les droits root.
    if let Some(programme) = premier_existant(&["/sbin/shutdown", "/usr/sbin/shutdown"]) {
        methodes.push(Methode {
            nom: "shutdown",
            programme,
            arguments: &["-r", "now"],
        });
    }

    if let Some(programme) = premier_existant(&["/sbin/reboot", "/usr/sbin/reboot"]) {
        methodes.push(Methode {
            nom: "reboot",
            programme,
            arguments: &[],
        });
    }

    // 4. Dernier recours : le meme arret propre, mais avec les droits root
    //    obtenus par pkexec. Demande une authentification, d'ou sa place en
    //    fin de liste — on ne derange l'utilisateur que si rien d'autre n'a
    //    fonctionne.
    if let (Some(pkexec), Some(_)) = (
        premier_existant(&["/usr/bin/pkexec", "/bin/pkexec"]),
        premier_existant(&["/sbin/shutdown", "/usr/sbin/shutdown"]),
    ) {
        methodes.push(Methode {
            nom: "pkexec shutdown",
            programme: pkexec,
            arguments: &["/sbin/shutdown", "-r", "now"],
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
}

/// Premier chemin absolu existant et executable de la liste.
#[cfg(not(test))]
fn premier_existant(chemins: &[&'static str]) -> Option<&'static str> {
    chemins
        .iter()
        .find(|c| std::path::Path::new(c).is_file())
        .copied()
}

/// Lance une commande de redemarrage et attend brievement son verdict.
#[cfg(not(test))]
fn tenter(methode: &Methode) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(methode.programme)
        .args(methode.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{e}"))?;

    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                let mut details = String::new();
                if let Some(mut err) = child.stderr.take() {
                    use std::io::Read;
                    let mut buffer = String::new();
                    let _ = err.read_to_string(&mut buffer);
                    details = buffer.lines().next().unwrap_or("").to_string();
                }
                return Err(format!("code {} {details}", status.code().unwrap_or(-1)));
            }
            // Une commande qui ne rend jamais la main est bloquee, pas en
            // train de redemarrer : on ne la prend plus pour un succes.
            Ok(None) if std::time::Instant::now() >= deadline => {
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
    fn every_program_is_an_absolute_path() {
        // Le PATH d'une application graphique ne contient pas /sbin :
        // `Command::new("shutdown")` echouait avec « fichier introuvable »
        // alors que le programme existait.
        let code = shipped_source();
        for chemin in ["/sbin/shutdown", "/sbin/reboot", "/usr/bin/dbus-send"] {
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
        for forbidden in ["sh -c", "\"bash\"", "format!(\"systemctl"] {
            assert!(
                !code.contains(forbidden),
                "aucune commande ne doit passer par un interpreteur : {forbidden}"
            );
        }
    }
}
