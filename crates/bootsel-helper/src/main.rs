//! # bootsel-helper
//!
//! Le seul binaire privilegie d'Universal Boot Selector, et le seul capable
//! d'ecrire quoi que ce soit sur la machine.
//!
//! ## Ce qu'il sait faire, exhaustivement
//!
//! - lire les variables de demarrage du firmware ;
//! - ecrire deux octets dans la variable UEFI `BootNext`.
//!
//! Il ne redemarre pas la machine : cela ne demande aucun privilege
//! particulier, et le faire ici elargirait sa surface pour rien.
//!
//! ## Ce qu'il ne sait pas faire
//!
//! Il n'a aucune notion de fichier, de disque, de partition, de commande
//! systeme, ni de nom de variable arbitraire. Ces capacites ne sont pas
//! desactivees : le code correspondant n'existe pas. Un appelant hostile ne
//! dispose d'aucun verbe pour les demander.
//!
//! ## Modes
//!
//! - `--serve --pipe <nom>` : se connecte au tube nomme de l'interface et
//!   traite les requetes du protocole.
//! - `--self-test` : verifie la lecture du firmware et sort. N'ecrit rien.
//! - `--version`
//!
//! Aucun autre argument n'est accepte. Tout argument inconnu fait sortir le
//! programme sans rien faire.

#![cfg_attr(not(windows), allow(unused))]

#[cfg(windows)]
mod firmware;
#[cfg(target_os = "linux")]
mod linux_firmware;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod privilege;
mod service;

/// Code de sortie : usage incorrect.
const EXIT_USAGE: i32 = 2;
/// Code de sortie : defaillance a l'execution.
const EXIT_FAILURE: i32 = 3;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match parse_args(&args) {
        Ok(Mode::Version) => {
            println!("bootsel-helper {}", env!("CARGO_PKG_VERSION"));
        }
        Ok(Mode::SelfTest) => run_self_test(),
        Ok(Mode::Serve { pipe_name }) => run_serve(&pipe_name),
        Ok(Mode::OneShot) => run_oneshot(),
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            eprintln!("Usage : bootsel-helper --serve --pipe <nom>");
            eprintln!("        bootsel-helper --oneshot");
            eprintln!("        bootsel-helper --self-test");
            eprintln!("        bootsel-helper --version");
            std::process::exit(EXIT_USAGE);
        }
    }
}

/// Modes acceptes. Toute autre combinaison d'arguments est refusee.
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    /// Windows : tube nomme, une elevation pour toute la session.
    Serve { pipe_name: String },
    /// Linux : une requete sur l'entree standard, une reponse sur la sortie.
    ///
    /// Sous Linux la lecture ne demande aucun privilege ; seule l'ecriture en
    /// exige. Une invocation ponctuelle par `pkexec` est donc plus simple et
    /// plus sobre qu'un service permanent : le processus privilegie ne vit que
    /// le temps d'une operation.
    OneShot,
    SelfTest,
    Version,
}

/// Analyse les arguments avec une tolerance nulle.
///
/// Le nom du tube est valide caractere par caractere : seuls des lettres,
/// chiffres et tirets sont acceptes. Cela interdit toute traversee de chemin
/// ou tout nom de tube inattendu.
fn parse_args(args: &[String]) -> Result<Mode, String> {
    match args {
        [] => Err("aucun argument fourni".into()),
        [a] if a == "--version" || a == "-V" => Ok(Mode::Version),
        [a] if a == "--self-test" => Ok(Mode::SelfTest),
        [a] if a == "--oneshot" => Ok(Mode::OneShot),
        [a, b, c] if a == "--serve" && b == "--pipe" => {
            if is_valid_pipe_name(c) {
                Ok(Mode::Serve {
                    pipe_name: c.clone(),
                })
            } else {
                Err(format!("nom de tube invalide : {c:?}"))
            }
        }
        _ => Err("arguments non reconnus".into()),
    }
}

/// Un nom de tube acceptable : 8 a 64 caracteres alphanumeriques ou tirets.
pub(crate) fn is_valid_pipe_name(name: &str) -> bool {
    (8..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

#[cfg(windows)]
fn run_self_test() {
    println!("bootsel-helper {} — autotest", env!("CARGO_PKG_VERSION"));

    match firmware::firmware_mode() {
        Ok(mode) => println!("Mode firmware : {mode:?}"),
        Err(e) => {
            eprintln!("Mode firmware indeterminable : {e}");
            std::process::exit(EXIT_FAILURE);
        }
    }

    println!("Privilege firmware : {}", if firmware::is_elevated() { "obtenu" } else { "indisponible" });

    match firmware::read_state() {
        Ok(state) => {
            println!("Variables lues : {}", state.variables.len());
            println!("Entrees de demarrage : {}", state.entry_ids().len());
            match state.boot_order() {
                Some(order) => println!(
                    "BootOrder : {}",
                    order
                        .iter()
                        .map(|id| id.variable_name())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                None => println!("BootOrder : illisible"),
            }
            match state.boot_next() {
                Some(id) => println!("BootNext : {id}"),
                None => println!("BootNext : non defini"),
            }
        }
        Err(e) => println!("Lecture du firmware impossible : {e}"),
    }

    println!();
    println!("Aucune modification n'a ete effectuee.");
}

#[cfg(windows)]
fn run_serve(pipe_name: &str) {
    if let Err(e) = service::serve(pipe_name) {
        eprintln!("helper : {e}");
        std::process::exit(EXIT_FAILURE);
    }
}

#[cfg(target_os = "linux")]
fn run_self_test() {
    println!("bootsel-helper {} — autotest", env!("CARGO_PKG_VERSION"));
    println!("Mode firmware : {:?}", linux_firmware::firmware_mode());
    match linux_firmware::read_state() {
        Ok(state) => {
            println!("Variables lues : {}", state.variables.len());
            println!("Entrees de demarrage : {}", state.entry_ids().len());
            match state.boot_order() {
                Some(o) => println!(
                    "BootOrder : {}",
                    o.iter().map(|i| i.variable_name()).collect::<Vec<_>>().join(", ")
                ),
                None => println!("BootOrder : illisible"),
            }
        }
        Err(e) => println!("Lecture du firmware impossible : {e}"),
    }
    println!();
    println!("Aucune modification n'a ete effectuee.");
}

#[cfg(not(any(windows, target_os = "linux")))]
fn run_self_test() {
    eprintln!("plateforme non prise en charge");
    std::process::exit(EXIT_FAILURE);
}

#[cfg(not(windows))]
fn run_serve(_pipe_name: &str) {
    eprintln!("le mode tube nomme est propre a Windows ; utilisez --oneshot");
    std::process::exit(EXIT_FAILURE);
}

/// Lit une requete sur l'entree standard, ecrit une reponse, et sort.
///
/// C'est le mode d'appel sous Linux : `pkexec bootsel-helper --oneshot`. Le
/// processus privilegie ne vit que le temps d'une operation, et la cible
/// voyage dans le JSON plutot que sur la ligne de commande — donc aucun
/// echappement d'argument a maitriser.
fn run_oneshot() {
    use std::io::{BufRead, Write};

    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        eprintln!("helper : requete illisible");
        std::process::exit(EXIT_FAILURE);
    }

    let response = service::handle_line(line.trim());
    let encoded = serde_json::to_string(&response).unwrap_or_else(|_| {
        String::from(
            r#"{"reply":"error","kind":"internal","message":"reponse non serialisable"}"#,
        )
    });

    let mut stdout = std::io::stdout();
    let _ = writeln!(stdout, "{encoded}");
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn accepts_the_three_documented_modes() {
        assert_eq!(parse_args(&args(&["--version"])), Ok(Mode::Version));
        assert_eq!(parse_args(&args(&["-V"])), Ok(Mode::Version));
        assert_eq!(parse_args(&args(&["--self-test"])), Ok(Mode::SelfTest));
        assert_eq!(
            parse_args(&args(&["--serve", "--pipe", "bootsel-abc123def456"])),
            Ok(Mode::Serve {
                pipe_name: "bootsel-abc123def456".into()
            })
        );
    }

    #[test]
    fn rejects_everything_else() {
        for hostile in [
            vec![],
            args(&["--help"]),
            args(&["--serve"]),
            args(&["--serve", "--pipe"]),
            args(&["--serve", "--pipe", "a", "b"]),
            args(&["--self-test", "--serve"]),
            args(&["set-boot-next", "0002"]),
            args(&["--write", "BootOrder", "0200"]),
            args(&["--version", "--self-test"]),
        ] {
            assert!(
                parse_args(&hostile).is_err(),
                "aurait du rejeter : {hostile:?}"
            );
        }
    }

    #[test]
    fn pipe_names_cannot_escape_their_namespace() {
        for hostile in [
            "",
            "short",
            &"x".repeat(65),
            "../../../etc/passwd",
            "bootsel\\..\\..\\pipe",
            "bootsel/../other",
            "bootsel abc12345",
            "bootsel;calc.exe",
            "bootsel\0abc12345",
            "\\\\.\\pipe\\bootsel1",
        ] {
            assert!(
                !is_valid_pipe_name(hostile),
                "aurait du rejeter : {hostile:?}"
            );
        }
    }

    #[test]
    fn accepts_the_names_the_interface_actually_generates() {
        for good in [
            "bootsel-0123456789abcdef0123456789abcdef",
            "bootsel-aaaaaaaa",
            &"a".repeat(64),
        ] {
            assert!(is_valid_pipe_name(good), "aurait du accepter : {good:?}");
        }
    }
}
