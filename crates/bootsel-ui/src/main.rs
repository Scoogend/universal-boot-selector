//! # Universal Boot Selector
//!
//! Point d'entree de l'interface. **Processus non privilegie.**
//!
//! Ce binaire ne contient aucun code capable d'ecrire dans le firmware :
//! l'ecriture de `BootNext` appartient a `bootsel-helper`, lance a la demande
//! avec une elevation, et joignable par un tube nomme.
//!
//! ## Options
//!
//! - `--mock-boot <scenario>` : firmware simule, aucun acces au materiel.
//! - `--dry-run` : interdit toute ecriture, meme demandee explicitement.
//! - `--no-elevate` : reste strictement non privilegie ; les entrees UEFI ne
//!   seront pas lues et l'interface le signalera.

// Sous Windows, evite l'ouverture d'une console derriere la fenetre.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config_store;
mod state;

use state::{AppState, Startup};

fn main() {
    force_software_webview_if_needed();

    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let startup = Startup {
        mock_scenario: args
            .iter()
            .position(|a| a == "--mock-boot")
            .and_then(|i| args.get(i + 1))
            .cloned(),
        read_only: args.iter().any(|a| a == "--dry-run"),
        // L'elevation est demandee au lancement, conformement au choix retenu
        // pour ce projet : une seule invite UAC, puis une interface complete.
        // Elle reste refusable sans consequence.
        elevate: !args.iter().any(|a| a == "--no-elevate"),
    };

    let state = match AppState::new(startup) {
        Ok(state) => state,
        Err(e) => {
            eprintln!("Demarrage impossible : {e}");
            std::process::exit(1);
        }
    };

    tauri::Builder::default()
        .setup(|app| {
            start_device_watcher(app.handle().clone());
            Ok(())
        })
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            commands::refresh,
            commands::request_elevation,
            commands::prepare_selection,
            commands::confirm_and_reboot,
            commands::set_default_system,
            commands::set_alias,
            commands::clear_alias,
            commands::set_preference,
        ])
        .run(tauri::generate_context!())
        .expect("lancement de l interface");
}

/// Neutralise le rendu accelere de WebKit sous Linux si l'appelant ne s'est
/// pas deja prononce.
///
/// Constate sur une machine reelle : avec le pilote `nouveau` et une carte
/// NVIDIA, WebKitGTK echoue silencieusement au rendu — le noyau rejette les
/// commandes graphiques — et la fenetre reste **entierement blanche**, sans le
/// moindre message d'erreur exploitable.
///
/// Ces deux variables font retomber WebKit sur un rendu logiciel. Le cout est
/// negligeable : cette interface affiche une liste et du texte, elle n'anime
/// rien. Mieux vaut un rendu logiciel qui marche partout qu'une acceleration
/// qui laisse certains utilisateurs devant une page blanche.
///
/// Un reglage deja present dans l'environnement est respecte : on ne prive
/// personne d'un choix explicite.
#[cfg(target_os = "linux")]
fn force_software_webview_if_needed() {
    for name in ["WEBKIT_DISABLE_COMPOSITING_MODE", "WEBKIT_DISABLE_DMABUF_RENDERER"] {
        if std::env::var_os(name).is_none() {
            // SAFETY: appel effectue avant tout demarrage de fil, donc sans
            // concurrence sur l'environnement du processus.
            unsafe { std::env::set_var(name, "1") };
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn force_software_webview_if_needed() {}

/// Relaie les branchements et retraits de peripheriques vers l'interface.
///
/// La surveillance est un simple signal : elle ne lit rien du peripherique.
/// L'interface reagit en relancant un inventaire en lecture seule.
///
/// Un echec de demarrage n'est pas bloquant : l'application fonctionne
/// simplement sans mise a jour automatique de la liste.
#[cfg(windows)]
fn start_device_watcher(app: tauri::AppHandle) {
    use tauri::Emitter;

    let receiver = match bootsel_platform::windows::hotplug::watch() {
        Ok(receiver) => receiver,
        Err(e) => {
            eprintln!("Surveillance des peripheriques indisponible : {e}");
            return;
        }
    };

    std::thread::spawn(move || {
        while receiver.recv().is_ok() {
            // L'interface decide quoi faire ; on ne fait que la prevenir.
            if app.emit("devices-changed", ()).is_err() {
                return;
            }
        }
    });
}

#[cfg(not(windows))]
fn start_device_watcher(_app: tauri::AppHandle) {}

fn print_help() {
    println!("Universal Boot Selector {}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Usage : bootsel [options]");
    println!();
    println!("  --mock-boot <scenario>  Firmware simule, aucun acces au materiel reel.");
    println!("  --dry-run               Interdit toute ecriture, meme demandee.");
    println!("  --no-elevate            Reste non privilegie ; entrees UEFI non lues.");
    println!("  --help, -h              Affiche cette aide.");
    println!();
    println!("L application ne modifie que la variable UEFI BootNext, et seulement");
    println!("sur action explicite. L ordre de demarrage permanent n est jamais touche.");
}
