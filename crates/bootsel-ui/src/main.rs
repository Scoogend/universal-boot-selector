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
            commands::set_alias,
            commands::clear_alias,
            commands::set_preference,
        ])
        .run(tauri::generate_context!())
        .expect("lancement de l interface");
}

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
