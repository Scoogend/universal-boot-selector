//! Outil de diagnostic en ligne de commande. **Lecture seule, sans exception.**
//!
//! Sert a verifier la detection sur une machine reelle avant qu'il existe une
//! interface graphique, et a produire un rapport lisible en cas de probleme.
//!
//! Ce binaire n'ecrit jamais : il ne connait pas la selection de boot. Il
//! n'appelle que `firmware_mode`, `read_state` et `list_devices`.

use bootsel_core::alias::Config;
use bootsel_core::backend::BackendError;
use bootsel_core::detect::detect;
use bootsel_core::model::{format_size, Availability, FirmwareMode};
use bootsel_platform::{create_backend, BackendOptions};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return;
    }

    let mock_scenario = args
        .iter()
        .position(|a| a == "--mock-boot")
        .and_then(|i| args.get(i + 1))
        .cloned();

    let options = BackendOptions {
        mock_scenario,
        // Ce binaire est toujours en lecture seule, quelles que soient les
        // options : c'est un outil de diagnostic, pas un selecteur.
        read_only: true,
    };

    let backend = match create_backend(&options) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Impossible d'initialiser le backend : {e}");
            std::process::exit(2);
        }
    };

    println!("Universal Boot Selector — diagnostic (lecture seule)");
    println!("Backend : {}\n", backend.name());

    // L'inventaire materiel est affiche en premier : il ne demande aucun
    // privilege et reste disponible meme si le firmware est inaccessible.
    match backend.list_devices() {
        Ok(devices) => print_devices(&devices),
        Err(e) => println!("Disques : indisponibles ({e})\n"),
    }

    match backend.firmware_mode() {
        Ok(FirmwareMode::Uefi) => println!("Firmware : UEFI\n"),
        Ok(FirmwareMode::LegacyBios) => {
            println!("Firmware : BIOS Legacy");
            println!(
                "La selection securisee du prochain demarrage via UEFI n'est pas disponible.\n"
            );
            return;
        }
        Err(e) => {
            println!("Firmware : indeterminable ({e})\n");
            return;
        }
    }

    match detect(backend.as_ref(), &Config::default()) {
        Ok(detection) => print_detection(&detection),
        Err(BackendError::PrivilegeRequired) => {
            println!("Entrees UEFI : non lues.");
            println!();
            println!("Sous Windows, lire les variables de demarrage du firmware exige des");
            println!("privileges administrateur — y compris en lecture seule. Relancez cet");
            println!("outil depuis un terminal administrateur pour voir les entrees UEFI.");
            println!();
            println!("Aucune modification n'a ete effectuee.");
        }
        Err(e) => {
            println!("Detection impossible : {e}");
            if e.guarantees_no_write() {
                println!("Aucune modification n'a ete effectuee.");
            }
        }
    }
}

fn print_devices(devices: &[bootsel_core::model::StorageDevice]) {
    println!("Disques detectes ({})", devices.len());
    for d in devices {
        let kind = if d.removable { "amovible" } else { "interne" };
        println!(
            "  [{}] {} — {} ({kind})",
            d.system_name,
            d.label(),
            d.serial.as_deref().unwrap_or("sans numero de serie")
        );
        for p in &d.partitions {
            let tag = if p.is_esp { "ESP" } else { "   " };
            println!(
                "        {tag} partition {} — {:>10}  {}",
                p.number,
                format_size(p.size_bytes),
                p.unique_guid
                    .map(|g| g.to_hyphenated())
                    .unwrap_or_else(|| "-".into())
            );
        }
    }
    println!();
}

fn print_detection(detection: &bootsel_core::detect::Detection) {
    if let Some(order) = &detection.boot_order {
        let names: Vec<String> = order.iter().map(|id| id.variable_name()).collect();
        println!("BootOrder : {}", names.join(", "));
    }
    match detection.boot_next {
        Some(id) => println!("BootNext  : {id} (un demarrage unique est deja programme)"),
        None => println!("BootNext  : non defini"),
    }
    if let Some(current) = detection.boot_current {
        println!("BootCurrent : {current}");
    }
    println!();

    println!("Entrees de demarrage ({})", detection.entries.len());
    for e in &detection.entries {
        let state = match &e.availability {
            Availability::Available => "disponible".to_string(),
            Availability::DeviceMissing => "peripherique absent".to_string(),
            Availability::Inactive => "inactive".to_string(),
            Availability::NotSelectable(r) => r.clone(),
        };
        let current = if e.is_current { " <- demarrage courant" } else { "" };

        println!("  {} — {}{current}", e.id, e.display_name);
        println!(
            "        {} · {} · {}",
            e.bootloader.label(),
            e.device_label.as_deref().unwrap_or(e.transport.label()),
            e.confidence.label()
        );
        if let Some(path) = &e.efi_path {
            println!("        {path}");
        }
        println!("        etat : {state}");
    }

    print_unlisted_media(detection);

    if !detection.warnings.is_empty() {
        println!("\nAvertissements");
        for w in &detection.warnings {
            println!("  - {w}");
        }
    }

    println!("\nAucune modification n'a ete effectuee.");
}

/// Affiche les supports bootables qu'aucune entree UEFI ne designe.
///
/// Ils ne sont jamais presentes comme selectionnables : sans entree
/// `Boot####`, `BootNext` n'a rien a cibler, et en creer une est interdit.
fn print_unlisted_media(detection: &bootsel_core::detect::Detection) {
    if detection.unlisted_media.is_empty() {
        return;
    }

    println!("
Supports bootables sans entree UEFI ({})", detection.unlisted_media.len());
    for m in &detection.unlisted_media {
        println!("  {} — {}", m.display_name, m.device_label);
        println!(
            "        ESP en partition {} · {} · non selectionnable",
            m.esp_partition,
            m.confidence.label()
        );
        println!("        {}", m.reason);
        println!("        {}", m.suggestion);
    }
}

fn print_help() {
    println!("Universal Boot Selector — outil de diagnostic (lecture seule)");
    println!();
    println!("Usage : bootsel-cli [--mock-boot <scenario>]");
    println!();
    println!("  --mock-boot <scenario>  Utilise un firmware simule au lieu du materiel reel.");
    println!("  --help, -h              Affiche cette aide.");
    println!();
    println!("Cet outil n'ecrit jamais : ni firmware, ni disque, ni partition.");
}
