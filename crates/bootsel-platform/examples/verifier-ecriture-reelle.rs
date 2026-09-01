//! Validation du chemin d'ecriture sur un firmware **reel**, sans changer le
//! comportement de la machine.
//!
//! # Ce que fait cet outil
//!
//! Il programme `BootNext` sur l'entree qui a servi au demarrage courant.
//! Autrement dit : au prochain redemarrage, la machine demarrera sur ce
//! qu'elle a deja demarre cette fois-ci. Le resultat observable est donc
//! **identique a un redemarrage normal**, alors que le chemin d'ecriture
//! complet a bien ete exerce : activation du privilege, ecriture de deux
//! octets, relecture, verification par le garde-fou.
//!
//! # Ce qu'il refuse de faire
//!
//! Il refuse toute cible autre que l'entree de demarrage courante. Ce n'est
//! pas une option, c'est une condition de sortie : viser autre chose ferait de
//! cet outil un selecteur de boot, ce qu'il n'est pas.
//!
//! Il ne redemarre jamais la machine.
//!
//! # Pourquoi un exemple et pas un test
//!
//! Un test s'execute automatiquement, y compris en CI et sur la machine de
//! quelqu'un qui ne s'y attend pas. Ecrire dans le firmware ne doit jamais
//! arriver par surprise : il faut le demander explicitement.

use bootsel_core::alias::Config;
use bootsel_core::detect::detect;
use bootsel_core::guard;
use bootsel_core::select::{commit_selection, prepare};
use bootsel_platform::{create_backend, BackendOptions};

fn main() {
    println!("Validation du chemin d'ecriture sur firmware reel");
    println!("=================================================\n");

    let backend = match create_backend(&BackendOptions {
        mock_scenario: None,
        read_only: false,
        elevate: true,
    }) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Backend indisponible : {e}");
            std::process::exit(2);
        }
    };
    println!("Backend : {}\n", backend.name());

    let config = Config::default();

    // --- Etat avant, releve integralement -------------------------------
    let before = match backend.read_state() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Lecture du firmware impossible : {e}");
            std::process::exit(2);
        }
    };

    let boot_order_before = before.get("BootOrder").map(|v| v.to_vec());
    println!("AVANT");
    println!("  BootOrder   : {}", render_order(&before));
    println!("  BootCurrent : {}", render_scalar(before.boot_current()));
    println!("  BootNext    : {}", render_scalar(before.boot_next()));
    println!("  Variables   : {}\n", before.variables.len());

    // --- La cible est imposee : l'entree de demarrage courante ----------
    let Some(current) = before.boot_current() else {
        eprintln!("BootCurrent est illisible : impossible de garantir une cible sans effet.");
        eprintln!("Aucune modification n'a ete effectuee.");
        std::process::exit(2);
    };

    let detection = match detect(backend.as_ref(), &config) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Detection impossible : {e}");
            std::process::exit(2);
        }
    };

    let Some(entry) = detection.entries.iter().find(|e| e.id == current) else {
        eprintln!("L'entree de demarrage courante {current} n'apparait pas dans la detection.");
        eprintln!("Aucune modification n'a ete effectuee.");
        std::process::exit(2);
    };

    let plan = match prepare(&detection.entries, &entry.stable_id) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Cible inutilisable : {e}");
            std::process::exit(2);
        }
    };

    // Garde-fou de cet outil : la cible ne peut etre que le demarrage courant.
    if plan.observed_id != current {
        eprintln!(
            "REFUS : la cible resolue est {} au lieu du demarrage courant {current}.",
            plan.observed_id
        );
        eprintln!("Aucune modification n'a ete effectuee.");
        std::process::exit(3);
    }

    println!("CIBLE (imposee : le demarrage courant)");
    println!("  {} — {}", current, plan.display_name);
    println!("  {}\n", plan.efi_path.as_deref().unwrap_or("-"));
    println!("Au prochain redemarrage, la machine demarrera sur ce qu'elle a");
    println!("deja demarre cette fois-ci. Aucun changement de comportement.\n");

    // --- L'ecriture, par le chemin de production complet -----------------
    println!("Ecriture de BootNext...");
    let outcome = match commit_selection(backend.as_ref(), &config, &plan) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("\nECHEC : {e}");
            if e.guarantees_no_write() {
                eprintln!("Aucune modification n'a ete effectuee.");
            }
            std::process::exit(1);
        }
    };

    // --- Etat apres, releve integralement --------------------------------
    let after = match backend.read_state() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Relecture impossible : {e}");
            std::process::exit(1);
        }
    };
    let boot_order_after = after.get("BootOrder").map(|v| v.to_vec());

    println!("\nAPRES");
    println!("  BootOrder   : {}", render_order(&after));
    println!("  BootNext    : {}", render_scalar(after.boot_next()));
    println!("  Variables   : {}\n", after.variables.len());

    // --- La preuve --------------------------------------------------------
    println!("VERIFICATIONS");

    let changes = guard::diff(&before, &after);
    let names: Vec<&str> = changes.iter().map(|c| c.name()).collect();
    println!(
        "  Variables modifiees            : {}",
        if names.is_empty() { "aucune".to_string() } else { names.join(", ") }
    );

    let only_boot_next = names == ["BootNext"];
    let order_intact = boot_order_before == boot_order_after;

    println!(
        "  Seule BootNext a change        : {}",
        verdict(only_boot_next)
    );
    println!(
        "  BootOrder identique, octet a octet : {}",
        verdict(order_intact)
    );
    println!(
        "  BootNext vaut la cible         : {}",
        verdict(after.boot_next() == Some(outcome.target))
    );
    println!(
        "  Nombre d'entrees inchange      : {}",
        verdict(before.entry_ids() == after.entry_ids())
    );

    if only_boot_next && order_intact {
        println!("\nRESULTAT : le chemin d'ecriture fonctionne sur ce firmware.");
        println!("Le prochain redemarrage ira sur {} — comme d'habitude.", plan.display_name);
        println!("Aucun redemarrage n'a ete declenche.");
    } else {
        eprintln!("\nRESULTAT : une variable inattendue a change. A examiner.");
        std::process::exit(1);
    }
}

fn render_order(state: &bootsel_core::model::FirmwareState) -> String {
    match state.boot_order() {
        Some(ids) => ids
            .iter()
            .map(|id| id.variable_name())
            .collect::<Vec<_>>()
            .join(", "),
        None => "illisible".to_string(),
    }
}

fn render_scalar(id: Option<bootsel_core::model::BootId>) -> String {
    id.map(|i| i.variable_name())
        .unwrap_or_else(|| "non defini".to_string())
}

fn verdict(ok: bool) -> &'static str {
    if ok {
        "OUI"
    } else {
        "NON"
    }
}
