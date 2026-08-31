//! Barriere de revue automatisee : interdit qu'une operation destructive ou
//! privilegiee apparaisse ailleurs que dans les rares fichiers autorises.
//!
//! Ce test lit le code source de tous les crates du projet et echoue si un
//! symbole interdit y apparait. Il ne remplace pas une relecture humaine ; il
//! garantit qu'un ajout involontaire ne passe pas inapercu, y compris dans un
//! crate qui n'existe pas encore au moment ou ces lignes sont ecrites.
//!
//! **Elargir la liste d'exceptions est un acte deliberer et relu.** Toute
//! entree ajoutee a `PRIVILEGED_ALLOWLIST` doit etre justifiee dans
//! `SECURITY.md`.
//!
//! Seuls les repertoires `src/` sont analyses : c'est le code livre. Les
//! repertoires `tests/` en sont exclus, sans quoi ce fichier se signalerait
//! lui-meme.

use std::fs;
use std::path::{Path, PathBuf};

/// Racine du workspace, deduite de l'emplacement de ce crate.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("le crate vit dans <racine>/crates/<nom>")
        .to_path_buf()
}

/// Tous les fichiers `.rs` sous les repertoires `src/` des crates du projet.
fn shipped_sources() -> Vec<PathBuf> {
    let crates_dir = workspace_root().join("crates");
    let mut files = Vec::new();

    let Ok(entries) = fs::read_dir(&crates_dir) else {
        panic!("repertoire crates/ introuvable : {}", crates_dir.display());
    };

    for entry in entries.flatten() {
        let src = entry.path().join("src");
        if src.is_dir() {
            collect_rs(&src, &mut files);
        }
    }

    assert!(
        !files.is_empty(),
        "aucune source analysee : le test ne garantirait rien"
    );
    files
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Chemin relatif a la racine, avec des barres obliques, pour les messages et
/// les comparaisons d'exception.
fn relative(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

// ---------------------------------------------------------------------------
// Interdits absolus : nulle part, pas meme dans le helper privilegie
// ---------------------------------------------------------------------------

/// Outils et appels capables de detruire des donnees, une table de partitions
/// ou un chargeur de demarrage. L'application n'a aucune raison legitime d'en
/// contenir la moindre trace : ce n'est ni un partitionneur, ni un
/// installateur, ni un reparateur de boot.
const FORBIDDEN_EVERYWHERE: &[(&str, &str)] = &[
    ("diskpart", "outil de partitionnement Windows"),
    ("mkfs", "creation de systeme de fichiers"),
    ("sgdisk", "edition de table GPT"),
    ("wipefs", "effacement de signatures de systeme de fichiers"),
    ("bcdedit", "modification du magasin BCD de Windows"),
    ("bootsect", "reecriture de secteur d'amorcage"),
    ("bootrec", "reparation de boot Windows"),
    ("grub-install", "installation de chargeur"),
    ("bootctl install", "installation de systemd-boot"),
    ("efibootmgr -o", "modification de BootOrder"),
    ("efibootmgr --bootorder", "modification de BootOrder"),
    ("IOCTL_DISK_SET", "ecriture de disposition de disque"),
    ("IOCTL_DISK_DELETE", "suppression de partition"),
    ("IOCTL_DISK_CREATE", "creation de partition"),
    ("IOCTL_DISK_FORMAT", "formatage"),
    ("FSCTL_", "operation de bas niveau sur systeme de fichiers"),
    ("DeleteFile", "suppression de fichier systeme"),
    ("SetFileAttributes", "modification d'attributs de fichier systeme"),
];

/// Certains motifs sont trop courts pour etre cherches tels quels sans faux
/// positif. On les cherche comme mots entiers ou avec leur contexte d'appel.
const FORBIDDEN_EVERYWHERE_EXACT: &[(&str, &str)] = &[
    ("\"parted\"", "outil de partitionnement"),
    ("\"fdisk\"", "outil de partitionnement"),
    ("\"format\"", "commande de formatage"),
    ("\"dd\"", "copie brute de blocs"),
];

// ---------------------------------------------------------------------------
// Operations privilegiees : reservees aux fichiers explicitement autorises
// ---------------------------------------------------------------------------

/// Symboles capables d'ecrire dans le firmware, de redemarrer la machine ou de
/// lancer un processus. Autorises uniquement dans les fichiers listes.
const PRIVILEGED: &[(&str, &str)] = &[
    ("SetFirmwareEnvironmentVariable", "ecriture de variable UEFI"),
    ("ExitWindowsEx", "redemarrage Windows"),
    ("InitiateSystemShutdown", "redemarrage Windows"),
    ("AdjustTokenPrivileges", "elevation de privileges"),
    ("Command::new", "lancement d'un processus"),
    ("ShellExecute", "lancement d'un processus"),
    ("CreateProcess", "lancement d'un processus"),
];

/// Fichiers autorises a contenir une operation privilegiee.
///
/// Chaque entree est un suffixe de chemin. La liste est volontairement courte :
/// c'est la surface exacte a relire lors d'un audit.
const PRIVILEGED_ALLOWLIST: &[&str] = &[
    // Le helper est le seul binaire capable d'ecrire dans le firmware.
    "crates/bootsel-helper/src/",
    // La couche d'elevation lance le helper ; elle ne fait que cela.
    "crates/bootsel-platform/src/elevate.rs",
    // Backends systeme : lecture du firmware et redemarrage, apres validation.
    "crates/bootsel-platform/src/windows/firmware.rs",
    "crates/bootsel-platform/src/windows/power.rs",
    "crates/bootsel-platform/src/linux/firmware.rs",
    "crates/bootsel-platform/src/linux/power.rs",
];

fn is_allowed(path: &str) -> bool {
    PRIVILEGED_ALLOWLIST.iter().any(|a| path.contains(a))
}

// ---------------------------------------------------------------------------
// Les tests
// ---------------------------------------------------------------------------

/// Aucun symbole destructeur nulle part dans le code livre.
#[test]
fn test_no_destructive_symbols() {
    let mut violations = Vec::new();

    for path in shipped_sources() {
        let rel = relative(&path);
        let content = fs::read_to_string(&path).expect("source lisible");

        for (needle, why) in FORBIDDEN_EVERYWHERE {
            if let Some(line) = find_line(&content, needle) {
                violations.push(format!("{rel}:{line} contient {needle:?} ({why})"));
            }
        }
        for (needle, why) in FORBIDDEN_EVERYWHERE_EXACT {
            if let Some(line) = find_line(&content, needle) {
                violations.push(format!("{rel}:{line} contient {needle} ({why})"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "operations destructives detectees dans le code livre :\n  {}",
        violations.join("\n  ")
    );
}

/// Les operations privilegiees restent confinees aux fichiers autorises.
#[test]
fn test_privileged_operations_are_confined() {
    let mut violations = Vec::new();

    for path in shipped_sources() {
        let rel = relative(&path);
        if is_allowed(&rel) {
            continue;
        }
        let content = fs::read_to_string(&path).expect("source lisible");

        for (needle, why) in PRIVILEGED {
            if let Some(line) = find_line(&content, needle) {
                violations.push(format!(
                    "{rel}:{line} contient {needle:?} ({why}) hors de la liste autorisee"
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "operations privilegiees hors de leur perimetre :\n  {}\n\n\
         Si c'est intentionnel, ajouter le fichier a PRIVILEGED_ALLOWLIST \
         et justifier dans SECURITY.md.",
        violations.join("\n  ")
    );
}

/// Le coeur metier n'a aucun acces au systeme : ni fichiers, ni processus,
/// ni code `unsafe`.
#[test]
fn test_core_crate_has_no_system_access() {
    let core_src = workspace_root().join("crates/bootsel-core/src");
    let mut files = Vec::new();
    collect_rs(&core_src, &mut files);

    let mut violations = Vec::new();
    for path in &files {
        let rel = relative(path);
        let content = fs::read_to_string(path).expect("source lisible");

        for needle in [
            "std::fs",
            "std::process",
            "std::net",
            "File::open",
            "File::create",
            "OpenOptions",
            "unsafe ",
        ] {
            if let Some(line) = find_line(&content, needle) {
                violations.push(format!("{rel}:{line} contient {needle:?}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "bootsel-core doit rester purement calculatoire :\n  {}",
        violations.join("\n  ")
    );
}

/// Le coeur metier declare explicitement l'interdiction du code `unsafe`.
#[test]
fn test_core_crate_forbids_unsafe_code() {
    let lib = workspace_root().join("crates/bootsel-core/src/lib.rs");
    let content = fs::read_to_string(&lib).expect("lib.rs lisible");
    assert!(
        content.contains("#![forbid(unsafe_code)]"),
        "bootsel-core doit declarer #![forbid(unsafe_code)]"
    );
}

/// `BootOrder` n'apparait jamais comme cible d'une ecriture.
///
/// Recherche des formes d'appel qui ecriraient la variable, plutot que du
/// simple nom : celui-ci apparait legitimement partout ou on la lit et ou on
/// verifie qu'elle n'a pas bouge.
#[test]
fn test_boot_order_is_never_written() {
    let mut violations = Vec::new();

    for path in shipped_sources() {
        let rel = relative(&path);
        let content = fs::read_to_string(&path).expect("source lisible");

        for needle in [
            "set_variable(VAR_BOOT_ORDER",
            "set_variable(\"BootOrder",
            "write_variable(VAR_BOOT_ORDER",
            "write_variable(\"BootOrder",
            "SetFirmwareEnvironmentVariableW(w!(\"BootOrder",
            "BootOrder-8be4df61",
        ] {
            if let Some(line) = find_line(&content, needle) {
                violations.push(format!("{rel}:{line} : {needle:?}"));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "ecriture de BootOrder detectee — interdiction absolue du projet :\n  {}",
        violations.join("\n  ")
    );
}

/// Renvoie le numero de la premiere ligne contenant le motif, hors commentaires.
///
/// Les commentaires sont ignores : ce fichier-ci parle abondamment de
/// `diskpart` et de `bcdedit` pour expliquer pourquoi ils sont interdits, et
/// la documentation du projet doit pouvoir en faire autant.
fn find_line(content: &str, needle: &str) -> Option<usize> {
    content.lines().enumerate().find_map(|(i, line)| {
        let code = strip_comment(line);
        code.contains(needle).then_some(i + 1)
    })
}

/// Retire la partie commentaire d'une ligne (`//` et `//!`).
fn strip_comment(line: &str) -> &str {
    match line.find("//") {
        Some(idx) => &line[..idx],
        None => line,
    }
}

#[cfg(test)]
mod meta {
    use super::*;

    /// Le detecteur doit reellement detecter : sans ce test, une regression
    /// silencieuse rendrait tous les autres tests de ce fichier inutiles.
    #[test]
    fn the_detector_actually_detects() {
        assert_eq!(find_line("a\nb\nlet x = diskpart;\n", "diskpart"), Some(3));
        assert_eq!(find_line("rien ici", "diskpart"), None);
    }

    /// Une mention en commentaire ne doit pas declencher de faux positif.
    #[test]
    fn comments_are_ignored() {
        assert_eq!(find_line("// on n'utilise jamais diskpart", "diskpart"), None);
        assert_eq!(find_line("//! ni bcdedit", "bcdedit"), None);
        // Mais du code suivi d'un commentaire reste analyse.
        assert_eq!(
            find_line("let x = diskpart; // explication", "diskpart"),
            Some(1)
        );
    }

    #[test]
    fn the_allowlist_stays_small_enough_to_audit() {
        assert!(
            PRIVILEGED_ALLOWLIST.len() <= 8,
            "la surface privilegiee grandit : {} entrees. Chaque ajout doit \
             etre justifie dans SECURITY.md.",
            PRIVILEGED_ALLOWLIST.len()
        );
    }
}
