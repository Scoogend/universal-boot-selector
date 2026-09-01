//! Lecture des variables de demarrage sous Linux. **Lecture seule.**
//!
//! # Pourquoi c'est plus simple que sous Windows
//!
//! Le noyau expose les variables UEFI comme des fichiers ordinaires dans
//! `/sys/firmware/efi/efivars/`, **lisibles par tout utilisateur**. La
//! detection complete fonctionne donc sans aucun privilege — contrairement a
//! Windows, ou meme lire exige des droits administrateur.
//!
//! # Disposition d'un fichier efivars
//!
//! Le nom combine la variable et son espace de nommage :
//! `BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c`.
//!
//! Le contenu commence par **quatre octets d'attributs** que le noyau ajoute,
//! suivis de la valeur reelle. Ces quatre octets sont retires ici : le reste
//! du projet ne manipule que des valeurs UEFI brutes, identiques a ce que
//! Windows renvoie.
//!
//! # Racine injectable
//!
//! Toutes les fonctions acceptent une racine de systeme de fichiers. En
//! production c'est `/`, dans les tests c'est un repertoire temporaire. C'est
//! ce qui permet de tester integralement ce module depuis n'importe quelle
//! plateforme, y compris Windows.

use bootsel_core::backend::BackendError;
use bootsel_core::model::{
    BootId, FirmwareMode, FirmwareState, VAR_BOOT_CURRENT, VAR_BOOT_NEXT, VAR_BOOT_ORDER,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Espace de nommage des variables globales UEFI, tel qu'il apparait dans les
/// noms de fichiers.
pub const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Nombre d'octets d'attributs ajoutes par le noyau en tete de chaque fichier.
const ATTRIBUTE_PREFIX: usize = 4;

/// Taille au-dela de laquelle un fichier est considere comme aberrant.
const MAX_VARIABLE_SIZE: u64 = 64 * 1024;

/// Racine du systeme de fichiers a inspecter.
pub fn efivars_dir(root: &Path) -> PathBuf {
    root.join("sys/firmware/efi/efivars")
}

/// Detecte le mode de demarrage. **Non privilegie.**
///
/// La presence de `/sys/firmware/efi` est le critere retenu par le noyau
/// lui-meme : ce repertoire n'existe que lorsque la machine a demarre en UEFI.
pub fn firmware_mode(root: &Path) -> FirmwareMode {
    if root.join("sys/firmware/efi").is_dir() {
        FirmwareMode::Uefi
    } else {
        FirmwareMode::LegacyBios
    }
}

/// Nom de fichier d'une variable dans `efivars`.
pub fn variable_file_name(name: &str) -> String {
    format!("{name}-{EFI_GLOBAL_GUID}")
}

/// Extrait le nom d'une variable depuis un nom de fichier efivars.
///
/// Ne reconnait que l'espace de nommage global : les variables des autres
/// espaces ne concernent pas le demarrage et sont ignorees.
fn variable_name_from_file(file_name: &str) -> Option<&str> {
    let suffix = format!("-{EFI_GLOBAL_GUID}");
    file_name.strip_suffix(&suffix).filter(|n| !n.is_empty())
}

/// Lit une variable et retire les quatre octets d'attributs.
///
/// `Ok(None)` signale une variable absente, ce qui est normal : `BootNext`
/// n'existe pas la plupart du temps.
pub fn read_variable(root: &Path, name: &str) -> Result<Option<Vec<u8>>, BackendError> {
    let path = efivars_dir(root).join(variable_file_name(name));

    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(BackendError::PrivilegeRequired)
        }
        Err(e) => return Err(BackendError::Io(format!("{}: {e}", path.display()))),
    };

    if metadata.len() > MAX_VARIABLE_SIZE {
        return Err(BackendError::FirmwareUnavailable(format!(
            "{} fait {} octets : valeur aberrante, ignoree",
            path.display(),
            metadata.len()
        )));
    }

    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(BackendError::PrivilegeRequired)
        }
        Err(e) => return Err(BackendError::Io(format!("{}: {e}", path.display()))),
    };

    // Un fichier plus court que son en-tete d'attributs est corrompu : on
    // l'ignore plutot que d'en tirer une valeur fausse.
    if raw.len() < ATTRIBUTE_PREFIX {
        return Ok(None);
    }

    Ok(Some(raw[ATTRIBUTE_PREFIX..].to_vec()))
}

/// Instantane complet des variables de demarrage. **Lecture seule.**
///
/// Enumere reellement le repertoire au lieu de sonder des identifiants : sous
/// Linux, la liste des variables est directement lisible.
pub fn read_state(root: &Path) -> Result<FirmwareState, BackendError> {
    let dir = efivars_dir(root);

    if !dir.is_dir() {
        return Err(BackendError::NotUefi);
    }

    let entries = std::fs::read_dir(&dir).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            BackendError::PrivilegeRequired
        } else {
            BackendError::Io(format!("lecture de {}: {e}", dir.display()))
        }
    })?;

    let mut variables = BTreeMap::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(name) = variable_name_from_file(file_name) else {
            continue;
        };

        // On ne retient que ce qui concerne le demarrage. Les autres variables
        // du firmware ne nous regardent pas, et les lire elargirait
        // inutilement ce que l'application observe.
        let wanted = matches!(name, VAR_BOOT_ORDER | VAR_BOOT_NEXT | VAR_BOOT_CURRENT)
            || BootId::from_variable_name(name).is_some();
        if !wanted {
            continue;
        }

        // Une variable illisible est ignoree, pas fatale : mieux vaut une
        // entree manquante qu'une detection impossible.
        if let Ok(Some(value)) = read_variable(root, name) {
            variables.insert(name.to_string(), value);
        }
    }

    Ok(FirmwareState::new(variables))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construit une arborescence `/sys/firmware/efi/efivars` simulee.
    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Fixture {
            let root = std::env::temp_dir().join(format!("bootsel-efivars-{name}"));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(efivars_dir(&root)).expect("arborescence de test");
            Fixture { root }
        }

        /// Ecrit une variable comme le noyau le ferait : attributs puis valeur.
        fn put(&self, name: &str, value: &[u8]) -> &Fixture {
            let attributes: u32 = 0x0000_0007; // NV | BS | RT
            let mut raw = attributes.to_le_bytes().to_vec();
            raw.extend_from_slice(value);
            std::fs::write(efivars_dir(&self.root).join(variable_file_name(name)), raw)
                .expect("ecriture de fixture");
            self
        }

        /// Ecrit un fichier brut, pour les cas corrompus.
        fn put_raw(&self, file_name: &str, raw: &[u8]) -> &Fixture {
            std::fs::write(efivars_dir(&self.root).join(file_name), raw)
                .expect("ecriture de fixture");
            self
        }

        fn legacy(name: &str) -> Fixture {
            let root = std::env::temp_dir().join(format!("bootsel-legacy-{name}"));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("arborescence de test");
            Fixture { root }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    /// Reproduit un double amorcage Windows + Debian, tel qu'on le trouve sur
    /// une machine reelle.
    fn dual_boot(name: &str) -> Fixture {
        let f = Fixture::new(name);
        f.put(VAR_BOOT_ORDER, &bootsel_core::efi::testdata::boot_order(&[1, 2]))
            .put(VAR_BOOT_CURRENT, &bootsel_core::efi::testdata::boot_id(1))
            .put("Boot0001", &bootsel_core::efi::testdata::load_option_windows())
            .put("Boot0002", &bootsel_core::efi::testdata::load_option_debian());
        f
    }

    #[test]
    fn detects_uefi_from_the_kernel_directory() {
        let f = Fixture::new("mode-uefi");
        assert_eq!(firmware_mode(&f.root), FirmwareMode::Uefi);
    }

    #[test]
    fn detects_legacy_bios_when_the_directory_is_absent() {
        let f = Fixture::legacy("mode-bios");
        assert_eq!(firmware_mode(&f.root), FirmwareMode::LegacyBios);
    }

    #[test]
    fn the_file_name_matches_what_the_kernel_uses() {
        assert_eq!(
            variable_file_name("BootOrder"),
            "BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
        assert_eq!(
            EFI_GLOBAL_GUID,
            bootsel_core::efi::Guid::EFI_GLOBAL_VARIABLE.to_hyphenated()
        );
    }

    #[test]
    fn the_four_attribute_bytes_are_stripped() {
        let f = Fixture::new("attributs");
        f.put(VAR_BOOT_NEXT, &[0x02, 0x00]);

        // La valeur rendue doit etre celle d'UEFI, pas celle du noyau.
        assert_eq!(
            read_variable(&f.root, VAR_BOOT_NEXT).unwrap(),
            Some(vec![0x02, 0x00])
        );
    }

    #[test]
    fn a_missing_variable_is_not_an_error() {
        let f = Fixture::new("absente");
        assert_eq!(read_variable(&f.root, VAR_BOOT_NEXT).unwrap(), None);
    }

    #[test]
    fn a_truncated_file_yields_nothing_rather_than_a_wrong_value() {
        let f = Fixture::new("tronquee");
        f.put_raw(&variable_file_name(VAR_BOOT_NEXT), &[0x07, 0x00]);
        assert_eq!(read_variable(&f.root, VAR_BOOT_NEXT).unwrap(), None);
    }

    #[test]
    fn reads_a_complete_dual_boot_state() {
        let f = dual_boot("dual");
        let state = read_state(&f.root).expect("lecture");

        assert_eq!(state.boot_order(), Some(vec![BootId(1), BootId(2)]));
        assert_eq!(state.boot_current(), Some(BootId(1)));
        assert_eq!(state.boot_next(), None);
        assert_eq!(state.entry_ids(), vec![BootId(1), BootId(2)]);

        let windows = state.load_option(BootId(1)).unwrap().unwrap();
        assert_eq!(windows.description, "Windows Boot Manager");
    }

    #[test]
    fn variables_outside_the_boot_namespace_are_ignored() {
        let f = dual_boot("hors-perimetre");
        // Variables reelles d une machine Linux, sans rapport avec le demarrage.
        f.put("SecureBoot", &[0x01])
            .put("Timeout", &[0x05, 0x00])
            .put_raw("dump-type0-0-1-1234-0", b"donnees de plantage")
            .put_raw(
                "MokListRT-605dab50-e046-4300-abb6-3dd810dd8b23",
                b"autre espace de nommage",
            );

        let state = read_state(&f.root).expect("lecture");

        // Seules les variables de demarrage sont retenues.
        let names: Vec<&String> = state.variables.keys().collect();
        assert_eq!(
            names,
            vec!["Boot0001", "Boot0002", "BootCurrent", "BootOrder"]
        );
    }

    #[test]
    fn an_unreadable_entry_does_not_break_the_whole_snapshot() {
        let f = dual_boot("entree-cassee");
        f.put_raw(&variable_file_name("Boot0003"), &[0x07]); // trop court

        let state = read_state(&f.root).expect("lecture");
        assert_eq!(state.entry_ids(), vec![BootId(1), BootId(2)]);
    }

    #[test]
    fn a_legacy_bios_machine_is_reported_as_such() {
        let f = Fixture::legacy("etat-bios");
        assert_eq!(read_state(&f.root), Err(BackendError::NotUefi));
    }

    #[test]
    fn an_empty_efivars_directory_yields_an_empty_snapshot() {
        let f = Fixture::new("vide");
        let state = read_state(&f.root).expect("lecture");
        assert!(state.variables.is_empty());
        assert_eq!(state.boot_order(), None);
    }

    #[test]
    fn reading_never_modifies_the_directory() {
        let f = dual_boot("lecture-passive");
        let dir = efivars_dir(&f.root);

        let before: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        let _ = read_state(&f.root);
        let _ = read_variable(&f.root, VAR_BOOT_ORDER);
        let _ = firmware_mode(&f.root);

        let after: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();

        assert_eq!(before, after, "la lecture ne doit rien changer");
    }

    #[test]
    fn this_module_defines_no_write_operation() {
        // Garde-fou de revue : l ecriture de BootNext appartient au helper.
        let source = include_str!("firmware.rs");
        let shipped = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];
        for forbidden in ["fs::write", "fs::remove", "OpenOptions", "File::create"] {
            assert!(
                !shipped.contains(forbidden),
                "ce module doit rester en lecture seule : {forbidden}"
            );
        }
    }
}
