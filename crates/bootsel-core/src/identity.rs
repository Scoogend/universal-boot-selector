//! Identite stable d'une entree de demarrage.
//!
//! Les identifiants `Boot####` sont **volatils** : un firmware peut renumeroter
//! ses entrees apres une mise a jour, un changement de disque ou une
//! reinitialisation NVRAM. Memoriser un alias sous la cle `Boot0002` conduirait
//! donc a afficher « Mon Linux » devant Windows apres une renumerotation.
//!
//! On derive a la place une cle stable a partir de ce qui identifie reellement
//! la cible : le GUID unique de sa partition GPT et son chemin EFI. Ces deux
//! elements survivent a une renumerotation ; ils ne changent que si la
//! partition est recreee, auquel cas il est correct de perdre l'alias.

use crate::efi::LoadOption;
use sha2::{Digest, Sha256};

/// Version du schema de derivation. Toute evolution de la methode incremente
/// ce prefixe, ce qui invalide proprement les anciens alias au lieu de les
/// faire pointer sur la mauvaise entree.
const SCHEME_VERSION: &str = "v1";

/// Derive la cle stable d'une entree de demarrage.
///
/// Trois strategies, par ordre de robustesse decroissante :
/// - `gpt`  — GUID unique de partition + chemin EFI. Le cas normal.
/// - `mbr`  — signature de disque MBR + numero de partition + chemin EFI.
/// - `desc` — description firmware + chemin EFI. Dernier recours, pour les
///   entrees sans noeud de partition (amorcage reseau, entrees firmware).
pub fn stable_id_for(option: &LoadOption) -> String {
    let efi_path = option
        .efi_path()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if let Some(guid) = option.partition_guid() {
        return hash("gpt", &[guid.to_hyphenated().as_str(), efi_path.as_str()]);
    }

    if let Some(hd) = option.device_path.hard_drive() {
        if let crate::efi::PartitionSignature::Mbr(sig) = hd.signature {
            return hash(
                "mbr",
                &[
                    &format!("{sig:08x}"),
                    &hd.partition_number.to_string(),
                    efi_path.as_str(),
                ],
            );
        }
    }

    hash(
        "desc",
        &[option.description.trim(), efi_path.as_str()],
    )
}

/// Concatene les composants avec un separateur non ambigu puis hache.
///
/// Le separateur `\x1f` (unit separator) ne peut apparaitre ni dans un GUID,
/// ni dans un chemin EFI, ce qui empeche deux jeux de composants differents
/// de produire la meme empreinte.
fn hash(scheme: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SCHEME_VERSION.as_bytes());
    hasher.update([0x1f]);
    hasher.update(scheme.as_bytes());
    for p in parts {
        hasher.update([0x1f]);
        hasher.update(p.as_bytes());
    }
    let digest = hasher.finalize();
    // 128 bits suffisent largement : quelques dizaines d'entrees au maximum.
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{SCHEME_VERSION}-{scheme}:{hex}")
}

/// Verifie qu'une chaine a la forme d'une cle stable produite par ce module.
/// Sert a rejeter les cles inconnues trouvees dans un fichier de configuration
/// edite a la main.
pub fn is_well_formed(id: &str) -> bool {
    let Some((prefix, hex)) = id.split_once(':') else {
        return false;
    };
    let Some((version, scheme)) = prefix.split_once('-') else {
        return false;
    };
    version == SCHEME_VERSION
        && matches!(scheme, "gpt" | "mbr" | "desc")
        && hex.len() == 32
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;

    fn parse(raw: Vec<u8>) -> LoadOption {
        LoadOption::parse(&raw).expect("fixture valide")
    }

    #[test]
    fn produces_a_well_formed_key() {
        let id = stable_id_for(&parse(testdata::load_option_windows()));
        assert!(is_well_formed(&id), "cle mal formee : {id}");
        assert!(id.starts_with("v1-gpt:"));
    }

    #[test]
    fn is_deterministic_across_calls() {
        let opt = parse(testdata::load_option_debian());
        assert_eq!(stable_id_for(&opt), stable_id_for(&opt));
    }

    #[test]
    fn distinguishes_two_systems_sharing_one_esp() {
        // Windows et Debian vivent sur la meme partition ESP : seul le chemin
        // EFI les separe. C'est le cas le plus courant en double amorcage.
        let windows = parse(testdata::load_option_windows());
        let debian = parse(testdata::load_option_debian());
        assert_eq!(windows.partition_guid(), debian.partition_guid());
        assert_ne!(stable_id_for(&windows), stable_id_for(&debian));
    }

    #[test]
    fn distinguishes_the_same_loader_on_two_different_disks() {
        // Meme chemin `\EFI\BOOT\BOOTX64.EFI`, partitions differentes.
        let usb = parse(testdata::load_option_usb());
        let other_path = {
            let mut p = testdata::hard_drive_node(1, testdata::ESP2_PART_GUID);
            p.extend_from_slice(&testdata::file_path_node("\\EFI\\BOOT\\BOOTX64.EFI"));
            p.extend_from_slice(&testdata::end_node());
            parse(testdata::load_option(1, "UEFI: autre", &p, &[]))
        };
        assert_ne!(stable_id_for(&usb), stable_id_for(&other_path));
    }

    #[test]
    fn survives_a_firmware_renumbering() {
        // La cle ne depend que du contenu de l'entree, jamais de son index :
        // le meme octet-a-octet donne la meme cle, quel que soit le Boot####
        // sous lequel le firmware l'a rangee.
        let raw = testdata::load_option_debian();
        let as_boot0002 = parse(raw.clone());
        let as_boot0007 = parse(raw);
        assert_eq!(stable_id_for(&as_boot0002), stable_id_for(&as_boot0007));
    }

    #[test]
    fn is_insensitive_to_efi_path_casing() {
        // Les firmwares ne sont pas coherents sur la casse des chemins EFI.
        let lower = {
            let mut p = testdata::hard_drive_node(2, testdata::ESP_PART_GUID);
            p.extend_from_slice(&testdata::file_path_node("\\efi\\debian\\shimx64.efi"));
            p.extend_from_slice(&testdata::end_node());
            parse(testdata::load_option(1, "debian", &p, &[]))
        };
        let upper = {
            let mut p = testdata::hard_drive_node(2, testdata::ESP_PART_GUID);
            p.extend_from_slice(&testdata::file_path_node("\\EFI\\Debian\\ShimX64.efi"));
            p.extend_from_slice(&testdata::end_node());
            parse(testdata::load_option(1, "debian", &p, &[]))
        };
        assert_eq!(stable_id_for(&lower), stable_id_for(&upper));
    }

    #[test]
    fn ignores_the_firmware_description_when_a_partition_is_known() {
        // Renommer l'entree cote firmware ne doit pas perdre l'alias local.
        let a = {
            let p = testdata::debian_device_path();
            parse(testdata::load_option(1, "debian", &p, &[]))
        };
        let b = {
            let p = testdata::debian_device_path();
            parse(testdata::load_option(1, "Debian GNU/Linux", &p, &[]))
        };
        assert_eq!(stable_id_for(&a), stable_id_for(&b));
    }

    #[test]
    fn falls_back_to_description_when_there_is_no_partition_node() {
        let opt = parse(testdata::load_option_firmware_setup());
        let id = stable_id_for(&opt);
        assert!(id.starts_with("v1-desc:"), "obtenu {id}");
        assert!(is_well_formed(&id));
    }

    #[test]
    fn rejects_malformed_keys() {
        for bad in [
            "",
            "v1-gpt",                                   // pas de deux-points
            "v1-gpt:",                                  // pas d'empreinte
            "v1-gpt:abc",                               // empreinte trop courte
            "v2-gpt:0123456789abcdef0123456789abcdef",  // version inconnue
            "v1-xxx:0123456789abcdef0123456789abcdef",  // schema inconnu
            "v1-gpt:0123456789abcdef0123456789abcdeZ",  // non hexadecimal
            "Boot0002",                                 // un identifiant volatil
        ] {
            assert!(!is_well_formed(bad), "aurait du rejeter : {bad:?}");
        }
    }

    #[test]
    fn accepts_every_key_it_produces() {
        for raw in [
            testdata::load_option_windows(),
            testdata::load_option_debian(),
            testdata::load_option_ubuntu(),
            testdata::load_option_usb(),
            testdata::load_option_orphan(),
            testdata::load_option_firmware_setup(),
        ] {
            let id = stable_id_for(&parse(raw));
            assert!(is_well_formed(&id), "cle refusee : {id}");
        }
    }
}
