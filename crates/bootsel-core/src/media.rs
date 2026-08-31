//! Supports bootables detectes qu'aucune entree UEFI ne designe.
//!
//! # Le probleme que ce module resout
//!
//! Un disque peut porter un systeme parfaitement bootable sans que le firmware
//! ait cree d'entree `Boot####` pour lui. C'est le cas le plus courant avec un
//! peripherique branche **apres** le demarrage : les firmwares enumerent les
//! supports amovibles au POST, pas a chaud.
//!
//! Situation constatee sur la machine de developpement : un disque externe
//! portant une ESP et trois partitions Linux, et un `BootOrder` ne contenant
//! que Windows.
//!
//! # Pourquoi on ne peut pas le rendre selectionnable
//!
//! `BootNext` designe une entree `Boot####` par son numero. Sans entree, il
//! n'y a rien a designer. La seule facon de rendre ce disque selectionnable
//! serait de **creer** une entree UEFI — operation formellement interdite par
//! le projet, au meme titre que modifier `BootOrder`.
//!
//! On affiche donc le support, on explique honnetement pourquoi il n'est pas
//! selectionnable, et on indique la marche a suivre. Mieux vaut un « je ne
//! peux pas » clair qu'une action risquee.

use crate::gpt::{role_of, PartitionRole};
use crate::model::{BootEntry, Confidence, OsKind, StorageDevice};
use serde::{Deserialize, Serialize};

/// Un support portant une ESP, mais qu'aucune entree du firmware ne designe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlistedMedium {
    /// Cle stable du peripherique.
    pub device_id: String,
    /// Libelle affichable, ex. « USB ACME HD320 298 Go ».
    pub device_label: String,
    /// Nom propose a l'affichage.
    pub display_name: String,
    /// Systeme devine a partir des seuls types de partitions.
    pub os: OsKind,
    pub confidence: Confidence,
    pub removable: bool,
    /// Numero de la partition systeme EFI trouvee sur ce support.
    pub esp_partition: u32,
    /// Ce que l'utilisateur doit savoir, en une phrase.
    pub reason: String,
    /// Ce que l'utilisateur peut faire.
    pub suggestion: String,
}

/// Texte explicatif commun. Formule au present, sans jargon inutile.
const REASON: &str =
    "Aucune entree UEFI du firmware ne designe ce peripherique : il ne peut pas etre \
     choisi comme cible de demarrage.";

const SUGGESTION_REMOVABLE: &str =
    "Redemarrez en laissant le peripherique branche. La plupart des firmwares creent \
     alors une entree pour lui, et il apparaitra ici comme selectionnable. Vous pouvez \
     aussi passer par le menu de demarrage du firmware, souvent accessible avec F12 ou F11.";

const SUGGESTION_FIXED: &str =
    "Ce disque porte un systeme mais le firmware ne lui connait pas d'entree de demarrage. \
     Utilisez le menu de demarrage du firmware, souvent accessible avec F12 ou F11.";

/// Recense les supports bootables qu'aucune entree de boot ne couvre.
///
/// Un support est retenu s'il porte au moins une partition systeme EFI et
/// qu'aucune entree du firmware ne pointe vers l'une de ses partitions.
pub fn find_unlisted_media(
    devices: &[StorageDevice],
    entries: &[BootEntry],
) -> Vec<UnlistedMedium> {
    devices
        .iter()
        .filter_map(|device| {
            // Sans ESP, rien ne permet de penser que ce disque est amorcable
            // en UEFI. On ne l'affiche pas : ce serait du bruit.
            let esp = device.esp_partitions().next()?;

            // Une entree du firmware designe-t-elle deja une partition de ce
            // disque ? Le rattachement se fait par GUID unique de partition,
            // la seule correspondance fiable.
            let already_listed = entries.iter().any(|entry| {
                entry
                    .partition_guid
                    .is_some_and(|guid| device.has_partition_guid(guid))
            });
            if already_listed {
                return None;
            }

            let (os, confidence) = infer_os(device);

            Some(UnlistedMedium {
                device_id: device.id.clone(),
                device_label: device.label(),
                display_name: build_name(os, device),
                os,
                confidence,
                removable: device.removable,
                esp_partition: esp.number,
                reason: REASON.to_string(),
                suggestion: if device.removable {
                    SUGGESTION_REMOVABLE.to_string()
                } else {
                    SUGGESTION_FIXED.to_string()
                },
            })
        })
        .collect()
}

/// Devine le systeme present sur un disque a partir des seuls GUID de type de
/// ses partitions.
///
/// Aucune partition n'est montee ni lue : la conclusion repose entierement sur
/// des metadonnees deja connues du systeme. La confiance renvoyee reste donc
/// [`Confidence::Probable`] — un type de partition dit ce qu'une partition
/// est, pas qu'un systeme installe dessus demarre reellement.
pub fn infer_os(device: &StorageDevice) -> (OsKind, Confidence) {
    let roles: Vec<PartitionRole> = device
        .partitions
        .iter()
        .filter_map(|p| p.gpt_type.map(role_of))
        .collect();

    let linux = roles.iter().filter(|r| r.is_linux()).count();
    let windows = roles.iter().filter(|r| r.is_windows()).count();

    match (linux, windows) {
        // Les deux presents : on ne tranche pas, ce serait arbitraire.
        (l, w) if l > 0 && w > 0 => (OsKind::Unknown, Confidence::Probable),
        (l, _) if l > 0 => (OsKind::LinuxGeneric, Confidence::Probable),
        (_, w) if w > 0 => (OsKind::Windows, Confidence::Probable),
        // Une ESP seule, sans partition de systeme : typiquement une cle
        // d'installation ou un support « live ».
        _ if device.removable => (OsKind::RemovableMedia, Confidence::Probable),
        _ => (OsKind::Unknown, Confidence::Unverifiable),
    }
}

fn build_name(os: OsKind, device: &StorageDevice) -> String {
    let model = device.model.trim();
    match os {
        OsKind::Unknown if model.is_empty() => "Support bootable".to_string(),
        OsKind::Unknown => format!("Support bootable ({model})"),
        OsKind::RemovableMedia if model.is_empty() => "Support amovible".to_string(),
        OsKind::RemovableMedia => model.to_string(),
        os if model.is_empty() => os.label().to_string(),
        os => format!("{} ({model})", os.label()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::Guid;
    use crate::model::{Availability, BootId, BootloaderKind, BusType, PartitionInfo};
    use crate::efi::Transport;

    fn part(number: u32, type_guid: &str, unique: &str) -> PartitionInfo {
        let gpt_type = Guid::parse(type_guid);
        PartitionInfo {
            number,
            gpt_type,
            unique_guid: Guid::parse(unique),
            size_bytes: 1_000_000_000,
            is_esp: gpt_type == Some(Guid::ESP_PARTITION_TYPE),
            drive_letter: None,
            label: None,
            filesystem: None,
        }
    }

    const ESP: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
    const LINUX: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";
    const WIN_DATA: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
    const WIN_RESERVED: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";

    /// Reproduit le disque externe reellement branche sur la machine de
    /// developpement : une ESP et trois partitions Linux.
    fn real_linux_usb() -> StorageDevice {
        StorageDevice {
            id: "serial:SN-EXT-0001".into(),
            system_name: "2".into(),
            model: "ACME HD320".into(),
            bus: BusType::Usb,
            size_bytes: 320_072_933_376,
            removable: true,
            serial: Some("SN-EXT-0001".into()),
            partitions: vec![
                part(1, ESP, "aaaa0002-0000-4000-8000-000000000002"),
                part(2, LINUX, "aaaa0003-0000-4000-8000-000000000003"),
                part(3, LINUX, "aaaa0004-0000-4000-8000-000000000004"),
                part(4, LINUX, "aaaa0005-0000-4000-8000-000000000005"),
            ],
        }
    }

    /// Reproduit le disque interne de la machine : Windows, deja couvert par
    /// une entree du firmware.
    fn real_windows_nvme() -> StorageDevice {
        StorageDevice {
            id: "serial:AA0001".into(),
            system_name: "0".into(),
            model: "ACME NV1000".into(),
            bus: BusType::Nvme,
            size_bytes: 1_024_209_543_168,
            removable: false,
            serial: Some("AA0001".into()),
            partitions: vec![
                part(2, ESP, "aaaa0001-0000-4000-8000-000000000001"),
                part(3, WIN_RESERVED, "aaaa0006-0000-4000-8000-000000000006"),
                part(4, WIN_DATA, "aaaa0007-0000-4000-8000-000000000007"),
            ],
        }
    }

    fn entry_on(partition_guid: &str) -> BootEntry {
        BootEntry {
            id: BootId(0),
            stable_id: "v1-gpt:0123456789abcdef0123456789abcdef".into(),
            firmware_description: "Windows Boot Manager".into(),
            display_name: "Windows Boot Manager".into(),
            detected_name: "Windows Boot Manager".into(),
            os: OsKind::Windows,
            bootloader: BootloaderKind::WindowsBootManager,
            transport: Transport::Nvme,
            confidence: Confidence::Confirmed,
            availability: Availability::Available,
            active: true,
            efi_path: Some("\\EFI\\MICROSOFT\\BOOT\\BOOTMGFW.EFI".into()),
            partition_guid: Guid::parse(partition_guid),
            partition_number: Some(2),
            device_label: None,
            is_current: true,
        }
    }

    #[test]
    fn reports_the_real_linux_usb_that_has_no_firmware_entry() {
        let devices = vec![real_windows_nvme(), real_linux_usb()];
        let entries = vec![entry_on("aaaa0001-0000-4000-8000-000000000001")];

        let media = find_unlisted_media(&devices, &entries);

        assert_eq!(media.len(), 1, "seul le disque externe doit remonter");
        let m = &media[0];
        assert_eq!(m.device_id, "serial:SN-EXT-0001");
        assert_eq!(m.os, OsKind::LinuxGeneric);
        assert_eq!(m.display_name, "Linux (ACME HD320)");
        assert_eq!(m.esp_partition, 1);
        assert!(m.removable);
        assert_eq!(m.confidence, Confidence::Probable);
        assert!(m.reason.contains("Aucune entree UEFI"));
        assert!(m.suggestion.contains("Redemarrez"));
    }

    #[test]
    fn a_disk_already_covered_by_a_boot_entry_is_not_reported() {
        let devices = vec![real_windows_nvme()];
        let entries = vec![entry_on("aaaa0001-0000-4000-8000-000000000001")];
        assert!(find_unlisted_media(&devices, &entries).is_empty());
    }

    #[test]
    fn a_disk_without_an_esp_is_never_reported() {
        // Le disque de donnees exFAT de la machine : aucune ESP, donc aucune
        // raison de le presenter comme bootable.
        let data_disk = StorageDevice {
            id: "serial:SN-DATA-0002".into(),
            system_name: "1".into(),
            model: "ACME PX500".into(),
            bus: BusType::Usb,
            size_bytes: 1_000_204_886_016,
            removable: true,
            serial: Some("SN-DATA-0002".into()),
            partitions: vec![
                part(1, "e3c9e316-0b5c-4db8-817d-f92df00215ae", "aaaa0008-0000-4000-8000-000000000008"),
                part(2, WIN_DATA, "aaaa0009-0000-4000-8000-000000000009"),
            ],
        };
        assert!(find_unlisted_media(&[data_disk], &[]).is_empty());
    }

    #[test]
    fn infers_linux_from_partition_types_alone() {
        let (os, confidence) = infer_os(&real_linux_usb());
        assert_eq!(os, OsKind::LinuxGeneric);
        // Un type de partition ne prouve pas qu'un systeme demarre.
        assert_eq!(confidence, Confidence::Probable);
    }

    #[test]
    fn infers_windows_from_partition_types_alone() {
        assert_eq!(infer_os(&real_windows_nvme()).0, OsKind::Windows);
    }

    #[test]
    fn refuses_to_choose_when_both_systems_are_present() {
        let mut dual = real_windows_nvme();
        dual.partitions.push(part(5, LINUX, "aaaaaaaa-0000-4000-8000-000000000005"));
        assert_eq!(infer_os(&dual).0, OsKind::Unknown);
    }

    #[test]
    fn an_esp_only_removable_disk_is_treated_as_installation_media() {
        let stick = StorageDevice {
            id: "serial:USB1".into(),
            system_name: "3".into(),
            model: "ACME UK64".into(),
            bus: BusType::Usb,
            size_bytes: 64_000_000_000,
            removable: true,
            serial: Some("USB1".into()),
            partitions: vec![part(1, ESP, "0a5b9d44-1e6c-4f30-b287-5c94ad3e10f6")],
        };
        let media = find_unlisted_media(&[stick], &[]);
        assert_eq!(media[0].os, OsKind::RemovableMedia);
        assert_eq!(media[0].display_name, "ACME UK64");
    }

    #[test]
    fn a_fixed_disk_gets_a_suggestion_that_does_not_mention_unplugging() {
        let mut fixed = real_linux_usb();
        fixed.removable = false;
        fixed.bus = BusType::Sata;
        let media = find_unlisted_media(&[fixed], &[]);
        assert!(!media[0].suggestion.contains("Redemarrez en laissant"));
        assert!(media[0].suggestion.contains("menu de demarrage"));
    }

    #[test]
    fn nothing_here_can_make_a_medium_selectable() {
        // Garde-fou de conception : le type ne porte aucun identifiant de boot,
        // donc rien dans le reste du code ne peut le transformer en cible.
        let media = find_unlisted_media(&[real_linux_usb()], &[]);
        let json = serde_json::to_string(&media[0]).unwrap();
        assert!(!json.contains("boot_id"));
        assert!(!json.contains("Boot0"));
    }

    #[test]
    fn handles_an_empty_inventory_without_panicking() {
        assert!(find_unlisted_media(&[], &[]).is_empty());
    }
}
