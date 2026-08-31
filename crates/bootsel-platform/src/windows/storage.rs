//! Inventaire des disques et partitions sous Windows. **Lecture seule.**
//!
//! Interroge WMI dans l'espace `root\Microsoft\Windows\Storage`, qui expose
//! `MSFT_Disk` et `MSFT_Partition`. Ces classes sont interrogeables **sans
//! privilege administrateur**, contrairement aux variables du firmware : c'est
//! ce qui permet a l'application d'afficher un inventaire utile des le
//! lancement, avant toute elevation.
//!
//! `MSFT_Partition` fournit le **GUID unique de partition**, qui est
//! exactement la valeur inscrite dans les chemins de peripheriques UEFI. C'est
//! lui qui permet de rattacher une entree de boot au disque physique qui la
//! porte.
//!
//! Aucune partition n'est montee, aucun disque n'est ouvert en ecriture,
//! aucune structure de bas niveau n'est lue : WMI repond a partir des
//! metadonnees deja connues du systeme.

use bootsel_core::backend::BackendError;
use bootsel_core::efi::Guid;
use bootsel_core::model::{BusType, PartitionInfo, StorageDevice};
use serde::Deserialize;
use wmi::WMIConnection;

/// Espace de nommage WMI du sous-systeme de stockage.
const STORAGE_NAMESPACE: &str = "root\\Microsoft\\Windows\\Storage";

/// Valeurs de `MSFT_Disk.BusType` (documentation Microsoft Storage WMI).
mod bus {
    pub const SCSI: u16 = 1;
    pub const ATAPI: u16 = 2;
    pub const ATA: u16 = 3;
    pub const USB: u16 = 7;
    pub const RAID: u16 = 8;
    pub const SAS: u16 = 10;
    pub const SATA: u16 = 11;
    pub const VIRTUAL: u16 = 14;
    pub const FILE_BACKED_VIRTUAL: u16 = 15;
    pub const NVME: u16 = 17;
}

fn map_bus(raw: u16) -> BusType {
    match raw {
        bus::NVME => BusType::Nvme,
        bus::SATA | bus::ATA => BusType::Sata,
        bus::USB => BusType::Usb,
        bus::SAS => BusType::Sas,
        bus::SCSI | bus::ATAPI => BusType::Scsi,
        bus::RAID => BusType::Raid,
        bus::VIRTUAL | bus::FILE_BACKED_VIRTUAL => BusType::Virtual,
        _ => BusType::Unknown,
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename = "MSFT_Disk")]
#[serde(rename_all = "PascalCase")]
struct MsftDisk {
    number: u32,
    friendly_name: Option<String>,
    model: Option<String>,
    serial_number: Option<String>,
    bus_type: Option<u16>,
    size: Option<u64>,
    /// 1 = MBR, 2 = GPT, 0 = brut.
    partition_style: Option<u16>,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "MSFT_Partition")]
#[serde(rename_all = "PascalCase")]
struct MsftPartition {
    disk_number: u32,
    partition_number: u32,
    /// GUID **unique** de la partition, entre accolades. C'est la valeur
    /// presente dans les chemins de peripheriques UEFI.
    guid: Option<String>,
    /// GUID de **type** de partition, entre accolades.
    gpt_type: Option<String>,
    size: Option<u64>,
}

/// Inventorie les disques et leurs partitions. **Non privilegie.**
pub fn list_devices() -> Result<Vec<StorageDevice>, BackendError> {
    let wmi = WMIConnection::with_namespace_path(STORAGE_NAMESPACE)
        .map_err(|e| BackendError::Io(format!("connexion WMI impossible : {e}")))?;

    let disks: Vec<MsftDisk> = wmi
        .query()
        .map_err(|e| BackendError::Io(format!("requete MSFT_Disk : {e}")))?;

    // Les partitions sont interrogees en une seule fois puis regroupees, plutot
    // qu'une requete par disque : moins d'aller-retours, resultat identique.
    let partitions: Vec<MsftPartition> = wmi
        .query()
        .map_err(|e| BackendError::Io(format!("requete MSFT_Partition : {e}")))?;

    let mut devices: Vec<StorageDevice> = disks
        .into_iter()
        .map(|d| build_device(d, &partitions))
        .collect();

    devices.sort_by_key(|d| d.system_name.parse::<u32>().unwrap_or(u32::MAX));
    Ok(devices)
}

fn build_device(disk: MsftDisk, all_partitions: &[MsftPartition]) -> StorageDevice {
    let mut partitions: Vec<PartitionInfo> = all_partitions
        .iter()
        .filter(|p| p.disk_number == disk.number)
        .map(build_partition)
        .collect();
    partitions.sort_by_key(|p| p.number);

    // Le modele est prefere au nom convivial : il identifie le materiel, la
    // ou `FriendlyName` peut avoir ete renomme.
    let model = disk
        .model
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| disk.friendly_name.as_deref().map(str::trim))
        .unwrap_or("Disque")
        .to_string();

    let serial = disk
        .serial_number
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let bus = disk.bus_type.map(map_bus).unwrap_or(BusType::Unknown);

    StorageDevice {
        // Le numero de serie est l'identifiant le plus stable ; a defaut, le
        // numero de disque, qui peut changer entre deux branchements.
        id: serial
            .clone()
            .map(|s| format!("serial:{s}"))
            .unwrap_or_else(|| format!("disk:{}", disk.number)),
        system_name: disk.number.to_string(),
        model,
        bus,
        size_bytes: disk.size.unwrap_or(0),
        // Un disque sur bus USB est traite comme amovible : c'est ce qui
        // compte pour l'interface, quel que soit son type reel.
        removable: bus == BusType::Usb,
        serial,
        partitions: if disk.partition_style == Some(2) {
            partitions
        } else {
            // Hors GPT, les GUID de partition n'ont pas de sens : on n'expose
            // rien plutot que des valeurs trompeuses.
            Vec::new()
        },
    }
}

fn build_partition(p: &MsftPartition) -> PartitionInfo {
    let gpt_type = p.gpt_type.as_deref().and_then(Guid::parse);

    PartitionInfo {
        number: p.partition_number,
        gpt_type,
        unique_guid: p.guid.as_deref().and_then(Guid::parse),
        size_bytes: p.size.unwrap_or(0),
        is_esp: gpt_type == Some(Guid::ESP_PARTITION_TYPE),
        // Ces trois champs demanderaient d'inspecter les volumes montes. Ils
        // n'entrent dans aucune decision : on prefere ne rien afficher plutot
        // que d'aller chercher une information dont on n'a pas besoin.
        drive_letter: None,
        label: None,
        filesystem: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_documented_bus_type() {
        assert_eq!(map_bus(bus::NVME), BusType::Nvme);
        assert_eq!(map_bus(bus::USB), BusType::Usb);
        assert_eq!(map_bus(bus::SATA), BusType::Sata);
        assert_eq!(map_bus(bus::ATA), BusType::Sata);
        assert_eq!(map_bus(bus::SAS), BusType::Sas);
        assert_eq!(map_bus(bus::RAID), BusType::Raid);
        assert_eq!(map_bus(bus::VIRTUAL), BusType::Virtual);
        // Une valeur inconnue ne doit pas etre devinee.
        assert_eq!(map_bus(999), BusType::Unknown);
    }

    #[test]
    fn recognises_an_esp_by_its_type_guid() {
        let p = MsftPartition {
            disk_number: 0,
            partition_number: 2,
            guid: Some("{aaaa0001-0000-4000-8000-000000000001}".into()),
            gpt_type: Some("{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}".into()),
            size: Some(104_857_600),
        };
        let info = build_partition(&p);
        assert!(info.is_esp);
        assert_eq!(
            info.unique_guid.map(|g| g.to_hyphenated()),
            Some("aaaa0001-0000-4000-8000-000000000001".to_string())
        );
    }

    #[test]
    fn a_data_partition_is_not_mistaken_for_an_esp() {
        let p = MsftPartition {
            disk_number: 0,
            partition_number: 4,
            guid: Some("{aaaa0007-0000-4000-8000-000000000007}".into()),
            gpt_type: Some("{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}".into()),
            size: Some(1_022_000_000_000),
        };
        assert!(!build_partition(&p).is_esp);
    }

    #[test]
    fn malformed_guids_become_none_rather_than_panicking() {
        let p = MsftPartition {
            disk_number: 0,
            partition_number: 1,
            guid: Some("pas un guid".into()),
            gpt_type: None,
            size: None,
        };
        let info = build_partition(&p);
        assert!(info.unique_guid.is_none());
        assert!(info.gpt_type.is_none());
        assert!(!info.is_esp);
        assert_eq!(info.size_bytes, 0);
    }

    #[test]
    fn a_non_gpt_disk_exposes_no_partition_guids() {
        let disk = MsftDisk {
            number: 3,
            friendly_name: Some("Vieux disque".into()),
            model: None,
            serial_number: None,
            bus_type: Some(bus::USB),
            size: Some(4_000_000_000),
            partition_style: Some(1), // MBR
        };
        let dev = build_device(disk, &[]);
        assert!(dev.partitions.is_empty());
        assert!(dev.removable);
    }

    #[test]
    fn prefers_the_serial_number_as_a_stable_device_key() {
        let with_serial = build_device(
            MsftDisk {
                number: 0,
                friendly_name: None,
                model: Some("ACME NV1000".into()),
                serial_number: Some("  ABC123  ".into()),
                bus_type: Some(bus::NVME),
                size: Some(1_024_209_543_168),
                partition_style: Some(2),
            },
            &[],
        );
        assert_eq!(with_serial.id, "serial:ABC123");
        assert_eq!(with_serial.model, "ACME NV1000");
        assert!(!with_serial.removable);

        let without_serial = build_device(
            MsftDisk {
                number: 5,
                friendly_name: Some("Disque".into()),
                model: None,
                serial_number: Some("   ".into()),
                bus_type: None,
                size: None,
                partition_style: Some(2),
            },
            &[],
        );
        assert_eq!(without_serial.id, "disk:5");
    }

    /// Interroge le vrai systeme. Ne verifie que des invariants structurels,
    /// pour rester valable sur n'importe quelle machine.
    #[test]
    fn inventories_this_machine_without_any_privilege() {
        let devices = list_devices().expect("WMI doit repondre sans elevation");
        assert!(!devices.is_empty(), "au moins un disque doit etre detecte");

        for d in &devices {
            assert!(!d.id.is_empty());
            assert!(!d.model.is_empty());
            for p in &d.partitions {
                assert!(p.number > 0);
                // Une partition marquee ESP doit l'etre pour la bonne raison.
                if p.is_esp {
                    assert_eq!(p.gpt_type, Some(Guid::ESP_PARTITION_TYPE));
                }
            }
        }
    }
}
