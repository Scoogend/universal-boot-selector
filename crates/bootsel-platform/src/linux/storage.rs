//! Inventaire des disques sous Linux. **Lecture seule, non privilegiee.**
//!
//! Tout vient de `/sys/block` et `/sys/class/block`, que le noyau expose en
//! lecture a tout utilisateur. Aucun disque n'est ouvert, aucune partition
//! n'est montee, aucune structure de bas niveau n'est lue : on se contente
//! des metadonnees que le noyau publie deja.
//!
//! Les GUID de partition GPT viennent des attributs `partition`, `start` et
//! `size` completes par `/dev/disk/by-partuuid`, un lien symbolique que
//! l'espace utilisateur maintient et qui donne directement le GUID unique.
//!
//! Comme pour le firmware, la racine est injectable afin de rendre le module
//! testable sur fixtures depuis n'importe quelle plateforme.

use bootsel_core::backend::BackendError;
use bootsel_core::efi::Guid;
use bootsel_core::model::{BusType, PartitionInfo, StorageDevice};
use std::collections::BTreeMap;
use std::path::Path;

/// Taille d'un secteur telle que le noyau la rapporte dans `size`.
const SECTOR_SIZE: u64 = 512;

/// Lit un attribut sysfs en le nettoyant, ou `None` s'il est absent ou vide.
fn attribute(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn attribute_u64(path: &Path) -> Option<u64> {
    attribute(path)?.parse().ok()
}

/// Devine le bus a partir du chemin materiel du peripherique.
///
/// Le lien `device` de sysfs pointe vers l'arborescence materielle, dont le
/// chemin contient le type de bus. C'est l'indice le plus fiable disponible
/// sans interroger de service.
fn bus_from_device_path(path: &Path) -> BusType {
    let Ok(target) = std::fs::read_link(path) else {
        return BusType::Unknown;
    };
    let text = target.to_string_lossy().to_lowercase();

    if text.contains("/usb") {
        BusType::Usb
    } else if text.contains("nvme") {
        BusType::Nvme
    } else if text.contains("/ata") || text.contains("ahci") {
        BusType::Sata
    } else if text.contains("/sas") {
        BusType::Sas
    } else if text.contains("virtio") || text.contains("/vmbus") {
        BusType::Virtual
    } else if text.contains("scsi") {
        BusType::Scsi
    } else {
        BusType::Unknown
    }
}

/// Nom de peripherique deduit du bus, quand sysfs ne fournit pas de modele.
fn bus_from_name(name: &str) -> BusType {
    if name.starts_with("nvme") {
        BusType::Nvme
    } else if name.starts_with("vd") {
        BusType::Virtual
    } else {
        BusType::Unknown
    }
}

/// Table `GUID unique de partition -> nom de peripherique`, construite depuis
/// `/dev/disk/by-partuuid`.
fn partition_guids(root: &Path) -> BTreeMap<String, Guid> {
    let dir = root.join("dev/disk/by-partuuid");
    let mut map = BTreeMap::new();

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return map;
    };

    for entry in entries.flatten() {
        let Some(uuid) = entry.file_name().to_str().and_then(Guid::parse) else {
            continue;
        };
        // Le lien pointe vers `../../sdb2` : seul le nom final nous interesse.
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let Some(device) = target.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        map.insert(device.to_string(), uuid);
    }

    map
}

/// Table `nom de peripherique -> GUID de type de partition`, depuis
/// `/dev/disk/by-parttypeuuid` lorsque cette arborescence existe.
fn partition_types(root: &Path) -> BTreeMap<String, Guid> {
    let dir = root.join("dev/disk/by-parttypeuuid");
    let mut map = BTreeMap::new();

    let Ok(entries) = std::fs::read_dir(&dir) else {
        return map;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // La forme est `<type-uuid>.<part-uuid>` ; seul le type nous interesse.
        let Some(type_guid) = name.split('.').next().and_then(Guid::parse) else {
            continue;
        };
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let Some(device) = target.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        map.insert(device.to_string(), type_guid);
    }

    map
}

/// Inventorie les disques et leurs partitions. **Non privilegie.**
pub fn list_devices(root: &Path) -> Result<Vec<StorageDevice>, BackendError> {
    let block = root.join("sys/block");

    let entries = std::fs::read_dir(&block)
        .map_err(|e| BackendError::Io(format!("lecture de {}: {e}", block.display())))?;

    let guids = partition_guids(root);
    let types = partition_types(root);

    let mut devices: Vec<StorageDevice> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();

            // On ignore ce qui n'est pas un disque physique : boucles, RAM,
            // lecteurs optiques et mappages du gestionnaire de volumes.
            if name.starts_with("loop")
                || name.starts_with("ram")
                || name.starts_with("sr")
                || name.starts_with("dm-")
                || name.starts_with("zram")
            {
                return None;
            }

            Some(build_device(&entry.path(), &name, &guids, &types))
        })
        .collect();

    devices.sort_by(|a, b| a.system_name.cmp(&b.system_name));
    Ok(devices)
}

fn build_device(
    path: &Path,
    name: &str,
    guids: &BTreeMap<String, Guid>,
    types: &BTreeMap<String, Guid>,
) -> StorageDevice {
    let model = attribute(&path.join("device/model"))
        .or_else(|| attribute(&path.join("device/name")))
        .unwrap_or_else(|| "Disque".to_string());

    let serial = attribute(&path.join("device/serial"))
        .or_else(|| attribute(&path.join("device/wwid")));

    let size_bytes = attribute_u64(&path.join("size")).unwrap_or(0) * SECTOR_SIZE;

    let removable = attribute(&path.join("removable")).as_deref() == Some("1");

    let mut bus = bus_from_device_path(&path.join("device"));
    if bus == BusType::Unknown {
        bus = bus_from_name(name);
    }

    StorageDevice {
        id: serial
            .clone()
            .map(|s| format!("serial:{s}"))
            .unwrap_or_else(|| format!("block:{name}")),
        system_name: name.to_string(),
        model,
        bus,
        size_bytes,
        // Un disque USB est traite comme amovible meme si le noyau ne le
        // marque pas ainsi : c'est ce qui compte pour l'interface.
        removable: removable || bus == BusType::Usb,
        serial,
        partitions: build_partitions(path, name, guids, types),
    }
}

/// Les partitions d'un disque sont ses sous-repertoires portant un fichier
/// `partition`.
fn build_partitions(
    path: &Path,
    device: &str,
    guids: &BTreeMap<String, Guid>,
    types: &BTreeMap<String, Guid>,
) -> Vec<PartitionInfo> {
    let Ok(entries) = std::fs::read_dir(path) else {
        return Vec::new();
    };

    let mut partitions: Vec<PartitionInfo> = entries
        .flatten()
        .filter_map(|entry| {
            let child = entry.file_name().to_str()?.to_string();
            if !child.starts_with(device) {
                return None;
            }

            let child_path = entry.path();
            let number = attribute_u64(&child_path.join("partition"))? as u32;
            let size_bytes = attribute_u64(&child_path.join("size")).unwrap_or(0) * SECTOR_SIZE;
            let gpt_type = types.get(&child).copied();

            Some(PartitionInfo {
                number,
                gpt_type,
                unique_guid: guids.get(&child).copied(),
                size_bytes,
                is_esp: gpt_type == Some(Guid::ESP_PARTITION_TYPE),
                // Determiner ces champs demanderait d'inspecter les montages.
                // Ils n'entrent dans aucune decision : on prefere ne rien
                // afficher plutot que d'aller les chercher.
                drive_letter: None,
                label: None,
                filesystem: None,
            })
        })
        .collect();

    partitions.sort_by_key(|p| p.number);
    partitions
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Arborescence sysfs simulee, reproduisant la forme reelle du noyau.
    struct Sysfs {
        root: PathBuf,
    }

    impl Sysfs {
        fn new(name: &str) -> Sysfs {
            let root = std::env::temp_dir().join(format!("bootsel-sysfs-{name}"));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("sys/block")).expect("arborescence");
            Sysfs { root }
        }

        fn disk(&self, name: &str, model: &str, serial: &str, sectors: u64, removable: bool) -> &Sysfs {
            let d = self.root.join("sys/block").join(name);
            std::fs::create_dir_all(d.join("device")).expect("disque");
            std::fs::write(d.join("size"), sectors.to_string()).expect("taille");
            std::fs::write(d.join("removable"), if removable { "1" } else { "0" })
                .expect("amovible");
            std::fs::write(d.join("device/model"), model).expect("modele");
            std::fs::write(d.join("device/serial"), serial).expect("serie");
            self
        }

        fn partition(&self, disk: &str, part: &str, number: u32, sectors: u64) -> &Sysfs {
            let p = self.root.join("sys/block").join(disk).join(part);
            std::fs::create_dir_all(&p).expect("partition");
            std::fs::write(p.join("partition"), number.to_string()).expect("numero");
            std::fs::write(p.join("size"), sectors.to_string()).expect("taille");
            self
        }
    }

    impl Drop for Sysfs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn simple_disk(name: &str) -> Sysfs {
        let s = Sysfs::new(name);
        s.disk("nvme0n1", "ACME NV1000", "SN-NVME-0001", 2_000_409_264, false)
            .partition("nvme0n1", "nvme0n1p1", 1, 204_800)
            .partition("nvme0n1", "nvme0n1p2", 2, 1_999_000_000);
        s
    }

    #[test]
    fn inventories_a_disk_and_its_partitions() {
        let s = simple_disk("simple");
        let devices = list_devices(&s.root).expect("inventaire");

        assert_eq!(devices.len(), 1);
        let d = &devices[0];
        assert_eq!(d.system_name, "nvme0n1");
        assert_eq!(d.model, "ACME NV1000");
        assert_eq!(d.serial.as_deref(), Some("SN-NVME-0001"));
        assert_eq!(d.id, "serial:SN-NVME-0001");
        assert_eq!(d.size_bytes, 2_000_409_264 * 512);
        assert!(!d.removable);

        assert_eq!(d.partitions.len(), 2);
        assert_eq!(d.partitions[0].number, 1);
        assert_eq!(d.partitions[1].number, 2);
    }

    #[test]
    fn the_bus_is_deduced_from_the_device_name_when_sysfs_is_silent() {
        let s = simple_disk("bus-nvme");
        assert_eq!(list_devices(&s.root).unwrap()[0].bus, BusType::Nvme);
    }

    #[test]
    fn a_removable_disk_is_reported_as_such() {
        let s = Sysfs::new("amovible");
        s.disk("sdb", "ACME UK64", "SN-USB-0001", 125_000_000, true);
        assert!(list_devices(&s.root).unwrap()[0].removable);
    }

    #[test]
    fn virtual_and_pseudo_devices_are_skipped() {
        let s = Sysfs::new("pseudo");
        s.disk("sda", "ACME SA500", "SN-SATA-0001", 976_773_168, false)
            .disk("loop0", "boucle", "-", 1000, false)
            .disk("ram0", "memoire", "-", 1000, false)
            .disk("sr0", "optique", "-", 1000, true)
            .disk("dm-0", "mappage", "-", 1000, false)
            .disk("zram0", "compresse", "-", 1000, false);

        let devices = list_devices(&s.root).expect("inventaire");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].system_name, "sda");
    }

    #[test]
    fn a_disk_without_a_serial_still_gets_a_stable_key() {
        let s = Sysfs::new("sans-serie");
        let d = s.root.join("sys/block/sdc");
        std::fs::create_dir_all(d.join("device")).unwrap();
        std::fs::write(d.join("size"), "1000").unwrap();

        let devices = list_devices(&s.root).expect("inventaire");
        assert_eq!(devices[0].id, "block:sdc");
        assert_eq!(devices[0].model, "Disque");
    }

    #[test]
    fn an_absent_sys_block_is_reported_rather_than_pretending_no_disk_exists() {
        let root = std::env::temp_dir().join("bootsel-sysfs-inexistant");
        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(
            list_devices(&root),
            Err(BackendError::Io(_))
        ));
    }

    #[test]
    fn devices_are_listed_in_a_deterministic_order() {
        let s = Sysfs::new("ordre");
        s.disk("sdc", "C", "3", 100, false)
            .disk("sda", "A", "1", 100, false)
            .disk("sdb", "B", "2", 100, false);

        let devices = list_devices(&s.root).expect("inventaire");
        let names: Vec<&str> = devices.iter().map(|d| d.system_name.as_str()).collect();
        assert_eq!(names, vec!["sda", "sdb", "sdc"]);
    }

    #[test]
    fn this_module_never_writes_and_never_mounts() {
        let source = include_str!("storage.rs").replace("
", "
");
        let end = source.find("
#[cfg(test)]
mod tests").unwrap_or(source.len());
        let shipped = &source[..end];
        for forbidden in ["fs::write", "OpenOptions", "File::create", "mount", "Command"] {
            assert!(
                !shipped.contains(forbidden),
                "l inventaire doit rester passif : {forbidden}"
            );
        }
    }
}
