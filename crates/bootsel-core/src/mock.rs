//! Backend simule, pour le developpement et les tests.
//!
//! Il reproduit un espace NVRAM en memoire et **journalise chaque appel**.
//! C'est ce journal qui permet de prouver qu'un cycle de detection n'ecrit
//! rien : il suffit de verifier qu'aucune operation d'ecriture n'y figure.
//!
//! Il sait aussi se comporter comme un firmware defaillant ou hostile
//! (ecriture ignoree, `BootOrder` modifie en douce), ce qui permet de tester
//! que le garde-fou detecte ces situations au lieu de les laisser passer.

use crate::backend::{BackendError, BootBackend};
use crate::efi::{testdata, Guid};
use crate::model::{
    BootId, BusType, FirmwareMode, FirmwareState, PartitionInfo, StorageDevice, VAR_BOOT_CURRENT,
    VAR_BOOT_NEXT, VAR_BOOT_ORDER,
};
use std::collections::BTreeMap;
use std::sync::{Mutex, RwLock};

/// Une operation observee sur le backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    FirmwareMode,
    ReadState,
    ListDevices,
    /// Seule variante representant une ecriture.
    SetBootNext(BootId),
    Reboot,
}

impl Op {
    /// Vrai si l'operation modifie l'etat de la machine.
    pub fn is_write(&self) -> bool {
        matches!(self, Op::SetBootNext(_) | Op::Reboot)
    }
}

/// Comportement du firmware simule face a une ecriture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteBehavior {
    /// Ecrit `BootNext` correctement. Cas nominal.
    Correct,
    /// Renvoie une erreur sans rien ecrire.
    Refuse(String),
    /// Repond « succes » mais n'ecrit rien. Certains firmwares le font.
    SilentlyIgnore,
    /// Ecrit `BootNext` mais reordonne aussi `BootOrder`. Le garde-fou doit
    /// le detecter et refuser le redemarrage.
    AlsoReorderBootOrder,
    /// Ecrit `BootNext` mais supprime une entree au passage.
    AlsoDeleteEntry(BootId),
    /// Ecrit une valeur differente de celle demandee.
    WriteWrongTarget(BootId),
}

/// Firmware simule.
#[derive(Debug)]
pub struct MockBootBackend {
    state: RwLock<FirmwareState>,
    devices: RwLock<Vec<StorageDevice>>,
    firmware_mode: FirmwareMode,
    ops: Mutex<Vec<Op>>,
    write_behavior: RwLock<WriteBehavior>,
    read_only: bool,
    reboots: Mutex<u32>,
}

impl MockBootBackend {
    pub fn new(state: FirmwareState, devices: Vec<StorageDevice>, mode: FirmwareMode) -> Self {
        MockBootBackend {
            state: RwLock::new(state),
            devices: RwLock::new(devices),
            firmware_mode: mode,
            ops: Mutex::new(Vec::new()),
            write_behavior: RwLock::new(WriteBehavior::Correct),
            read_only: false,
            reboots: Mutex::new(0),
        }
    }

    /// Rend le backend incapable d'ecrire, comme le mode `--dry-run`.
    pub fn read_only(mut self) -> Self {
        self.read_only = true;
        self
    }

    pub fn with_write_behavior(self, behavior: WriteBehavior) -> Self {
        *self.write_behavior.write().expect("verrou sain") = behavior;
        self
    }

    /// Journal complet des appels, dans l'ordre.
    pub fn ops(&self) -> Vec<Op> {
        self.ops.lock().expect("verrou sain").clone()
    }

    /// Les seules operations ayant modifie l'etat.
    pub fn writes(&self) -> Vec<Op> {
        self.ops().into_iter().filter(Op::is_write).collect()
    }

    pub fn reboot_count(&self) -> u32 {
        *self.reboots.lock().expect("verrou sain")
    }

    pub fn clear_ops(&self) {
        self.ops.lock().expect("verrou sain").clear();
    }

    /// Instantane courant, pour les assertions de test.
    pub fn snapshot(&self) -> FirmwareState {
        self.state.read().expect("verrou sain").clone()
    }

    /// Simule le debranchement d'un peripherique.
    pub fn remove_device(&self, id: &str) {
        self.devices
            .write()
            .expect("verrou sain")
            .retain(|d| d.id != id);
    }

    /// Simule le branchement d'un peripherique.
    pub fn add_device(&self, device: StorageDevice) {
        self.devices.write().expect("verrou sain").push(device);
    }

    /// Simule la disparition d'une entree cote firmware, entre l'affichage et
    /// la validation.
    pub fn remove_entry(&self, id: BootId) {
        self.state
            .write()
            .expect("verrou sain")
            .variables
            .remove(&id.variable_name());
    }

    fn record(&self, op: Op) {
        self.ops.lock().expect("verrou sain").push(op);
    }
}

impl BootBackend for MockBootBackend {
    fn firmware_mode(&self) -> Result<FirmwareMode, BackendError> {
        self.record(Op::FirmwareMode);
        Ok(self.firmware_mode)
    }

    fn read_state(&self) -> Result<FirmwareState, BackendError> {
        self.record(Op::ReadState);
        if self.firmware_mode == FirmwareMode::LegacyBios {
            return Err(BackendError::NotUefi);
        }
        Ok(self.state.read().expect("verrou sain").clone())
    }

    fn list_devices(&self) -> Result<Vec<StorageDevice>, BackendError> {
        self.record(Op::ListDevices);
        Ok(self.devices.read().expect("verrou sain").clone())
    }

    fn set_boot_next(&self, target: BootId) -> Result<(), BackendError> {
        self.record(Op::SetBootNext(target));

        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }
        if self.firmware_mode == FirmwareMode::LegacyBios {
            return Err(BackendError::NotUefi);
        }

        let behavior = self.write_behavior.read().expect("verrou sain").clone();
        let mut state = self.state.write().expect("verrou sain");

        match behavior {
            WriteBehavior::Refuse(msg) => return Err(BackendError::WriteRefused(msg)),
            WriteBehavior::SilentlyIgnore => {}
            WriteBehavior::Correct => {
                state
                    .variables
                    .insert(VAR_BOOT_NEXT.into(), target.to_le_bytes().to_vec());
            }
            WriteBehavior::WriteWrongTarget(other) => {
                state
                    .variables
                    .insert(VAR_BOOT_NEXT.into(), other.to_le_bytes().to_vec());
            }
            WriteBehavior::AlsoReorderBootOrder => {
                state
                    .variables
                    .insert(VAR_BOOT_NEXT.into(), target.to_le_bytes().to_vec());
                if let Some(mut order) = state.boot_order() {
                    // Promeut la cible en tete : le comportement precisement
                    // interdit par le cahier des charges.
                    order.retain(|id| *id != target);
                    order.insert(0, target);
                    let raw: Vec<u8> = order.iter().flat_map(|id| id.to_le_bytes()).collect();
                    state.variables.insert(VAR_BOOT_ORDER.into(), raw);
                }
            }
            WriteBehavior::AlsoDeleteEntry(victim) => {
                state
                    .variables
                    .insert(VAR_BOOT_NEXT.into(), target.to_le_bytes().to_vec());
                state.variables.remove(&victim.variable_name());
            }
        }

        Ok(())
    }

    fn reboot(&self) -> Result<(), BackendError> {
        self.record(Op::Reboot);
        if self.read_only {
            return Err(BackendError::ReadOnlyMode);
        }
        *self.reboots.lock().expect("verrou sain") += 1;
        Ok(())
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

// ---------------------------------------------------------------------------
// Scenarios pretcomposes
// ---------------------------------------------------------------------------

/// Scenarios disponibles via `--mock-boot <nom>`.
pub const SCENARIOS: [&str; 6] = [
    "windows-only",
    "windows-debian",
    "multi-os",
    "legacy-bios",
    "orphan-entry",
    "no-entries",
];

/// Construit un backend simule a partir du nom d'un scenario.
pub fn scenario(name: &str) -> Option<MockBootBackend> {
    match name {
        "windows-only" => Some(windows_only()),
        "windows-debian" => Some(windows_debian()),
        "multi-os" => Some(multi_os()),
        "legacy-bios" => Some(legacy_bios()),
        "orphan-entry" => Some(orphan_entry()),
        "no-entries" => Some(no_entries()),
        _ => None,
    }
}

fn nvme_disk() -> StorageDevice {
    StorageDevice {
        id: "mock-nvme-0".into(),
        system_name: "0".into(),
        model: "ACME NV1000".into(),
        bus: BusType::Nvme,
        size_bytes: 1_024_209_543_168,
        removable: false,
        serial: Some("SN-NVME-0001".into()),
        partitions: vec![
            PartitionInfo {
                number: 1,
                gpt_type: Guid::parse("de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
                unique_guid: Guid::parse("aaaaaaaa-0000-4000-8000-000000000001"),
                size_bytes: 262_144_000,
                is_esp: false,
                drive_letter: None,
                label: Some("Recovery".into()),
                filesystem: Some("NTFS".into()),
            },
            PartitionInfo {
                number: 2,
                gpt_type: Some(Guid::ESP_PARTITION_TYPE),
                unique_guid: Guid::parse(testdata::ESP_PART_GUID),
                size_bytes: 104_857_600,
                is_esp: true,
                drive_letter: None,
                label: None,
                filesystem: Some("FAT32".into()),
            },
            PartitionInfo {
                number: 4,
                gpt_type: Guid::parse("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"),
                unique_guid: Guid::parse("aaaaaaaa-0000-4000-8000-000000000004"),
                size_bytes: 1_022_000_000_000,
                is_esp: false,
                drive_letter: Some('C'),
                label: Some("Windows".into()),
                filesystem: Some("NTFS".into()),
            },
        ],
    }
}

fn sata_disk() -> StorageDevice {
    StorageDevice {
        id: "mock-sata-1".into(),
        system_name: "1".into(),
        model: "ACME SA500".into(),
        bus: BusType::Sata,
        size_bytes: 500_107_862_016,
        removable: false,
        serial: Some("SN-SATA-0001".into()),
        partitions: vec![PartitionInfo {
            number: 1,
            gpt_type: Some(Guid::ESP_PARTITION_TYPE),
            unique_guid: Guid::parse(testdata::ESP2_PART_GUID),
            size_bytes: 536_870_912,
            is_esp: true,
            drive_letter: None,
            label: None,
            filesystem: Some("FAT32".into()),
        }],
    }
}

/// Cle USB amovible, pour les tests de branchement a chaud.
pub fn usb_stick() -> StorageDevice {
    StorageDevice {
        id: "mock-usb-2".into(),
        system_name: "2".into(),
        model: "ACME UK64".into(),
        bus: BusType::Usb,
        size_bytes: 64_000_000_000,
        removable: true,
        serial: Some("SN-USB-0001".into()),
        partitions: vec![PartitionInfo {
            number: 1,
            gpt_type: Some(Guid::ESP_PARTITION_TYPE),
            unique_guid: Guid::parse(testdata::USB_PART_GUID),
            size_bytes: 536_870_912,
            is_esp: true,
            drive_letter: Some('E'),
            label: Some("LIVE".into()),
            filesystem: Some("FAT32".into()),
        }],
    }
}

fn build_state(entries: &[(u16, Vec<u8>)], order: &[u16], current: u16) -> FirmwareState {
    let mut vars = BTreeMap::new();
    vars.insert(VAR_BOOT_ORDER.into(), testdata::boot_order(order));
    vars.insert(VAR_BOOT_CURRENT.into(), testdata::boot_id(current));
    vars.insert("Timeout".into(), vec![0x03, 0x00]);
    for (id, raw) in entries {
        vars.insert(BootId(*id).variable_name(), raw.clone());
    }
    FirmwareState::new(vars)
}

pub fn windows_only() -> MockBootBackend {
    MockBootBackend::new(
        build_state(&[(1, testdata::load_option_windows())], &[1], 1),
        vec![nvme_disk()],
        FirmwareMode::Uefi,
    )
}

pub fn windows_debian() -> MockBootBackend {
    MockBootBackend::new(
        build_state(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_debian()),
            ],
            &[1, 2],
            1,
        ),
        vec![nvme_disk()],
        FirmwareMode::Uefi,
    )
}

pub fn multi_os() -> MockBootBackend {
    MockBootBackend::new(
        build_state(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_debian()),
                (3, testdata::load_option_ubuntu()),
                (4, testdata::load_option_usb()),
                (5, testdata::load_option_firmware_setup()),
            ],
            &[1, 2, 3, 4, 5],
            1,
        ),
        vec![nvme_disk(), sata_disk(), usb_stick()],
        FirmwareMode::Uefi,
    )
}

pub fn legacy_bios() -> MockBootBackend {
    MockBootBackend::new(
        FirmwareState::default(),
        vec![nvme_disk()],
        FirmwareMode::LegacyBios,
    )
}

/// Une entree pointe une partition absente de l'inventaire.
pub fn orphan_entry() -> MockBootBackend {
    MockBootBackend::new(
        build_state(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_orphan()),
            ],
            &[1, 2],
            1,
        ),
        vec![nvme_disk()],
        FirmwareMode::Uefi,
    )
}

/// Firmware UEFI sans aucune entree exploitable.
pub fn no_entries() -> MockBootBackend {
    MockBootBackend::new(
        build_state(&[], &[], 0),
        vec![nvme_disk()],
        FirmwareMode::Uefi,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_scenario_can_be_built() {
        for name in SCENARIOS {
            assert!(scenario(name).is_some(), "scenario manquant : {name}");
        }
        assert!(scenario("inexistant").is_none());
    }

    #[test]
    fn reading_never_records_a_write() {
        let mock = multi_os();
        let _ = mock.firmware_mode();
        let _ = mock.read_state();
        let _ = mock.list_devices();
        assert!(mock.writes().is_empty());
        assert_eq!(mock.ops().len(), 3);
    }

    #[test]
    fn a_correct_write_touches_only_boot_next() {
        let mock = windows_debian();
        let before = mock.snapshot();
        mock.set_boot_next(BootId(2)).unwrap();
        let after = mock.snapshot();

        assert_eq!(
            crate::guard::diff(&before, &after),
            vec![crate::guard::VarChange::Added(VAR_BOOT_NEXT.into())]
        );
    }

    #[test]
    fn read_only_mode_refuses_to_write_or_reboot() {
        let mock = windows_debian().read_only();
        assert_eq!(
            mock.set_boot_next(BootId(2)),
            Err(BackendError::ReadOnlyMode)
        );
        assert_eq!(mock.reboot(), Err(BackendError::ReadOnlyMode));
        assert_eq!(mock.reboot_count(), 0);
        // L'etat n'a pas bouge malgre les tentatives.
        assert!(mock.snapshot().boot_next().is_none());
    }

    #[test]
    fn hostile_behaviors_actually_corrupt_the_state() {
        // Verifie que les scenarios hostiles font bien ce qu'ils annoncent,
        // faute de quoi les tests du garde-fou seraient vides de sens.
        let mock = windows_debian().with_write_behavior(WriteBehavior::AlsoReorderBootOrder);
        mock.set_boot_next(BootId(2)).unwrap();
        assert_eq!(
            mock.snapshot().boot_order(),
            Some(vec![BootId(2), BootId(1)])
        );

        let mock = windows_debian().with_write_behavior(WriteBehavior::SilentlyIgnore);
        mock.set_boot_next(BootId(2)).unwrap();
        assert!(mock.snapshot().boot_next().is_none());

        let mock = windows_debian().with_write_behavior(WriteBehavior::AlsoDeleteEntry(BootId(1)));
        mock.set_boot_next(BootId(2)).unwrap();
        assert!(!mock.snapshot().contains_entry(BootId(1)));
    }

    #[test]
    fn devices_can_be_plugged_and_unplugged() {
        let mock = windows_debian();
        assert_eq!(mock.list_devices().unwrap().len(), 1);
        mock.add_device(usb_stick());
        assert_eq!(mock.list_devices().unwrap().len(), 2);
        mock.remove_device("mock-usb-2");
        assert_eq!(mock.list_devices().unwrap().len(), 1);
    }

    #[test]
    fn legacy_bios_scenario_refuses_state_reads() {
        let mock = legacy_bios();
        assert_eq!(mock.firmware_mode().unwrap(), FirmwareMode::LegacyBios);
        assert_eq!(mock.read_state(), Err(BackendError::NotUefi));
    }
}
