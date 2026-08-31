//! Assemblage de la liste affichable a partir d'un instantane firmware et
//! d'un inventaire de disques.
//!
//! Cette etape est purement calculatoire : elle ne lit ni le firmware ni les
//! disques, elle combine ce que le backend a deja fourni. Elle est donc
//! entierement testable sans machine reelle.

use crate::alias::Config;
use crate::backend::{BackendError, BootBackend};
use crate::efi::LoadOption;
use crate::identify;
use crate::identity::stable_id_for;
use crate::media::{find_unlisted_media, UnlistedMedium};
use crate::model::{
    Availability, BootEntry, BootId, Confidence, FirmwareMode, FirmwareState, OsKind,
    StorageDevice,
};
use serde::{Deserialize, Serialize};

/// Resultat complet d'un cycle de detection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub firmware_mode: FirmwareMode,
    /// Entrees dans l'ordre d'affichage.
    pub entries: Vec<BootEntry>,
    pub devices: Vec<StorageDevice>,
    /// Supports portant une ESP mais qu'aucune entree du firmware ne designe.
    /// Affiches, jamais selectionnables : voir [`crate::media`].
    pub unlisted_media: Vec<UnlistedMedium>,
    /// Ordre de demarrage permanent, affiche a titre informatif. Jamais modifie.
    pub boot_order: Option<Vec<BootId>>,
    /// Demarrage unique deja programme, s'il y en a un.
    pub boot_next: Option<BootId>,
    pub boot_current: Option<BootId>,
    /// Anomalies non bloquantes rencontrees pendant l'assemblage.
    pub warnings: Vec<String>,
}

impl Detection {
    /// Les entrees reellement proposables a l'utilisateur.
    pub fn selectable(&self) -> impl Iterator<Item = &BootEntry> {
        self.entries.iter().filter(|e| e.availability.is_selectable())
    }

    /// Retrouve une entree par sa cle stable.
    pub fn find_by_stable_id(&self, stable_id: &str) -> Option<&BootEntry> {
        self.entries.iter().find(|e| e.stable_id == stable_id)
    }
}

/// Execute un cycle de detection complet en **lecture seule**.
///
/// N'appelle que les methodes de lecture du backend. Aucun chemin de code
/// n'atteint `set_boot_next` depuis ici.
pub fn detect(backend: &dyn BootBackend, config: &Config) -> Result<Detection, BackendError> {
    let firmware_mode = backend.firmware_mode()?;
    let devices = backend.list_devices().unwrap_or_default();

    // En BIOS herite, il n'y a pas de variables de demarrage a lire : on
    // renvoie l'inventaire materiel et l'interface affichera le message dedie.
    if firmware_mode == FirmwareMode::LegacyBios {
        return Ok(Detection {
            firmware_mode,
            entries: Vec::new(),
            unlisted_media: Vec::new(),
            devices,
            boot_order: None,
            boot_next: None,
            boot_current: None,
            warnings: vec![
                "Ce systeme utilise le mode BIOS Legacy. La selection securisee \
                 du prochain demarrage via UEFI n'est pas disponible."
                    .to_string(),
            ],
        });
    }

    let state = backend.read_state()?;
    let (entries, warnings) = build_entries(&state, &devices, config);
    let unlisted_media = find_unlisted_media(&devices, &entries);

    Ok(Detection {
        firmware_mode,
        entries,
        unlisted_media,
        devices,
        boot_order: state.boot_order(),
        boot_next: state.boot_next(),
        boot_current: state.boot_current(),
        warnings,
    })
}

/// Construit la liste affichable. Fonction pure : memes entrees, meme sortie.
pub fn build_entries(
    state: &FirmwareState,
    devices: &[StorageDevice],
    config: &Config,
) -> (Vec<BootEntry>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut entries = Vec::new();
    let boot_current = state.boot_current();

    for id in ordered_ids(state) {
        let Some(raw) = state.raw_entry(id) else {
            // Reference dans BootOrder vers une entree inexistante : anomalie
            // du firmware, signalee mais non corrigee. Reparer n'est pas notre
            // role.
            warnings.push(format!(
                "{id} est reference par BootOrder mais la variable est absente."
            ));
            continue;
        };

        let option = match LoadOption::parse(raw) {
            Ok(o) => o,
            Err(e) => {
                warnings.push(format!("{id} est illisible et sera ignoree ({e})."));
                continue;
            }
        };

        entries.push(build_entry(id, &option, devices, config, boot_current));
    }

    (entries, warnings)
}

/// Ordre d'affichage : celui de `BootOrder` d'abord — c'est celui que
/// l'utilisateur voit dans son firmware — puis les entrees restantes, triees.
fn ordered_ids(state: &FirmwareState) -> Vec<BootId> {
    let all = state.entry_ids();
    let mut ordered = Vec::with_capacity(all.len());

    if let Some(order) = state.boot_order() {
        for id in order {
            if !ordered.contains(&id) {
                ordered.push(id);
            }
        }
    }
    for id in all {
        if !ordered.contains(&id) {
            ordered.push(id);
        }
    }
    ordered
}

fn build_entry(
    id: BootId,
    option: &LoadOption,
    devices: &[StorageDevice],
    config: &Config,
    boot_current: Option<BootId>,
) -> BootEntry {
    let ident = identify::identify(option);
    let stable_id = stable_id_for(option);
    let partition_guid = option.partition_guid();

    // Rattachement au peripherique physique par GUID unique de partition.
    let device = partition_guid.and_then(|g| devices.iter().find(|d| d.has_partition_guid(g)));

    // On ne conclut a l'absence d'un peripherique que si l'inventaire est
    // exploitable : une liste vide signifie « je n'ai pas pu regarder », pas
    // « rien n'est branche ».
    let device_known = !devices.is_empty() && partition_guid.is_some();
    let device_found = device.is_some();

    let availability = if option.is_firmware_internal() {
        Availability::NotSelectable("entree interne au firmware".to_string())
    } else if !option.is_active() {
        Availability::Inactive
    } else if device_known && !device_found {
        Availability::DeviceMissing
    } else {
        Availability::Available
    };

    let confidence = match availability {
        Availability::DeviceMissing => Confidence::Unverifiable,
        _ => ident.confidence,
    };

    let display_name = config.display_name(&stable_id, &ident.name);

    BootEntry {
        id,
        stable_id,
        firmware_description: option.description.clone(),
        display_name,
        detected_name: ident.name,
        os: ident.os,
        bootloader: ident.bootloader,
        transport: option.transport(),
        confidence,
        availability,
        active: option.is_active(),
        efi_path: option.efi_path(),
        partition_guid,
        partition_number: option.partition_number(),
        device_label: device.map(|d| d.label()),
        is_current: Some(id) == boot_current,
    }
}

/// Filtre d'affichage applique selon les preferences utilisateur.
pub fn visible_entries<'a>(
    detection: &'a Detection,
    config: &Config,
) -> Vec<&'a BootEntry> {
    detection
        .entries
        .iter()
        .filter(|e| {
            if e.os == OsKind::FirmwareUtility && !config.ui.show_firmware_entries {
                return false;
            }
            if matches!(e.availability, Availability::DeviceMissing)
                && !config.ui.show_unavailable_entries
            {
                return false;
            }
            true
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;
    use crate::model::{BusType, PartitionInfo, VAR_BOOT_CURRENT, VAR_BOOT_ORDER};
    use crate::efi::Guid;
    use std::collections::BTreeMap;

    fn esp_device(guid: &str, model: &str, bus: BusType, removable: bool) -> StorageDevice {
        StorageDevice {
            id: format!("dev-{model}"),
            system_name: model.to_string(),
            model: model.to_string(),
            bus,
            size_bytes: 1_000_204_886_016,
            removable,
            serial: None,
            partitions: vec![PartitionInfo {
                number: 2,
                gpt_type: Some(Guid::ESP_PARTITION_TYPE),
                unique_guid: Guid::parse(guid),
                size_bytes: 104_857_600,
                is_esp: true,
                drive_letter: None,
                label: None,
                filesystem: Some("FAT32".into()),
            }],
        }
    }

    fn state_with(entries: &[(u16, Vec<u8>)], order: &[u16]) -> FirmwareState {
        let mut vars = BTreeMap::new();
        vars.insert(VAR_BOOT_ORDER.into(), testdata::boot_order(order));
        vars.insert(VAR_BOOT_CURRENT.into(), testdata::boot_id(order[0]));
        for (id, raw) in entries {
            vars.insert(BootId(*id).variable_name(), raw.clone());
        }
        FirmwareState::new(vars)
    }

    #[test]
    fn builds_entries_in_boot_order() {
        let state = state_with(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_debian()),
                (3, testdata::load_option_usb()),
            ],
            &[2, 1, 3],
        );
        let (entries, warnings) = build_entries(&state, &[], &Config::default());

        assert!(warnings.is_empty());
        let ids: Vec<u16> = entries.iter().map(|e| e.id.0).collect();
        assert_eq!(ids, vec![2, 1, 3]);
        assert_eq!(entries[0].os, OsKind::Debian);
        assert_eq!(entries[1].os, OsKind::Windows);
    }

    #[test]
    fn appends_entries_missing_from_boot_order() {
        let state = state_with(
            &[
                (1, testdata::load_option_windows()),
                (9, testdata::load_option_ubuntu()),
            ],
            &[1], // Boot0009 n'est pas dans BootOrder
        );
        let (entries, _) = build_entries(&state, &[], &Config::default());
        let ids: Vec<u16> = entries.iter().map(|e| e.id.0).collect();
        assert_eq!(ids, vec![1, 9]);
    }

    #[test]
    fn marks_the_current_boot_entry() {
        let state = state_with(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_debian()),
            ],
            &[1, 2],
        );
        let (entries, _) = build_entries(&state, &[], &Config::default());
        assert!(entries[0].is_current);
        assert!(!entries[1].is_current);
    }

    #[test]
    fn attaches_the_physical_device_label() {
        let state = state_with(&[(1, testdata::load_option_windows())], &[1]);
        let devices = vec![esp_device(
            testdata::ESP_PART_GUID,
            "ACME NV1000",
            BusType::Nvme,
            false,
        )];
        let (entries, _) = build_entries(&state, &devices, &Config::default());
        assert_eq!(entries[0].device_label.as_deref(), Some("NVMe ACME NV1000 932 Go"));
        assert_eq!(entries[0].availability, Availability::Available);
    }

    #[test]
    fn flags_an_entry_whose_device_is_gone() {
        // L'inventaire ne contient pas la partition ciblee par l'entree.
        let state = state_with(&[(1, testdata::load_option_orphan())], &[1]);
        let devices = vec![esp_device(
            testdata::ESP_PART_GUID,
            "ACME NV1000",
            BusType::Nvme,
            false,
        )];
        let (entries, _) = build_entries(&state, &devices, &Config::default());
        assert_eq!(entries[0].availability, Availability::DeviceMissing);
        assert_eq!(entries[0].confidence, Confidence::Unverifiable);
        assert!(!entries[0].availability.is_selectable());
    }

    #[test]
    fn an_empty_device_inventory_does_not_declare_everything_missing() {
        // Sans admin, l'inventaire peut etre vide : ne rien conclure vaut
        // mieux que declarer a tort tous les systemes introuvables.
        let state = state_with(&[(1, testdata::load_option_windows())], &[1]);
        let (entries, _) = build_entries(&state, &[], &Config::default());
        assert_eq!(entries[0].availability, Availability::Available);
    }

    #[test]
    fn firmware_internal_entries_are_not_selectable() {
        let state = state_with(&[(1, testdata::load_option_firmware_setup())], &[1]);
        let (entries, _) = build_entries(&state, &[], &Config::default());
        assert!(matches!(
            entries[0].availability,
            Availability::NotSelectable(_)
        ));
    }

    #[test]
    fn inactive_entries_are_reported_and_not_selectable() {
        let state = state_with(&[(1, testdata::load_option_inactive())], &[1]);
        let (entries, _) = build_entries(&state, &[], &Config::default());
        assert_eq!(entries[0].availability, Availability::Inactive);
        assert!(!entries[0].active);
    }

    #[test]
    fn an_unreadable_entry_is_skipped_with_a_warning_not_a_failure() {
        let mut state = state_with(&[(1, testdata::load_option_windows())], &[1, 2]);
        state
            .variables
            .insert("Boot0002".into(), vec![0xFF, 0xFF, 0xFF]);

        let (entries, warnings) = build_entries(&state, &[], &Config::default());
        assert_eq!(entries.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Boot0002"));
    }

    #[test]
    fn a_dangling_boot_order_reference_is_reported_not_repaired() {
        let state = state_with(&[(1, testdata::load_option_windows())], &[1, 7]);
        let (entries, warnings) = build_entries(&state, &[], &Config::default());
        assert_eq!(entries.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Boot0007"));
    }

    #[test]
    fn applies_the_local_alias_to_the_displayed_name() {
        let state = state_with(&[(2, testdata::load_option_debian())], &[2]);
        let (probe, _) = build_entries(&state, &[], &Config::default());
        let stable_id = probe[0].stable_id.clone();

        let mut config = Config::default();
        config.set_alias(&stable_id, "Mon Linux").unwrap();

        let (entries, _) = build_entries(&state, &[], &config);
        assert_eq!(entries[0].display_name, "Mon Linux");
        // Le nom detecte reste disponible : l'alias n'ecrase rien.
        assert_eq!(entries[0].detected_name, "debian");
        assert_eq!(entries[0].firmware_description, "debian");
    }

    #[test]
    fn visibility_filters_follow_user_preferences() {
        let state = state_with(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_firmware_setup()),
                (3, testdata::load_option_orphan()),
            ],
            &[1, 2, 3],
        );
        let devices = vec![esp_device(
            testdata::ESP_PART_GUID,
            "ACME NV1000",
            BusType::Nvme,
            false,
        )];
        let (entries, _) = build_entries(&state, &devices, &Config::default());
        let detection = Detection {
            firmware_mode: FirmwareMode::Uefi,
            entries,
            unlisted_media: Vec::new(),
            devices,
            boot_order: None,
            boot_next: None,
            boot_current: None,
            warnings: Vec::new(),
        };

        let mut config = Config::default();
        // Par defaut : entrees firmware masquees, entrees indisponibles visibles.
        assert_eq!(visible_entries(&detection, &config).len(), 2);

        config.ui.show_unavailable_entries = false;
        assert_eq!(visible_entries(&detection, &config).len(), 1);

        config.ui.show_firmware_entries = true;
        assert_eq!(visible_entries(&detection, &config).len(), 2);
    }

    #[test]
    fn stable_ids_are_unique_across_a_realistic_setup() {
        let state = state_with(
            &[
                (1, testdata::load_option_windows()),
                (2, testdata::load_option_debian()),
                (3, testdata::load_option_ubuntu()),
                (4, testdata::load_option_usb()),
            ],
            &[1, 2, 3, 4],
        );
        let (entries, _) = build_entries(&state, &[], &Config::default());
        let mut ids: Vec<&str> = entries.iter().map(|e| e.stable_id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "collision de cle stable");
    }
}
