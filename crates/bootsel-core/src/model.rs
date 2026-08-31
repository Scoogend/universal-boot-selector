//! Modele de donnees partage entre la detection, l'interface et le helper.

use crate::efi::{parse_boot_id, parse_boot_id_list, Guid, LoadOption, Transport};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Mode de demarrage du firmware de la machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirmwareMode {
    Uefi,
    /// BIOS herite : `BootNext` n'existe pas, aucune selection sure n'est possible.
    LegacyBios,
}

impl FirmwareMode {
    pub fn supports_boot_next(&self) -> bool {
        matches!(self, FirmwareMode::Uefi)
    }
}

/// Identifiant d'une entree de boot UEFI : le `####` de `Boot####`.
///
/// Ces identifiants sont **volatils** : le firmware peut les renumeroter. Ils
/// ne servent qu'a designer une entree dans l'instant present, jamais a
/// memoriser une preference (voir [`crate::identity::StableId`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BootId(pub u16);

impl BootId {
    /// Nom de la variable UEFI correspondante, ex. `Boot0002`.
    pub fn variable_name(&self) -> String {
        format!("Boot{:04X}", self.0)
    }

    /// Les 4 chiffres hexadecimaux seuls, ex. `0002`.
    pub fn hex4(&self) -> String {
        format!("{:04X}", self.0)
    }

    /// Reconnait `Boot0002` et en extrait l'identifiant.
    /// Refuse tout ce qui n'est pas exactement ce format.
    pub fn from_variable_name(name: &str) -> Option<BootId> {
        let digits = name.strip_prefix("Boot")?;
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(digits, 16).ok().map(BootId)
    }

    /// Reconnait `0002`. C'est la seule forme acceptee en entree du helper
    /// privilegie : quatre chiffres hexadecimaux, rien d'autre.
    pub fn from_hex4(s: &str) -> Option<BootId> {
        if s.len() != 4 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u16::from_str_radix(s, 16).ok().map(BootId)
    }

    /// Encodage little-endian sur 2 octets, tel qu'attendu par `BootNext`.
    pub fn to_le_bytes(&self) -> [u8; 2] {
        self.0.to_le_bytes()
    }
}

impl fmt::Display for BootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.variable_name())
    }
}

/// Instantane complet et immuable des variables de demarrage du firmware.
///
/// C'est la structure sur laquelle repose l'invariant de securite du projet :
/// on en prend un avant et un apres l'ecriture de `BootNext`, et on exige que
/// la seule difference soit `BootNext` lui-meme.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FirmwareState {
    /// Contenu brut de chaque variable lue, indexe par nom.
    /// `BTreeMap` pour que la comparaison et l'affichage soient deterministes.
    pub variables: BTreeMap<String, Vec<u8>>,
}

/// Nom de la variable d'ordre de demarrage permanent. **Jamais ecrite.**
pub const VAR_BOOT_ORDER: &str = "BootOrder";
/// Nom de la variable de demarrage unique. Seule variable que l'application ecrit.
pub const VAR_BOOT_NEXT: &str = "BootNext";
/// Nom de la variable indiquant l'entree ayant servi au demarrage courant.
pub const VAR_BOOT_CURRENT: &str = "BootCurrent";

impl FirmwareState {
    pub fn new(variables: BTreeMap<String, Vec<u8>>) -> Self {
        FirmwareState { variables }
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.variables.get(name).map(|v| v.as_slice())
    }

    /// Ordre de demarrage permanent, decode. `None` si la variable est absente
    /// ou illisible : on ne devine jamais.
    pub fn boot_order(&self) -> Option<Vec<BootId>> {
        let raw = self.get(VAR_BOOT_ORDER)?;
        parse_boot_id_list(raw)
            .ok()
            .map(|ids| ids.into_iter().map(BootId).collect())
    }

    /// Demarrage unique deja programme, s'il y en a un.
    pub fn boot_next(&self) -> Option<BootId> {
        parse_boot_id(self.get(VAR_BOOT_NEXT)?).ok().map(BootId)
    }

    /// Entree ayant servi a demarrer la session courante.
    pub fn boot_current(&self) -> Option<BootId> {
        parse_boot_id(self.get(VAR_BOOT_CURRENT)?).ok().map(BootId)
    }

    /// Tous les identifiants `Boot####` presents dans l'instantane, tries.
    pub fn entry_ids(&self) -> Vec<BootId> {
        let mut ids: Vec<BootId> = self
            .variables
            .keys()
            .filter_map(|k| BootId::from_variable_name(k))
            .collect();
        ids.sort_unstable();
        ids
    }

    /// Contenu brut d'une entree.
    pub fn raw_entry(&self, id: BootId) -> Option<&[u8]> {
        self.get(&id.variable_name())
    }

    /// Decode une entree. `None` si absente, `Some(Err)` si illisible.
    pub fn load_option(&self, id: BootId) -> Option<Result<LoadOption, crate::efi::EfiParseError>> {
        self.raw_entry(id).map(LoadOption::parse)
    }

    pub fn contains_entry(&self, id: BootId) -> bool {
        self.variables.contains_key(&id.variable_name())
    }
}

/// Systeme d'exploitation devine a partir du chemin EFI et de la description.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsKind {
    Windows,
    Debian,
    Ubuntu,
    LinuxMint,
    PopOs,
    Fedora,
    Arch,
    /// Linux non identifie plus precisement.
    LinuxGeneric,
    /// Chargeur amovible standard, typiquement une cle USB d'installation.
    RemovableMedia,
    /// Menu Setup, shell EFI, diagnostic constructeur.
    FirmwareUtility,
    Unknown,
}

impl OsKind {
    pub fn label(&self) -> &'static str {
        match self {
            OsKind::Windows => "Windows",
            OsKind::Debian => "Debian",
            OsKind::Ubuntu => "Ubuntu",
            OsKind::LinuxMint => "Linux Mint",
            OsKind::PopOs => "Pop!_OS",
            OsKind::Fedora => "Fedora",
            OsKind::Arch => "Arch Linux",
            OsKind::LinuxGeneric => "Linux",
            OsKind::RemovableMedia => "Support amovible",
            OsKind::FirmwareUtility => "Utilitaire firmware",
            OsKind::Unknown => "Systeme inconnu",
        }
    }

    /// Nom de l'icone a afficher. Le frontend fournit un repli generique.
    pub fn icon(&self) -> &'static str {
        match self {
            OsKind::Windows => "windows",
            OsKind::Debian => "debian",
            OsKind::Ubuntu => "ubuntu",
            OsKind::LinuxMint | OsKind::PopOs | OsKind::Fedora | OsKind::Arch
            | OsKind::LinuxGeneric => "linux",
            OsKind::RemovableMedia => "usb",
            OsKind::FirmwareUtility => "firmware",
            OsKind::Unknown => "generic",
        }
    }

    pub fn is_linux(&self) -> bool {
        matches!(
            self,
            OsKind::Debian
                | OsKind::Ubuntu
                | OsKind::LinuxMint
                | OsKind::PopOs
                | OsKind::Fedora
                | OsKind::Arch
                | OsKind::LinuxGeneric
        )
    }
}

/// Chargeur de demarrage devine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootloaderKind {
    WindowsBootManager,
    Grub,
    SystemdBoot,
    /// `shim` : maillon Secure Boot qui charge ensuite GRUB.
    Shim,
    Refind,
    /// Chargeur amovible `\EFI\BOOT\BOOTX64.EFI`.
    RemovableFallback,
    Unknown,
}

impl BootloaderKind {
    pub fn label(&self) -> &'static str {
        match self {
            BootloaderKind::WindowsBootManager => "Windows Boot Manager",
            BootloaderKind::Grub => "GRUB",
            BootloaderKind::SystemdBoot => "systemd-boot",
            BootloaderKind::Shim => "shim (GRUB)",
            BootloaderKind::Refind => "rEFInd",
            BootloaderKind::RemovableFallback => "Chargeur EFI amovible",
            BootloaderKind::Unknown => "Chargeur EFI",
        }
    }
}

/// Degre de certitude de l'identification.
///
/// Une entree n'est jamais presumee demarrable simplement parce qu'un fichier
/// EFI existe : la confiance est affichee a l'utilisateur.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Le firmware liste cette entree et son support est present.
    Confirmed,
    /// Identification vraisemblable, mais un element manque.
    Probable,
    /// L'entree existe dans le firmware mais son support est introuvable.
    Unverifiable,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::Confirmed => "Confirme",
            Confidence::Probable => "Probable",
            Confidence::Unverifiable => "Non verifiable",
        }
    }
}

/// Disponibilite d'une entree au moment de l'affichage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum Availability {
    /// Selectionnable.
    Available,
    /// Presente dans le firmware mais son peripherique n'est pas connecte.
    DeviceMissing,
    /// Marquee inactive par le firmware.
    Inactive,
    /// Entree interne au firmware, non proposee comme cible.
    NotSelectable(String),
}

impl Availability {
    pub fn is_selectable(&self) -> bool {
        matches!(self, Availability::Available)
    }
}

/// Une entree de demarrage prete a etre affichee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootEntry {
    /// Identifiant firmware courant. Volatil.
    pub id: BootId,
    /// Cle stable, utilisee pour les alias. Voir [`crate::identity`].
    pub stable_id: String,
    /// Description telle qu'ecrite dans le firmware.
    pub firmware_description: String,
    /// Nom affiche : l'alias local s'il existe, sinon le nom deduit.
    pub display_name: String,
    /// Nom deduit par les heuristiques, avant application de l'alias.
    pub detected_name: String,
    pub os: OsKind,
    pub bootloader: BootloaderKind,
    pub transport: Transport,
    pub confidence: Confidence,
    pub availability: Availability,
    pub active: bool,
    pub efi_path: Option<String>,
    pub partition_guid: Option<Guid>,
    pub partition_number: Option<u32>,
    /// Description lisible du peripherique porteur, ex. « NVMe ACME NV1000 954 Go ».
    pub device_label: Option<String>,
    /// Vrai si l'entree est celle ayant servi au demarrage courant.
    pub is_current: bool,
}

/// Type de bus d'un peripherique de stockage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BusType {
    Nvme,
    Sata,
    Usb,
    Sas,
    Scsi,
    Raid,
    Virtual,
    Unknown,
}

impl BusType {
    pub fn label(&self) -> &'static str {
        match self {
            BusType::Nvme => "NVMe",
            BusType::Sata => "SATA",
            BusType::Usb => "USB",
            BusType::Sas => "SAS",
            BusType::Scsi => "SCSI",
            BusType::Raid => "RAID",
            BusType::Virtual => "Virtuel",
            BusType::Unknown => "Inconnu",
        }
    }
}

/// Un disque physique detecte, avec ses partitions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageDevice {
    /// Cle stable du peripherique (numero de serie si disponible).
    pub id: String,
    /// Numero de disque tel que vu par le systeme (Windows) ou nom (`sda`, Linux).
    pub system_name: String,
    pub model: String,
    pub bus: BusType,
    pub size_bytes: u64,
    pub removable: bool,
    pub serial: Option<String>,
    pub partitions: Vec<PartitionInfo>,
}

impl StorageDevice {
    /// Libelle court destine a l'interface, ex. « NVMe ACME NV1000 954 Go ».
    pub fn label(&self) -> String {
        let model = self.model.trim();
        let model = if model.is_empty() { "Disque" } else { model };
        format!("{} {} {}", self.bus.label(), model, format_size(self.size_bytes))
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Les partitions systeme EFI de ce disque.
    pub fn esp_partitions(&self) -> impl Iterator<Item = &PartitionInfo> {
        self.partitions.iter().filter(|p| p.is_esp)
    }

    pub fn has_partition_guid(&self, guid: Guid) -> bool {
        self.partitions
            .iter()
            .any(|p| p.unique_guid == Some(guid))
    }
}

/// Une partition, decrite en lecture seule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionInfo {
    pub number: u32,
    /// GUID de **type** de partition (ce qu'elle est).
    pub gpt_type: Option<Guid>,
    /// GUID **unique** de la partition (qui elle est) — la cle d'identite stable.
    pub unique_guid: Option<Guid>,
    pub size_bytes: u64,
    pub is_esp: bool,
    pub drive_letter: Option<char>,
    pub label: Option<String>,
    pub filesystem: Option<String>,
}

/// Formate une taille en unites binaires lisibles.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    if bytes == 0 {
        return "0 o".to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else if value >= 100.0 {
        format!("{:.0} {}", value, UNITS[unit])
    } else {
        format!("{:.1} {}", value, UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;

    #[test]
    fn boot_id_formats_as_the_firmware_does() {
        assert_eq!(BootId(2).variable_name(), "Boot0002");
        assert_eq!(BootId(2).hex4(), "0002");
        assert_eq!(BootId(0xABCD).variable_name(), "BootABCD");
        assert_eq!(BootId(0xFFFF).hex4(), "FFFF");
        assert_eq!(BootId(2).to_le_bytes(), [0x02, 0x00]);
    }

    #[test]
    fn boot_id_parses_valid_variable_names() {
        assert_eq!(BootId::from_variable_name("Boot0002"), Some(BootId(2)));
        assert_eq!(BootId::from_variable_name("BootAbCd"), Some(BootId(0xABCD)));
    }

    #[test]
    fn boot_id_rejects_anything_that_is_not_a_boot_variable() {
        for bad in [
            "BootOrder",   // ne doit surtout pas passer pour une entree
            "BootNext",
            "BootCurrent",
            "Boot002",     // trop court
            "Boot00002",   // trop long
            "Boot",
            "",
            "boot0002",    // casse du prefixe
            "Boot00G2",    // non hexadecimal
            "Timeout",
        ] {
            assert_eq!(
                BootId::from_variable_name(bad),
                None,
                "aurait du rejeter : {bad:?}"
            );
        }
    }

    #[test]
    fn boot_id_hex4_accepts_only_four_hex_digits() {
        assert_eq!(BootId::from_hex4("0002"), Some(BootId(2)));
        assert_eq!(BootId::from_hex4("ffff"), Some(BootId(0xFFFF)));
        for bad in ["002", "00002", "", "000g", "0x02", " 002", "0002 "] {
            assert_eq!(BootId::from_hex4(bad), None, "aurait du rejeter : {bad:?}");
        }
    }

    fn sample_state() -> FirmwareState {
        let mut vars = BTreeMap::new();
        vars.insert(VAR_BOOT_ORDER.into(), testdata::boot_order(&[1, 2, 3]));
        vars.insert(VAR_BOOT_CURRENT.into(), testdata::boot_id(1));
        vars.insert("Boot0001".into(), testdata::load_option_windows());
        vars.insert("Boot0002".into(), testdata::load_option_debian());
        vars.insert("Boot0003".into(), testdata::load_option_usb());
        vars.insert("Timeout".into(), vec![0x05, 0x00]);
        FirmwareState::new(vars)
    }

    #[test]
    fn decodes_boot_order_and_current() {
        let s = sample_state();
        assert_eq!(
            s.boot_order(),
            Some(vec![BootId(1), BootId(2), BootId(3)])
        );
        assert_eq!(s.boot_current(), Some(BootId(1)));
        assert_eq!(s.boot_next(), None);
    }

    #[test]
    fn entry_ids_ignores_non_entry_variables() {
        let s = sample_state();
        assert_eq!(s.entry_ids(), vec![BootId(1), BootId(2), BootId(3)]);
    }

    #[test]
    fn decodes_individual_entries() {
        let s = sample_state();
        let opt = s.load_option(BootId(1)).unwrap().unwrap();
        assert_eq!(opt.description, "Windows Boot Manager");
        assert!(s.load_option(BootId(99)).is_none());
        assert!(s.contains_entry(BootId(2)));
        assert!(!s.contains_entry(BootId(99)));
    }

    #[test]
    fn malformed_variables_yield_none_rather_than_a_wrong_guess() {
        let mut vars = BTreeMap::new();
        vars.insert(VAR_BOOT_ORDER.into(), vec![0x01]); // longueur impaire
        vars.insert(VAR_BOOT_NEXT.into(), vec![0x01, 0x02, 0x03]); // taille invalide
        let s = FirmwareState::new(vars);
        assert_eq!(s.boot_order(), None);
        assert_eq!(s.boot_next(), None);
    }

    #[test]
    fn formats_sizes_readably() {
        assert_eq!(format_size(0), "0 o");
        assert_eq!(format_size(512), "512 o");
        assert_eq!(format_size(1024), "1.0 Ko");
        assert_eq!(format_size(100 * 1024 * 1024), "100 Mo");
        assert_eq!(format_size(1_000_204_886_016), "932 Go");
    }

    #[test]
    fn legacy_bios_does_not_support_boot_next() {
        assert!(FirmwareMode::Uefi.supports_boot_next());
        assert!(!FirmwareMode::LegacyBios.supports_boot_next());
    }
}
