//! Roles des partitions GPT, deduits de leur GUID de **type**.
//!
//! Le GUID de type dit ce qu'une partition *est*, sans qu'il faille l'ouvrir,
//! la monter ou en lire le contenu. C'est l'information la plus riche
//! disponible en pure lecture de metadonnees, et elle suffit a caracteriser un
//! disque : « celui-ci porte un systeme Linux », « celui-la porte Windows ».
//!
//! Cette approche est volontairement passive. L'application n'a besoin d'aucun
//! acces au systeme de fichiers pour en arriver la, ce qui respecte
//! l'interdiction de monter une partition simplement pour la detecter.

use crate::efi::Guid;
use serde::{Deserialize, Serialize};

/// Ce qu'une partition contient, d'apres son GUID de type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    /// Partition systeme EFI : c'est la que vivent les chargeurs de demarrage.
    EfiSystem,
    /// Donnees Linux generiques, le type qu'utilise la plupart des installeurs.
    LinuxData,
    /// Racine Linux declaree selon la specification des partitions decouvrables.
    LinuxRoot,
    LinuxHome,
    LinuxSwap,
    LinuxLvm,
    LinuxRaid,
    /// Partition de donnees Microsoft : le type d'un volume Windows.
    WindowsData,
    /// Partition reservee Microsoft, presente sur tout disque Windows en GPT.
    WindowsReserved,
    WindowsRecovery,
    /// Amorcage BIOS herite (GRUB en mode BIOS sur un disque GPT).
    BiosBoot,
    /// Partition d'amorcage etendue (XBOOTLDR).
    ExtendedBoot,
    Apple,
    Unknown,
}

impl PartitionRole {
    pub fn label(&self) -> &'static str {
        match self {
            PartitionRole::EfiSystem => "Partition systeme EFI",
            PartitionRole::LinuxData => "Donnees Linux",
            PartitionRole::LinuxRoot => "Racine Linux",
            PartitionRole::LinuxHome => "Dossier personnel Linux",
            PartitionRole::LinuxSwap => "Echange Linux",
            PartitionRole::LinuxLvm => "Volume logique Linux",
            PartitionRole::LinuxRaid => "RAID Linux",
            PartitionRole::WindowsData => "Donnees Windows",
            PartitionRole::WindowsReserved => "Reserve Microsoft",
            PartitionRole::WindowsRecovery => "Recuperation Windows",
            PartitionRole::BiosBoot => "Amorcage BIOS",
            PartitionRole::ExtendedBoot => "Amorcage etendu",
            PartitionRole::Apple => "Partition Apple",
            PartitionRole::Unknown => "Type inconnu",
        }
    }

    /// Vrai pour les partitions qui trahissent la presence d'un systeme Linux.
    pub fn is_linux(&self) -> bool {
        matches!(
            self,
            PartitionRole::LinuxData
                | PartitionRole::LinuxRoot
                | PartitionRole::LinuxHome
                | PartitionRole::LinuxSwap
                | PartitionRole::LinuxLvm
                | PartitionRole::LinuxRaid
        )
    }

    /// Vrai pour les partitions caracteristiques d'une installation Windows.
    pub fn is_windows(&self) -> bool {
        matches!(
            self,
            PartitionRole::WindowsData
                | PartitionRole::WindowsReserved
                | PartitionRole::WindowsRecovery
        )
    }
}

/// Table des GUID de type standardises, en forme canonique minuscule.
///
/// Sources : specification UEFI (annexe des GUID de type de partition) et
/// specification des partitions decouvrables de systemd.
const KNOWN_TYPES: &[(&str, PartitionRole)] = &[
    ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", PartitionRole::EfiSystem),
    ("0fc63daf-8483-4772-8e79-3d69d8477de4", PartitionRole::LinuxData),
    ("4f68bce3-e8cd-4db1-96e7-fbcaf984b709", PartitionRole::LinuxRoot),
    ("44479540-f297-41b2-9af7-d131d5f0458a", PartitionRole::LinuxRoot),
    ("933ac7e1-2eb4-4f13-b844-0e14e2aef915", PartitionRole::LinuxHome),
    ("0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", PartitionRole::LinuxSwap),
    ("e6d6d379-f507-44c2-a23c-238f2a3df928", PartitionRole::LinuxLvm),
    ("a19d880f-05fc-4d3b-a006-743f0f84911e", PartitionRole::LinuxRaid),
    ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", PartitionRole::WindowsData),
    ("e3c9e316-0b5c-4db8-817d-f92df00215ae", PartitionRole::WindowsReserved),
    ("de94bba4-06d1-4d40-a16a-bfd50179d6ac", PartitionRole::WindowsRecovery),
    ("21686148-6449-6e6f-744e-656564454649", PartitionRole::BiosBoot),
    ("bc13c2ff-59e6-4262-a352-b275fd6f7172", PartitionRole::ExtendedBoot),
    ("48465300-0000-11aa-aa11-00306543ecac", PartitionRole::Apple),
    ("7c3457ef-0000-11aa-aa11-00306543ecac", PartitionRole::Apple),
];

/// Determine le role d'une partition a partir de son GUID de type.
///
/// Un GUID inconnu renvoie [`PartitionRole::Unknown`] : on ne devine pas.
pub fn role_of(type_guid: Guid) -> PartitionRole {
    let hyphenated = type_guid.to_hyphenated();
    KNOWN_TYPES
        .iter()
        .find(|(guid, _)| *guid == hyphenated)
        .map(|(_, role)| *role)
        .unwrap_or(PartitionRole::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(s: &str) -> PartitionRole {
        role_of(Guid::parse(s).expect("GUID de test valide"))
    }

    #[test]
    fn recognises_the_efi_system_partition() {
        assert_eq!(
            role("c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
            PartitionRole::EfiSystem
        );
        assert_eq!(role_of(Guid::ESP_PARTITION_TYPE), PartitionRole::EfiSystem);
    }

    #[test]
    fn recognises_the_linux_types_seen_on_a_real_install() {
        // Type effectivement observe sur le disque externe de la machine de
        // developpement : ses trois partitions non-ESP le portent.
        assert_eq!(
            role("0fc63daf-8483-4772-8e79-3d69d8477de4"),
            PartitionRole::LinuxData
        );
        assert!(role("0fc63daf-8483-4772-8e79-3d69d8477de4").is_linux());
        assert!(role("0657fd6d-a4ab-43c4-84e5-0933c84b4f4f").is_linux());
        assert!(role("e6d6d379-f507-44c2-a23c-238f2a3df928").is_linux());
    }

    #[test]
    fn recognises_the_windows_types_seen_on_a_real_install() {
        // Types effectivement observes sur le disque interne de la machine.
        assert_eq!(
            role("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"),
            PartitionRole::WindowsData
        );
        assert_eq!(
            role("e3c9e316-0b5c-4db8-817d-f92df00215ae"),
            PartitionRole::WindowsReserved
        );
        assert_eq!(
            role("de94bba4-06d1-4d40-a16a-bfd50179d6ac"),
            PartitionRole::WindowsRecovery
        );
        assert!(role("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7").is_windows());
    }

    #[test]
    fn linux_and_windows_roles_never_overlap() {
        for (guid, _) in KNOWN_TYPES {
            let r = role(guid);
            assert!(
                !(r.is_linux() && r.is_windows()),
                "{guid} classe a la fois Linux et Windows"
            );
        }
    }

    #[test]
    fn an_esp_belongs_to_neither_system() {
        // L'ESP est partagee entre systemes : elle ne doit en designer aucun.
        let esp = role_of(Guid::ESP_PARTITION_TYPE);
        assert!(!esp.is_linux());
        assert!(!esp.is_windows());
    }

    #[test]
    fn an_unknown_guid_is_not_guessed() {
        assert_eq!(
            role("deadbeef-0000-4000-8000-000000000000"),
            PartitionRole::Unknown
        );
        assert!(!role("deadbeef-0000-4000-8000-000000000000").is_linux());
        assert!(!role("deadbeef-0000-4000-8000-000000000000").is_windows());
    }

    #[test]
    fn the_table_contains_no_duplicate_guid() {
        let mut seen: Vec<&str> = KNOWN_TYPES.iter().map(|(g, _)| *g).collect();
        let total = seen.len();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), total, "GUID en double dans la table");
    }

    #[test]
    fn every_table_entry_is_a_parseable_canonical_guid() {
        for (guid, _) in KNOWN_TYPES {
            let parsed = Guid::parse(guid).unwrap_or_else(|| panic!("GUID invalide : {guid}"));
            assert_eq!(
                parsed.to_hyphenated(),
                *guid,
                "la table doit etre en forme canonique minuscule"
            );
        }
    }

    #[test]
    fn every_role_has_a_label() {
        for (guid, _) in KNOWN_TYPES {
            assert!(!role(guid).label().is_empty());
        }
        assert!(!PartitionRole::Unknown.label().is_empty());
    }
}
