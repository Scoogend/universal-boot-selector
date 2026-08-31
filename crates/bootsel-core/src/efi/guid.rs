//! GUID EFI (mixed-endian) : representation memoire et affichage canonique.

use serde::{Deserialize, Serialize};
use std::fmt;

/// GUID tel que stocke par UEFI : les 3 premiers champs sont little-endian,
/// les 8 derniers octets sont big-endian (ordre reseau).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const ZERO: Guid = Guid([0u8; 16]);

    /// GUID de l'espace de nommage des variables globales UEFI.
    /// `8be4df61-93ca-11d2-aa0d-00e098032b8c`
    pub const EFI_GLOBAL_VARIABLE: Guid = Guid([
        0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b,
        0x8c,
    ]);

    /// Type de partition GPT « EFI System Partition ».
    /// `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`
    pub const ESP_PARTITION_TYPE: Guid = Guid([
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9,
        0x3b,
    ]);

    pub fn from_bytes(b: [u8; 16]) -> Self {
        Guid(b)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }

    /// Forme canonique minuscule sans accolades : `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`.
    pub fn to_hyphenated(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3], b[2], b[1], b[0], // Data1, little-endian
            b[5], b[4],             // Data2, little-endian
            b[7], b[6],             // Data3, little-endian
            b[8], b[9],             // Data4[0..2], big-endian
            b[10], b[11], b[12], b[13], b[14], b[15], // Data4[2..8], big-endian
        )
    }

    /// Forme avec accolades, telle qu'attendue par les APIs Windows.
    pub fn to_braced(&self) -> String {
        format!("{{{}}}", self.to_hyphenated())
    }

    /// Parse une forme canonique, avec ou sans accolades. Insensible a la casse.
    pub fn parse(s: &str) -> Option<Guid> {
        let s = s.trim();
        let s = s.strip_prefix('{').unwrap_or(s);
        let s = s.strip_suffix('}').unwrap_or(s);

        let groups: Vec<&str> = s.split('-').collect();
        if groups.len() != 5
            || groups[0].len() != 8
            || groups[1].len() != 4
            || groups[2].len() != 4
            || groups[3].len() != 4
            || groups[4].len() != 12
        {
            return None;
        }

        let flat: String = groups.concat();
        let mut raw = [0u8; 16];
        for (i, slot) in raw.iter_mut().enumerate() {
            *slot = u8::from_str_radix(flat.get(i * 2..i * 2 + 2)?, 16).ok()?;
        }

        // `raw` est en ordre d'affichage ; on repasse en ordre memoire UEFI.
        Some(Guid([
            raw[3], raw[2], raw[1], raw[0], // Data1
            raw[5], raw[4], // Data2
            raw[7], raw[6], // Data3
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]))
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hyphenated())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self.to_hyphenated())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esp_guid_renders_canonically() {
        assert_eq!(
            Guid::ESP_PARTITION_TYPE.to_hyphenated(),
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
        );
        assert_eq!(
            Guid::ESP_PARTITION_TYPE.to_braced(),
            "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
        );
    }

    #[test]
    fn efi_global_variable_guid_renders_canonically() {
        assert_eq!(
            Guid::EFI_GLOBAL_VARIABLE.to_hyphenated(),
            "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    #[test]
    fn parse_roundtrips_both_forms() {
        for g in [Guid::ESP_PARTITION_TYPE, Guid::EFI_GLOBAL_VARIABLE] {
            assert_eq!(Guid::parse(&g.to_hyphenated()), Some(g));
            assert_eq!(Guid::parse(&g.to_braced()), Some(g));
            assert_eq!(Guid::parse(&g.to_hyphenated().to_uppercase()), Some(g));
        }
    }

    #[test]
    fn parse_rejects_malformed_input() {
        for bad in [
            "",
            "not-a-guid",
            "c12a7328-f81f-11d2-ba4b",                     // trop peu de groupes
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b-extra",  // trop de groupes
            "c12a732-f81f-11d2-ba4b-00a0c93ec93b",         // groupe trop court
            "zzzzzzzz-f81f-11d2-ba4b-00a0c93ec93b",        // non hexadecimal
        ] {
            assert_eq!(Guid::parse(bad), None, "aurait du rejeter : {bad:?}");
        }
    }

    #[test]
    fn zero_guid_is_detected() {
        assert!(Guid::ZERO.is_zero());
        assert!(!Guid::ESP_PARTITION_TYPE.is_zero());
    }
}
