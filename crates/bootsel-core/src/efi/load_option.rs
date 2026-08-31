//! Parsing d'`EFI_LOAD_OPTION` (UEFI spec §3.1.3), le contenu de chaque
//! variable `Boot####`.
//!
//! Disposition binaire :
//! ```text
//! u32   Attributes
//! u16   FilePathListLength   // longueur en octets de FilePathList
//! u16[] Description          // UCS-2, terminee par 0x0000
//! []    FilePathList         // suite de noeuds EFI_DEVICE_PATH
//! u8[]  OptionalData         // le reste, longueur implicite
//! ```

use super::device_path::{DevicePath, Transport};
use super::guid::Guid;
use super::reader::Reader;
use super::EfiParseError;
use serde::{Deserialize, Serialize};

/// L'entree est active et candidate au demarrage.
pub const LOAD_OPTION_ACTIVE: u32 = 0x0000_0001;
/// L'entree est masquee dans le menu du firmware.
pub const LOAD_OPTION_HIDDEN: u32 = 0x0000_0008;
/// L'entree a ete generee automatiquement par le firmware.
pub const LOAD_OPTION_CATEGORY_APP: u32 = 0x0000_0100;

/// Une option de demarrage decodee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoadOption {
    pub attributes: u32,
    pub description: String,
    pub device_path: DevicePath,
    pub optional_data: Vec<u8>,
}

impl LoadOption {
    /// Decode le contenu brut d'une variable `Boot####`.
    pub fn parse(buf: &[u8]) -> Result<LoadOption, EfiParseError> {
        let mut r = Reader::new(buf);

        let attributes = r.u32_le()?;
        let file_path_list_length = r.u16_le()? as usize;
        let description = r.ucs2_nul_terminated()?;

        if r.remaining() < file_path_list_length {
            return Err(EfiParseError::FilePathListOutOfRange {
                declared: file_path_list_length,
                available: r.remaining(),
            });
        }

        let path_bytes = r.take(file_path_list_length)?;
        let device_path = DevicePath::parse(path_bytes)?;
        let optional_data = r.rest().to_vec();

        Ok(LoadOption {
            attributes,
            description,
            device_path,
            optional_data,
        })
    }

    pub fn is_active(&self) -> bool {
        self.attributes & LOAD_OPTION_ACTIVE != 0
    }

    pub fn is_hidden(&self) -> bool {
        self.attributes & LOAD_OPTION_HIDDEN != 0
    }

    /// Chemin du fichier EFI cible, normalise.
    pub fn efi_path(&self) -> Option<String> {
        self.device_path.efi_file_path()
    }

    /// GUID unique de la partition GPT hebergeant le chargeur.
    pub fn partition_guid(&self) -> Option<Guid> {
        self.device_path.gpt_partition_guid()
    }

    pub fn partition_number(&self) -> Option<u32> {
        self.device_path.hard_drive().map(|hd| hd.partition_number)
    }

    pub fn transport(&self) -> Transport {
        self.device_path.transport()
    }

    /// Vrai pour les entrees internes au firmware (« Enter Setup », shell EFI),
    /// qui ne correspondent a aucun systeme installe et n'ont pas a etre
    /// proposees comme cible de demarrage.
    pub fn is_firmware_internal(&self) -> bool {
        self.device_path.is_firmware_internal()
    }
}

/// Decode une liste d'identifiants `Boot####` (variables `BootOrder`).
/// Le tampon est une suite d'entiers 16 bits little-endian.
pub fn parse_boot_id_list(buf: &[u8]) -> Result<Vec<u16>, EfiParseError> {
    if buf.len() % 2 != 0 {
        return Err(EfiParseError::OddLengthIdList { length: buf.len() });
    }
    Ok(buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect())
}

/// Decode un identifiant unique 16 bits (`BootNext`, `BootCurrent`).
pub fn parse_boot_id(buf: &[u8]) -> Result<u16, EfiParseError> {
    if buf.len() != 2 {
        return Err(EfiParseError::BadScalarLength {
            expected: 2,
            actual: buf.len(),
        });
    }
    Ok(u16::from_le_bytes([buf[0], buf[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;

    #[test]
    fn parses_the_windows_boot_manager_entry() {
        let raw = testdata::load_option_windows();
        let opt = LoadOption::parse(&raw).unwrap();

        assert_eq!(opt.description, "Windows Boot Manager");
        assert!(opt.is_active());
        assert!(!opt.is_hidden());
        assert_eq!(
            opt.efi_path().as_deref(),
            Some("\\EFI\\Microsoft\\Boot\\bootmgfw.efi")
        );
        assert_eq!(opt.partition_number(), Some(2));
        assert!(opt.partition_guid().is_some());
        assert!(!opt.is_firmware_internal());
    }

    #[test]
    fn parses_the_debian_entry() {
        let raw = testdata::load_option_debian();
        let opt = LoadOption::parse(&raw).unwrap();
        assert_eq!(opt.description, "debian");
        assert_eq!(
            opt.efi_path().as_deref(),
            Some("\\EFI\\debian\\shimx64.efi")
        );
    }

    #[test]
    fn parses_a_usb_entry_and_detects_its_transport() {
        let raw = testdata::load_option_usb();
        let opt = LoadOption::parse(&raw).unwrap();
        assert_eq!(opt.description, "UEFI: ACME UK64");
        assert_eq!(opt.transport(), Transport::Usb);
    }

    #[test]
    fn parses_optional_data_when_present() {
        let raw = testdata::load_option_with_optional_data(b"root=/dev/sda2");
        let opt = LoadOption::parse(&raw).unwrap();
        assert_eq!(opt.optional_data, b"root=/dev/sda2");
    }

    #[test]
    fn inactive_entries_are_reported_as_such() {
        let raw = testdata::load_option_inactive();
        let opt = LoadOption::parse(&raw).unwrap();
        assert!(!opt.is_active());
    }

    #[test]
    fn recognises_a_firmware_internal_entry() {
        let raw = testdata::load_option_firmware_setup();
        let opt = LoadOption::parse(&raw).unwrap();
        assert!(opt.is_firmware_internal());
        assert!(opt.efi_path().is_none());
    }

    #[test]
    fn rejects_an_empty_buffer() {
        assert!(matches!(
            LoadOption::parse(&[]).unwrap_err(),
            EfiParseError::UnexpectedEof { .. }
        ));
    }

    #[test]
    fn rejects_a_truncated_header() {
        assert!(LoadOption::parse(&[0x01, 0x00, 0x00]).is_err());
    }

    #[test]
    fn rejects_an_unterminated_description() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&LOAD_OPTION_ACTIVE.to_le_bytes());
        raw.extend_from_slice(&0u16.to_le_bytes());
        for c in "jamais termine".encode_utf16() {
            raw.extend_from_slice(&c.to_le_bytes());
        }
        assert!(matches!(
            LoadOption::parse(&raw).unwrap_err(),
            EfiParseError::UnterminatedString { .. }
        ));
    }

    #[test]
    fn rejects_a_file_path_list_longer_than_the_buffer() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&LOAD_OPTION_ACTIVE.to_le_bytes());
        raw.extend_from_slice(&9999u16.to_le_bytes()); // longueur mensongere
        raw.extend_from_slice(&0u16.to_le_bytes()); // description vide
        assert!(matches!(
            LoadOption::parse(&raw).unwrap_err(),
            EfiParseError::FilePathListOutOfRange { declared: 9999, .. }
        ));
    }

    #[test]
    fn parses_boot_order_lists() {
        let raw = [0x01, 0x00, 0x02, 0x00, 0x0A, 0x00];
        assert_eq!(parse_boot_id_list(&raw).unwrap(), vec![1, 2, 10]);
        assert_eq!(parse_boot_id_list(&[]).unwrap(), Vec::<u16>::new());
    }

    #[test]
    fn rejects_an_odd_length_boot_order() {
        assert!(matches!(
            parse_boot_id_list(&[0x01, 0x00, 0x02]).unwrap_err(),
            EfiParseError::OddLengthIdList { length: 3 }
        ));
    }

    #[test]
    fn parses_and_validates_scalar_boot_ids() {
        assert_eq!(parse_boot_id(&[0x02, 0x00]).unwrap(), 2);
        assert_eq!(parse_boot_id(&[0xFF, 0xFF]).unwrap(), 0xFFFF);
        assert!(parse_boot_id(&[0x02]).is_err());
        assert!(parse_boot_id(&[0x02, 0x00, 0x00]).is_err());
    }

    #[test]
    fn never_panics_on_truncated_prefixes_of_a_valid_entry() {
        let full = testdata::load_option_windows();
        for n in 0..full.len() {
            let _ = LoadOption::parse(&full[..n]);
        }
    }

    #[test]
    fn never_panics_on_single_bit_corruption_of_a_valid_entry() {
        let full = testdata::load_option_windows();
        for byte_idx in 0..full.len() {
            for bit in 0..8 {
                let mut corrupted = full.clone();
                corrupted[byte_idx] ^= 1 << bit;
                let _ = LoadOption::parse(&corrupted);
            }
        }
    }
}
