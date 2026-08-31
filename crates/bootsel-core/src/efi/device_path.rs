//! Parsing des noeuds `EFI_DEVICE_PATH_PROTOCOL` (UEFI spec, chapitre 10).
//!
//! Seuls les noeuds porteurs d'information utile a l'identification sont
//! decodes en detail ; les autres sont conserves sous forme brute plutot que
//! rejetes, afin de ne jamais faire disparaitre une entree de boot a cause
//! d'un noeud exotique.

use super::guid::Guid;
use super::reader::Reader;
use super::EfiParseError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Nombre maximal de noeuds acceptes dans un chemin. Une valeur superieure
/// traduit forcement des donnees corrompues : on refuse plutot que de boucler.
const MAX_NODES: usize = 128;

/// Taille de l'en-tete commun a tous les noeuds : type(1) + sous-type(1) + longueur(2).
const NODE_HEADER_LEN: usize = 4;

// Types de noeuds.
const TYPE_HARDWARE: u8 = 0x01;
const TYPE_ACPI: u8 = 0x02;
const TYPE_MESSAGING: u8 = 0x03;
const TYPE_MEDIA: u8 = 0x04;
const TYPE_BIOS_BOOT_SPEC: u8 = 0x05;
const TYPE_END: u8 = 0x7F;

/// Un noeud de chemin de peripherique.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DevicePathNode {
    /// Type 4 / sous-type 1 — designe une partition precise.
    /// C'est le noeud le plus important : sa signature GPT fournit l'identite stable.
    HardDrive(HardDrive),
    /// Type 4 / sous-type 2 — support optique ou image ISO (« El Torito »).
    CdRom {
        boot_entry: u32,
        partition_start: u64,
        partition_size: u64,
    },
    /// Type 4 / sous-type 4 — chemin de fichier, ex. `\EFI\debian\shimx64.efi`.
    FilePath(String),
    /// Type 4 / sous-type 6 — fichier interne au firmware (menu Setup, shell EFI...).
    FirmwareFile(Guid),
    /// Type 4 / sous-type 7 — volume interne au firmware.
    FirmwareVolume(Guid),
    /// Type 3 / sous-type 5 — port USB.
    Usb {
        parent_port: u8,
        interface: u8,
    },
    /// Type 3 / sous-type 16 — identifiant USB persistant (WWID).
    UsbWwid {
        interface: u16,
        vendor_id: u16,
        product_id: u16,
        serial: String,
    },
    /// Type 3 / sous-type 23 — namespace NVMe.
    Nvme {
        namespace_id: u32,
        namespace_uuid: u64,
    },
    /// Type 3 / sous-type 18 — port SATA.
    Sata {
        hba_port: u16,
        port_multiplier: u16,
        lun: u16,
    },
    /// Type 3 / sous-type 1 — peripherique ATAPI/IDE.
    Atapi {
        primary: bool,
        slave: bool,
        lun: u16,
    },
    /// Type 3 / sous-type 2 — peripherique SCSI.
    Scsi {
        target: u16,
        lun: u16,
    },
    /// Type 3 / sous-type 11 — adresse MAC (amorcage reseau / PXE).
    MacAddress {
        address: [u8; 32],
        if_type: u8,
    },
    /// Type 5 — entree heritee « BIOS Boot Specification ».
    BiosBootSpec {
        device_type: u16,
        status_flag: u16,
        description: String,
    },
    /// Type 0x7F — fin de chemin (ou fin d'instance).
    End {
        end_entire: bool,
    },
    /// Tout noeud non decode, conserve tel quel.
    Other {
        node_type: u8,
        subtype: u8,
        data: Vec<u8>,
    },
}

/// Noeud « Hard Drive Media Device Path ».
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardDrive {
    pub partition_number: u32,
    pub partition_start: u64,
    pub partition_size: u64,
    /// Interpretation de `signature_raw` selon `signature_type`.
    pub signature: PartitionSignature,
    /// 0x01 = MBR, 0x02 = GPT.
    pub mbr_type: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PartitionSignature {
    /// Signature de partition GPT : le GUID unique de la partition.
    Gpt(Guid),
    /// Signature de disque MBR sur 32 bits.
    Mbr(u32),
    /// Aucune signature fournie.
    None,
}

impl HardDrive {
    /// GUID unique de partition, uniquement si le disque est en GPT.
    pub fn gpt_guid(&self) -> Option<Guid> {
        match self.signature {
            PartitionSignature::Gpt(g) if !g.is_zero() => Some(g),
            _ => None,
        }
    }
}

impl DevicePathNode {
    /// Parse un unique noeud et renvoie sa longueur totale consommee.
    fn parse_one(r: &mut Reader<'_>) -> Result<(DevicePathNode, usize), EfiParseError> {
        let start = r.position();
        let node_type = r.u8()?;
        let subtype = r.u8()?;
        let length = r.u16_le()? as usize;

        // Un noeud plus court que son en-tete rendrait la progression nulle et
        // ferait boucler le parseur a l'infini. C'est le garde-fou essentiel.
        if length < NODE_HEADER_LEN {
            return Err(EfiParseError::NodeTooShort {
                offset: start,
                node_type,
                subtype,
                length: length as u16,
            });
        }

        let body_len = length - NODE_HEADER_LEN;
        let body = r.take(body_len).map_err(|_| EfiParseError::NodeOverruns {
            offset: start,
            node_type,
            subtype,
            length: length as u16,
        })?;

        let node = Self::decode_body(node_type, subtype, body);
        Ok((node, length))
    }

    /// Decode le corps d'un noeud. Ne peut pas echouer : si le corps ne
    /// correspond pas a la forme attendue, on retombe sur `Other` plutot que
    /// de rejeter toute l'entree de boot.
    fn decode_body(node_type: u8, subtype: u8, body: &[u8]) -> DevicePathNode {
        let fallback = || DevicePathNode::Other {
            node_type,
            subtype,
            data: body.to_vec(),
        };

        match (node_type, subtype) {
            (TYPE_END, st) => DevicePathNode::End {
                end_entire: st == 0xFF,
            },

            (TYPE_MEDIA, 0x01) => {
                let mut r = Reader::new(body);
                let parsed = (|| -> Result<HardDrive, EfiParseError> {
                    let partition_number = r.u32_le()?;
                    let partition_start = r.u64_le()?;
                    let partition_size = r.u64_le()?;
                    let sig_bytes = r.take(16)?;
                    let mbr_type = r.u8()?;
                    let signature_type = r.u8()?;

                    let mut raw = [0u8; 16];
                    raw.copy_from_slice(sig_bytes);
                    let signature = match signature_type {
                        0x02 => PartitionSignature::Gpt(Guid(raw)),
                        0x01 => PartitionSignature::Mbr(u32::from_le_bytes([
                            raw[0], raw[1], raw[2], raw[3],
                        ])),
                        _ => PartitionSignature::None,
                    };

                    Ok(HardDrive {
                        partition_number,
                        partition_start,
                        partition_size,
                        signature,
                        mbr_type,
                    })
                })();
                parsed.map(DevicePathNode::HardDrive).unwrap_or_else(|_| fallback())
            }

            (TYPE_MEDIA, 0x02) => {
                let mut r = Reader::new(body);
                match (|| Ok::<_, EfiParseError>((r.u32_le()?, r.u64_le()?, r.u64_le()?)))() {
                    Ok((boot_entry, partition_start, partition_size)) => DevicePathNode::CdRom {
                        boot_entry,
                        partition_start,
                        partition_size,
                    },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MEDIA, 0x04) => {
                let mut r = Reader::new(body);
                match r.ucs2_fixed(body.len()) {
                    Ok(path) => DevicePathNode::FilePath(path),
                    Err(_) => fallback(),
                }
            }

            (TYPE_MEDIA, 0x06) => match Reader::new(body).guid() {
                Ok(g) => DevicePathNode::FirmwareFile(g),
                Err(_) => fallback(),
            },

            (TYPE_MEDIA, 0x07) => match Reader::new(body).guid() {
                Ok(g) => DevicePathNode::FirmwareVolume(g),
                Err(_) => fallback(),
            },

            (TYPE_MESSAGING, 0x01) => {
                let mut r = Reader::new(body);
                match (|| Ok::<_, EfiParseError>((r.u8()?, r.u8()?, r.u16_le()?)))() {
                    Ok((primary, slave, lun)) => DevicePathNode::Atapi {
                        primary: primary == 0,
                        slave: slave != 0,
                        lun,
                    },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MESSAGING, 0x02) => {
                let mut r = Reader::new(body);
                match (|| Ok::<_, EfiParseError>((r.u16_le()?, r.u16_le()?)))() {
                    Ok((target, lun)) => DevicePathNode::Scsi { target, lun },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MESSAGING, 0x05) => {
                let mut r = Reader::new(body);
                match (|| Ok::<_, EfiParseError>((r.u8()?, r.u8()?)))() {
                    Ok((parent_port, interface)) => DevicePathNode::Usb {
                        parent_port,
                        interface,
                    },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MESSAGING, 0x0B) => {
                let mut r = Reader::new(body);
                match (|| -> Result<_, EfiParseError> {
                    let raw = r.take(32)?;
                    let mut address = [0u8; 32];
                    address.copy_from_slice(raw);
                    Ok((address, r.u8()?))
                })() {
                    Ok((address, if_type)) => DevicePathNode::MacAddress { address, if_type },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MESSAGING, 0x10) => {
                let mut r = Reader::new(body);
                match (|| -> Result<_, EfiParseError> {
                    let interface = r.u16_le()?;
                    let vendor_id = r.u16_le()?;
                    let product_id = r.u16_le()?;
                    let remaining = r.remaining();
                    let serial = r.ucs2_fixed(remaining)?;
                    Ok((interface, vendor_id, product_id, serial))
                })() {
                    Ok((interface, vendor_id, product_id, serial)) => DevicePathNode::UsbWwid {
                        interface,
                        vendor_id,
                        product_id,
                        serial,
                    },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MESSAGING, 0x12) => {
                let mut r = Reader::new(body);
                match (|| Ok::<_, EfiParseError>((r.u16_le()?, r.u16_le()?, r.u16_le()?)))() {
                    Ok((hba_port, port_multiplier, lun)) => DevicePathNode::Sata {
                        hba_port,
                        port_multiplier,
                        lun,
                    },
                    Err(_) => fallback(),
                }
            }

            (TYPE_MESSAGING, 0x17) => {
                let mut r = Reader::new(body);
                match (|| Ok::<_, EfiParseError>((r.u32_le()?, r.u64_le()?)))() {
                    Ok((namespace_id, namespace_uuid)) => DevicePathNode::Nvme {
                        namespace_id,
                        namespace_uuid,
                    },
                    Err(_) => fallback(),
                }
            }

            (TYPE_BIOS_BOOT_SPEC, 0x01) => {
                let mut r = Reader::new(body);
                match (|| -> Result<_, EfiParseError> {
                    let device_type = r.u16_le()?;
                    let status_flag = r.u16_le()?;
                    // La description est ici en ASCII, pas en UCS-2.
                    let bytes = r.rest();
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    let description = String::from_utf8_lossy(&bytes[..end]).into_owned();
                    Ok((device_type, status_flag, description))
                })() {
                    Ok((device_type, status_flag, description)) => DevicePathNode::BiosBootSpec {
                        device_type,
                        status_flag,
                        description,
                    },
                    Err(_) => fallback(),
                }
            }

            // Noeuds materiels et ACPI : conserves bruts, ils n'apportent rien
            // a l'identification d'un systeme.
            (TYPE_HARDWARE, _) | (TYPE_ACPI, _) => fallback(),

            _ => fallback(),
        }
    }
}

impl fmt::Display for DevicePathNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DevicePathNode::HardDrive(hd) => match hd.signature {
                PartitionSignature::Gpt(g) => {
                    write!(f, "HD({},GPT,{})", hd.partition_number, g)
                }
                PartitionSignature::Mbr(s) => {
                    write!(f, "HD({},MBR,{:#010x})", hd.partition_number, s)
                }
                PartitionSignature::None => write!(f, "HD({},None)", hd.partition_number),
            },
            DevicePathNode::CdRom { boot_entry, .. } => write!(f, "CDROM({boot_entry})"),
            DevicePathNode::FilePath(p) => write!(f, "File({p})"),
            DevicePathNode::FirmwareFile(g) => write!(f, "FvFile({g})"),
            DevicePathNode::FirmwareVolume(g) => write!(f, "Fv({g})"),
            DevicePathNode::Usb {
                parent_port,
                interface,
            } => write!(f, "USB({parent_port},{interface})"),
            DevicePathNode::UsbWwid {
                vendor_id,
                product_id,
                serial,
                ..
            } => write!(f, "UsbWwid({vendor_id:04x},{product_id:04x},{serial})"),
            DevicePathNode::Nvme { namespace_id, .. } => write!(f, "NVMe({namespace_id})"),
            DevicePathNode::Sata { hba_port, lun, .. } => write!(f, "Sata({hba_port},{lun})"),
            DevicePathNode::Atapi { primary, slave, .. } => {
                write!(f, "Ata({},{})", if *primary { "P" } else { "S" }, slave)
            }
            DevicePathNode::Scsi { target, lun } => write!(f, "Scsi({target},{lun})"),
            DevicePathNode::MacAddress { if_type, .. } => write!(f, "MAC(if={if_type})"),
            DevicePathNode::BiosBootSpec { description, .. } => {
                write!(f, "BBS({description})")
            }
            DevicePathNode::End { end_entire } => {
                if *end_entire {
                    f.write_str("End")
                } else {
                    f.write_str("EndInstance")
                }
            }
            DevicePathNode::Other {
                node_type, subtype, ..
            } => write!(f, "Path({node_type:#04x},{subtype:#04x})"),
        }
    }
}

/// Une liste de noeuds formant un chemin de peripherique complet.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DevicePath {
    pub nodes: Vec<DevicePathNode>,
}

impl DevicePath {
    /// Parse une liste de noeuds. S'arrete au noeud de fin ou en fin de tampon.
    pub fn parse(buf: &[u8]) -> Result<DevicePath, EfiParseError> {
        let mut r = Reader::new(buf);
        let mut nodes = Vec::new();

        while !r.is_empty() {
            if nodes.len() >= MAX_NODES {
                return Err(EfiParseError::TooManyNodes { max: MAX_NODES });
            }
            let (node, _len) = DevicePathNode::parse_one(&mut r)?;
            let is_end = matches!(node, DevicePathNode::End { end_entire: true });
            nodes.push(node);
            if is_end {
                break;
            }
        }

        Ok(DevicePath { nodes })
    }

    /// Le chemin de fichier EFI, normalise avec des antislashs.
    pub fn efi_file_path(&self) -> Option<String> {
        self.nodes.iter().find_map(|n| match n {
            DevicePathNode::FilePath(p) => Some(normalize_efi_path(p)),
            _ => None,
        })
    }

    /// Le GUID unique de la partition GPT ciblee, s'il y en a une.
    pub fn gpt_partition_guid(&self) -> Option<Guid> {
        self.nodes.iter().find_map(|n| match n {
            DevicePathNode::HardDrive(hd) => hd.gpt_guid(),
            _ => None,
        })
    }

    /// Le noeud de partition, s'il y en a un.
    pub fn hard_drive(&self) -> Option<&HardDrive> {
        self.nodes.iter().find_map(|n| match n {
            DevicePathNode::HardDrive(hd) => Some(hd),
            _ => None,
        })
    }

    /// Le moyen de transport devine a partir des noeuds messaging.
    pub fn transport(&self) -> Transport {
        for n in &self.nodes {
            match n {
                DevicePathNode::Usb { .. } | DevicePathNode::UsbWwid { .. } => {
                    return Transport::Usb
                }
                DevicePathNode::Nvme { .. } => return Transport::Nvme,
                DevicePathNode::Sata { .. } => return Transport::Sata,
                DevicePathNode::Atapi { .. } => return Transport::Atapi,
                DevicePathNode::Scsi { .. } => return Transport::Scsi,
                DevicePathNode::MacAddress { .. } => return Transport::Network,
                _ => {}
            }
        }
        Transport::Unknown
    }

    /// Vrai si le chemin designe un composant interne au firmware
    /// (« Enter Setup », « Boot Menu », shell EFI) plutot qu'un systeme installe.
    pub fn is_firmware_internal(&self) -> bool {
        self.nodes.iter().any(|n| {
            matches!(
                n,
                DevicePathNode::FirmwareFile(_) | DevicePathNode::FirmwareVolume(_)
            )
        })
    }
}

impl fmt::Display for DevicePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let parts: Vec<String> = self
            .nodes
            .iter()
            .filter(|n| !matches!(n, DevicePathNode::End { .. }))
            .map(|n| n.to_string())
            .collect();
        f.write_str(&parts.join("/"))
    }
}

/// Moyen de transport du peripherique portant l'entree de boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Nvme,
    Sata,
    Usb,
    Atapi,
    Scsi,
    Network,
    Unknown,
}

impl Transport {
    pub fn label(&self) -> &'static str {
        match self {
            Transport::Nvme => "NVMe",
            Transport::Sata => "SATA",
            Transport::Usb => "USB",
            Transport::Atapi => "ATAPI",
            Transport::Scsi => "SCSI",
            Transport::Network => "Reseau",
            Transport::Unknown => "Inconnu",
        }
    }
}

/// Normalise un chemin EFI : antislashs, pas de doublons, prefixe garanti.
pub fn normalize_efi_path(path: &str) -> String {
    let unified = path.replace('/', "\\");
    let mut out = String::with_capacity(unified.len() + 1);
    if !unified.starts_with('\\') {
        out.push('\\');
    }
    let mut last_was_sep = false;
    for c in unified.chars() {
        let is_sep = c == '\\';
        if is_sep && last_was_sep {
            continue;
        }
        out.push(c);
        last_was_sep = is_sep;
    }
    while out.len() > 1 && out.ends_with('\\') {
        out.pop();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;

    #[test]
    fn parses_a_hard_drive_node() {
        let node = testdata::hard_drive_node(2, testdata::ESP_PART_GUID);
        let path = DevicePath::parse(&node).unwrap();
        let hd = path.hard_drive().expect("noeud HardDrive attendu");
        assert_eq!(hd.partition_number, 2);
        assert_eq!(hd.mbr_type, 0x02);
        assert_eq!(
            hd.gpt_guid().map(|g| g.to_hyphenated()),
            Some(testdata::ESP_PART_GUID.to_string())
        );
    }

    #[test]
    fn parses_a_file_path_node() {
        let node = testdata::file_path_node("\\EFI\\debian\\shimx64.efi");
        let path = DevicePath::parse(&node).unwrap();
        assert_eq!(
            path.efi_file_path().as_deref(),
            Some("\\EFI\\debian\\shimx64.efi")
        );
    }

    #[test]
    fn parses_a_full_windows_path() {
        let buf = testdata::windows_device_path();
        let path = DevicePath::parse(&buf).unwrap();
        assert_eq!(
            path.efi_file_path().as_deref(),
            Some("\\EFI\\Microsoft\\Boot\\bootmgfw.efi")
        );
        assert!(path.gpt_partition_guid().is_some());
        assert_eq!(path.hard_drive().unwrap().partition_number, 2);
    }

    #[test]
    fn detects_usb_transport() {
        let buf = testdata::usb_device_path();
        let path = DevicePath::parse(&buf).unwrap();
        assert_eq!(path.transport(), Transport::Usb);
    }

    #[test]
    fn detects_nvme_transport() {
        let mut buf = testdata::nvme_node(1);
        buf.extend_from_slice(&testdata::hard_drive_node(2, testdata::ESP_PART_GUID));
        buf.extend_from_slice(&testdata::end_node());
        let path = DevicePath::parse(&buf).unwrap();
        assert_eq!(path.transport(), Transport::Nvme);
    }

    #[test]
    fn recognises_firmware_internal_entries() {
        let buf = testdata::firmware_internal_path();
        let path = DevicePath::parse(&buf).unwrap();
        assert!(path.is_firmware_internal());
        assert!(path.efi_file_path().is_none());
    }

    #[test]
    fn stops_at_the_end_node_and_ignores_trailing_bytes() {
        let mut buf = testdata::file_path_node("\\EFI\\BOOT\\BOOTX64.EFI");
        buf.extend_from_slice(&testdata::end_node());
        buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // ne doit pas etre parse
        let path = DevicePath::parse(&buf).unwrap();
        assert_eq!(path.nodes.len(), 2);
        assert!(matches!(
            path.nodes[1],
            DevicePathNode::End { end_entire: true }
        ));
    }

    #[test]
    fn rejects_a_node_shorter_than_its_header() {
        // Longueur declaree = 3, inferieure a l'en-tete de 4 octets.
        let buf = [0x04u8, 0x04, 0x03, 0x00];
        let err = DevicePath::parse(&buf).unwrap_err();
        assert!(matches!(err, EfiParseError::NodeTooShort { .. }));
    }

    #[test]
    fn rejects_a_zero_length_node_instead_of_looping_forever() {
        let buf = [0x04u8, 0x04, 0x00, 0x00];
        assert!(matches!(
            DevicePath::parse(&buf).unwrap_err(),
            EfiParseError::NodeTooShort { .. }
        ));
    }

    #[test]
    fn rejects_a_node_claiming_more_bytes_than_available() {
        // Longueur declaree = 200, tampon de 4 octets.
        let buf = [0x04u8, 0x04, 0xC8, 0x00];
        assert!(matches!(
            DevicePath::parse(&buf).unwrap_err(),
            EfiParseError::NodeOverruns { .. }
        ));
    }

    #[test]
    fn unknown_nodes_are_preserved_not_rejected() {
        let buf = [0x01u8, 0x42, 0x06, 0x00, 0xAA, 0xBB];
        let path = DevicePath::parse(&buf).unwrap();
        assert_eq!(
            path.nodes[0],
            DevicePathNode::Other {
                node_type: 0x01,
                subtype: 0x42,
                data: vec![0xAA, 0xBB],
            }
        );
    }

    #[test]
    fn truncated_hard_drive_body_degrades_to_other_without_panicking() {
        // Type 4 / sous-type 1 mais corps de 2 octets au lieu de 38.
        let buf = [0x04u8, 0x01, 0x06, 0x00, 0x01, 0x00];
        let path = DevicePath::parse(&buf).unwrap();
        assert!(matches!(path.nodes[0], DevicePathNode::Other { .. }));
        assert!(path.hard_drive().is_none());
    }

    #[test]
    fn normalizes_efi_paths() {
        assert_eq!(normalize_efi_path("EFI/debian/grubx64.efi"), "\\EFI\\debian\\grubx64.efi");
        assert_eq!(normalize_efi_path("\\\\EFI\\\\BOOT\\\\"), "\\EFI\\BOOT");
        assert_eq!(normalize_efi_path("\\"), "\\");
        assert_eq!(normalize_efi_path(""), "\\");
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        // Balayage exhaustif de petits tampons : aucun ne doit paniquer.
        for a in 0u8..=255 {
            for b in [0u8, 1, 2, 4, 0x7F, 0xFF] {
                for len in [0u8, 1, 3, 4, 6, 42, 0xFF] {
                    let buf = [a, b, len, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
                    let _ = DevicePath::parse(&buf);
                }
            }
        }
    }
}
