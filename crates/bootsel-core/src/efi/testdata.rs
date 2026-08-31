//! Constructeurs de donnees UEFI binaires realistes, pour les tests.
//!
//! Ces fonctions reproduisent octet pour octet la disposition decrite par la
//! specification UEFI. Elles servent a tester le parsing sans jamais lire le
//! firmware reel de la machine.

use super::guid::Guid;
use super::load_option::LOAD_OPTION_ACTIVE;

/// GUID unique de la partition ESP utilisee par les fixtures.
pub const ESP_PART_GUID: &str = "1f8a4d3c-9b2e-4a71-8c05-6e3d7f210b44";
/// GUID unique d'une seconde partition ESP (deuxieme disque).
pub const ESP2_PART_GUID: &str = "77c1e2b0-3a54-4d98-9f16-2b8ea450c7d1";
/// GUID unique de la partition d'une cle USB.
pub const USB_PART_GUID: &str = "0a5b9d44-1e6c-4f30-b287-5c94ad3e10f6";

fn ucs2(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn ucs2_nul(s: &str) -> Vec<u8> {
    let mut out = ucs2(s);
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn node(node_type: u8, subtype: u8, body: &[u8]) -> Vec<u8> {
    let length = (body.len() + 4) as u16;
    let mut out = Vec::with_capacity(length as usize);
    out.push(node_type);
    out.push(subtype);
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Noeud « Hard Drive Media Device Path » (type 4 / sous-type 1), 42 octets.
pub fn hard_drive_node(partition_number: u32, partition_guid: &str) -> Vec<u8> {
    let guid = Guid::parse(partition_guid).expect("GUID de fixture valide");
    let mut body = Vec::with_capacity(38);
    body.extend_from_slice(&partition_number.to_le_bytes());
    body.extend_from_slice(&2048u64.to_le_bytes()); // PartitionStart (LBA)
    body.extend_from_slice(&204_800u64.to_le_bytes()); // PartitionSize (100 Mio)
    body.extend_from_slice(guid.as_bytes());
    body.push(0x02); // MBRType = GPT
    body.push(0x02); // SignatureType = GUID
    node(0x04, 0x01, &body)
}

/// Noeud « File Path » (type 4 / sous-type 4).
pub fn file_path_node(path: &str) -> Vec<u8> {
    node(0x04, 0x04, &ucs2_nul(path))
}

/// Noeud USB (type 3 / sous-type 5).
pub fn usb_node(parent_port: u8, interface: u8) -> Vec<u8> {
    node(0x03, 0x05, &[parent_port, interface])
}

/// Noeud NVMe (type 3 / sous-type 23).
pub fn nvme_node(namespace_id: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&namespace_id.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes()); // NamespaceUuid
    node(0x03, 0x17, &body)
}

/// Noeud SATA (type 3 / sous-type 18).
pub fn sata_node(hba_port: u16) -> Vec<u8> {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&hba_port.to_le_bytes());
    body.extend_from_slice(&0xFFFFu16.to_le_bytes()); // pas de multiplicateur de port
    body.extend_from_slice(&0u16.to_le_bytes());
    node(0x03, 0x12, &body)
}

/// Noeud « PIWG Firmware File » (type 4 / sous-type 6) : entree interne au firmware.
pub fn firmware_file_node(guid: &str) -> Vec<u8> {
    let g = Guid::parse(guid).expect("GUID de fixture valide");
    node(0x04, 0x06, g.as_bytes())
}

/// Noeud de fin de chemin (type 0x7F / sous-type 0xFF).
pub fn end_node() -> Vec<u8> {
    node(0x7F, 0xFF, &[])
}

/// Chemin complet vers le gestionnaire de demarrage Windows sur NVMe.
pub fn windows_device_path() -> Vec<u8> {
    let mut buf = hard_drive_node(2, ESP_PART_GUID);
    buf.extend_from_slice(&file_path_node("\\EFI\\Microsoft\\Boot\\bootmgfw.efi"));
    buf.extend_from_slice(&end_node());
    buf
}

/// Chemin complet vers le shim Debian sur le meme disque.
pub fn debian_device_path() -> Vec<u8> {
    let mut buf = hard_drive_node(2, ESP_PART_GUID);
    buf.extend_from_slice(&file_path_node("\\EFI\\debian\\shimx64.efi"));
    buf.extend_from_slice(&end_node());
    buf
}

/// Chemin complet vers GRUB Ubuntu sur un second disque.
pub fn ubuntu_device_path() -> Vec<u8> {
    let mut buf = sata_node(1);
    buf.extend_from_slice(&hard_drive_node(1, ESP2_PART_GUID));
    buf.extend_from_slice(&file_path_node("\\EFI\\ubuntu\\shimx64.efi"));
    buf.extend_from_slice(&end_node());
    buf
}

/// Chemin complet vers le chargeur amovible d'une cle USB.
pub fn usb_device_path() -> Vec<u8> {
    let mut buf = usb_node(3, 0);
    buf.extend_from_slice(&hard_drive_node(1, USB_PART_GUID));
    buf.extend_from_slice(&file_path_node("\\EFI\\BOOT\\BOOTX64.EFI"));
    buf.extend_from_slice(&end_node());
    buf
}

/// Chemin d'une entree interne au firmware (« Enter Setup »).
pub fn firmware_internal_path() -> Vec<u8> {
    let mut buf = firmware_file_node("721c8b66-426c-4e86-8e99-3457c46ab0b9");
    buf.extend_from_slice(&end_node());
    buf
}

/// Assemble un `EFI_LOAD_OPTION` complet.
pub fn load_option(attributes: u32, description: &str, device_path: &[u8], optional: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&attributes.to_le_bytes());
    out.extend_from_slice(&(device_path.len() as u16).to_le_bytes());
    out.extend_from_slice(&ucs2_nul(description));
    out.extend_from_slice(device_path);
    out.extend_from_slice(optional);
    out
}

pub fn load_option_windows() -> Vec<u8> {
    load_option(
        LOAD_OPTION_ACTIVE,
        "Windows Boot Manager",
        &windows_device_path(),
        &[],
    )
}

pub fn load_option_debian() -> Vec<u8> {
    load_option(LOAD_OPTION_ACTIVE, "debian", &debian_device_path(), &[])
}

pub fn load_option_ubuntu() -> Vec<u8> {
    load_option(LOAD_OPTION_ACTIVE, "ubuntu", &ubuntu_device_path(), &[])
}

pub fn load_option_usb() -> Vec<u8> {
    load_option(
        LOAD_OPTION_ACTIVE,
        "UEFI: ACME UK64",
        &usb_device_path(),
        &[],
    )
}

pub fn load_option_inactive() -> Vec<u8> {
    load_option(0, "Entree desactivee", &debian_device_path(), &[])
}

pub fn load_option_firmware_setup() -> Vec<u8> {
    load_option(
        LOAD_OPTION_ACTIVE,
        "Enter Setup",
        &firmware_internal_path(),
        &[],
    )
}

pub fn load_option_with_optional_data(optional: &[u8]) -> Vec<u8> {
    load_option(
        LOAD_OPTION_ACTIVE,
        "debian",
        &debian_device_path(),
        optional,
    )
}

/// Entree pointant une partition qui n'existe plus sur aucun disque.
pub fn load_option_orphan() -> Vec<u8> {
    let mut path = hard_drive_node(9, "deadbeef-0000-4000-8000-000000000001");
    path.extend_from_slice(&file_path_node("\\EFI\\fedora\\shimx64.efi"));
    path.extend_from_slice(&end_node());
    load_option(LOAD_OPTION_ACTIVE, "Fedora", &path, &[])
}

/// Serialise une liste d'identifiants comme le fait `BootOrder`.
pub fn boot_order(ids: &[u16]) -> Vec<u8> {
    ids.iter().flat_map(|id| id.to_le_bytes()).collect()
}

/// Serialise un identifiant unique comme le fait `BootNext`.
pub fn boot_id(id: u16) -> Vec<u8> {
    id.to_le_bytes().to_vec()
}
