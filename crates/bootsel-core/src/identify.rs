//! Identification heuristique du systeme et du chargeur derriere une entree.
//!
//! Tout est deduit de donnees deja lues : le chemin EFI et la description
//! ecrite par le firmware. Aucune partition n'est montee, aucun fichier n'est
//! ouvert. La consequence est que l'identification reste une **hypothese**,
//! restituee avec un niveau de confiance plutot qu'affirmee.

use crate::efi::{LoadOption, Transport};
use crate::model::{BootloaderKind, Confidence, OsKind};

/// Resultat de l'identification d'une entree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identification {
    pub os: OsKind,
    pub bootloader: BootloaderKind,
    /// Nom propose a l'affichage, avant application d'un eventuel alias.
    pub name: String,
    pub confidence: Confidence,
}

/// Identifie une entree a partir de son chemin EFI et de sa description.
pub fn identify(option: &LoadOption) -> Identification {
    let path = option.efi_path().unwrap_or_default().to_ascii_lowercase();
    let desc = option.description.trim();
    let desc_lower = desc.to_ascii_lowercase();
    let transport = option.transport();

    // Les entrees internes au firmware sont reconnues par leur chemin, pas par
    // leur libelle : elles n'ont pas de fichier EFI sur une partition.
    if option.is_firmware_internal() {
        return Identification {
            os: OsKind::FirmwareUtility,
            bootloader: BootloaderKind::Unknown,
            name: if desc.is_empty() {
                "Utilitaire firmware".to_string()
            } else {
                desc.to_string()
            },
            confidence: Confidence::Confirmed,
        };
    }

    let bootloader = identify_bootloader(&path, &desc_lower);
    let (os, os_confidence) = identify_os(&path, &desc_lower, transport);

    // Le chemin EFI est une preuve bien plus forte que la description, que
    // certains firmwares reecrivent librement.
    let confidence = if path.is_empty() {
        Confidence::Probable
    } else {
        os_confidence
    };

    let name = build_name(os, desc, transport);

    Identification {
        os,
        bootloader,
        name,
        confidence,
    }
}

fn identify_bootloader(path: &str, desc_lower: &str) -> BootloaderKind {
    if path.contains("bootmgfw.efi") || path.contains("\\microsoft\\boot") {
        return BootloaderKind::WindowsBootManager;
    }
    if path.contains("shim") {
        // shim precede systematiquement GRUB sur les distributions Secure Boot.
        return BootloaderKind::Shim;
    }
    if path.contains("grub") {
        return BootloaderKind::Grub;
    }
    if path.contains("systemd-boot") || path.contains("\\systemd\\") {
        return BootloaderKind::SystemdBoot;
    }
    if path.contains("refind") {
        return BootloaderKind::Refind;
    }
    if is_removable_fallback(path) {
        return BootloaderKind::RemovableFallback;
    }
    // Repli sur la description, moins fiable.
    if desc_lower.contains("windows boot manager") {
        return BootloaderKind::WindowsBootManager;
    }
    if desc_lower.contains("grub") {
        return BootloaderKind::Grub;
    }
    BootloaderKind::Unknown
}

fn identify_os(path: &str, desc_lower: &str, transport: Transport) -> (OsKind, Confidence) {
    // 1. Le repertoire du chargeur sur l'ESP est l'indice le plus fiable :
    //    c'est l'installateur de la distribution qui le nomme.
    let by_dir = [
        ("\\microsoft\\", OsKind::Windows),
        ("\\debian\\", OsKind::Debian),
        ("\\ubuntu\\", OsKind::Ubuntu),
        ("\\linuxmint\\", OsKind::LinuxMint),
        ("\\pop\\", OsKind::PopOs),
        ("\\fedora\\", OsKind::Fedora),
        ("\\arch\\", OsKind::Arch),
    ];
    for (needle, os) in by_dir {
        if path.contains(needle) {
            return (os, Confidence::Confirmed);
        }
    }

    // 2. Le chargeur amovible standard ne dit rien du systeme qu'il demarre.
    if is_removable_fallback(path) {
        let os = if transport == Transport::Usb {
            OsKind::RemovableMedia
        } else {
            OsKind::Unknown
        };
        return (os, Confidence::Probable);
    }

    // 3. Repli sur la description, que le firmware peut avoir reecrite.
    let by_desc = [
        ("windows", OsKind::Windows),
        ("debian", OsKind::Debian),
        ("ubuntu", OsKind::Ubuntu),
        ("mint", OsKind::LinuxMint),
        ("pop!_os", OsKind::PopOs),
        ("pop_os", OsKind::PopOs),
        ("fedora", OsKind::Fedora),
        ("arch", OsKind::Arch),
        ("linux", OsKind::LinuxGeneric),
    ];
    for (needle, os) in by_desc {
        if desc_lower.contains(needle) {
            return (os, Confidence::Probable);
        }
    }

    // 4. Un chargeur Linux connu sans distribution identifiee.
    if path.contains("grub") || path.contains("vmlinuz") || path.contains("systemd-boot") {
        return (OsKind::LinuxGeneric, Confidence::Probable);
    }

    (OsKind::Unknown, Confidence::Probable)
}

/// Reconnait le chemin de repli normalise des supports amovibles, pour toutes
/// les architectures definies par la specification UEFI.
fn is_removable_fallback(path: &str) -> bool {
    const FALLBACKS: [&str; 4] = [
        "\\efi\\boot\\bootx64.efi",
        "\\efi\\boot\\bootia32.efi",
        "\\efi\\boot\\bootaa64.efi",
        "\\efi\\boot\\bootarm.efi",
    ];
    FALLBACKS.iter().any(|f| path == *f)
}

/// Construit le nom affiche par defaut.
///
/// On prefere la description du firmware quand elle est parlante — elle
/// contient souvent la marque de la cle USB — et on retombe sur le libelle du
/// systeme sinon.
fn build_name(os: OsKind, desc: &str, transport: Transport) -> String {
    let cleaned = clean_description(desc);

    if cleaned.is_empty() {
        return match (os, transport) {
            (OsKind::Unknown, Transport::Usb) => "Peripherique USB".to_string(),
            (OsKind::Unknown, _) => "Entree de demarrage".to_string(),
            (os, _) => os.label().to_string(),
        };
    }

    // Une description generique n'apporte rien de plus que le libelle du systeme.
    let generic = [
        "boot",
        "os",
        "uefi os",
        "efi",
        "hard drive",
        "hdd",
        "os boot manager",
    ];
    if generic.contains(&cleaned.to_ascii_lowercase().as_str()) && os != OsKind::Unknown {
        return os.label().to_string();
    }

    cleaned
}

/// Retire les prefixes decoratifs ajoutes par les firmwares.
///
/// Un prefixe nu n'est retire que s'il est suivi d'une espace : « UEFI OS »
/// donne « OS », mais « UEFIRuntime Tool » reste intact. Amputer un nom propre
/// serait pire que de laisser une decoration.
fn clean_description(desc: &str) -> String {
    let s = desc.trim();

    for prefix in ["UEFI:", "UEFI :", "Legacy:", "Legacy :"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.trim().to_string();
        }
    }
    for prefix in ["UEFI ", "Legacy "] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.trim().to_string();
        }
    }

    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;

    fn identify_raw(raw: Vec<u8>) -> Identification {
        identify(&LoadOption::parse(&raw).expect("fixture valide"))
    }

    fn identify_path(path: &str, desc: &str) -> Identification {
        let mut dp = testdata::hard_drive_node(2, testdata::ESP_PART_GUID);
        dp.extend_from_slice(&testdata::file_path_node(path));
        dp.extend_from_slice(&testdata::end_node());
        identify_raw(testdata::load_option(1, desc, &dp, &[]))
    }

    #[test]
    fn identifies_windows_boot_manager() {
        let id = identify_raw(testdata::load_option_windows());
        assert_eq!(id.os, OsKind::Windows);
        assert_eq!(id.bootloader, BootloaderKind::WindowsBootManager);
        assert_eq!(id.confidence, Confidence::Confirmed);
        assert_eq!(id.name, "Windows Boot Manager");
    }

    #[test]
    fn identifies_debian_behind_shim() {
        let id = identify_raw(testdata::load_option_debian());
        assert_eq!(id.os, OsKind::Debian);
        assert_eq!(id.bootloader, BootloaderKind::Shim);
        assert_eq!(id.confidence, Confidence::Confirmed);
        assert_eq!(id.name, "debian");
    }

    #[test]
    fn identifies_ubuntu() {
        let id = identify_raw(testdata::load_option_ubuntu());
        assert_eq!(id.os, OsKind::Ubuntu);
        assert_eq!(id.confidence, Confidence::Confirmed);
    }

    #[test]
    fn identifies_grub_without_shim() {
        let id = identify_path("\\EFI\\debian\\grubx64.efi", "debian");
        assert_eq!(id.os, OsKind::Debian);
        assert_eq!(id.bootloader, BootloaderKind::Grub);
    }

    #[test]
    fn identifies_systemd_boot() {
        let id = identify_path("\\EFI\\systemd\\systemd-bootx64.efi", "Linux Boot Manager");
        assert_eq!(id.bootloader, BootloaderKind::SystemdBoot);
        assert!(id.os.is_linux());
    }

    #[test]
    fn identifies_other_debian_derivatives() {
        assert_eq!(
            identify_path("\\EFI\\linuxmint\\grubx64.efi", "mint").os,
            OsKind::LinuxMint
        );
        assert_eq!(
            identify_path("\\EFI\\pop\\grubx64.efi", "Pop!_OS").os,
            OsKind::PopOs
        );
        assert_eq!(
            identify_path("\\EFI\\fedora\\shimx64.efi", "Fedora").os,
            OsKind::Fedora
        );
    }

    #[test]
    fn a_usb_fallback_loader_is_never_claimed_as_a_known_distribution() {
        // `\EFI\BOOT\BOOTX64.EFI` ne dit rien du systeme qu'il demarre :
        // pretendre le contraire serait exactement le genre de supposition
        // que le projet s'interdit.
        let id = identify_raw(testdata::load_option_usb());
        assert_eq!(id.os, OsKind::RemovableMedia);
        assert_eq!(id.bootloader, BootloaderKind::RemovableFallback);
        assert_eq!(id.confidence, Confidence::Probable);
    }

    #[test]
    fn strips_firmware_decorations_from_the_displayed_name() {
        let id = identify_raw(testdata::load_option_usb());
        assert_eq!(id.name, "ACME UK64");
    }

    #[test]
    fn identifies_firmware_internal_entries() {
        let id = identify_raw(testdata::load_option_firmware_setup());
        assert_eq!(id.os, OsKind::FirmwareUtility);
        assert_eq!(id.name, "Enter Setup");
    }

    #[test]
    fn a_generic_description_yields_the_os_label() {
        let id = identify_path("\\EFI\\debian\\shimx64.efi", "UEFI OS");
        assert_eq!(id.os, OsKind::Debian);
        assert_eq!(id.name, "Debian");
    }

    #[test]
    fn an_unknown_loader_stays_unknown_rather_than_guessing() {
        let id = identify_path("\\EFI\\vendorx\\mystery.efi", "");
        assert_eq!(id.os, OsKind::Unknown);
        assert_eq!(id.bootloader, BootloaderKind::Unknown);
        assert_eq!(id.confidence, Confidence::Probable);
        assert_eq!(id.name, "Entree de demarrage");
    }

    #[test]
    fn path_evidence_beats_a_misleading_description() {
        // Le chemin dit Debian, la description dit Windows : le chemin gagne.
        let id = identify_path("\\EFI\\debian\\shimx64.efi", "Windows Boot Manager");
        assert_eq!(id.os, OsKind::Debian);
        assert_eq!(id.confidence, Confidence::Confirmed);
    }

    #[test]
    fn recognises_every_architecture_fallback_path() {
        for p in [
            "\\EFI\\BOOT\\BOOTX64.EFI",
            "\\EFI\\BOOT\\BOOTIA32.EFI",
            "\\EFI\\BOOT\\BOOTAA64.EFI",
        ] {
            let id = identify_path(p, "");
            assert_eq!(
                id.bootloader,
                BootloaderKind::RemovableFallback,
                "chemin non reconnu : {p}"
            );
        }
    }

    #[test]
    fn cleans_descriptions_without_mangling_them() {
        assert_eq!(clean_description("UEFI: ACME"), "ACME");
        assert_eq!(clean_description("UEFI : ACME"), "ACME");
        assert_eq!(clean_description("  debian  "), "debian");
        assert_eq!(clean_description("Windows Boot Manager"), "Windows Boot Manager");
        assert_eq!(clean_description("UEFI OS"), "OS");
        // Ne doit pas amputer un nom qui commence par les memes lettres.
        assert_eq!(clean_description("UEFIRuntime Tool"), "UEFIRuntime Tool");
    }

    #[test]
    fn never_panics_on_odd_descriptions() {
        for desc in ["", " ", "UEFI:", "\u{FFFD}", "🙂", &"x".repeat(500)] {
            let _ = identify_path("\\EFI\\debian\\shimx64.efi", desc);
        }
    }
}
