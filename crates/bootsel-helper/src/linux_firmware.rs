//! Acces privilegie au firmware sous Linux. **Le seul module Linux qui ecrive.**
//!
//! # Disposition d'efivarfs
//!
//! Chaque variable est un fichier `<Nom>-<GUID>` dont le contenu est
//! `attributs(4 octets) || valeur`. Le noyau impose deux contraintes :
//!
//! - un fichier existant porte l'attribut **immuable**, qu'il faut retirer
//!   avant toute ecriture ;
//! - l'ecriture doit tenir en **un seul appel** `write`, sinon le noyau la
//!   rejette.
//!
//! # Ce qui peut etre ecrit, exhaustivement
//!
//! Deux variables, nommees par des constantes litterales :
//!
//! - `BootNext`, deux octets, le demarrage unique ;
//! - `BootOrder`, uniquement pour **reordonner** des entrees existantes.
//!
//! Il n'existe pas de fonction generique `write(nom, valeur)` : ecrire autre
//! chose demanderait d'ajouter du code, pas de passer une autre chaine.

use bootsel_core::backend::BackendError;
use bootsel_core::model::{
    BootId, FirmwareMode, FirmwareState, VAR_BOOT_CURRENT, VAR_BOOT_NEXT, VAR_BOOT_ORDER,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;

const EFI_GLOBAL_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// `NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS`.
const ATTRS: u32 = 0x0000_0007;

/// **Les deux seuls noms que ce module ecrit.** Constantes litterales.
const WRITABLE_BOOT_NEXT: &str = VAR_BOOT_NEXT;
const WRITABLE_BOOT_ORDER: &str = VAR_BOOT_ORDER;

const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
const FS_IMMUTABLE_FL: libc::c_int = 0x0000_0010;

fn path_of(name: &str) -> PathBuf {
    PathBuf::from(EFIVARS).join(format!("{name}-{EFI_GLOBAL_GUID}"))
}

pub fn firmware_mode() -> FirmwareMode {
    if std::path::Path::new("/sys/firmware/efi").is_dir() {
        FirmwareMode::Uefi
    } else {
        FirmwareMode::LegacyBios
    }
}

/// Lit une variable en retirant les quatre octets d'attributs.
fn read_variable(name: &str) -> Option<Vec<u8>> {
    let raw = std::fs::read(path_of(name)).ok()?;
    (raw.len() >= 4).then(|| raw[4..].to_vec())
}

/// Instantane complet des variables de demarrage. **Lecture seule.**
pub fn read_state() -> Result<FirmwareState, BackendError> {
    let dir = std::path::Path::new(EFIVARS);
    if !dir.is_dir() {
        return Err(BackendError::NotUefi);
    }

    let entries = std::fs::read_dir(dir)
        .map_err(|e| BackendError::Io(format!("lecture de {EFIVARS} : {e}")))?;

    let suffix = format!("-{EFI_GLOBAL_GUID}");
    let mut variables = BTreeMap::new();

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else { continue };
        let Some(name) = file_name.strip_suffix(&suffix) else { continue };

        let wanted = matches!(name, VAR_BOOT_ORDER | VAR_BOOT_NEXT | VAR_BOOT_CURRENT)
            || BootId::from_variable_name(name).is_some();
        if !wanted {
            continue;
        }
        if let Some(value) = read_variable(name) {
            variables.insert(name.to_string(), value);
        }
    }

    Ok(FirmwareState::new(variables))
}

/// Retire l'attribut immuable qu'efivarfs pose sur les fichiers existants.
///
/// Sans cela, toute ecriture echoue avec « operation non permise », y compris
/// en tant que root.
fn clear_immutable(file: &std::fs::File) -> Result<(), BackendError> {
    let fd = file.as_raw_fd();
    let mut flags: libc::c_int = 0;

    // SAFETY: `fd` est un descripteur valide et ouvert ; `flags` est une
    // variable locale de la taille attendue par l'ioctl.
    let read = unsafe { libc::ioctl(fd, FS_IOC_GETFLAGS, &mut flags) };
    if read < 0 {
        // Certains noyaux n'exposent pas ces ioctls sur efivarfs. L'ecriture
        // peut malgre tout reussir : on n'echoue pas ici.
        return Ok(());
    }

    if flags & FS_IMMUTABLE_FL == 0 {
        return Ok(());
    }
    flags &= !FS_IMMUTABLE_FL;

    // SAFETY: memes garanties que ci-dessus.
    let written = unsafe { libc::ioctl(fd, FS_IOC_SETFLAGS, &flags) };
    if written < 0 {
        return Err(BackendError::WriteRefused(
            "impossible de retirer l attribut immuable de la variable".into(),
        ));
    }
    Ok(())
}

/// Ecrit une variable. Le nom vient toujours d'une constante de ce module.
fn write_variable(name: &str, value: &[u8]) -> Result<(), BackendError> {
    debug_assert!(
        name == WRITABLE_BOOT_NEXT || name == WRITABLE_BOOT_ORDER,
        "seules BootNext et BootOrder sont ecrites"
    );

    let path = path_of(name);

    if path.exists() {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| BackendError::WriteRefused(format!("{} : {e}", path.display())))?;
        clear_immutable(&file)?;
    }

    // Attributs puis valeur, en **un seul** appel write : le noyau rejette
    // toute ecriture partielle.
    let mut payload = ATTRS.to_le_bytes().to_vec();
    payload.extend_from_slice(value);

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|e| BackendError::WriteRefused(format!("{} : {e}", path.display())))?;

    file.write_all(&payload)
        .map_err(|e| BackendError::WriteRefused(format!("ecriture de {name} : {e}")))?;

    Ok(())
}

/// Ecrit `BootNext` et verifie que rien d'autre n'a bouge.
pub fn write_boot_next(target: BootId) -> Result<FirmwareState, BackendError> {
    if !firmware_mode().supports_boot_next() {
        return Err(BackendError::NotUefi);
    }

    let before = read_state()?;
    if !before.contains_entry(target) {
        return Err(BackendError::EntryNotFound(target));
    }

    write_variable(WRITABLE_BOOT_NEXT, &target.to_le_bytes())?;

    let after = read_state()?;
    bootsel_core::guard::verify_only_boot_next_changed(&before, &after, target)?;
    Ok(after)
}

/// Place une entree en tete de l'ordre de demarrage permanent.
///
/// # Pourquoi cette operation est traitee a part
///
/// C'est la seule ecriture du projet qui soit **permanente**. Elle est donc
/// bornee au strict minimum : un **reordonnancement**. La nouvelle liste doit
/// contenir exactement les memes identifiants que l'ancienne, ni plus ni
/// moins. Aucune entree ne peut etre creee, supprimee, ni inventee.
///
/// [`bootsel_core::guard::verify_only_boot_order_reordered`] le verifie apres
/// coup sur le firmware relu, et l'operation echoue si ce n'est pas le cas.
pub fn write_default_system(target: BootId) -> Result<FirmwareState, BackendError> {
    if !firmware_mode().supports_boot_next() {
        return Err(BackendError::NotUefi);
    }

    let before = read_state()?;
    if !before.contains_entry(target) {
        return Err(BackendError::EntryNotFound(target));
    }

    let Some(order) = before.boot_order() else {
        return Err(BackendError::FirmwareUnavailable(
            "BootOrder est illisible : refus de le reecrire".into(),
        ));
    };
    if !order.contains(&target) {
        return Err(BackendError::NotSelectable(
            "cette entree n est pas dans l ordre de demarrage".into(),
        ));
    }

    // Reordonnancement pur : la cible passe en tete, les autres conservent
    // leur ordre relatif.
    let mut reordered = vec![target];
    reordered.extend(order.iter().copied().filter(|id| *id != target));

    let payload: Vec<u8> = reordered.iter().flat_map(|id| id.to_le_bytes()).collect();
    write_variable(WRITABLE_BOOT_ORDER, &payload)?;

    let after = read_state()?;
    bootsel_core::guard::verify_only_boot_order_reordered(&before, &after, target)?;
    Ok(after)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_two_variable_names_are_ever_writable() {
        assert_eq!(WRITABLE_BOOT_NEXT, "BootNext");
        assert_eq!(WRITABLE_BOOT_ORDER, "BootOrder");
    }

    #[test]
    fn the_namespace_guid_matches_the_specification() {
        assert_eq!(
            EFI_GLOBAL_GUID,
            bootsel_core::efi::Guid::EFI_GLOBAL_VARIABLE.to_hyphenated()
        );
    }

    #[test]
    fn the_path_stays_inside_efivars() {
        let p = path_of("BootNext");
        assert!(p.starts_with(EFIVARS));
        assert!(!p.to_string_lossy().contains(".."));
        assert_eq!(
            p.file_name().unwrap().to_str().unwrap(),
            "BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        );
    }

    #[test]
    fn the_attributes_are_the_three_uefi_boot_variables_need() {
        // NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
        assert_eq!(ATTRS, 0x07);
    }

    #[test]
    fn this_module_defines_no_generic_write() {
        // Garde-fou de revue : aucune fonction publique ne doit accepter un
        // nom de variable arbitraire.
        let source = include_str!("linux_firmware.rs").replace("\r\n", "\n");
        let end = source.find("\n#[cfg(test)]\nmod tests").unwrap_or(source.len());
        let shipped = &source[..end];
        assert!(!shipped.contains("pub fn write_variable"));
        assert!(!shipped.contains("pub fn write("));
    }
}
