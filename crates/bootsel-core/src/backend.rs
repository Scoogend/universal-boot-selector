//! Abstraction du firmware.
//!
//! Toute la logique metier ne parle qu'a ce trait, jamais directement au
//! systeme. Cela permet trois choses : tester l'integralite du comportement
//! sans toucher au firmware reel, garder les implementations Windows et Linux
//! interchangeables, et confiner l'unique operation d'ecriture derriere une
//! seule methode dont chaque implementation est auditee separement.

use crate::guard::GuardError;
use crate::model::{BootId, FirmwareMode, FirmwareState, StorageDevice};
use thiserror::Error;

/// Erreurs remontees par un backend.
///
/// Aucune variante ne declenche de tentative de contournement : en cas
/// d'echec, l'application affiche le message et s'arrete la.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum BackendError {
    #[error(
        "ce systeme demarre en mode BIOS herite. La selection securisee du \
         prochain demarrage via UEFI n'est pas disponible."
    )]
    NotUefi,

    #[error(
        "l'acces aux variables de demarrage du firmware demande des privileges \
         administrateur. Aucune modification n'a ete effectuee."
    )]
    PrivilegeRequired,

    #[error("le firmware n'est pas accessible : {0}")]
    FirmwareUnavailable(String),

    #[error("la variable {0} est introuvable dans le firmware")]
    VariableNotFound(String),

    #[error("l'entree {0} n'existe plus dans le firmware")]
    EntryNotFound(BootId),

    #[error("aucune entree de demarrage ne correspond a la selection : elle a disparu depuis l'affichage")]
    TargetVanished,

    #[error("le peripherique de cette entree n'est plus connecte")]
    DeviceMissing,

    #[error("cette entree ne peut pas etre choisie comme cible de demarrage : {0}")]
    NotSelectable(String),

    #[error("le firmware a refuse l'ecriture : {0}")]
    WriteRefused(String),

    #[error("l'application fonctionne en mode lecture seule : aucune ecriture n'est autorisee")]
    ReadOnlyMode,

    #[error(transparent)]
    Guard(#[from] GuardError),

    #[error("erreur d'entree-sortie : {0}")]
    Io(String),

    #[error("operation non prise en charge sur cette plateforme : {0}")]
    Unsupported(String),
}

impl BackendError {
    /// Vrai si l'erreur garantit qu'aucune ecriture n'a eu lieu.
    ///
    /// Sert a formuler le message d'erreur : on ne promet « aucune
    /// modification n'a ete effectuee » que lorsque c'est certain.
    pub fn guarantees_no_write(&self) -> bool {
        match self {
            BackendError::NotUefi
            | BackendError::PrivilegeRequired
            | BackendError::FirmwareUnavailable(_)
            | BackendError::VariableNotFound(_)
            | BackendError::EntryNotFound(_)
            | BackendError::TargetVanished
            | BackendError::DeviceMissing
            | BackendError::NotSelectable(_)
            | BackendError::ReadOnlyMode
            | BackendError::Unsupported(_) => true,

            // Une ecriture refusee ou un invariant viole laissent planer un
            // doute : on ne l'affirme pas.
            BackendError::WriteRefused(_)
            | BackendError::Guard(_)
            | BackendError::Io(_) => false,
        }
    }
}

/// Acces au firmware. Une seule methode ecrit : [`BootBackend::set_boot_next`].
///
/// `Debug` est requis pour que les journaux puissent nommer le backend actif
/// sans supposition, y compris derriere un `Box<dyn BootBackend>`.
pub trait BootBackend: Send + Sync + std::fmt::Debug {
    /// Mode de demarrage de la machine. Lecture seule, non privilegiee.
    fn firmware_mode(&self) -> Result<FirmwareMode, BackendError>;

    /// Instantane complet des variables de demarrage. **Lecture seule.**
    fn read_state(&self) -> Result<FirmwareState, BackendError>;

    /// Inventaire des disques et partitions. **Lecture seule, non privilegiee.**
    fn list_devices(&self) -> Result<Vec<StorageDevice>, BackendError>;

    /// Ecrit `BootNext`. **Unique operation d'ecriture de toute l'application.**
    ///
    /// Le contrat impose a chaque implementation :
    /// - n'ecrire que la variable `BootNext`, jamais `BootOrder` ni `Boot####` ;
    /// - ecrire exactement deux octets, l'identifiant en little-endian ;
    /// - ne jamais creer, supprimer ni reordonner d'entree.
    ///
    /// La verification de ce contrat n'est pas laissee a la bonne foi de
    /// l'implementation : [`crate::select::commit_selection`] relit le
    /// firmware et applique [`crate::guard`] apres l'appel.
    fn set_boot_next(&self, target: BootId) -> Result<(), BackendError>;

    /// Place une entree en tete de l'ordre de demarrage permanent.
    ///
    /// **Seule ecriture permanente du projet**, et la seule qui touche
    /// `BootOrder`. Elle est bornee a un reordonnancement : aucune entree ne
    /// peut etre creee ni supprimee. Le contrat est verifie apres coup par
    /// [`crate::guard::verify_only_boot_order_reordered`].
    ///
    /// Par defaut, un backend la refuse : il faut l'implementer explicitement.
    fn set_default_system(&self, _target: BootId) -> Result<(), BackendError> {
        Err(BackendError::Unsupported(
            "ce backend ne sait pas changer le systeme par defaut".to_string(),
        ))
    }

    /// Redemarre la machine. Appele uniquement apres validation du garde-fou.
    fn reboot(&self) -> Result<(), BackendError>;

    /// Vrai si ce backend refuse toute ecriture (mode `--dry-run`, mock en
    /// lecture seule). L'interface s'en sert pour desactiver l'action.
    fn is_read_only(&self) -> bool {
        false
    }

    /// Nom du backend, pour les journaux et l'affichage de diagnostic.
    fn name(&self) -> &'static str;
}
