//! # bootsel-core
//!
//! Coeur d'Universal Boot Selector : modele de donnees, decodage des
//! structures UEFI, identification des systemes, et **invariants de
//! non-destruction**.
//!
//! ## Ce que ce crate ne fait pas
//!
//! Il n'ouvre aucun fichier, ne lance aucun processus, n'appelle aucune API
//! systeme et ne contient aucun code `unsafe`. Il transforme des donnees
//! fournies par un [`backend::BootBackend`] et n'a aucun moyen d'agir sur la
//! machine par lui-meme.
//!
//! C'est la premiere des quatre barrieres decrites dans `SECURITY.md` : meme
//! en cas de bug, rien ici ne peut ecrire sur un disque, modifier une
//! partition ou toucher au firmware.
//!
//! ## Organisation
//!
//! - [`efi`] — decodage binaire des structures UEFI (`EFI_LOAD_OPTION`,
//!   chemins de peripheriques, GUID).
//! - [`model`] — types partages, dont [`model::FirmwareState`], l'instantane
//!   sur lequel repose la verification de non-destruction.
//! - [`identify`] — heuristiques d'identification des systemes et chargeurs.
//! - [`identity`] — derivation de la cle stable servant aux alias.
//! - [`alias`] — configuration locale : alias et preferences d'affichage.
//! - [`detect`] — assemblage de la liste affichable. Lecture seule.
//! - [`select`] — sequence de selection, avec revalidation avant ecriture.
//! - [`guard`] — verification que seule `BootNext` a change.
//! - [`backend`] — abstraction du firmware.
//! - [`mock`] — firmware simule (tests et developpement).
//!
//! ## Regle centrale
//!
//! `BootNext` est la seule variable que l'application ecrit. `BootOrder`,
//! l'ordre de demarrage permanent, n'est jamais modifie : aucun chemin de
//! code de ce crate ne produit d'ecriture, et [`guard`] verifie apres coup que
//! l'implementation reelle a respecte ce contrat.

#![forbid(unsafe_code)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![warn(missing_debug_implementations)]

pub mod alias;
pub mod backend;
pub mod detect;
pub mod efi;
pub mod guard;
pub mod identify;
pub mod identity;
pub mod model;
pub mod select;

#[cfg(any(test, feature = "testdata"))]
pub mod mock;

pub use alias::Config;
pub use backend::{BackendError, BootBackend};
pub use detect::{detect, Detection};
pub use guard::{GuardError, VarChange};
pub use model::{
    Availability, BootEntry, BootId, BootloaderKind, BusType, Confidence, FirmwareMode,
    FirmwareState, OsKind, PartitionInfo, StorageDevice, VAR_BOOT_CURRENT, VAR_BOOT_NEXT,
    VAR_BOOT_ORDER,
};
pub use select::{commit_selection, reboot_after, SelectionOutcome, SelectionPlan};

/// Nom de l'application, utilise pour les repertoires de configuration.
pub const APP_NAME: &str = "bootsel";

/// Version du crate, reprise du manifeste.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
