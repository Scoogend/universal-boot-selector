//! Decodage des structures binaires UEFI.
//!
//! Ce module ne lit rien : il transforme des tampons d'octets deja obtenus par
//! ailleurs. Il ne contient aucun code `unsafe`, aucune E/S, et ne peut pas
//! paniquer sur des donnees malformees.

pub mod device_path;
pub mod guid;
pub mod load_option;
mod reader;

#[cfg(any(test, feature = "testdata"))]
pub mod testdata;

pub use device_path::{DevicePath, DevicePathNode, HardDrive, PartitionSignature, Transport};
pub use guid::Guid;
pub use load_option::{parse_boot_id, parse_boot_id_list, LoadOption};

use thiserror::Error;

/// Erreurs de decodage. Toutes sont recuperables : une entree illisible est
/// signalee puis ignoree, elle ne fait jamais echouer la detection entiere.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EfiParseError {
    #[error("fin de tampon prematuree a l'offset {offset} : {needed} octets requis, {available} disponibles")]
    UnexpectedEof {
        offset: usize,
        needed: usize,
        available: usize,
    },

    #[error("chaine UCS-2 non terminee a partir de l'offset {offset}")]
    UnterminatedString { offset: usize },

    #[error("noeud de chemin ({node_type:#04x}/{subtype:#04x}) a l'offset {offset} : longueur declaree {length}, inferieure a l'en-tete de 4 octets")]
    NodeTooShort {
        offset: usize,
        node_type: u8,
        subtype: u8,
        length: u16,
    },

    #[error("noeud de chemin ({node_type:#04x}/{subtype:#04x}) a l'offset {offset} : longueur declaree {length} au-dela du tampon")]
    NodeOverruns {
        offset: usize,
        node_type: u8,
        subtype: u8,
        length: u16,
    },

    #[error("chemin de peripherique de plus de {max} noeuds : donnees corrompues")]
    TooManyNodes { max: usize },

    #[error("FilePathList declare {declared} octets, {available} disponibles")]
    FilePathListOutOfRange { declared: usize, available: usize },

    #[error("liste d'identifiants de longueur impaire ({length} octets)")]
    OddLengthIdList { length: usize },

    #[error("valeur scalaire de {actual} octets, {expected} attendus")]
    BadScalarLength { expected: usize, actual: usize },
}
