//! Protocole entre l'interface non privilegiee et le helper privilegie.
//!
//! # Pourquoi un protocole aussi pauvre
//!
//! Le helper detient le privilege d'ecriture du firmware. Tout ce qu'il
//! accepte constitue la surface d'attaque du projet. Ce protocole est donc
//! reduit a **deux commandes** et un salut de version, sans aucun champ libre :
//! le seul parametre variable de toute l'interface est un identifiant de
//! quatre chiffres hexadecimaux.
//!
//! Il n'existe volontairement aucune commande permettant de nommer une
//! variable a ecrire, un chemin de fichier, un disque ou une commande systeme.
//! Meme un appelant hostile ne dispose d'aucun verbe pour exprimer une
//! operation destructrice.

use crate::model::BootId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version du protocole. Les deux cotes doivent presenter la meme valeur,
/// sinon la connexion est refusee : un helper d'une autre version pourrait
/// avoir des garanties differentes.
pub const PROTOCOL_VERSION: u32 = 1;

/// Requetes acceptees par le helper. **Liste exhaustive.**
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Salut initial, verification de version.
    Hello { protocol: u32 },
    /// Lecture de l'instantane complet des variables de demarrage.
    ReadState,
    /// Ecriture de `BootNext`. **Unique operation d'ecriture du projet.**
    ///
    /// `id` doit etre exactement quatre chiffres hexadecimaux. Toute autre
    /// forme est rejetee avant d'atteindre le firmware.
    SetBootNext { id: String },
}

/// Reponses du helper.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum Response {
    Hello {
        protocol: u32,
        helper_version: String,
        /// Vrai si le helper a effectivement obtenu le privilege firmware.
        elevated: bool,
    },
    /// Instantane des variables, valeurs en hexadecimal minuscule.
    State { variables: BTreeMap<String, String> },
    /// Ecriture effectuee et verifiee par le helper lui-meme.
    Written { id: String },
    Error { kind: ErrorKind, message: String },
}

/// Categories d'erreur transmissibles. Volontairement grossieres : le detail
/// va dans `message`, la categorie sert a decider quoi faire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Privilege firmware indisponible.
    PrivilegeRequired,
    /// Machine en BIOS herite.
    NotUefi,
    /// Requete mal formee ou identifiant invalide.
    BadRequest,
    /// L'entree visee n'existe pas dans le firmware.
    EntryNotFound,
    /// Le firmware a refuse l'ecriture.
    WriteRefused,
    /// Le garde-fou a detecte un changement interdit.
    GuardViolation,
    /// Defaillance interne du helper.
    Internal,
}

/// Valide un identifiant recu sur le fil.
///
/// C'est le point d'entree unique de toute donnee exterieure vers le firmware.
/// La validation est un `and` de trois conditions strictes : longueur exacte,
/// alphabet hexadecimal, conversion reussie. Rien d'autre ne passe.
pub fn parse_target_id(raw: &str) -> Option<BootId> {
    BootId::from_hex4(raw)
}

/// Encode des octets en hexadecimal minuscule.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        out.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    out
}

/// Decode une chaine hexadecimale. Refuse toute longueur impaire ou tout
/// caractere hors alphabet.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}

/// Convertit un instantane firmware en representation transmissible.
pub fn encode_state(state: &crate::model::FirmwareState) -> BTreeMap<String, String> {
    state
        .variables
        .iter()
        .map(|(k, v)| (k.clone(), to_hex(v)))
        .collect()
}

/// Reconstruit un instantane firmware depuis la representation transmise.
///
/// Une variable dont la valeur est illisible est **ignoree** plutot que de
/// faire echouer tout l'instantane : mieux vaut une entree manquante qu'une
/// detection impossible.
pub fn decode_state(variables: &BTreeMap<String, String>) -> crate::model::FirmwareState {
    crate::model::FirmwareState::new(
        variables
            .iter()
            .filter_map(|(k, v)| from_hex(v).map(|bytes| (k.clone(), bytes)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;
    use crate::model::{FirmwareState, VAR_BOOT_NEXT, VAR_BOOT_ORDER};

    #[test]
    fn hex_round_trips_arbitrary_bytes() {
        for case in [
            vec![],
            vec![0x00],
            vec![0xff],
            vec![0x01, 0x00, 0x02, 0x00],
            (0u8..=255).collect::<Vec<u8>>(),
        ] {
            let hex = to_hex(&case);
            assert_eq!(from_hex(&hex), Some(case.clone()), "aller-retour sur {hex}");
        }
    }

    #[test]
    fn hex_encoding_is_lowercase_and_zero_padded() {
        assert_eq!(to_hex(&[0x0a, 0xbc, 0x00]), "0abc00");
    }

    #[test]
    fn from_hex_rejects_malformed_input() {
        for bad in ["a", "abc", "zz", "0x02", " 02", "02 ", "--"] {
            assert_eq!(from_hex(bad), None, "aurait du rejeter : {bad:?}");
        }
    }

    #[test]
    fn a_firmware_snapshot_survives_the_round_trip_unchanged() {
        let mut vars = BTreeMap::new();
        vars.insert(VAR_BOOT_ORDER.into(), testdata::boot_order(&[1, 2, 3]));
        vars.insert("Boot0001".into(), testdata::load_option_windows());
        vars.insert("Boot0002".into(), testdata::load_option_debian());
        let original = FirmwareState::new(vars);

        let restored = decode_state(&encode_state(&original));

        // Egalite octet pour octet : le garde-fou compare des octets bruts,
        // le transport ne doit donc rien alterer.
        assert_eq!(original, restored);
    }

    #[test]
    fn an_unreadable_variable_is_dropped_rather_than_failing_the_snapshot() {
        let mut wire = BTreeMap::new();
        wire.insert(VAR_BOOT_ORDER.into(), "01000200".to_string());
        wire.insert("Boot0001".into(), "pas du hex".to_string());

        let state = decode_state(&wire);
        assert!(state.get(VAR_BOOT_ORDER).is_some());
        assert!(state.get("Boot0001").is_none());
    }

    #[test]
    fn the_only_variable_parameter_is_a_four_digit_identifier() {
        assert_eq!(parse_target_id("0002"), Some(BootId(2)));
        assert_eq!(parse_target_id("ffff"), Some(BootId(0xFFFF)));

        for hostile in [
            "",
            "0",
            "00002",
            "BootOrder",
            "Boot0002",
            "0002; shutdown",
            "0002\n0003",
            "../../../etc/passwd",
            "$(rm -rf /)",
            "0002 && format C:",
            "\u{0}002",
            "0x02",
        ] {
            assert_eq!(
                parse_target_id(hostile),
                None,
                "aurait du rejeter : {hostile:?}"
            );
        }
    }

    #[test]
    fn requests_round_trip_through_json() {
        for req in [
            Request::Hello {
                protocol: PROTOCOL_VERSION,
            },
            Request::ReadState,
            Request::SetBootNext { id: "0002".into() },
        ] {
            let json = serde_json::to_string(&req).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&json).unwrap(), req);
            // Une requete doit tenir sur une seule ligne : le transport est
            // decoupe par retours a la ligne.
            assert!(!json.contains('\n'));
        }
    }

    #[test]
    fn responses_round_trip_through_json() {
        let responses = vec![
            Response::Hello {
                protocol: PROTOCOL_VERSION,
                helper_version: "0.1.0".into(),
                elevated: true,
            },
            Response::State {
                variables: BTreeMap::from([(VAR_BOOT_NEXT.to_string(), "0200".to_string())]),
            },
            Response::Written { id: "0002".into() },
            Response::Error {
                kind: ErrorKind::GuardViolation,
                message: "BootOrder modifie".into(),
            },
        ];
        for r in responses {
            let json = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Response>(&json).unwrap(), r);
            assert!(!json.contains('\n'));
        }
    }

    #[test]
    fn unknown_commands_are_rejected_by_deserialisation() {
        for hostile in [
            r#"{"cmd":"delete_partition"}"#,
            r#"{"cmd":"set_boot_order","ids":[2,1]}"#,
            r#"{"cmd":"write_variable","name":"BootOrder","value":"0200"}"#,
            r#"{"cmd":"exec","command":"format C:"}"#,
            r#"{"cmd":"read_state","extra":"ignored"}"#,
            r#"not json at all"#,
            r#"{}"#,
        ] {
            let parsed = serde_json::from_str::<Request>(hostile);
            if hostile.contains("read_state") {
                // serde ignore les champs surnumeraires : la commande reste
                // read_state, qui ne peut rien ecrire.
                assert_eq!(parsed.unwrap(), Request::ReadState);
            } else {
                assert!(parsed.is_err(), "aurait du etre rejete : {hostile}");
            }
        }
    }

    #[test]
    fn the_protocol_offers_no_verb_that_could_destroy_anything() {
        // Garde-fou de revue : la liste des commandes est figee. Ajouter un
        // verbe capable de nommer une variable, un fichier ou un disque
        // reviendrait a elargir la surface privilegiee du projet.
        let vocabulary = [
            serde_json::to_string(&Request::Hello { protocol: 1 }).unwrap(),
            serde_json::to_string(&Request::ReadState).unwrap(),
            serde_json::to_string(&Request::SetBootNext { id: "0002".into() }).unwrap(),
        ]
        .join(" ");

        for forbidden in [
            "boot_order", "variable", "path", "file", "disk", "partition", "exec", "command",
            "delete", "format", "write_",
        ] {
            assert!(
                !vocabulary.contains(forbidden),
                "le protocole expose le terme interdit : {forbidden}"
            );
        }
    }
}
