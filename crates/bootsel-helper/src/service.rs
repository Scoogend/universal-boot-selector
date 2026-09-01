//! Boucle de service : lit des requetes, repond, recommence.
//!
//! # Regle de traitement
//!
//! Chaque requete est traitee de maniere autonome. Le helper ne conserve aucun
//! etat entre deux requetes : pas de cible « selectionnee » memorisee, pas
//! d'instantane mis en cache. Une ecriture relit donc toujours le firmware
//! juste avant d'agir, ce qui rend impossible d'operer sur des informations
//! perimees.
//!
//! Toute requete non reconnue est refusee sans effet. Il n'existe aucun chemin
//! par lequel une entree malformee atteindrait le firmware.

#[cfg(windows)]
use crate::firmware;
#[cfg(windows)]
use crate::pipe::Connection;
#[cfg(target_os = "linux")]
use crate::linux_firmware as firmware;
use bootsel_core::backend::BackendError;
use bootsel_core::ipc::{
    encode_state, parse_target_id, ErrorKind, Request, Response, PROTOCOL_VERSION,
};

/// Se connecte a l'interface et traite les requetes jusqu'a la fermeture.
#[cfg(windows)]
pub fn serve(pipe_name: &str) -> Result<(), String> {
    let mut connection = Connection::connect(pipe_name)
        .map_err(|e| format!("connexion au tube {pipe_name} impossible : {e}"))?;

    loop {
        let line = match connection.read_line() {
            Ok(Some(line)) => line,
            // L'interface a ferme : fin normale du helper.
            Ok(None) => return Ok(()),
            Err(e) => return Err(format!("lecture du tube : {e}")),
        };

        if line.trim().is_empty() {
            continue;
        }

        let response = handle_line(&line);
        let encoded = serde_json::to_string(&response)
            .unwrap_or_else(|_| internal_error_json("reponse non serialisable"));

        if let Err(e) = connection.write_line(&encoded) {
            return Err(format!("ecriture sur le tube : {e}"));
        }
    }
}

/// Traite une ligne brute. Fonction pure du point de vue du protocole :
/// une entree, une reponse, aucun etat conserve.
pub fn handle_line(line: &str) -> Response {
    match serde_json::from_str::<Request>(line) {
        Ok(request) => handle_request(request),
        // Une ligne illisible n'est jamais interpretee « au mieux ».
        Err(e) => Response::Error {
            kind: ErrorKind::BadRequest,
            message: format!("requete illisible : {e}"),
        },
    }
}

fn handle_request(request: Request) -> Response {
    match request {
        Request::Hello { protocol } => {
            if protocol != PROTOCOL_VERSION {
                return Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!(
                        "version de protocole {protocol} incompatible avec {PROTOCOL_VERSION}"
                    ),
                };
            }
            Response::Hello {
                protocol: PROTOCOL_VERSION,
                helper_version: env!("CARGO_PKG_VERSION").to_string(),
                #[cfg(windows)]
                elevated: firmware::is_elevated(),
                // Sous Linux le helper n'est lance que par pkexec : s'il
                // s'execute, il est deja privilegie.
                #[cfg(not(windows))]
                elevated: true,
            }
        }

        Request::ReadState => match firmware::read_state() {
            Ok(state) => Response::State {
                variables: encode_state(&state),
            },
            Err(e) => error_response(e),
        },

        Request::SetBootNext { id } => {
            // Point d'entree unique de toute donnee exterieure vers le
            // firmware. Quatre chiffres hexadecimaux, ou rien.
            let Some(target) = parse_target_id(&id) else {
                return Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!(
                        "identifiant invalide : {id:?}. Quatre chiffres hexadecimaux attendus."
                    ),
                };
            };

            match firmware::write_boot_next(target) {
                Ok(_) => Response::Written {
                    id: target.hex4(),
                },
                Err(e) => error_response(e),
            }
        }

        Request::SetDefaultSystem { id } => {
            // Meme validation stricte que pour BootNext : quatre chiffres
            // hexadecimaux, ou rien.
            let Some(target) = parse_target_id(&id) else {
                return Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: format!(
                        "identifiant invalide : {id:?}. Quatre chiffres hexadecimaux attendus."
                    ),
                };
            };

            match set_default_system(target) {
                Ok(()) => Response::DefaultApplied {
                    id: target.hex4(),
                },
                Err(e) => error_response(e),
            }
        }
    }
}

/// Change le systeme par defaut. Disponible sous Linux uniquement pour
/// l'instant : l'equivalent Windows reste a ecrire.
#[cfg(target_os = "linux")]
fn set_default_system(target: bootsel_core::model::BootId) -> Result<(), BackendError> {
    firmware::write_default_system(target).map(|_| ())
}

#[cfg(not(target_os = "linux"))]
fn set_default_system(_target: bootsel_core::model::BootId) -> Result<(), BackendError> {
    Err(BackendError::Unsupported(
        "le changement de systeme par defaut n'est pas encore implemente sur cette plateforme"
            .to_string(),
    ))
}

/// Traduit une erreur interne en categorie transmissible, sans perdre le
/// detail utile au diagnostic.
fn error_response(error: BackendError) -> Response {
    let kind = match &error {
        BackendError::PrivilegeRequired => ErrorKind::PrivilegeRequired,
        BackendError::NotUefi => ErrorKind::NotUefi,
        BackendError::EntryNotFound(_) | BackendError::TargetVanished => ErrorKind::EntryNotFound,
        BackendError::WriteRefused(_) => ErrorKind::WriteRefused,
        BackendError::Guard(_) => ErrorKind::GuardViolation,
        _ => ErrorKind::Internal,
    };

    Response::Error {
        kind,
        message: error.to_string(),
    }
}

fn internal_error_json(message: &str) -> String {
    format!(r#"{{"reply":"error","kind":"internal","message":"{message}"}}"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Toute entree hostile doit produire une erreur, jamais une action.
    #[test]
    fn malformed_lines_are_refused_without_effect() {
        for hostile in [
            "",
            "   ",
            "pas du json",
            "{}",
            r#"{"cmd":"unknown"}"#,
            r#"{"cmd":"set_boot_order","ids":[2,1]}"#,
            r#"{"cmd":"write_variable","name":"BootOrder","value":"0200"}"#,
            r#"{"cmd":"exec","command":"format C:"}"#,
            r#"{"cmd":"delete_partition","disk":0}"#,
            "[1,2,3]",
            "null",
        ] {
            let response = handle_line(hostile);
            assert!(
                matches!(
                    response,
                    Response::Error {
                        kind: ErrorKind::BadRequest,
                        ..
                    }
                ),
                "aurait du etre refuse : {hostile:?} — obtenu {response:?}"
            );
        }
    }

    #[test]
    fn a_malformed_identifier_never_reaches_the_firmware() {
        for hostile in [
            "",
            "0",
            "00002",
            "BootOrder",
            "Boot0002",
            "0002; shutdown /r",
            "0002\n0003",
            "../../etc/passwd",
            "$(whoami)",
            "0x02",
            "    ",
        ] {
            let response = handle_request(Request::SetBootNext {
                id: hostile.to_string(),
            });
            match response {
                Response::Error {
                    kind: ErrorKind::BadRequest,
                    message,
                } => assert!(
                    message.contains("identifiant invalide"),
                    "message inattendu pour {hostile:?} : {message}"
                ),
                other => panic!("aurait du etre refuse : {hostile:?} — obtenu {other:?}"),
            }
        }
    }

    #[test]
    fn the_handshake_refuses_a_mismatched_protocol_version() {
        for wrong in [0, 2, 99, u32::MAX] {
            assert!(matches!(
                handle_request(Request::Hello { protocol: wrong }),
                Response::Error {
                    kind: ErrorKind::BadRequest,
                    ..
                }
            ));
        }
    }

    #[test]
    fn the_handshake_accepts_the_current_protocol_version() {
        match handle_request(Request::Hello {
            protocol: PROTOCOL_VERSION,
        }) {
            Response::Hello {
                protocol,
                helper_version,
                ..
            } => {
                assert_eq!(protocol, PROTOCOL_VERSION);
                assert_eq!(helper_version, env!("CARGO_PKG_VERSION"));
            }
            other => panic!("salut attendu, obtenu {other:?}"),
        }
    }

    #[test]
    fn reading_the_state_either_works_or_reports_a_clean_error() {
        match handle_request(Request::ReadState) {
            Response::State { variables } => {
                // Session elevee : l'instantane doit etre coherent.
                assert!(variables.contains_key("BootOrder"));
            }
            Response::Error { kind, .. } => assert!(matches!(
                kind,
                ErrorKind::PrivilegeRequired | ErrorKind::NotUefi
            )),
            other => panic!("reponse inattendue : {other:?}"),
        }
    }

    #[test]
    fn errors_are_classified_without_losing_their_detail() {
        let cases = [
            (BackendError::PrivilegeRequired, ErrorKind::PrivilegeRequired),
            (BackendError::NotUefi, ErrorKind::NotUefi),
            (
                BackendError::EntryNotFound(bootsel_core::model::BootId(2)),
                ErrorKind::EntryNotFound,
            ),
            (
                BackendError::WriteRefused("refus".into()),
                ErrorKind::WriteRefused,
            ),
            (
                BackendError::Guard(bootsel_core::guard::GuardError::BootOrderModified),
                ErrorKind::GuardViolation,
            ),
        ];

        for (error, expected) in cases {
            let text = error.to_string();
            match error_response(error) {
                Response::Error { kind, message } => {
                    assert_eq!(kind, expected);
                    assert_eq!(message, text, "le detail ne doit pas etre perdu");
                }
                other => panic!("erreur attendue, obtenu {other:?}"),
            }
        }
    }

    #[test]
    fn a_guard_violation_is_never_reported_as_a_success() {
        // Le cas le plus important : si le garde-fou detecte que BootOrder a
        // change, la reponse doit etre une erreur explicite, jamais Written.
        let response = error_response(BackendError::Guard(
            bootsel_core::guard::GuardError::BootOrderModified,
        ));
        assert!(matches!(
            response,
            Response::Error {
                kind: ErrorKind::GuardViolation,
                ..
            }
        ));
        assert!(!matches!(response, Response::Written { .. }));
    }

    #[test]
    fn the_fallback_error_json_is_valid_and_parseable() {
        let raw = internal_error_json("test");
        let parsed: Response = serde_json::from_str(&raw).expect("JSON de repli valide");
        assert!(matches!(
            parsed,
            Response::Error {
                kind: ErrorKind::Internal,
                ..
            }
        ));
    }
}
