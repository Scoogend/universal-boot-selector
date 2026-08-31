//! Lecture et ecriture du fichier de configuration de l'application.
//!
//! # Ce qui est ecrit
//!
//! Un unique fichier JSON dans le repertoire de configuration de
//! l'utilisateur. Il ne contient que des alias d'affichage et des preferences
//! d'interface — jamais de secret, jamais de donnee personnelle, jamais rien
//! qui touche au demarrage de la machine.
//!
//! Renommer un systeme dans l'application modifie **ce fichier et rien
//! d'autre** : ni le disque, ni la partition, ni le chargeur, ni la
//! description de l'entree UEFI.

use bootsel_core::alias::Config;
use std::path::{Path, PathBuf};

/// Repertoire de configuration, selon la plateforme.
///
/// Windows : `%APPDATA%\bootsel`
/// Linux   : `$XDG_CONFIG_HOME/bootsel`, sinon `~/.config/bootsel`
pub fn config_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .map(|p| p.join(bootsel_core::APP_NAME))
    }

    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
            .map(|p| p.join(bootsel_core::APP_NAME))
    }
}

pub fn config_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config.json"))
}

/// Charge la configuration.
///
/// Un fichier absent, illisible ou corrompu donne une configuration par
/// defaut : l'application doit demarrer quoi qu'il arrive. Les entrees
/// invalides d'un fichier edite a la main sont ecartees silencieusement par
/// [`Config::sanitize`].
pub fn load() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Config::default();
    };
    let mut config: Config = serde_json::from_str(&text).unwrap_or_default();
    config.sanitize();
    config
}

/// Enregistre la configuration.
///
/// Ecriture atomique : on ecrit un fichier temporaire voisin puis on le
/// renomme. Une coupure de courant en cours d'ecriture laisse donc l'ancien
/// fichier intact plutot qu'un fichier tronque.
pub fn save(config: &Config) -> Result<(), String> {
    let path = config_path().ok_or("repertoire de configuration introuvable")?;
    let dir = path
        .parent()
        .ok_or("chemin de configuration sans repertoire parent")?;

    std::fs::create_dir_all(dir)
        .map_err(|e| format!("creation du repertoire de configuration : {e}"))?;

    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("serialisation de la configuration : {e}"))?;

    write_atomically(&path, &json)
}

fn write_atomically(path: &Path, contents: &str) -> Result<(), String> {
    let temporary = path.with_extension("json.tmp");

    std::fs::write(&temporary, contents)
        .map_err(|e| format!("ecriture de la configuration : {e}"))?;

    std::fs::rename(&temporary, path).map_err(|e| {
        // Le renommage a echoue : on retire le fichier temporaire pour ne pas
        // laisser de residu.
        let _ = std::fs::remove_file(&temporary);
        format!("enregistrement de la configuration : {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_lives_in_the_user_directory() {
        let path = config_path().expect("chemin de configuration");
        assert!(path.is_absolute());
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("config.json"));
        assert!(
            path.to_string_lossy().contains(bootsel_core::APP_NAME),
            "le fichier doit vivre dans un repertoire dedie"
        );
    }

    #[test]
    fn loading_never_fails_even_without_a_file() {
        // `load` ne renvoie pas de `Result` : l'application demarre toujours.
        let config = load();
        assert_eq!(config.version, bootsel_core::alias::CONFIG_VERSION);
    }

    #[test]
    fn a_corrupted_file_yields_defaults_rather_than_a_crash() {
        let corrupted: Config = serde_json::from_str("{ ceci n est pas du json")
            .unwrap_or_default();
        assert_eq!(corrupted, Config::default());
    }

    #[test]
    fn a_hand_edited_file_is_sanitized_on_load() {
        let mut config: Config = serde_json::from_str(
            r#"{"version":1,"aliases":{"Boot0002":"cle volatile","v1-gpt:0123456789abcdef0123456789abcdef":"valide"}}"#,
        )
        .expect("JSON valide");

        let dropped = config.sanitize();
        assert_eq!(dropped, 1, "la cle volatile doit disparaitre");
        assert_eq!(
            config.alias("v1-gpt:0123456789abcdef0123456789abcdef"),
            Some("valide")
        );
    }

    #[test]
    fn the_written_file_contains_no_secret_bearing_field() {
        let json = serde_json::to_string(&Config::default()).expect("serialisation");
        for forbidden in ["password", "token", "secret", "key", "credential"] {
            assert!(
                !json.to_lowercase().contains(forbidden),
                "le fichier ne doit jamais porter de champ {forbidden}"
            );
        }
    }

    #[test]
    fn a_round_trip_through_json_preserves_everything() {
        let mut config = Config::default();
        config
            .set_alias("v1-gpt:0123456789abcdef0123456789abcdef", "Mon Linux")
            .expect("alias valide");
        config.ui.theme = "dark".into();

        let text = serde_json::to_string_pretty(&config).expect("serialisation");
        let back: Config = serde_json::from_str(&text).expect("relecture");
        assert_eq!(config, back);
    }
}
