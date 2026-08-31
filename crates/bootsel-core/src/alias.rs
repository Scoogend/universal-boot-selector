//! Alias locaux et preferences d'interface.
//!
//! Renommer une entree dans l'application est un **alias purement local** :
//! rien n'est ecrit sur le disque cible, la partition, le chargeur, ni dans la
//! description de l'entree UEFI. Seul le fichier de configuration de
//! l'application change.

use crate::identity::is_well_formed;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Longueur maximale d'un alias. Au-dela, l'interface deviendrait illisible.
pub const MAX_ALIAS_LEN: usize = 64;

/// Version du format de configuration, pour les migrations futures.
pub const CONFIG_VERSION: u32 = 1;

/// Preferences d'affichage. Rien de critique, jamais de secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiPreferences {
    /// `system`, `light` ou `dark`.
    pub theme: String,
    /// Afficher les entrees internes au firmware (Setup, shell EFI).
    pub show_firmware_entries: bool,
    /// Afficher les entrees dont le peripherique est absent.
    pub show_unavailable_entries: bool,
}

impl Default for UiPreferences {
    fn default() -> Self {
        UiPreferences {
            theme: "system".to_string(),
            show_firmware_entries: false,
            show_unavailable_entries: true,
        }
    }
}

/// Contenu du fichier de configuration de l'application.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub version: u32,
    /// Cle stable -> nom choisi par l'utilisateur.
    pub aliases: BTreeMap<String, String>,
    /// Ordre d'affichage souhaite, exprime en cles stables.
    pub display_order: Vec<String>,
    pub ui: UiPreferences,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: CONFIG_VERSION,
            aliases: BTreeMap::new(),
            display_order: Vec::new(),
            ui: UiPreferences::default(),
        }
    }
}

/// Pourquoi un alias a ete refuse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    #[error("identifiant stable invalide : {0}")]
    InvalidStableId(String),
    #[error("un alias ne peut pas etre vide")]
    Empty,
    #[error("alias trop long : {actual} caracteres, maximum {MAX_ALIAS_LEN}")]
    TooLong { actual: usize },
    #[error("un alias ne peut pas contenir de caractere de controle")]
    ControlCharacters,
}

impl Config {
    /// Definit un alias. Le nom est normalise (espaces reduits, bords rognes).
    pub fn set_alias(&mut self, stable_id: &str, name: &str) -> Result<(), AliasError> {
        if !is_well_formed(stable_id) {
            return Err(AliasError::InvalidStableId(stable_id.to_string()));
        }
        let normalized = normalize_alias(name)?;
        self.aliases.insert(stable_id.to_string(), normalized);
        Ok(())
    }

    /// Supprime un alias. Rendre son nom detecte a une entree ne doit jamais
    /// echouer, meme si la cle n'existait pas.
    pub fn clear_alias(&mut self, stable_id: &str) {
        self.aliases.remove(stable_id);
    }

    pub fn alias(&self, stable_id: &str) -> Option<&str> {
        self.aliases.get(stable_id).map(|s| s.as_str())
    }

    /// Nom a afficher : l'alias s'il existe, sinon le nom detecte.
    pub fn display_name(&self, stable_id: &str, detected: &str) -> String {
        self.alias(stable_id)
            .map(|s| s.to_string())
            .unwrap_or_else(|| detected.to_string())
    }

    /// Retire les entrees devenues invalides apres une edition manuelle du
    /// fichier. On nettoie plutot que de refuser de demarrer.
    pub fn sanitize(&mut self) -> usize {
        let before = self.aliases.len();
        self.aliases
            .retain(|k, v| is_well_formed(k) && normalize_alias(v).is_ok());
        self.display_order.retain(|k| is_well_formed(k));
        self.display_order.dedup();
        before - self.aliases.len()
    }
}

/// Valide et normalise un alias saisi par l'utilisateur.
pub fn normalize_alias(name: &str) -> Result<String, AliasError> {
    // L'absence de contenu est diagnostiquee avant tout le reste : une saisie
    // faite uniquement d'espaces et de tabulations est vide, pas hostile.
    if name.trim().is_empty() {
        return Err(AliasError::Empty);
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(AliasError::ControlCharacters);
    }

    let collapsed: String = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let count = collapsed.chars().count();
    if count > MAX_ALIAS_LEN {
        return Err(AliasError::TooLong { actual: count });
    }
    Ok(collapsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: &str = "v1-gpt:0123456789abcdef0123456789abcdef";
    const ID_B: &str = "v1-desc:fedcba9876543210fedcba9876543210";

    #[test]
    fn stores_and_reads_back_an_alias() {
        let mut c = Config::default();
        c.set_alias(ID_A, "Mon Linux").unwrap();
        assert_eq!(c.alias(ID_A), Some("Mon Linux"));
        assert_eq!(c.display_name(ID_A, "debian"), "Mon Linux");
    }

    #[test]
    fn falls_back_to_the_detected_name() {
        let c = Config::default();
        assert_eq!(c.display_name(ID_A, "debian"), "debian");
    }

    #[test]
    fn clearing_an_alias_restores_the_detected_name() {
        let mut c = Config::default();
        c.set_alias(ID_A, "Mon Linux").unwrap();
        c.clear_alias(ID_A);
        assert_eq!(c.display_name(ID_A, "debian"), "debian");
        // Supprimer une cle absente ne doit pas paniquer.
        c.clear_alias("v1-gpt:00000000000000000000000000000000");
    }

    #[test]
    fn rejects_aliases_keyed_on_a_volatile_boot_id() {
        // Utiliser « Boot0002 » comme cle serait le bug que l'identite stable
        // existe precisement pour eviter.
        assert_eq!(
            Config::default().set_alias("Boot0002", "Mon Linux"),
            Err(AliasError::InvalidStableId("Boot0002".into()))
        );
    }

    #[test]
    fn rejects_empty_and_whitespace_only_aliases() {
        let mut c = Config::default();
        assert_eq!(c.set_alias(ID_A, ""), Err(AliasError::Empty));
        assert_eq!(c.set_alias(ID_A, "   \t "), Err(AliasError::Empty));
    }

    #[test]
    fn rejects_control_characters() {
        let mut c = Config::default();
        assert_eq!(
            c.set_alias(ID_A, "Mon\nLinux"),
            Err(AliasError::ControlCharacters)
        );
        assert_eq!(
            c.set_alias(ID_A, "Mon\0Linux"),
            Err(AliasError::ControlCharacters)
        );
    }

    #[test]
    fn rejects_overlong_aliases() {
        let mut c = Config::default();
        let long = "a".repeat(MAX_ALIAS_LEN + 1);
        assert_eq!(
            c.set_alias(ID_A, &long),
            Err(AliasError::TooLong {
                actual: MAX_ALIAS_LEN + 1
            })
        );
        // La limite exacte doit passer.
        assert!(c.set_alias(ID_A, &"a".repeat(MAX_ALIAS_LEN)).is_ok());
    }

    #[test]
    fn normalizes_whitespace() {
        assert_eq!(normalize_alias("  Mon   Linux  ").unwrap(), "Mon Linux");
    }

    #[test]
    fn accepts_unicode_names() {
        let mut c = Config::default();
        c.set_alias(ID_A, "Débian de Léa").unwrap();
        assert_eq!(c.alias(ID_A), Some("Débian de Léa"));
    }

    #[test]
    fn sanitize_drops_hand_edited_garbage_without_failing() {
        let mut c = Config::default();
        c.aliases.insert(ID_A.into(), "Valide".into());
        c.aliases.insert("Boot0002".into(), "Cle volatile".into());
        c.aliases.insert("n'importe quoi".into(), "Cle invalide".into());
        c.aliases.insert(ID_B.into(), "".into()); // valeur invalide
        c.display_order = vec![ID_A.into(), "Boot0002".into()];

        let dropped = c.sanitize();
        assert_eq!(dropped, 3);
        assert_eq!(c.aliases.len(), 1);
        assert_eq!(c.alias(ID_A), Some("Valide"));
        assert_eq!(c.display_order, vec![ID_A.to_string()]);
    }

    #[test]
    fn round_trips_through_json() {
        let mut c = Config::default();
        c.set_alias(ID_A, "Mon Linux").unwrap();
        c.ui.theme = "dark".into();

        let json = serde_json::to_string_pretty(&c).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn reads_a_minimal_hand_written_config() {
        // Un fichier reduit au strict minimum doit se charger avec des defauts.
        let c: Config = serde_json::from_str("{}").unwrap();
        assert_eq!(c.version, CONFIG_VERSION);
        assert_eq!(c.ui.theme, "system");
        assert!(c.aliases.is_empty());
    }

    #[test]
    fn config_contains_no_field_that_could_hold_a_secret() {
        // Garde-fou de revue : la serialisation d'une config vierge ne doit
        // exposer que les quatre champs attendus.
        let json = serde_json::to_value(Config::default()).unwrap();
        let keys: Vec<&str> = json.as_object().unwrap().keys().map(|s| s.as_str()).collect();
        assert_eq!(keys, vec!["aliases", "display_order", "ui", "version"]);
    }
}
