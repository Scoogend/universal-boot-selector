//! Commandes exposees a l'interface.
//!
//! # Ce que l'interface peut demander, exhaustivement
//!
//! Lire l'etat, renommer une entree localement, preparer une selection, la
//! confirmer, et redemarrer. Il n'existe aucune commande capable de nommer un
//! fichier, un disque, une partition ou une variable du firmware.
//!
//! # Le seul chemin qui redemarre
//!
//! [`confirm_and_reboot`] est la seule fonction du projet qui arme le verrou
//! de redemarrage, et elle ne le fait qu'apres que
//! [`bootsel_core::select::commit_selection`] a valide le garde-fou. Une
//! erreur, a n'importe quelle etape, laisse le verrou ferme.

use crate::config_store;
use crate::state::AppState;
use bootsel_core::alias::normalize_alias;
use bootsel_core::detect::{detect, Detection};
use bootsel_core::select::{commit_selection, prepare, reboot_after, SelectionPlan};
use serde::Serialize;
use tauri::State;

/// Etat complet renvoye a l'interface a chaque rafraichissement.
#[derive(Debug, Serialize)]
pub struct AppView {
    /// `None` si le firmware n'a pas pu etre lu.
    pub detection: Option<Detection>,
    /// Message a afficher lorsque la detection est partielle ou impossible.
    pub notice: Option<String>,
    /// Vrai si les entrees UEFI n'ont pas pu etre lues faute de privileges.
    pub needs_elevation: bool,
    /// Vrai si le backend refuse toute ecriture (`--dry-run`, mode simule).
    pub read_only: bool,
    /// Vrai si un backend privilegie est en place.
    pub elevated: bool,
    /// Nom du backend actif, affiche dans le pied de fenetre.
    pub backend: String,
    /// Inventaire materiel, disponible meme sans privilege.
    pub devices: Vec<bootsel_core::model::StorageDevice>,
    pub config: bootsel_core::alias::Config,
}

/// Rafraichit l'etat. **Lecture seule.**
#[tauri::command]
pub fn refresh(state: State<'_, AppState>) -> Result<AppView, String> {
    let guard = state.lock()?;
    let backend = guard.backend();
    let config = guard.config().clone();

    let devices = backend.list_devices().unwrap_or_default();

    match detect(backend, &config) {
        Ok(detection) => Ok(AppView {
            notice: None,
            needs_elevation: false,
            read_only: backend.is_read_only(),
            elevated: guard.is_elevated(),
            backend: backend.name().to_string(),
            devices: detection.devices.clone(),
            detection: Some(detection),
            config,
        }),

        // Cas normal sous Windows sans elevation : on garde l'inventaire
        // materiel et on explique ce qui manque, plutot que d'afficher une
        // fenetre vide.
        Err(bootsel_core::BackendError::PrivilegeRequired) => Ok(AppView {
            detection: None,
            notice: Some(
                "Les entrees de demarrage du firmware n'ont pas ete lues : Windows exige \
                 des privileges administrateur, meme en lecture seule."
                    .to_string(),
            ),
            needs_elevation: true,
            read_only: backend.is_read_only(),
            elevated: guard.is_elevated(),
            backend: backend.name().to_string(),
            devices,
            config,
        }),

        Err(e) => Ok(AppView {
            detection: None,
            notice: Some(format!("{e}")),
            needs_elevation: false,
            read_only: backend.is_read_only(),
            elevated: guard.is_elevated(),
            backend: backend.name().to_string(),
            devices,
            config,
        }),
    }
}

/// Demande une elevation, puis rafraichit.
///
/// Declenche une invite UAC. Un refus n'est pas une panne : l'application
/// revient simplement dans son etat precedent.
#[tauri::command]
pub fn request_elevation(state: State<'_, AppState>) -> Result<AppView, String> {
    {
        let mut guard = state.lock()?;
        guard.elevate()?;
    }
    refresh(state)
}

/// Prepare une selection et renvoie de quoi construire la confirmation.
///
/// **N'ecrit rien.** Sert uniquement a afficher ce qui sera fait.
#[tauri::command]
pub fn prepare_selection(
    state: State<'_, AppState>,
    stable_id: String,
) -> Result<SelectionPlan, String> {
    let guard = state.lock()?;
    let detection = detect(guard.backend(), guard.config()).map_err(|e| e.to_string())?;
    prepare(&detection.entries, &stable_id).map_err(|e| e.to_string())
}

/// Ce que l'utilisateur voit apres une selection reussie.
#[derive(Debug, Serialize)]
pub struct RebootReport {
    pub target: String,
    pub display_name: String,
    /// Preuve, relue sur le firmware, que l'ordre permanent n'a pas bouge.
    pub boot_order_preserved: bool,
    pub boot_order: Vec<String>,
}

/// Applique la selection puis redemarre.
///
/// # Sequence
///
/// 1. [`commit_selection`] relit le firmware, reresolue la cible par sa cle
///    stable, ecrit `BootNext`, relit, et applique le garde-fou.
/// 2. En cas d'echec a n'importe quelle etape, on s'arrete ici. Le verrou de
///    redemarrage reste ferme.
/// 3. Seulement en cas de succes, on arme le verrou et on redemarre.
#[tauri::command]
pub fn confirm_and_reboot(
    state: State<'_, AppState>,
    plan: SelectionPlan,
) -> Result<RebootReport, String> {
    let guard = state.lock()?;
    let backend = guard.backend();

    let outcome = commit_selection(backend, guard.config(), &plan).map_err(|e| {
        if e.guarantees_no_write() {
            format!("{e}\n\nAucune modification n'a ete effectuee.")
        } else {
            format!("{e}")
        }
    })?;

    let report = RebootReport {
        target: outcome.target.variable_name(),
        display_name: outcome.display_name.clone(),
        boot_order_preserved: outcome.boot_order_preserved(),
        boot_order: outcome
            .boot_order_after
            .clone()
            .unwrap_or_default()
            .iter()
            .map(|id| id.variable_name())
            .collect(),
    };

    // Ceinture supplementaire : le garde-fou a deja verifie ce point, mais on
    // refuse de redemarrer si l'issue elle-meme ne le confirme pas.
    if !outcome.boot_order_preserved() {
        return Err(
            "L'ordre de demarrage permanent a change pendant l'operation. \
             Aucun redemarrage ne sera declenche."
                .to_string(),
        );
    }

    // Unique point du projet ou le redemarrage est arme, apres validation.
    #[cfg(windows)]
    bootsel_platform::windows::power::arm_reboot();

    reboot_after(backend, &outcome).map_err(|e| e.to_string())?;

    Ok(report)
}

/// Renomme une entree. **Alias purement local.**
///
/// Ne modifie ni le disque, ni la partition, ni le chargeur, ni la description
/// de l'entree UEFI : seul le fichier de configuration change.
#[tauri::command]
pub fn set_alias(
    state: State<'_, AppState>,
    stable_id: String,
    name: String,
) -> Result<AppView, String> {
    {
        let mut guard = state.lock()?;
        // Valide avant d'ecrire quoi que ce soit.
        normalize_alias(&name).map_err(|e| e.to_string())?;
        guard
            .config_mut()
            .set_alias(&stable_id, &name)
            .map_err(|e| e.to_string())?;
        config_store::save(guard.config())?;
    }
    refresh(state)
}

/// Retire un alias et rend son nom detecte a l'entree.
#[tauri::command]
pub fn clear_alias(state: State<'_, AppState>, stable_id: String) -> Result<AppView, String> {
    {
        let mut guard = state.lock()?;
        guard.config_mut().clear_alias(&stable_id);
        config_store::save(guard.config())?;
    }
    refresh(state)
}

/// Enregistre une preference d'affichage.
#[tauri::command]
pub fn set_preference(
    state: State<'_, AppState>,
    key: String,
    value: String,
) -> Result<AppView, String> {
    {
        let mut guard = state.lock()?;
        let ui = &mut guard.config_mut().ui;
        match key.as_str() {
            "theme" => ui.theme = value,
            "show_firmware_entries" => ui.show_firmware_entries = value == "true",
            "show_unavailable_entries" => ui.show_unavailable_entries = value == "true",
            other => return Err(format!("preference inconnue : {other}")),
        }
        config_store::save(guard.config())?;
    }
    refresh(state)
}

#[cfg(test)]
mod tests {

    /// Portion livree du fichier : tout ce qui precede ce module de test.
    ///
    /// Indispensable pour un test qui inspecte son propre source : sans cette
    /// coupure, les assertions se signaleraient elles-memes, puisqu elles
    /// citent nommement ce qu elles interdisent.
    fn shipped_source() -> &'static str {
        let source = include_str!("commands.rs");
        let end = source.find("#[cfg(test)]").unwrap_or(source.len());
        &source[..end]
    }

    #[test]
    fn only_the_reboot_command_arms_the_lock() {
        // Garde-fou de revue : `arm_reboot` ne doit apparaitre qu une seule
        // fois dans le code livre, dans `confirm_and_reboot`, apres la
        // validation du garde-fou.
        let occurrences: Vec<&str> = shipped_source()
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains("arm_reboot"))
            .collect();

        assert_eq!(
            occurrences.len(),
            1,
            "l armement du redemarrage doit apparaitre une seule fois : {occurrences:?}"
        );
    }

    #[test]
    fn the_reboot_command_validates_before_arming() {
        // L armement doit venir apres le garde-fou, jamais avant.
        let body = shipped_source()
            .split("pub fn confirm_and_reboot")
            .nth(1)
            .expect("la commande de redemarrage doit exister");

        let commit = body.find("commit_selection").expect("appel au garde-fou");
        let arm = body.find("arm_reboot").expect("armement");
        let preserved = body
            .find("boot_order_preserved()")
            .expect("verification de BootOrder");

        assert!(commit < arm, "le garde-fou doit s executer avant l armement");
        assert!(
            preserved < arm,
            "la verification de BootOrder doit preceder l armement"
        );
    }

    #[test]
    fn no_command_exposes_a_free_form_system_parameter() {
        // Les seuls parametres acceptes sont des cles stables, des noms
        // d affichage et des preferences. Aucune commande ne prend de chemin,
        // de nom de variable ni de commande systeme.
        let source = shipped_source();
        for forbidden in [
            "path: String",
            "variable: String",
            "command: String",
            "disk: ",
            "partition: ",
        ] {
            assert!(
                !source.contains(forbidden),
                "parametre interdit expose : {forbidden}"
            );
        }
    }

    #[test]
    fn every_exposed_command_is_declared_in_the_handler() {
        // Une commande oubliee dans `generate_handler!` serait inutilisable ;
        // une commande presente mais non listee ici passerait inapercue.
        let commands: Vec<&str> = shipped_source()
            .lines()
            .filter(|l| l.starts_with("pub fn "))
            .filter_map(|l| l.strip_prefix("pub fn "))
            .filter_map(|l| l.split(['(', '<']).next())
            .collect();

        let main = include_str!("main.rs");
        for command in &commands {
            assert!(
                main.contains(&format!("commands::{command},")),
                "commande absente du handler Tauri : {command}"
            );
        }
        assert_eq!(commands.len(), 7, "commandes exposees : {commands:?}");
    }
}
