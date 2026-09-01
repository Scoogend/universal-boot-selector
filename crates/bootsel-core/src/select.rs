//! Selection securisee du prochain demarrage.
//!
//! C'est la seule sequence de l'application qui aboutit a une ecriture. Elle
//! applique la regle de double securite : **rien de ce qui a ete lu au moment
//! de l'affichage n'est reutilise au moment d'agir**. Le firmware est relu, la
//! cible est reidentifiee par sa cle stable, revalidee, puis seulement ecrite.
//!
//! Justification : entre le moment ou l'utilisateur voit la liste et celui ou
//! il clique, une cle USB a pu etre retiree, une mise a jour a pu renumeroter
//! les entrees, un autre outil a pu modifier la NVRAM. Agir sur un
//! `Boot####` lu plusieurs minutes plus tot reviendrait a demarrer sur une
//! cible differente de celle affichee.

use crate::alias::Config;
use crate::backend::{BackendError, BootBackend};
use crate::detect::build_entries;
use crate::guard;
use crate::model::{Availability, BootEntry, BootId, BootloaderKind, FirmwareState};
use serde::{Deserialize, Serialize};

/// Ce qui sera fait, presente a l'utilisateur avant confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionPlan {
    /// Cle stable de la cible. C'est **elle** qui est transmise, jamais le
    /// `Boot####` volatil.
    pub stable_id: String,
    pub display_name: String,
    pub bootloader_label: String,
    pub device_label: Option<String>,
    pub efi_path: Option<String>,
    /// Identifiant observe lors de la preparation, a titre purement informatif.
    /// Il est reresolu avant l'ecriture et peut differer.
    pub observed_id: BootId,
    /// Effets de bord previsibles du demarrage vise. Jamais bloquants : ils
    /// sont affiches avant confirmation pour que l'utilisateur decide en
    /// connaissance de cause.
    pub warnings: Vec<SelectionWarning>,
}

/// Un effet de bord que le demarrage vise est susceptible de produire.
///
/// Ces avertissements ne portent pas sur ce que fait l'application — elle
/// n'ecrit que `BootNext` — mais sur ce que **le chargeur cible** peut faire
/// une fois lance. Les taire reviendrait a promettre une innocuite qui n'est
/// pas la notre a garantir.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SelectionWarning {
    /// La cible est le chargeur de repli des supports amovibles,
    /// `\EFI\BOOT\BOOTX64.EFI`.
    ///
    /// Sur un systeme Secure Boot, ce fichier est generalement `shim`. Demarre
    /// par ce chemin, shim execute `fallback.efi`, qui **cree des entrees UEFI
    /// et reordonne l'ordre de demarrage permanent** d'apres les fichiers
    /// `BOOTX64.CSV` trouves sur la partition, puis redemarre la machine en
    /// affichant « Reset System » et un compte a rebours.
    ///
    /// Ce comportement appartient a shim, pas a cette application. Mais il en
    /// resulte que l'ordre de demarrage permanent peut changer, alors meme que
    /// l'application n'y a pas touche. L'utilisateur doit le savoir avant.
    ///
    /// Constate sur une machine reelle : selectionner une telle entree a fait
    /// apparaitre une nouvelle entree en tete de l'ordre de demarrage, et
    /// afficher un compte a rebours dont le libelle laisse craindre un
    /// effacement alors qu'il s'agit d'un simple redemarrage.
    RemovableFallbackLoader {
        /// Nom d'une entree designant le meme support par son chargeur
        /// propre, quand il en existe une. La preferer evite tout l'effet de
        /// bord.
        better_entry: Option<String>,
    },
}

impl SelectionWarning {
    /// Titre court, pour la ligne d'en-tete de l'avertissement.
    pub fn title(&self) -> &'static str {
        match self {
            SelectionWarning::RemovableFallbackLoader { .. } => {
                "Chargeur de repli : l'ordre de demarrage peut changer"
            }
        }
    }

    /// Explication complete, telle qu'elle doit etre montree a l'utilisateur.
    pub fn detail(&self) -> String {
        match self {
            SelectionWarning::RemovableFallbackLoader { better_entry } => {
                let mut text = String::from(
                    "Cette entree passe par le chargeur de repli des supports amovibles \
                     (\\EFI\\BOOT\\BOOTX64.EFI). Sur un systeme Secure Boot, ce fichier est \
                     generalement shim. Demarre par ce chemin, shim execute fallback.efi, \
                     qui cree des entrees UEFI et reordonne l'ordre de demarrage permanent, \
                     puis redemarre la machine en affichant « Reset System » avec un compte \
                     a rebours.\n\n\
                     « Reset System » signifie redemarrer, pas effacer : c'est le service \
                     UEFI qui relance la machine. Aucune donnee n'est touchee.\n\n\
                     Ce comportement appartient a shim, pas a cette application. Mais il en \
                     resulte que votre ordre de demarrage permanent peut changer, alors que \
                     l'application ne le modifie jamais.",
                );
                if let Some(better) = better_entry {
                    text.push_str(&format!(
                        "\n\nL'entree « {better} » designe le meme support par son chargeur \
                         propre. La choisir evite tout cet effet de bord."
                    ));
                }
                text
            }
        }
    }
}

impl SelectionPlan {
    /// Vrai si le texte de confirmation propose une meilleure entree.
    #[cfg(test)]
    fn detail_mentions_better_entry(&self) -> bool {
        self.warnings
            .iter()
            .any(|w| w.detail().contains("designe le meme support"))
    }

    /// Texte de confirmation affiche a l'utilisateur.
    pub fn confirmation_message(&self) -> String {
        let mut lines = vec![format!(
            "Le prochain demarrage sera effectue sur : {}",
            self.display_name
        )];
        let mut details = vec![self.bootloader_label.clone()];
        if let Some(d) = &self.device_label {
            details.push(d.clone());
        }
        lines.push(details.join(" \u{b7} "));
        lines.push(String::new());
        lines.push(
            "L'ordre de demarrage permanent ne sera pas modifie. Seule la variable \
             UEFI BootNext est ecrite ; le firmware la consomme au demarrage suivant."
                .to_string(),
        );

        // Les effets de bord du chargeur cible viennent apres la garantie, et
        // ne la contredisent pas : l'application ne modifie rien de plus, mais
        // ce qu'elle demarre peut le faire.
        for warning in &self.warnings {
            lines.push(String::new());
            lines.push(warning.title().to_string());
            lines.push(warning.detail());
        }

        lines.join("\n")
    }
}

/// Resultat d'une selection reussie.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionOutcome {
    /// Entree effectivement programmee, telle que reresolue juste avant l'ecriture.
    pub target: BootId,
    pub display_name: String,
    /// Ordre de demarrage permanent avant l'operation.
    pub boot_order_before: Option<Vec<BootId>>,
    /// Ordre de demarrage permanent apres l'operation. Doit etre identique.
    pub boot_order_after: Option<Vec<BootId>>,
}

impl SelectionOutcome {
    /// Confirmation, verifiee sur les faits, que l'ordre permanent n'a pas bouge.
    pub fn boot_order_preserved(&self) -> bool {
        self.boot_order_before == self.boot_order_after
    }
}

/// Prepare une selection a partir d'une detection deja affichee.
///
/// Ne touche a rien : sert uniquement a construire le texte de confirmation.
pub fn prepare(
    entries: &[BootEntry],
    stable_id: &str,
) -> Result<SelectionPlan, BackendError> {
    let entry = entries
        .iter()
        .find(|e| e.stable_id == stable_id)
        .ok_or(BackendError::TargetVanished)?;

    check_selectable(entry)?;

    Ok(SelectionPlan {
        stable_id: entry.stable_id.clone(),
        display_name: entry.display_name.clone(),
        bootloader_label: entry.bootloader.label().to_string(),
        device_label: entry.device_label.clone(),
        efi_path: entry.efi_path.clone(),
        observed_id: entry.id,
        warnings: warnings_for(entry, entries),
    })
}

/// Releve les effets de bord previsibles du demarrage vise.
fn warnings_for(target: &BootEntry, entries: &[BootEntry]) -> Vec<SelectionWarning> {
    let mut warnings = Vec::new();

    if target.bootloader == BootloaderKind::RemovableFallback {
        // Une autre entree designe-t-elle la meme partition par un chargeur
        // dedie ? Si oui, la proposer : elle evite entierement l'effet de bord.
        let better_entry = target.partition_guid.and_then(|guid| {
            entries
                .iter()
                .find(|e| {
                    e.stable_id != target.stable_id
                        && e.partition_guid == Some(guid)
                        && e.bootloader != BootloaderKind::RemovableFallback
                        && e.availability.is_selectable()
                })
                .map(|e| e.display_name.clone())
        });

        warnings.push(SelectionWarning::RemovableFallbackLoader { better_entry });
    }

    warnings
}

/// Applique la selection : relit, revalide, ecrit `BootNext`, verifie.
///
/// Ne redemarre pas. Le redemarrage est un appel distinct, pour que
/// l'appelant puisse journaliser et confirmer entre les deux.
pub fn commit_selection(
    backend: &dyn BootBackend,
    config: &Config,
    plan: &SelectionPlan,
) -> Result<SelectionOutcome, BackendError> {
    // 1. Un backend en lecture seule s'arrete ici, avant tout le reste.
    if backend.is_read_only() {
        return Err(BackendError::ReadOnlyMode);
    }

    // 2. BootNext n'existe pas en BIOS herite. Aucun contournement n'est tente.
    if !backend.firmware_mode()?.supports_boot_next() {
        return Err(BackendError::NotUefi);
    }

    // 3. Relecture fraiche du firmware. L'instantane ayant servi a l'affichage
    //    est deliberement ignore.
    let before = backend.read_state()?;
    let devices = backend.list_devices().unwrap_or_default();

    // 4. Reresolution de la cible par sa cle stable, sur l'etat qui vient
    //    d'etre lu. Si le firmware a renumerote ses entrees, on suit le
    //    deplacement ; si la cible a disparu, on abandonne.
    let (fresh_entries, _) = build_entries(&before, &devices, config);
    let target_entry = fresh_entries
        .iter()
        .find(|e| e.stable_id == plan.stable_id)
        .ok_or(BackendError::TargetVanished)?;

    // 5. Revalidation complete : l'entree doit toujours etre selectionnable.
    check_selectable(target_entry)?;
    let target = target_entry.id;

    // 6. Verification finale que la variable existe bien dans l'instantane.
    if !before.contains_entry(target) {
        return Err(BackendError::EntryNotFound(target));
    }

    // 7. L'unique ecriture de toute l'application.
    backend.set_boot_next(target)?;

    // 8. Relecture et application de l'invariant. En cas d'echec, on remonte
    //    l'erreur : l'appelant ne redemarrera pas.
    let after = backend.read_state()?;
    guard::verify_only_boot_next_changed(&before, &after, target)?;

    Ok(SelectionOutcome {
        target,
        display_name: target_entry.display_name.clone(),
        boot_order_before: before.boot_order(),
        boot_order_after: after.boot_order(),
    })
}

/// Refuse toute entree qui n'est pas franchement selectionnable.
fn check_selectable(entry: &BootEntry) -> Result<(), BackendError> {
    match &entry.availability {
        Availability::Available => Ok(()),
        Availability::DeviceMissing => Err(BackendError::DeviceMissing),
        Availability::Inactive => Err(BackendError::NotSelectable(
            "cette entree est marquee inactive par le firmware".to_string(),
        )),
        Availability::NotSelectable(reason) => {
            Err(BackendError::NotSelectable(reason.clone()))
        }
    }
}

/// Redemarre, apres qu'une selection a ete validee.
///
/// Prend l'issue de la selection en parametre pour rendre impossible, au
/// niveau du type, un redemarrage qui n'aurait pas ete precede d'une
/// verification reussie du garde-fou.
pub fn reboot_after(
    backend: &dyn BootBackend,
    outcome: &SelectionOutcome,
) -> Result<(), BackendError> {
    debug_assert!(
        outcome.boot_order_preserved(),
        "le garde-fou aurait du rejeter cette issue"
    );
    backend.reboot()
}

/// Lit `BootOrder` sans rien modifier. Utilitaire de journalisation.
pub fn boot_order_of(state: &FirmwareState) -> Option<Vec<BootId>> {
    state.boot_order()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::detect;
    use crate::mock::{self, MockBootBackend, Op, WriteBehavior};
    use crate::model::VAR_BOOT_ORDER;

    /// Prepare un plan pour l'entree dont le nom detecte correspond.
    fn plan_for(backend: &MockBootBackend, name: &str) -> SelectionPlan {
        let config = Config::default();
        let detection = detect(backend, &config).expect("detection");
        let entry = detection
            .entries
            .iter()
            .find(|e| e.detected_name == name)
            .unwrap_or_else(|| panic!("entree introuvable : {name}"));
        prepare(&detection.entries, &entry.stable_id).expect("plan")
    }

    // -- Cas nominal --------------------------------------------------------

    #[test]
    fn sets_boot_next_to_the_selected_target() {
        let backend = mock::windows_debian();
        let plan = plan_for(&backend, "debian");
        let outcome = commit_selection(&backend, &Config::default(), &plan).unwrap();

        assert_eq!(outcome.target, BootId(2));
        assert_eq!(backend.snapshot().boot_next(), Some(BootId(2)));
    }

    #[test]
    fn boot_order_is_identical_before_and_after() {
        let backend = mock::multi_os();
        let before = backend.snapshot().boot_order();

        let plan = plan_for(&backend, "debian");
        let outcome = commit_selection(&backend, &Config::default(), &plan).unwrap();

        assert_eq!(backend.snapshot().boot_order(), before);
        assert_eq!(outcome.boot_order_before, before);
        assert_eq!(outcome.boot_order_after, before);
        assert!(outcome.boot_order_preserved());
    }

    #[test]
    fn only_boot_next_differs_in_the_whole_nvram() {
        let backend = mock::multi_os();
        let before = backend.snapshot();

        let plan = plan_for(&backend, "debian");
        commit_selection(&backend, &Config::default(), &plan).unwrap();

        let after = backend.snapshot();
        let changes = guard::diff(&before, &after);
        assert_eq!(
            changes,
            vec![guard::VarChange::Added("BootNext".into())],
            "une variable autre que BootNext a change"
        );
    }

    #[test]
    fn exactly_one_write_operation_is_issued() {
        let backend = mock::multi_os();
        let plan = plan_for(&backend, "debian");
        backend.clear_ops();

        commit_selection(&backend, &Config::default(), &plan).unwrap();

        assert_eq!(backend.writes(), vec![Op::SetBootNext(BootId(2))]);
        assert_eq!(backend.reboot_count(), 0, "commit ne doit pas redemarrer");
    }

    #[test]
    fn reboot_is_a_separate_explicit_step() {
        let backend = mock::windows_debian();
        let plan = plan_for(&backend, "debian");
        let outcome = commit_selection(&backend, &Config::default(), &plan).unwrap();

        assert_eq!(backend.reboot_count(), 0);
        reboot_after(&backend, &outcome).unwrap();
        assert_eq!(backend.reboot_count(), 1);
    }

    // -- Double securite : revalidation avant ecriture ----------------------

    #[test]
    fn aborts_without_writing_if_the_target_vanished_after_display() {
        let backend = mock::windows_debian();
        let plan = plan_for(&backend, "debian");

        // Entre l'affichage et le clic, l'entree disparait du firmware.
        backend.remove_entry(BootId(2));
        backend.clear_ops();

        assert_eq!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::TargetVanished)
        );
        assert!(backend.writes().is_empty(), "aucune ecriture ne doit avoir lieu");
    }

    #[test]
    fn aborts_without_writing_if_the_device_was_unplugged() {
        let backend = mock::multi_os();
        let plan = plan_for(&backend, "ACME UK64");

        // La cle USB est retiree entre l'affichage et la validation.
        backend.remove_device("mock-usb-2");
        backend.clear_ops();

        assert_eq!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::DeviceMissing)
        );
        assert!(backend.writes().is_empty());
    }

    #[test]
    fn follows_a_firmware_renumbering_instead_of_writing_a_stale_id() {
        // L'entree Debian est deplacee de Boot0002 vers Boot0007 apres
        // l'affichage. Ecrire l'identifiant memorise ferait demarrer sur
        // Windows ; la reresolution par cle stable doit suivre le deplacement.
        let backend = mock::windows_debian();
        let plan = plan_for(&backend, "debian");
        assert_eq!(plan.observed_id, BootId(2));

        {
            let raw = backend.snapshot().raw_entry(BootId(2)).unwrap().to_vec();
            let mut state = backend.snapshot();
            state.variables.remove("Boot0002");
            state.variables.insert("Boot0007".into(), raw);
            state
                .variables
                .insert(VAR_BOOT_ORDER.into(), crate::efi::testdata::boot_order(&[1, 7]));
            // Reinjection de l'etat modifie.
            let fresh = MockBootBackend::new(
                state,
                backend.list_devices().unwrap(),
                crate::model::FirmwareMode::Uefi,
            );

            let outcome = commit_selection(&fresh, &Config::default(), &plan).unwrap();
            assert_eq!(outcome.target, BootId(7), "aurait du suivre la renumerotation");
            assert_eq!(fresh.snapshot().boot_next(), Some(BootId(7)));
        }
    }

    // -- Refus categoriques -------------------------------------------------

    #[test]
    fn refuses_on_legacy_bios_without_trying_anything_else() {
        let backend = mock::legacy_bios();
        let plan = SelectionPlan {
            stable_id: "v1-gpt:0123456789abcdef0123456789abcdef".into(),
            display_name: "Debian".into(),
            bootloader_label: "GRUB".into(),
            device_label: None,
            efi_path: None,
            observed_id: BootId(2),
            warnings: Vec::new(),
        };

        assert_eq!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::NotUefi)
        );
        assert!(backend.writes().is_empty());
    }

    #[test]
    fn refuses_in_read_only_mode_before_touching_anything() {
        let backend = mock::windows_debian();
        let plan = plan_for(&backend, "debian");

        let read_only = mock::windows_debian().read_only();
        assert_eq!(
            commit_selection(&read_only, &Config::default(), &plan),
            Err(BackendError::ReadOnlyMode)
        );
        assert!(read_only.ops().is_empty(), "rien ne doit meme etre lu");
    }

    #[test]
    fn refuses_a_firmware_internal_entry() {
        let backend = mock::multi_os();
        let config = Config::default();
        let detection = detect(&backend, &config).unwrap();
        let setup = detection
            .entries
            .iter()
            .find(|e| e.detected_name == "Enter Setup")
            .unwrap();

        assert!(matches!(
            prepare(&detection.entries, &setup.stable_id),
            Err(BackendError::NotSelectable(_))
        ));
    }

    #[test]
    fn refuses_an_entry_whose_device_is_already_missing() {
        let backend = mock::orphan_entry();
        let config = Config::default();
        let detection = detect(&backend, &config).unwrap();
        let orphan = detection
            .entries
            .iter()
            .find(|e| e.detected_name == "Fedora")
            .unwrap();

        assert_eq!(
            prepare(&detection.entries, &orphan.stable_id),
            Err(BackendError::DeviceMissing)
        );
    }

    #[test]
    fn refuses_an_unknown_stable_id() {
        let backend = mock::windows_debian();
        let detection = detect(&backend, &Config::default()).unwrap();
        assert_eq!(
            prepare(&detection.entries, "v1-gpt:00000000000000000000000000000000"),
            Err(BackendError::TargetVanished)
        );
    }

    // -- Le garde-fou face a un firmware defaillant ou hostile --------------

    #[test]
    fn detects_a_firmware_that_reorders_boot_order_behind_our_back() {
        let backend =
            mock::windows_debian().with_write_behavior(WriteBehavior::AlsoReorderBootOrder);
        let plan = plan_for(&backend, "debian");

        let err = commit_selection(&backend, &Config::default(), &plan).unwrap_err();
        assert_eq!(err, BackendError::Guard(guard::GuardError::BootOrderModified));
    }

    #[test]
    fn detects_a_firmware_that_silently_ignores_the_write() {
        let backend = mock::windows_debian().with_write_behavior(WriteBehavior::SilentlyIgnore);
        let plan = plan_for(&backend, "debian");

        assert_eq!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::Guard(guard::GuardError::BootNextNotSet))
        );
    }

    #[test]
    fn detects_a_firmware_that_deletes_an_entry_while_writing() {
        let backend =
            mock::windows_debian().with_write_behavior(WriteBehavior::AlsoDeleteEntry(BootId(1)));
        let plan = plan_for(&backend, "debian");

        assert!(matches!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::Guard(guard::GuardError::ForeignChanges { .. }))
        ));
    }

    #[test]
    fn detects_a_firmware_that_writes_the_wrong_target() {
        let backend = mock::windows_debian()
            .with_write_behavior(WriteBehavior::WriteWrongTarget(BootId(1)));
        let plan = plan_for(&backend, "debian");

        assert_eq!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::Guard(guard::GuardError::BootNextWrongValue {
                expected: BootId(2),
                actual: BootId(1),
            }))
        );
    }

    #[test]
    fn a_refused_write_is_reported_as_such() {
        let backend = mock::windows_debian()
            .with_write_behavior(WriteBehavior::Refuse("acces refuse".into()));
        let plan = plan_for(&backend, "debian");

        assert_eq!(
            commit_selection(&backend, &Config::default(), &plan),
            Err(BackendError::WriteRefused("acces refuse".into()))
        );
    }

    #[test]
    fn no_failure_path_ever_leaves_boot_order_modified() {
        // Balayage de tous les comportements defaillants : quoi qu'il arrive,
        // l'ordre de demarrage permanent doit etre intact a la sortie.
        for behavior in [
            WriteBehavior::Correct,
            WriteBehavior::Refuse("nope".into()),
            WriteBehavior::SilentlyIgnore,
            WriteBehavior::AlsoDeleteEntry(BootId(1)),
            WriteBehavior::WriteWrongTarget(BootId(1)),
        ] {
            let backend = mock::windows_debian().with_write_behavior(behavior.clone());
            let expected = backend.snapshot().boot_order();
            let plan = plan_for(&backend, "debian");

            let _ = commit_selection(&backend, &Config::default(), &plan);

            assert_eq!(
                backend.snapshot().boot_order(),
                expected,
                "BootOrder modifie avec le comportement {behavior:?}"
            );
        }
    }

    // -- Effets de bord du chargeur cible ----------------------------------
    //
    // Ces tests encodent un incident constate sur une machine reelle :
    // selectionner l'entree « UEFI OS » d'un disque MX Linux a lance shim par
    // le chemin de repli. shim a execute fallback.efi, qui a cree une entree
    // « MX Linux », l'a placee en tete de l'ordre de demarrage, puis a
    // redemarre en affichant « Reset System » et un compte a rebours.
    //
    // L'application n'y etait pour rien : son garde-fou avait verifie que
    // BootOrder etait intact juste apres l'ecriture. Mais l'utilisateur
    // meritait d'etre prevenu avant de confirmer.

    /// Construit une entree de test minimale.
    fn entry(name: &str, loader: BootloaderKind, partition: &str, path: &str) -> BootEntry {
        use crate::efi::{Guid, Transport};
        use crate::model::{Availability, Confidence, OsKind};

        BootEntry {
            id: BootId(1),
            stable_id: format!("v1-gpt:{:032x}", name.len()),
            firmware_description: name.to_string(),
            display_name: name.to_string(),
            detected_name: name.to_string(),
            os: OsKind::LinuxGeneric,
            bootloader: loader,
            transport: Transport::Usb,
            confidence: Confidence::Probable,
            availability: Availability::Available,
            active: true,
            efi_path: Some(path.to_string()),
            partition_guid: Guid::parse(partition),
            partition_number: Some(1),
            device_label: Some("USB ACME HD320".to_string()),
            is_current: false,
        }
    }

    const PART: &str = "db0f7ec2-3eab-482e-8958-d252c49c6bf9";

    #[test]
    fn a_removable_fallback_target_warns_about_the_boot_order_side_effect() {
        let fallback = entry(
            "UEFI OS",
            BootloaderKind::RemovableFallback,
            PART,
            "\\EFI\\BOOT\\BOOTX64.EFI",
        );
        let entries = vec![fallback.clone()];

        let plan = prepare(&entries, &fallback.stable_id).expect("plan");

        assert_eq!(plan.warnings.len(), 1, "un avertissement est attendu");
        let warning = &plan.warnings[0];
        assert!(matches!(
            warning,
            SelectionWarning::RemovableFallbackLoader { .. }
        ));

        let detail = warning.detail();
        // L'utilisateur doit comprendre que « Reset System » veut dire
        // redemarrer : c'est ce libelle qui a fait craindre un effacement.
        assert!(detail.contains("redemarrer, pas effacer"));
        assert!(detail.contains("ordre de demarrage permanent"));
        assert!(detail.contains("fallback.efi"));
    }

    #[test]
    fn the_warning_points_to_the_dedicated_loader_when_one_exists() {
        // Situation exacte de la machine de test : deux entrees sur la meme
        // partition, l'une de repli, l'autre propre a la distribution.
        let fallback = entry(
            "UEFI OS",
            BootloaderKind::RemovableFallback,
            PART,
            "\\EFI\\BOOT\\BOOTX64.EFI",
        );
        let dedicated = entry(
            "MX Linux",
            BootloaderKind::Shim,
            PART,
            "\\EFI\\MX\\shimx64.efi",
        );
        let entries = vec![fallback.clone(), dedicated];

        let plan = prepare(&entries, &fallback.stable_id).expect("plan");

        match &plan.warnings[0] {
            SelectionWarning::RemovableFallbackLoader { better_entry } => {
                assert_eq!(
                    better_entry.as_deref(),
                    Some("MX Linux"),
                    "l'entree dediee du meme support doit etre proposee"
                );
            }
        }
        assert!(plan.detail_mentions_better_entry());
    }

    #[test]
    fn a_dedicated_loader_produces_no_warning() {
        let dedicated = entry(
            "MX Linux",
            BootloaderKind::Shim,
            PART,
            "\\EFI\\MX\\shimx64.efi",
        );
        let plan = prepare(&[dedicated.clone()], &dedicated.stable_id).expect("plan");
        assert!(
            plan.warnings.is_empty(),
            "un chargeur dedie n'a pas cet effet de bord"
        );
    }

    #[test]
    fn a_loader_on_another_partition_is_not_proposed_as_an_alternative() {
        let fallback = entry(
            "UEFI OS",
            BootloaderKind::RemovableFallback,
            PART,
            "\\EFI\\BOOT\\BOOTX64.EFI",
        );
        let elsewhere = entry(
            "Windows Boot Manager",
            BootloaderKind::WindowsBootManager,
            "94582b83-d53d-48c6-a61f-4de3af63bed5",
            "\\EFI\\MICROSOFT\\BOOT\\BOOTMGFW.EFI",
        );
        let plan = prepare(
            &[fallback.clone(), elsewhere],
            &fallback.stable_id,
        )
        .expect("plan");

        match &plan.warnings[0] {
            SelectionWarning::RemovableFallbackLoader { better_entry } => {
                assert_eq!(
                    *better_entry, None,
                    "seule une entree du meme support est une alternative"
                );
            }
        }
    }

    #[test]
    fn the_warning_appears_in_the_confirmation_message() {
        let fallback = entry(
            "UEFI OS",
            BootloaderKind::RemovableFallback,
            PART,
            "\\EFI\\BOOT\\BOOTX64.EFI",
        );
        let plan = prepare(&[fallback.clone()], &fallback.stable_id).expect("plan");
        let message = plan.confirmation_message();

        // La garantie de l'application reste affichee...
        assert!(message.contains("ne sera pas modifie"));
        // ...et l'effet de bord du chargeur aussi, sans la contredire.
        assert!(message.contains("Reset System"));
        assert!(message.contains("ordre de demarrage permanent"));
    }

    #[test]
    fn the_confirmation_message_states_what_is_and_is_not_modified() {
        let backend = mock::multi_os();
        let plan = plan_for(&backend, "debian");
        let msg = plan.confirmation_message();

        assert!(msg.contains("debian"));
        assert!(msg.contains("BootNext"));
        assert!(
            msg.contains("ne sera pas modifie"),
            "le message doit dire explicitement ce qui reste intact"
        );
    }
}
