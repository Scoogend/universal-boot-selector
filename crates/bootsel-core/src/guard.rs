//! Invariant de non-destruction.
//!
//! Ce module compare deux instantanes du firmware et **exige** que la seule
//! difference soit la variable `BootNext`. Il est appele systematiquement
//! apres toute ecriture : si quoi que ce soit d'autre a bouge — en particulier
//! `BootOrder` ou une entree `Boot####` — l'operation est declaree en echec et
//! le redemarrage est refuse.
//!
//! C'est la troisieme des quatre barrieres decrites dans `SECURITY.md`, et la
//! seule qui agisse a l'execution sur le firmware reel.

use crate::model::{BootId, FirmwareState, VAR_BOOT_NEXT, VAR_BOOT_ORDER};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Une difference constatee entre deux instantanes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VarChange {
    Added(String),
    Removed(String),
    Modified(String),
}

impl VarChange {
    pub fn name(&self) -> &str {
        match self {
            VarChange::Added(n) | VarChange::Removed(n) | VarChange::Modified(n) => n,
        }
    }
}

impl fmt::Display for VarChange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VarChange::Added(n) => write!(f, "{n} ajoutee"),
            VarChange::Removed(n) => write!(f, "{n} supprimee"),
            VarChange::Modified(n) => write!(f, "{n} modifiee"),
        }
    }
}

/// Echec de l'invariant. Chaque variante correspond a un refus explicite
/// d'aller plus loin.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum GuardError {
    #[error(
        "l'ordre de demarrage permanent (BootOrder) a change pendant l'operation. \
         Aucun redemarrage ne sera declenche."
    )]
    BootOrderModified,

    #[error(
        "des variables autres que BootNext ont change pendant l'operation : {}. \
         Aucun redemarrage ne sera declenche.",
        .changes.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(", ")
    )]
    ForeignChanges { changes: Vec<VarChange> },

    #[error("BootNext n'a pas ete ecrite : le firmware a refuse l'ecriture sans le signaler")]
    BootNextNotSet,

    #[error("BootNext vaut {actual} au lieu de {expected} apres ecriture")]
    BootNextWrongValue { expected: BootId, actual: BootId },

    #[error("BootNext contient {length} octets au lieu de 2 : valeur inexploitable")]
    BootNextMalformed { length: usize },

    #[error("BootOrder est illisible : refus d'y toucher")]
    BootOrderUnreadable,

    #[error(
        "le contenu de BootOrder a change : des entrees ont ete ajoutees ou supprimees, \
         alors que seul un reordonnancement etait demande"
    )]
    BootOrderContentChanged,

    #[error(
        "le systeme par defaut n'a pas ete applique : BootOrder commence par {actual:?} \
         au lieu de {expected}"
    )]
    DefaultSystemNotApplied {
        expected: BootId,
        actual: Option<BootId>,
    },
}

/// Liste toutes les differences entre deux instantanes, triees par nom.
pub fn diff(before: &FirmwareState, after: &FirmwareState) -> Vec<VarChange> {
    let mut changes = Vec::new();

    for (name, old) in &before.variables {
        match after.variables.get(name) {
            None => changes.push(VarChange::Removed(name.clone())),
            Some(new) if new != old => changes.push(VarChange::Modified(name.clone())),
            Some(_) => {}
        }
    }
    for name in after.variables.keys() {
        if !before.variables.contains_key(name) {
            changes.push(VarChange::Added(name.clone()));
        }
    }

    changes.sort_by(|a, b| a.name().cmp(b.name()));
    changes
}

/// Verifie que `BootOrder` est rigoureusement identique entre deux instantanes.
///
/// Comparaison sur les octets bruts, pas sur la liste decodee : deux encodages
/// differents de la meme liste doivent quand meme etre signales.
pub fn boot_order_unchanged(before: &FirmwareState, after: &FirmwareState) -> bool {
    before.get(VAR_BOOT_ORDER) == after.get(VAR_BOOT_ORDER)
}

/// L'invariant complet, applique apres une ecriture de `BootNext`.
///
/// Reussit si et seulement si :
/// 1. `BootOrder` est inchangee, octet pour octet ;
/// 2. aucune autre variable n'a ete ajoutee, supprimee ou modifiee ;
/// 3. `BootNext` vaut exactement la cible demandee.
pub fn verify_only_boot_next_changed(
    before: &FirmwareState,
    after: &FirmwareState,
    expected: BootId,
) -> Result<(), GuardError> {
    // 1. BootOrder d'abord : c'est la garantie la plus importante du projet,
    //    on la verifie explicitement pour produire une erreur sans ambiguite.
    if !boot_order_unchanged(before, after) {
        return Err(GuardError::BootOrderModified);
    }

    // 2. Aucune autre variable n'a le droit de bouger.
    let foreign: Vec<VarChange> = diff(before, after)
        .into_iter()
        .filter(|c| c.name() != VAR_BOOT_NEXT)
        .collect();
    if !foreign.is_empty() {
        return Err(GuardError::ForeignChanges { changes: foreign });
    }

    // 3. BootNext doit valoir la cible demandee, ni plus ni moins.
    let raw = after
        .get(VAR_BOOT_NEXT)
        .ok_or(GuardError::BootNextNotSet)?;
    if raw.len() != 2 {
        return Err(GuardError::BootNextMalformed { length: raw.len() });
    }
    let actual = BootId(u16::from_le_bytes([raw[0], raw[1]]));
    if actual != expected {
        return Err(GuardError::BootNextWrongValue { expected, actual });
    }

    Ok(())
}

/// Verifie qu'une ecriture de `BootOrder` s'est bornee a un reordonnancement.
///
/// # Pourquoi cette verification est plus stricte qu'elle n'en a l'air
///
/// Changer le systeme par defaut est la seule ecriture **permanente** du
/// projet. Le risque n'est pas de reordonner : c'est d'ajouter, de supprimer
/// ou d'inventer une entree au passage, ce qui rendrait un systeme
/// inaccessible.
///
/// On exige donc que la nouvelle liste soit une **permutation exacte** de
/// l'ancienne — memes identifiants, meme nombre — avec la cible en tete. Et
/// qu'aucune entree `Boot####` n'ait ete creee ni detruite.
pub fn verify_only_boot_order_reordered(
    before: &FirmwareState,
    after: &FirmwareState,
    expected_first: BootId,
) -> Result<(), GuardError> {
    let (Some(old), Some(new)) = (before.boot_order(), after.boot_order()) else {
        return Err(GuardError::BootOrderUnreadable);
    };

    if new.first() != Some(&expected_first) {
        return Err(GuardError::DefaultSystemNotApplied {
            expected: expected_first,
            actual: new.first().copied(),
        });
    }

    // Permutation exacte : rien n'a ete ajoute ni retire.
    let (mut a, mut b) = (old.clone(), new.clone());
    a.sort_unstable();
    b.sort_unstable();
    if a != b {
        return Err(GuardError::BootOrderContentChanged);
    }

    // Les entrees elles-memes doivent etre intactes : seul l'ordre change.
    let foreign: Vec<VarChange> = diff(before, after)
        .into_iter()
        .filter(|c| c.name() != VAR_BOOT_ORDER)
        .collect();
    if !foreign.is_empty() {
        return Err(GuardError::ForeignChanges { changes: foreign });
    }

    Ok(())
}

/// Verifie qu'une operation de **lecture** n'a rien modifie du tout.
///
/// Utilise pour prouver que la detection est passive : appele autour de chaque
/// cycle de detection en mode debug et dans les tests.
pub fn verify_nothing_changed(
    before: &FirmwareState,
    after: &FirmwareState,
) -> Result<(), GuardError> {
    let changes = diff(before, after);
    if changes.is_empty() {
        Ok(())
    } else {
        Err(GuardError::ForeignChanges { changes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::testdata;
    use std::collections::BTreeMap;

    fn base_state() -> FirmwareState {
        let mut vars = BTreeMap::new();
        vars.insert(VAR_BOOT_ORDER.into(), testdata::boot_order(&[1, 2, 3]));
        vars.insert("BootCurrent".into(), testdata::boot_id(1));
        vars.insert("Boot0001".into(), testdata::load_option_windows());
        vars.insert("Boot0002".into(), testdata::load_option_debian());
        vars.insert("Boot0003".into(), testdata::load_option_usb());
        FirmwareState::new(vars)
    }

    fn with_boot_next(mut state: FirmwareState, id: u16) -> FirmwareState {
        state
            .variables
            .insert(VAR_BOOT_NEXT.into(), testdata::boot_id(id));
        state
    }

    #[test]
    fn identical_snapshots_have_no_differences() {
        let s = base_state();
        assert!(diff(&s, &s).is_empty());
        assert!(verify_nothing_changed(&s, &s).is_ok());
    }

    #[test]
    fn accepts_the_legitimate_case_of_setting_boot_next() {
        let before = base_state();
        let after = with_boot_next(base_state(), 2);
        assert!(verify_only_boot_next_changed(&before, &after, BootId(2)).is_ok());
    }

    #[test]
    fn accepts_overwriting_a_boot_next_that_already_existed() {
        let before = with_boot_next(base_state(), 3);
        let after = with_boot_next(base_state(), 2);
        assert!(verify_only_boot_next_changed(&before, &after, BootId(2)).is_ok());
    }

    #[test]
    fn rejects_a_reordered_boot_order() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        // Debian promu devant Windows : exactement ce que le projet interdit.
        after
            .variables
            .insert(VAR_BOOT_ORDER.into(), testdata::boot_order(&[2, 1, 3]));

        assert_eq!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::BootOrderModified)
        );
    }

    #[test]
    fn rejects_a_boot_order_with_an_entry_removed() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        after
            .variables
            .insert(VAR_BOOT_ORDER.into(), testdata::boot_order(&[1, 2]));

        assert_eq!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::BootOrderModified)
        );
    }

    #[test]
    fn rejects_a_deleted_boot_order() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        after.variables.remove(VAR_BOOT_ORDER);

        assert_eq!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::BootOrderModified)
        );
    }

    #[test]
    fn rejects_a_modified_boot_entry() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        after
            .variables
            .insert("Boot0001".into(), testdata::load_option_debian());

        let err = verify_only_boot_next_changed(&before, &after, BootId(2)).unwrap_err();
        assert_eq!(
            err,
            GuardError::ForeignChanges {
                changes: vec![VarChange::Modified("Boot0001".into())]
            }
        );
    }

    #[test]
    fn rejects_a_deleted_boot_entry() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        after.variables.remove("Boot0003");

        assert!(matches!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::ForeignChanges { .. })
        ));
    }

    #[test]
    fn rejects_an_added_boot_entry() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        after
            .variables
            .insert("Boot0009".into(), testdata::load_option_ubuntu());

        assert!(matches!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::ForeignChanges { .. })
        ));
    }

    #[test]
    fn rejects_when_boot_next_was_never_written() {
        let before = base_state();
        let after = base_state(); // le firmware a silencieusement ignore l'ecriture
        assert_eq!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::BootNextNotSet)
        );
    }

    #[test]
    fn rejects_when_boot_next_holds_the_wrong_target() {
        let before = base_state();
        let after = with_boot_next(base_state(), 3);
        assert_eq!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::BootNextWrongValue {
                expected: BootId(2),
                actual: BootId(3),
            })
        );
    }

    #[test]
    fn rejects_a_malformed_boot_next() {
        let before = base_state();
        let mut after = base_state();
        after
            .variables
            .insert(VAR_BOOT_NEXT.into(), vec![0x02, 0x00, 0x00, 0x00]);
        assert_eq!(
            verify_only_boot_next_changed(&before, &after, BootId(2)),
            Err(GuardError::BootNextMalformed { length: 4 })
        );
    }

    #[test]
    fn rejects_several_simultaneous_foreign_changes() {
        let before = base_state();
        let mut after = with_boot_next(base_state(), 2);
        after.variables.remove("Boot0003");
        after
            .variables
            .insert("Boot0001".into(), testdata::load_option_ubuntu());

        match verify_only_boot_next_changed(&before, &after, BootId(2)) {
            Err(GuardError::ForeignChanges { changes }) => {
                assert_eq!(changes.len(), 2);
                assert!(changes.contains(&VarChange::Modified("Boot0001".into())));
                assert!(changes.contains(&VarChange::Removed("Boot0003".into())));
            }
            other => panic!("attendait ForeignChanges, obtenu {other:?}"),
        }
    }

    #[test]
    fn boot_order_comparison_is_byte_exact() {
        let a = base_state();
        let mut b = base_state();
        // Meme liste logique, encodage different (un octet de rembourrage).
        let mut padded = testdata::boot_order(&[1, 2, 3]);
        padded.push(0x00);
        b.variables.insert(VAR_BOOT_ORDER.into(), padded);
        assert!(!boot_order_unchanged(&a, &b));
    }

    #[test]
    fn read_only_verification_catches_any_change_at_all() {
        let before = base_state();
        let after = with_boot_next(base_state(), 2);
        // Meme une ecriture de BootNext est une violation pour une lecture.
        assert!(verify_nothing_changed(&before, &after).is_err());
    }

    #[test]
    fn diff_is_deterministic_and_sorted() {
        let before = base_state();
        let mut after = base_state();
        after.variables.remove("Boot0003");
        after.variables.insert("Boot0001".into(), vec![0xFF]);
        after.variables.insert("Boot0007".into(), vec![0xFF]);

        let changes = diff(&before, &after);
        let names: Vec<&str> = changes.iter().map(|c| c.name()).collect();
        assert_eq!(names, vec!["Boot0001", "Boot0003", "Boot0007"]);
    }
}
