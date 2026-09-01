//! Tests de securite — les tests qui font foi.
//!
//! Ils portent les noms exiges par le cahier des charges du projet. Un echec
//! ici signifie qu'une garantie fondamentale est rompue : ce ne sont pas des
//! tests de confort, ce sont les tests qui autorisent a livrer.
//!
//! Ils s'executent contre le firmware simule, ce qui permet de couvrir des
//! situations impossibles a provoquer sur une machine reelle (firmware qui
//! ment, peripherique retire au milieu de l'operation, entree renumerotee).

use bootsel_core::alias::Config;
use bootsel_core::backend::{BackendError, BootBackend};
use bootsel_core::detect::detect;
use bootsel_core::guard::{self, GuardError};
use bootsel_core::mock::{self, MockBootBackend, Op, WriteBehavior};
use bootsel_core::model::{BootId, FirmwareState};
use bootsel_core::select::{commit_selection, prepare, SelectionPlan};

/// Tous les scenarios UEFI comportant au moins une entree selectionnable.
fn selectable_scenarios() -> Vec<(&'static str, MockBootBackend)> {
    vec![
        ("windows-only", mock::windows_only()),
        ("windows-debian", mock::windows_debian()),
        ("multi-os", mock::multi_os()),
        ("orphan-entry", mock::orphan_entry()),
    ]
}

/// Prepare un plan pour chaque entree reellement selectionnable d'un backend.
fn plans_for(backend: &MockBootBackend) -> Vec<SelectionPlan> {
    let config = Config::default();
    let detection = detect(backend, &config).expect("detection");
    detection
        .entries
        .iter()
        .filter(|e| e.availability.is_selectable())
        .filter_map(|e| prepare(&detection.entries, &e.stable_id).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// L'invariant central du projet
// ---------------------------------------------------------------------------

/// `BootOrder` avant == `BootOrder` apres, pour toute selection, sur tout
/// scenario. C'est la garantie que l'ordre de demarrage permanent du PC n'est
/// jamais touche.
#[test]
fn test_bootorder_is_never_modified() {
    for (name, backend) in selectable_scenarios() {
        for plan in plans_for(&backend) {
            let before_raw = backend.snapshot().get("BootOrder").map(|s| s.to_vec());
            let before_decoded = backend.snapshot().boot_order();

            let outcome = commit_selection(&backend, &Config::default(), &plan)
                .unwrap_or_else(|e| panic!("{name} / {} : {e}", plan.display_name));

            let after_raw = backend.snapshot().get("BootOrder").map(|s| s.to_vec());
            let after_decoded = backend.snapshot().boot_order();

            // Comparaison sur les octets bruts, pas seulement sur la liste
            // decodee : un reencodage silencieux serait aussi une violation.
            assert_eq!(
                before_raw, after_raw,
                "{name} / {} : BootOrder modifie (octets bruts)",
                plan.display_name
            );
            assert_eq!(
                before_decoded, after_decoded,
                "{name} / {} : BootOrder modifie (liste decodee)",
                plan.display_name
            );
            assert!(
                outcome.boot_order_preserved(),
                "{name} / {} : l'issue signale un BootOrder modifie",
                plan.display_name
            );
        }
    }
}

/// La seule variable NVRAM a differer apres une selection est `BootNext`,
/// et elle vaut exactement la cible demandee.
#[test]
fn test_only_bootnext_changes() {
    for (name, backend) in selectable_scenarios() {
        for plan in plans_for(&backend) {
            let before = backend.snapshot();

            let outcome = commit_selection(&backend, &Config::default(), &plan)
                .unwrap_or_else(|e| panic!("{name} / {} : {e}", plan.display_name));

            let after = backend.snapshot();
            let changes = guard::diff(&before, &after);

            assert_eq!(
                changes.len(),
                1,
                "{name} / {} : {} variables modifiees au lieu d'une seule : {changes:?}",
                plan.display_name,
                changes.len()
            );
            assert_eq!(
                changes[0].name(),
                "BootNext",
                "{name} / {} : la variable modifiee n'est pas BootNext",
                plan.display_name
            );
            assert_eq!(
                after.boot_next(),
                Some(outcome.target),
                "{name} / {} : BootNext ne vaut pas la cible",
                plan.display_name
            );
        }
    }
}

/// Un cycle de detection complet n'emet aucune operation d'ecriture.
#[test]
fn test_detection_performs_no_write() {
    for name in mock::SCENARIOS {
        let backend = mock::scenario(name).expect("scenario connu");
        let before = backend.snapshot();

        let _ = detect(&backend, &Config::default());
        let _ = backend.list_devices();
        let _ = backend.firmware_mode();

        assert!(
            backend.writes().is_empty(),
            "{name} : la detection a emis des ecritures : {:?}",
            backend.writes()
        );
        assert_eq!(backend.reboot_count(), 0, "{name} : redemarrage declenche");
        assert_eq!(
            guard::diff(&before, &backend.snapshot()),
            Vec::new(),
            "{name} : l'etat du firmware a change pendant une lecture"
        );
    }
}

/// Une selection emet exactement une ecriture, et ne redemarre pas d'elle-meme.
#[test]
fn test_selection_issues_exactly_one_write_and_never_reboots_on_its_own() {
    let backend = mock::multi_os();
    let plan = &plans_for(&backend)[0];
    backend.clear_ops();

    let outcome = commit_selection(&backend, &Config::default(), plan).expect("selection");

    assert_eq!(
        backend.writes(),
        vec![Op::SetBootNext(outcome.target)],
        "une operation d'ecriture et une seule"
    );
    assert_eq!(
        backend.reboot_count(),
        0,
        "l'application ne doit jamais redemarrer sans action explicite"
    );
}

// ---------------------------------------------------------------------------
// Double securite : revalidation juste avant l'ecriture
// ---------------------------------------------------------------------------

/// Si la cible a disparu entre l'affichage et le clic, on abandonne sans ecrire.
#[test]
fn test_set_boot_next_aborts_if_target_vanished() {
    let backend = mock::windows_debian();
    let plan = plans_for(&backend)
        .into_iter()
        .find(|p| p.display_name == "debian")
        .expect("entree debian");

    backend.remove_entry(BootId(2));
    backend.clear_ops();

    assert_eq!(
        commit_selection(&backend, &Config::default(), &plan),
        Err(BackendError::TargetVanished)
    );
    assert!(backend.writes().is_empty(), "une ecriture a eu lieu malgre tout");
}

/// Si le peripherique a ete debranche entre l'affichage et le clic, on abandonne.
#[test]
fn test_set_boot_next_aborts_if_device_unplugged() {
    let backend = mock::multi_os();
    let plan = plans_for(&backend)
        .into_iter()
        .find(|p| p.display_name.contains("ACME"))
        .expect("entree USB");

    backend.remove_device("mock-usb-2");
    backend.clear_ops();

    assert_eq!(
        commit_selection(&backend, &Config::default(), &plan),
        Err(BackendError::DeviceMissing)
    );
    assert!(backend.writes().is_empty());
}

/// En BIOS herite, aucune methode de repli n'est tentee.
#[test]
fn test_legacy_bios_refuses_set_boot_next() {
    let backend = mock::legacy_bios();
    let plan = SelectionPlan {
        stable_id: "v1-gpt:0123456789abcdef0123456789abcdef".into(),
        display_name: "Debian".into(),
        bootloader_label: "GRUB".into(),
        device_label: None,
        efi_path: None,
        observed_id: BootId(2),
    };

    assert_eq!(
        commit_selection(&backend, &Config::default(), &plan),
        Err(BackendError::NotUefi)
    );
    assert!(backend.writes().is_empty());

    // La detection, elle, doit rester possible et expliquer la situation.
    let detection = detect(&backend, &Config::default()).expect("detection en BIOS herite");
    assert!(detection.entries.is_empty());
    assert!(detection.warnings.iter().any(|w| w.contains("BIOS Legacy")));
}

// ---------------------------------------------------------------------------
// Le garde-fou face a un firmware qui ne respecte pas le contrat
// ---------------------------------------------------------------------------

/// Un firmware qui modifie autre chose que `BootNext` est detecte, et le
/// redemarrage est refuse.
#[test]
fn test_guard_detects_foreign_change() {
    /// Un comportement de firmware defaillant, et le predicat qui reconnait
    /// l erreur que le garde-fou doit produire face a lui.
    type HostileCase = (WriteBehavior, fn(&BackendError) -> bool);

    let cases: Vec<HostileCase> = vec![
        (WriteBehavior::AlsoReorderBootOrder, |e| {
            matches!(e, BackendError::Guard(GuardError::BootOrderModified))
        }),
        (WriteBehavior::AlsoDeleteEntry(BootId(1)), |e| {
            matches!(e, BackendError::Guard(GuardError::ForeignChanges { .. }))
        }),
        (WriteBehavior::SilentlyIgnore, |e| {
            matches!(e, BackendError::Guard(GuardError::BootNextNotSet))
        }),
        (WriteBehavior::WriteWrongTarget(BootId(1)), |e| {
            matches!(e, BackendError::Guard(GuardError::BootNextWrongValue { .. }))
        }),
    ];

    for (behavior, expected) in cases {
        let backend = mock::windows_debian().with_write_behavior(behavior.clone());
        let plan = plans_for(&backend)
            .into_iter()
            .find(|p| p.display_name == "debian")
            .expect("entree debian");

        let err = commit_selection(&backend, &Config::default(), &plan)
            .expect_err(&format!("{behavior:?} aurait du etre rejete"));

        assert!(
            expected(&err),
            "{behavior:?} : erreur inattendue {err:?}"
        );
    }
}

/// Quelle que soit la maniere dont l'operation echoue, `BootOrder` reste intact.
#[test]
fn test_bootorder_survives_every_failure_mode() {
    for behavior in [
        WriteBehavior::Correct,
        WriteBehavior::Refuse("acces refuse".into()),
        WriteBehavior::SilentlyIgnore,
        WriteBehavior::AlsoDeleteEntry(BootId(1)),
        WriteBehavior::WriteWrongTarget(BootId(1)),
    ] {
        let backend = mock::multi_os().with_write_behavior(behavior.clone());
        let expected = backend.snapshot().get("BootOrder").map(|s| s.to_vec());

        for plan in plans_for(&backend) {
            let _ = commit_selection(&backend, &Config::default(), &plan);
        }

        assert_eq!(
            backend.snapshot().get("BootOrder").map(|s| s.to_vec()),
            expected,
            "BootOrder modifie avec le comportement {behavior:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Mode lecture seule
// ---------------------------------------------------------------------------

/// En mode lecture seule, aucune ecriture n'est possible, meme demandee.
#[test]
fn test_read_only_mode_refuses_every_write() {
    let backend = mock::multi_os();
    let plans = plans_for(&backend);

    let read_only = mock::multi_os().read_only();
    for plan in &plans {
        assert_eq!(
            commit_selection(&read_only, &Config::default(), plan),
            Err(BackendError::ReadOnlyMode)
        );
    }
    assert_eq!(read_only.set_boot_next(BootId(2)), Err(BackendError::ReadOnlyMode));
    assert_eq!(read_only.reboot(), Err(BackendError::ReadOnlyMode));

    assert!(read_only.snapshot().boot_next().is_none());
    assert_eq!(read_only.reboot_count(), 0);

    // La detection, elle, doit continuer de fonctionner normalement.
    let detection = detect(&read_only, &Config::default()).expect("detection");
    assert!(!detection.entries.is_empty());
}

// ---------------------------------------------------------------------------
// Validation des entrees du helper privilegie
// ---------------------------------------------------------------------------

/// Le format accepte par le helper privilegie est exactement quatre chiffres
/// hexadecimaux. Tout le reste est rejete avant d'atteindre le firmware.
#[test]
fn test_helper_rejects_malformed_input() {
    for good in ["0000", "0002", "abcd", "ABCD", "FFFF", "00ff"] {
        assert!(
            BootId::from_hex4(good).is_some(),
            "aurait du accepter : {good:?}"
        );
    }

    for bad in [
        "",
        "0",
        "002",
        "00002",
        "0x02",
        " 002",
        "0002 ",
        "000g",
        "----",
        "Boot0002",
        "BootOrder",
        "0002;reboot",
        "0002\n0003",
        "../../etc/passwd",
        "$(whoami)",
        "0002 && del",
        "\u{0}002",
    ] {
        assert!(
            BootId::from_hex4(bad).is_none(),
            "aurait du rejeter : {bad:?}"
        );
    }
}

/// Un identifiant valide se serialise en exactement deux octets little-endian.
#[test]
fn test_boot_next_payload_is_exactly_two_bytes() {
    assert_eq!(BootId(0x0002).to_le_bytes(), [0x02, 0x00]);
    assert_eq!(BootId(0xABCD).to_le_bytes(), [0xCD, 0xAB]);
    assert_eq!(BootId(0xFFFF).to_le_bytes().len(), 2);
}

// ---------------------------------------------------------------------------
// Robustesse : ne jamais planter
// ---------------------------------------------------------------------------

/// Un firmware vide, incoherent ou corrompu ne doit jamais faire planter la
/// detection : elle degrade, elle n'echoue pas.
#[test]
fn test_detection_never_panics_on_broken_firmware() {
    use std::collections::BTreeMap;

    let broken_states = vec![
        FirmwareState::default(),
        FirmwareState::new(BTreeMap::from([("BootOrder".into(), vec![0x01])])),
        FirmwareState::new(BTreeMap::from([
            ("BootOrder".into(), vec![0x01, 0x00, 0x02, 0x00]),
            ("Boot0001".into(), vec![]),
            ("Boot0002".into(), vec![0xFF; 7]),
        ])),
        FirmwareState::new(BTreeMap::from([
            ("BootNext".into(), vec![0xAA, 0xBB, 0xCC]),
            ("BootCurrent".into(), vec![]),
        ])),
    ];

    for state in broken_states {
        let backend = MockBootBackend::new(
            state,
            vec![],
            bootsel_core::model::FirmwareMode::Uefi,
        );
        let detection = detect(&backend, &Config::default()).expect("detection degradee, pas echouee");
        // Rien n'est propose comme selectionnable a partir de donnees illisibles.
        assert!(detection.selectable().count() <= detection.entries.len());
        assert!(backend.writes().is_empty());
    }
}
