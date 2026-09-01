//! Detection a chaud des peripheriques de stockage, sous Windows.
//!
//! # Mecanisme
//!
//! Un fil dedie cree une fenetre *message-only* — invisible, sans barre de
//! titre, jamais affichee — et s'abonne aux notifications d'interface de
//! volume via `RegisterDeviceNotificationW`. Windows envoie alors
//! `WM_DEVICECHANGE` a chaque branchement ou retrait.
//!
//! C'est un mecanisme d'evenements, pas un sondage : la reaction est
//! immediate, sans consommer de ressources entre deux changements.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne lit **rien** du peripherique. Il signale seulement qu'un changement
//! a eu lieu ; c'est a l'appelant de relancer un inventaire en lecture seule
//! s'il le souhaite. Un peripherique inconnu n'est jamais ouvert, monte, ni
//! execute.

use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Ioctl::GUID_DEVINTERFACE_VOLUME;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DispatchMessageW, GetMessageW, RegisterClassW,
    RegisterDeviceNotificationW, TranslateMessage, DBT_DEVICEARRIVAL,
    DBT_DEVICEREMOVECOMPLETE, DEVICE_NOTIFY_WINDOW_HANDLE, DEV_BROADCAST_DEVICEINTERFACE_W,
    HWND_MESSAGE, MSG, WINDOW_EX_STYLE, WINDOW_STYLE, WM_DEVICECHANGE, WNDCLASSW,
};

/// Duree d'apaisement apres un evenement.
///
/// Windows emet plusieurs notifications pour un seul branchement — une par
/// volume, parfois plusieurs par volume. On attend que le flot se calme avant
/// de prevenir l'appelant, pour ne relancer l'inventaire qu'une fois.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// Nature du changement observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    /// Un peripherique est apparu.
    Arrived,
    /// Un peripherique a disparu.
    Removed,
}

/// Canal global vers le fil de surveillance. La procedure de fenetre etant
/// appelee par Windows, elle ne peut rien capturer : elle passe par ici.
static SENDER: OnceLock<Mutex<Option<Sender<DeviceEvent>>>> = OnceLock::new();

fn sender() -> &'static Mutex<Option<Sender<DeviceEvent>>> {
    SENDER.get_or_init(|| Mutex::new(None))
}

/// Demarre la surveillance et renvoie le canal des evenements apaises.
///
/// Le fil vit aussi longtemps que le processus. Appeler cette fonction
/// plusieurs fois renvoie une erreur : une seule surveillance suffit.
pub fn watch() -> Result<Receiver<DeviceEvent>, String> {
    let (raw_tx, raw_rx) = mpsc::channel::<DeviceEvent>();

    {
        let mut guard = sender().lock().map_err(|_| "canal corrompu".to_string())?;
        if guard.is_some() {
            return Err("la surveillance des peripheriques est deja active".into());
        }
        *guard = Some(raw_tx);
    }

    // Fil de la fenetre message-only : il ne fait que tourner sa boucle de
    // messages.
    std::thread::Builder::new()
        .name("bootsel-hotplug".into())
        .spawn(message_loop)
        .map_err(|e| format!("demarrage du fil de surveillance : {e}"))?;

    // Fil d'apaisement : convertit une rafale de notifications en un seul
    // evenement.
    let (tx, rx) = mpsc::channel::<DeviceEvent>();
    std::thread::Builder::new()
        .name("bootsel-hotplug-debounce".into())
        .spawn(move || debounce_loop(raw_rx, tx))
        .map_err(|e| format!("demarrage du fil d apaisement : {e}"))?;

    Ok(rx)
}

/// Regroupe les rafales de notifications en un evenement unique.
fn debounce_loop(raw: Receiver<DeviceEvent>, out: Sender<DeviceEvent>) {
    while let Ok(first) = raw.recv() {
        let mut last = first;
        let deadline = Instant::now() + DEBOUNCE;

        // Absorbe tout ce qui arrive pendant la fenetre d'apaisement.
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match raw.recv_timeout(remaining) {
                Ok(event) => last = event,
                Err(_) => break,
            }
        }

        // Le destinataire a disparu : la surveillance n'a plus d'objet.
        if out.send(last).is_err() {
            return;
        }
    }
}

fn message_loop() {
    // SAFETY: `None` demande le handle du module de l'executable courant, ce
    // qui reussit toujours.
    let Ok(instance) = (unsafe { GetModuleHandleW(PCWSTR::null()) }) else {
        return;
    };

    let class_name: Vec<u16> = "BootselDeviceWatcher\0".encode_utf16().collect();

    let class = WNDCLASSW {
        lpfnWndProc: Some(window_proc),
        hInstance: instance.into(),
        lpszClassName: PCWSTR(class_name.as_ptr()),
        ..Default::default()
    };

    // SAFETY: `class` est valide et ses pointeurs referencent des tampons
    // vivants pendant l'appel. Un echec d'enregistrement est tolere : la
    // classe peut deja exister.
    unsafe { RegisterClassW(&class) };

    // SAFETY: tous les pointeurs sont valides. `HWND_MESSAGE` comme parent
    // cree une fenetre message-only : elle n'apparait jamais a l'ecran et ne
    // figure ni dans la barre des taches ni dans Alt+Tab.
    let window = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR::null(),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(instance.into()),
            None,
        )
    };

    let Ok(window) = window else {
        return;
    };

    if register_for_volume_notifications(window).is_err() {
        return;
    }

    let mut message = MSG::default();
    loop {
        // SAFETY: `message` est une variable locale valide ; `None` demande
        // les messages de tous les fenetres du fil.
        let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
        if result.0 <= 0 {
            return;
        }
        // SAFETY: `message` vient d'etre rempli par `GetMessageW`.
        unsafe {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
}

fn register_for_volume_notifications(window: HWND) -> Result<(), ()> {
    let mut filter = DEV_BROADCAST_DEVICEINTERFACE_W {
        dbcc_size: std::mem::size_of::<DEV_BROADCAST_DEVICEINTERFACE_W>() as u32,
        // 0x00000005 = DBT_DEVTYP_DEVICEINTERFACE
        dbcc_devicetype: 0x0000_0005,
        dbcc_reserved: 0,
        dbcc_classguid: GUID_DEVINTERFACE_VOLUME,
        dbcc_name: [0],
    };

    // SAFETY: `window` est un handle de fenetre valide appartenant a ce fil.
    // `filter` est correctement dimensionne et vit jusqu'apres l'appel ;
    // Windows en copie le contenu.
    let handle = unsafe {
        RegisterDeviceNotificationW(
            HANDLE(window.0),
            &mut filter as *mut _ as *const std::ffi::c_void,
            DEVICE_NOTIFY_WINDOW_HANDLE,
        )
    };

    handle.map(|_| ()).map_err(|_| ())
}

/// Procedure de fenetre. Ne fait que traduire un message en evenement.
///
/// Aucun peripherique n'est ouvert, lu ni identifie ici : ce serait faire du
/// travail dans une procedure de fenetre, et surtout toucher a un materiel
/// inconnu depuis un contexte contraint.
extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_DEVICECHANGE {
        let event = match wparam.0 as u32 {
            DBT_DEVICEARRIVAL => Some(DeviceEvent::Arrived),
            DBT_DEVICEREMOVECOMPLETE => Some(DeviceEvent::Removed),
            _ => None,
        };

        if let Some(event) = event {
            if let Ok(guard) = sender().lock() {
                if let Some(tx) = guard.as_ref() {
                    // Un envoi echoue si plus personne n'ecoute : on ignore,
                    // la surveillance n'a alors plus d'objet.
                    let _ = tx.send(event);
                }
            }
            return LRESULT(1);
        }
    }

    // SAFETY: delegation au traitement par defaut, avec les memes arguments.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portion livree du fichier : tout ce qui precede le module de test.
    ///
    /// Deux precautions, apprises d un echec de CI :
    ///
    /// - les fins de ligne sont normalisees, car git peut livrer du CRLF sous
    ///   Windows et un motif ecrit avec des LF ne correspondrait plus ;
    /// - la coupure vise le **module** de test, pas le premier `#[cfg(test)]`
    ///   venu : il en existe a l interieur de fonctions, et couper la
    ///   amputerait le code livre que l on veut justement analyser.
    fn shipped_source() -> String {
        let source = include_str!("hotplug.rs").replace("
", "
");
        match source.find("
#[cfg(test)]
mod tests") {
            Some(end) => source[..end].to_string(),
            None => source,
        }
    }

    #[test]
    fn the_debounce_window_is_short_enough_to_feel_immediate() {
        // L'objectif annonce est une reaction percue en moins d'une seconde.
        assert!(DEBOUNCE <= Duration::from_millis(400));
        assert!(DEBOUNCE >= Duration::from_millis(100));
    }

    #[test]
    fn a_burst_of_notifications_produces_a_single_event() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || debounce_loop(raw_rx, tx));

        // Windows emet plusieurs notifications pour un seul branchement.
        for _ in 0..8 {
            raw_tx.send(DeviceEvent::Arrived).expect("envoi");
        }

        let first = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("un evenement apaise doit arriver");
        assert_eq!(first, DeviceEvent::Arrived);

        // Et un seul : rien d'autre ne doit suivre.
        assert!(
            rx.recv_timeout(Duration::from_millis(600)).is_err(),
            "la rafale aurait du etre regroupee en un evenement"
        );
    }

    #[test]
    fn the_last_event_of_a_burst_wins() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || debounce_loop(raw_rx, tx));

        raw_tx.send(DeviceEvent::Arrived).expect("envoi");
        raw_tx.send(DeviceEvent::Removed).expect("envoi");

        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).expect("evenement"),
            DeviceEvent::Removed
        );
    }

    #[test]
    fn separate_changes_produce_separate_events() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || debounce_loop(raw_rx, tx));

        raw_tx.send(DeviceEvent::Arrived).expect("envoi");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).expect("premier"),
            DeviceEvent::Arrived
        );

        std::thread::sleep(DEBOUNCE * 2);
        raw_tx.send(DeviceEvent::Removed).expect("envoi");
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(2)).expect("second"),
            DeviceEvent::Removed
        );
    }

    #[test]
    fn the_debounce_loop_stops_when_nobody_listens() {
        let (raw_tx, raw_rx) = mpsc::channel();
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || debounce_loop(raw_rx, tx));

        drop(rx);
        raw_tx.send(DeviceEvent::Arrived).expect("envoi");

        // Le fil doit se terminer de lui-meme, sans tourner indefiniment.
        let deadline = Instant::now() + Duration::from_secs(3);
        while !handle.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(handle.is_finished(), "le fil aurait du s arreter");
    }

    #[test]
    fn the_watcher_reads_nothing_from_the_device() {
        // Garde-fou de revue : signaler un changement ne doit jamais conduire
        // a ouvrir, monter ou lire le peripherique concerne.
        let code = shipped_source();
        for forbidden in [
            "CreateFile",
            "OpenOptions",
            "read_to_string",
            "std::fs::",
            "mount",
        ] {
            assert!(
                !code.contains(forbidden),
                "la surveillance ne doit rien lire du peripherique : {forbidden}"
            );
        }
    }

    #[test]
    fn the_window_is_message_only_and_never_visible() {
        let code = shipped_source();
        assert!(
            code.contains("HWND_MESSAGE"),
            "la fenetre doit etre message-only"
        );
        for forbidden in ["ShowWindow", "WS_VISIBLE", "SW_SHOW"] {
            assert!(
                !code.contains(forbidden),
                "la fenetre de surveillance ne doit jamais etre affichee : {forbidden}"
            );
        }
    }

    #[test]
    fn only_one_watcher_can_be_started() {
        // Le premier appel reussit ; tout appel suivant est refuse plutot que
        // de creer une seconde fenetre et de dupliquer les evenements.
        let first = watch();
        let second = watch();

        assert!(first.is_ok(), "la premiere surveillance doit demarrer");
        assert!(
            second.is_err(),
            "une seconde surveillance doit etre refusee"
        );
    }
}
