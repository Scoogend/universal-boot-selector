"use strict";

/* Universal Boot Selector — logique d'interface.
 *
 * Ce fichier ne fait que rendre l'etat renvoye par le coeur et transmettre
 * les intentions de l'utilisateur. Il ne connait ni le firmware, ni les
 * disques, ni la moindre commande systeme : la seule chose qu'il peut envoyer
 * pour designer une cible est une cle stable opaque.
 */

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const el = {
  list: document.getElementById("list"),
  detail: document.getElementById("detail"),
  status: document.getElementById("status"),
  backend: document.getElementById("backend"),
  firmwareMeta: document.getElementById("firmware-meta"),
  overlay: document.getElementById("overlay"),
  dialogTitle: document.getElementById("dlg-title"),
  dialogBody: document.getElementById("dlg-body"),
  dialogCancel: document.getElementById("dlg-cancel"),
  dialogConfirm: document.getElementById("dlg-confirm"),
};

/** Etat local : uniquement de l'affichage, jamais de decision. */
let view = null;
let selectedId = null;
let renaming = false;
let pendingPlan = null;

/* ------------------------------------------------------------- utilitaires */

function icon(name) {
  return `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
}

/** Echappe systematiquement : les descriptions viennent du firmware. */
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function iconFor(os) {
  if (os === "windows") return "windows";
  if (os === "removable_media") return "usb";
  if (os === "firmware_utility") return "firmware";
  if (os === "unknown") return "disk";
  return "linux";
}

function setStatus(message, kind) {
  el.status.textContent = message ?? "";
  el.status.className = "status" + (kind ? ` is-${kind}` : "");
}

/* ---------------------------------------------------------------- rendu */

let render = function () {
  if (!view) return;

  el.backend.textContent = [
    view.backend,
    view.read_only ? "lecture seule" : null,
  ].filter(Boolean).join(" · ");

  const d = view.detection;
  el.firmwareMeta.textContent = d
    ? (d.firmware_mode === "uefi" ? "UEFI" : "BIOS Legacy")
    : "";

  renderList();
  renderDetail();
};

function renderList() {
  const parts = [];
  const d = view.detection;

  if (view.notice) {
    parts.push(`
      <div class="notice">
        ${icon("warn")}
        <div>
          <p>${esc(view.notice)}</p>
          ${view.needs_elevation
            ? `<button type="button" class="btn" data-act="elevate">
                 ${icon("lock")} Lire les entrées UEFI
               </button>`
            : ""}
        </div>
      </div>`);
  }

  const entries = d ? d.entries.filter(visible) : [];
  if (entries.length) {
    parts.push(`<div class="group-label">Systèmes disponibles</div>`);
    parts.push(entries.map(entryRow).join(""));
  }

  const media = d ? d.unlisted_media : [];
  if (media.length) {
    parts.push(`<div class="group-label">Détectés, non sélectionnables</div>`);
    parts.push(media.map(mediumRow).join(""));
  }

  if (!entries.length && !media.length && !view.notice) {
    parts.push(`
      <div class="empty">
        <strong>Aucun autre système détecté.</strong>
        <span>Branchez un périphérique bootable pour qu'il apparaisse automatiquement.</span>
      </div>`);
  }

  el.list.innerHTML = parts.join("");
}

function visible(entry) {
  const ui = view.config.ui;
  if (entry.os === "firmware_utility" && !ui.show_firmware_entries) return false;
  if (entry.availability.state === "device_missing" && !ui.show_unavailable_entries) return false;
  return true;
}

function entryRow(entry) {
  const selected = entry.stable_id === selectedId;
  const blocked = entry.availability.state !== "available";

  const sub = [entry.bootloader_label ?? bootloaderLabel(entry.bootloader),
               entry.device_label].filter(Boolean).join(" · ");

  let tag = "";
  if (entry.is_current) tag = `<span class="row-tag is-current">démarrage actuel</span>`;
  else if (blocked) tag = `<span class="row-tag is-blocked">${esc(availabilityLabel(entry.availability))}</span>`;

  return `
    <button type="button" role="option" aria-selected="${selected}"
            class="row${selected ? " is-selected" : ""}"
            data-act="select" data-id="${esc(entry.stable_id)}">
      <span class="row-icon">${icon(iconFor(entry.os))}</span>
      <span class="row-text">
        <span class="row-name">${esc(entry.display_name)}</span>
        <span class="row-sub">${esc(sub)}</span>
      </span>
      ${tag}
    </button>`;
}

function mediumRow(medium) {
  const selected = medium.device_id === selectedId;
  return `
    <button type="button" role="option" aria-selected="${selected}"
            class="row is-inert${selected ? " is-selected" : ""}"
            data-act="select-medium" data-id="${esc(medium.device_id)}">
      <span class="row-icon">${icon(iconFor(medium.os))}</span>
      <span class="row-text">
        <span class="row-name">${esc(medium.display_name)}</span>
        <span class="row-sub">${esc(medium.device_label)}</span>
      </span>
      <span class="row-tag is-blocked">sans entrée UEFI</span>
    </button>`;
}

function bootloaderLabel(kind) {
  return {
    windows_boot_manager: "Windows Boot Manager",
    grub: "GRUB",
    systemd_boot: "systemd-boot",
    shim: "shim (GRUB)",
    refind: "rEFInd",
    removable_fallback: "Chargeur EFI amovible",
  }[kind] ?? "Chargeur EFI";
}

function availabilityLabel(availability) {
  return {
    available: "disponible",
    device_missing: "périphérique absent",
    inactive: "inactive",
    not_selectable: "non sélectionnable",
  }[availability.state] ?? "indisponible";
}

function confidenceLabel(c) {
  return { confirmed: "Confirmé", probable: "Probable", unverifiable: "Non vérifiable" }[c] ?? c;
}

/* --------------------------------------------------------------- détails */

function renderDetail() {
  const entry = findEntry(selectedId);
  if (entry) return renderEntryDetail(entry);

  const medium = findMedium(selectedId);
  if (medium) return renderMediumDetail(medium);

  el.detail.innerHTML = `
    <div class="empty">
      <span>Sélectionnez un système pour voir ses informations.</span>
    </div>`;
}

function findEntry(id) {
  return view.detection?.entries.find((e) => e.stable_id === id) ?? null;
}

function findMedium(id) {
  return view.detection?.unlisted_media.find((m) => m.device_id === id) ?? null;
}

function renderEntryDetail(entry) {
  const aliased = view.config.aliases[entry.stable_id] !== undefined;
  const blocked = entry.availability.state !== "available";

  const facts = [
    ["Type", osLabel(entry.os)],
    ["Chargeur", bootloaderLabel(entry.bootloader)],
    ["Périphérique", entry.device_label ?? "—"],
    ["Entrée UEFI", bootIdLabel(entry.id)],
    ["Partition EFI", entry.partition_number != null ? `partition ${entry.partition_number}` : "—"],
    ["Chemin EFI", entry.efi_path ?? "—"],
    ["Confiance", confidenceLabel(entry.confidence)],
    ["État", availabilityLabel(entry.availability)],
  ];

  el.detail.innerHTML = `
    <h2 class="detail-title selectable">${esc(entry.display_name)}</h2>
    <p class="detail-sub">${esc(entry.firmware_description)}</p>

    <dl class="facts selectable">
      ${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("")}
    </dl>

    ${renaming ? renameForm(entry) : ""}

    <div class="actions">
      ${renaming ? "" : `
        <button type="button" class="btn" data-act="rename">Renommer</button>
        ${aliased ? `<button type="button" class="btn" data-act="unname">Nom d'origine</button>` : ""}
        <button type="button" class="btn btn-primary" data-act="reboot"
                ${blocked || view.read_only ? "disabled" : ""}>
          ${icon("arrow")} Redémarrer sur ${esc(shortName(entry.display_name))}
        </button>`}
    </div>

    ${view.read_only ? `<p class="detail-sub" style="margin-top:var(--s-4)">
      Mode lecture seule : aucune écriture n'est possible.</p>` : ""}`;
}

function renameForm(entry) {
  const current = view.config.aliases[entry.stable_id] ?? entry.detected_name;
  return `
    <div style="margin-bottom:var(--s-4)">
      <input type="text" id="alias-input" maxlength="64"
             value="${esc(current)}" aria-label="Nom personnalisé">
      <div class="actions" style="margin-top:var(--s-2)">
        <button type="button" class="btn btn-primary" data-act="rename-save">Enregistrer</button>
        <button type="button" class="btn" data-act="rename-cancel">Annuler</button>
      </div>
      <p class="detail-sub" style="margin:var(--s-2) 0 0">
        Ce nom est local à l'application. Il ne modifie ni le disque, ni la
        partition, ni l'entrée UEFI.
      </p>
    </div>`;
}

function renderMediumDetail(medium) {
  el.detail.innerHTML = `
    <h2 class="detail-title selectable">${esc(medium.display_name)}</h2>
    <p class="detail-sub">${esc(medium.device_label)}</p>

    <dl class="facts selectable">
      <dt>Type</dt><dd>${esc(osLabel(medium.os))}</dd>
      <dt>Partition EFI</dt><dd>partition ${esc(medium.esp_partition)}</dd>
      <dt>Confiance</dt><dd>${esc(confidenceLabel(medium.confidence))}</dd>
      <dt>État</dt><dd>non sélectionnable</dd>
    </dl>

    <div class="notice" style="margin:0">
      ${icon("warn")}
      <div>
        <p>${esc(medium.reason)}</p>
        <p>${esc(medium.suggestion)}</p>
      </div>
    </div>`;
}

function osLabel(os) {
  return {
    windows: "Windows", debian: "Debian", ubuntu: "Ubuntu",
    linux_mint: "Linux Mint", pop_os: "Pop!_OS", fedora: "Fedora",
    arch: "Arch Linux", linux_generic: "Linux",
    removable_media: "Support amovible", firmware_utility: "Utilitaire firmware",
    unknown: "Système inconnu",
  }[os] ?? "Système inconnu";
}

/** `BootId` arrive comme un nombre ; le firmware le nomme `Boot####`. */
function bootIdLabel(id) {
  if (typeof id !== "number") return "—";
  return "Boot" + id.toString(16).toUpperCase().padStart(4, "0");
}

function shortName(name) {
  return name.length > 22 ? name.slice(0, 21) + "…" : name;
}

/* -------------------------------------------------------------- dialogue */

function openDialog(plan) {
  pendingPlan = plan;
  const sub = [plan.bootloader_label, plan.device_label].filter(Boolean).join(" · ");

  el.dialogTitle.textContent = `Redémarrer sur ${plan.display_name}`;
  el.dialogBody.innerHTML = `
    <p>Le prochain démarrage sera effectué sur :</p>
    <div class="target">
      <div class="target-name">${esc(plan.display_name)}</div>
      <div class="target-sub">${esc(sub)}</div>
      ${plan.efi_path ? `<div class="target-sub">${esc(plan.efi_path)}</div>` : ""}
    </div>
    <p class="guarantee">
      L'ordre de démarrage permanent ne sera pas modifié. Seule la variable
      UEFI <strong>BootNext</strong> est écrite ; le firmware la consomme au
      démarrage suivant, puis l'oublie.
    </p>`;

  el.dialogConfirm.textContent = `Redémarrer sur ${shortName(plan.display_name)}`;
  el.overlay.hidden = false;
  el.dialogCancel.focus();
}

function closeDialog() {
  el.overlay.hidden = true;
  pendingPlan = null;
  el.dialogConfirm.disabled = false;
}

/* --------------------------------------------------------------- actions */

async function call(command, args) {
  try {
    return await invoke(command, args);
  } catch (error) {
    setStatus(String(error), "error");
    return null;
  }
}

async function refresh() {
  const next = await call("refresh");
  if (next) {
    view = next;
    render();
  }
}

document.addEventListener("click", async (event) => {
  const target = event.target.closest("[data-act]");
  if (!target) return;
  const act = target.dataset.act;

  if (act === "select" || act === "select-medium") {
    selectedId = target.dataset.id;
    renaming = false;
    render();
    return;
  }

  if (act === "elevate") {
    setStatus("Demande d'élévation…");
    const next = await call("request_elevation");
    if (next) { view = next; render(); setStatus(""); }
    return;
  }

  if (act === "rename") { renaming = true; render();
    document.getElementById("alias-input")?.select(); return; }

  if (act === "rename-cancel") { renaming = false; render(); return; }

  if (act === "rename-save") {
    const name = document.getElementById("alias-input")?.value ?? "";
    const next = await call("set_alias", { stableId: selectedId, name });
    if (next) { view = next; renaming = false; render(); setStatus("Nom enregistré.", "ok"); }
    return;
  }

  if (act === "unname") {
    const next = await call("clear_alias", { stableId: selectedId });
    if (next) { view = next; render(); setStatus("Nom d'origine rétabli.", "ok"); }
    return;
  }

  if (act === "reboot") {
    setStatus("Vérification de la cible…");
    const plan = await call("prepare_selection", { stableId: selectedId });
    if (plan) { setStatus(""); openDialog(plan); }
    return;
  }
});

el.dialogCancel.addEventListener("click", closeDialog);

el.dialogConfirm.addEventListener("click", async () => {
  if (!pendingPlan) return;
  el.dialogConfirm.disabled = true;
  setStatus("Écriture de BootNext…");

  const report = await call("confirm_and_reboot", { plan: pendingPlan });
  if (report) {
    el.dialogBody.innerHTML = `
      <p>Le prochain démarrage est programmé sur <strong>${esc(report.display_name)}</strong>.</p>
      <p class="guarantee">Ordre de démarrage permanent inchangé :
        ${esc(report.boot_order.join(", ") || "—")}</p>
      <p>Redémarrage en cours…</p>`;
    el.dialogConfirm.hidden = true;
    el.dialogCancel.hidden = true;
  } else {
    closeDialog();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !el.overlay.hidden) closeDialog();
});

/* Branchement ou retrait d'un peripherique : le coeur nous previent, on
 * relance un inventaire. Jamais de demarrage automatique, quoi qu'il
 * apparaisse. */
listen("devices-changed", async () => {
  const before = countRows();
  await refresh();
  const after = countRows();

  if (after > before) setStatus("Nouveau peripherique detecte.", "ok");
  else if (after < before) setStatus("Peripherique retire.");
});

function countRows() {
  const d = view?.detection;
  return (d?.entries.length ?? 0) + (d?.unlisted_media.length ?? 0);
}

/* La selection courante peut disparaitre si son peripherique est debranche :
 * l'interface doit s'en remettre sans erreur. */
const baseRender = render;
render = function () {
  if (selectedId && view?.detection
      && !findEntry(selectedId) && !findMedium(selectedId)) {
    selectedId = null;
    renaming = false;
  }
  baseRender();
};

refresh();
