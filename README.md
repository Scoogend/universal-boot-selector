# Universal Boot Selector

Pick which operating system your PC boots into **next time**, then reboot into
it — without ever changing your permanent boot order.

Works on Windows and Linux. Written in Rust, ~3 MB, no runtime dependencies.

```
┌──────────────────────────────────┬──────────────────────────┐
│ AVAILABLE SYSTEMS                │  Debian                  │
│ ▪ Windows Boot Manager  [current]│                          │
│   Windows Boot Manager · NVMe    │  Type          Linux     │
│ ▪ Debian                         │  Loader        shim(GRUB)│
│   shim (GRUB) · NVMe SSD         │  Device        NVMe SSD  │
│ ▪ Linux USB                      │  UEFI entry    Boot0002  │
│   GRUB · SanDisk 64 GB           │  EFI path      \EFI\…    │
│                                  │  Confidence    Confirmed │
│                                  │                          │
│                                  │  [Rename] [Reboot into →]│
└──────────────────────────────────┴──────────────────────────┘
```

---

## The one thing this program writes

**Two bytes.** The UEFI variable `BootNext`, and only when you confirm.

`BootNext` tells the firmware: *for the next boot only, start this entry*. The
firmware consumes it and forgets it. Your permanent boot order — `BootOrder` —
is never touched, so your machine keeps starting the way it always has.

If the selected system fails to start, the firmware falls back to `BootOrder`.
You reboot and you are back where you were. Nothing is damaged.

## What it never does

It cannot format, create, delete, resize or move a partition. It cannot edit a
GPT or MBR table, write to an EFI System Partition, install or replace a boot
loader, modify Windows or Linux, or reorder your permanent boot sequence.

Not "it is configured not to" — **the code that would do those things does not
exist in this repository**, and a test fails the build if anyone adds it.

## Why you might trust that

Four independent barriers, each verifiable:

| # | Barrier | How you can check it |
|---|---|---|
| 1 | **Compilation** — the business-logic crate declares `#![forbid(unsafe_code)]` and has no filesystem, process or network access at all | `test_core_crate_has_no_system_access` |
| 2 | **Naming** — the written variable name is a literal constant, never a parameter. Writing `BootOrder` would require adding code, not passing a different string | read `crates/bootsel-helper/src/firmware.rs`, it is ~250 lines |
| 3 | **Runtime guard** — a full NVRAM snapshot is taken before and after every write, and the operation fails if anything other than `BootNext` differs | `test_only_bootnext_changes` |
| 4 | **Source scanning** — a test greps all shipped code for `diskpart`, `mkfs`, `sgdisk`, `bcdedit`, `efibootmgr -o` and friends, and confines privileged calls to a short allowlist | `test_no_destructive_symbols` |

The guard is tested against four *deliberately hostile* simulated firmwares:
one that quietly reorders `BootOrder` behind our back, one that reports success
without writing, one that deletes an entry while writing, and one that writes a
different target. All four are caught and the reboot is refused.

## Double safety before writing

Nothing read at display time is reused when acting. On confirmation, the
firmware is read again from scratch, the target is **re-resolved by a stable
key** rather than by its volatile `Boot####` number, revalidated, and only then
written. A test proves that an entry moved from `Boot0002` to `Boot0007` is
followed correctly instead of writing the stale id — which would have booted
the wrong system.

## Install

Grab the archive for your platform from
[Releases](../../releases), unzip, and run.

**Windows** — `bootsel.exe`. Keep `bootsel-helper.exe` next to it. Windows
shows one UAC prompt: reading firmware boot entries requires administrator
rights *even to read*, and there is no unprivileged API. Decline it and the app
still runs, showing your disks, and offers to retry.

**Linux** — `bootsel`. No elevation is asked at startup: `/sys/firmware/efi/efivars`
is world-readable, so detection works as a normal user. Only writing `BootNext`
asks for authentication.

## Try it with zero risk

```bash
bootsel --mock-boot multi-os --dry-run --no-elevate   # simulated firmware
bootsel-cli                                           # read-only report
```

`bootsel-cli` has no knowledge of boot selection whatsoever — it contains no
write code at all.

## Detection

Boot entries come from firmware variables, decoded from raw `EFI_LOAD_OPTION`
structures with a parser that cannot panic on malformed input (verified by
truncation and single-bit-corruption sweeps over valid fixtures).

Disks are enumerated read-only — WMI on Windows, `/sys/block` on Linux. A disk
is identified as carrying Linux or Windows **purely from GPT partition type
GUIDs**: nothing is mounted and no file is opened to reach that conclusion.

Removable devices appear within a second of being plugged in, via native device
notifications rather than polling.

### An honest limitation

A bootable disk plugged in *after* boot usually has no firmware entry, because
firmwares enumerate removable media at POST. `BootNext` can only target an entry
that exists, and creating one is forbidden here. Such a device is therefore
shown as **detected but not selectable**, with an explanation, rather than
offered as something that would silently fail.

## Build

```bash
cargo test --workspace --features bootsel-platform/mock
cargo build --release --workspace --features bootsel-platform/mock
```

Linux additionally needs `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`,
`librsvg2-dev` and `patchelf`.

## Layout

```
bootsel-core       pure logic — UEFI parsing, model, invariants. No I/O, no unsafe.
bootsel-platform   read-only detection. Windows and Linux. Defines no write.
bootsel-helper     the only binary that can write. Two commands. ~250 lines.
bootsel-ui         the interface. Unprivileged. Cannot write.
```

## Status

Windows is complete and tested on real hardware. Linux is implemented and
covered by fixture tests; real-firmware validation is pending.

## Licence

MIT
