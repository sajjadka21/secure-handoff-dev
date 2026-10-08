# Internal project codename: ClipBridge

## V1 platform priority

The first required cross-platform route is Windows ↔ Android, bidirectionally. Windows ↔ iPhone/iPad follows where the limited foreground PWA can support it. Windows ↔ Windows is secondary while it remains stable and low-cost. The eventual route plan is LAN, Wi-Fi Direct where practical, WebRTC direct, then capped TURN; BLE is only for useful discovery/bootstrap. The Android foundation starts with LAN and keeps the existing QR/SAS, pinned identity, Noise encryption, and revocation model. Later routes are not presented as available.

Phase 3 Windows cross-device E2E remains **OPEN** because an independent second Windows runtime was unavailable on the validation host. This is an environmental validation limit, not a failed implementation result. Android SDK/ADB/emulator availability and Android runtime evidence are recorded separately in `TEST_PLAN.md`.

## Phase 4 Android foundation status

`apps/android` contains a Kotlin/Jetpack Compose client source with Keystore-protected identity, QR joining, transcript SAS confirmation, clipcore trust/revocation, foreground LAN receive, and encrypted one-shot text send. Hosted Android CI has passed the Rust Android ABI builds, JNI tests, Kotlin unit tests, lint, and debug packaging. Emulator instrumentation has reached the app but exposed a protected-identity startup/persistence failure; a fail-closed atomic-write adjustment is committed and still awaits a successful rerun. No Windows↔Android pairing or transfer E2E is claimed. See `ROADMAP.md` and `TEST_PLAN.md`.

## Phase 3 desktop implementation status

The current desktop branch contains a Tauri v2 + React/TypeScript shell with Home, Devices, Add Device, Activity, Diagnostics, Settings, and Help & Guide screens. It loads identity through Windows Credential Manager or Linux Secret Service, persists local trust, implements QR-bound Noise pairing with SAS confirmation, and provides encrypted text send/receive over LAN. Clipboard access is explicit. The issuer’s LAN endpoint must currently be shared separately and the destination endpoint entered manually; no LAN discovery or cross-platform desktop E2E result has been verified yet. See `TEST_PLAN.md` for exact evidence and open gates.

Run from `apps/desktop` with `npm install`, then `npm run tauri dev`. Linux requires Tauri v2 WebKitGTK build prerequisites and an available Secret Service collection. Missing, locked, corrupt, or denied identity storage fails closed. Desktop Phase 3 remains OPEN pending two-instance app validation, tray/Privacy Pause verification, and Linux build/runtime evidence. See `ROADMAP.md`, `ARCHITECTURE.md`, and `TEST_PLAN.md` for details.

ClipBridge is an internal working codename only. It is not approved for public branding, package identifiers, domains, or releases. This repository describes a privacy-first, local-first clipboard synchronization and lightweight file-sharing project. No account is required; user content is never designed to be stored server-side. Phase 2 identity/pairing foundations are complete; Phase 3 desktop implementation is in progress. The core includes identity/trust models, Windows/Linux secure-store adapters, canonical QR parsing and a Noise-bound pairing state machine. The protocol wrapper has not had an independent security audit.

## Current state

The current application is the Phase 3 Windows/Linux desktop client in `apps/desktop`: Tauri v2, React/TypeScript, protected persistent identity, local trust database, QR/Noise pairing with transcript SAS, encrypted one-shot LAN text transfer, explicit clipboard read/write, Compose, metadata-only activity, diagnostics, settings, tray wiring, and Help & Guide. LAN endpoint entry is manual; discovery and non-LAN transports are not implemented.

Phase 3 remains **OPEN**. The latest recorded real-app review captured major desktop screens and a real invitation, checked Home/Settings at multiple window widths and both themes, and confirmed no clipping at the tested sizes. Pairing between two independent clients, transfers, tray behavior, full accessibility coverage, Linux app launch, and real X11/Wayland validation remain open. See `TEST_PLAN.md` for exact evidence.

The earlier command-line process exchange is a **historical Phase 1 prototype**, not the current application or a production workflow. It creates ephemeral process identities and uses an out-of-band fingerprint comparison. It remains useful only as a small core transport demonstration.

### Historical CLI demonstration

Build with `cargo build --workspace`. In terminal 1:

```powershell
target\debug\clipbridge.exe listen 0.0.0.0:45678 1
```

Copy the `READY` fingerprint shown by the listener. In terminal 2:

```powershell
target\debug\clipbridge.exe send 192.168.1.20:45678 1 "Hello from my other device"
```

Replace the address with the listener's LAN address. Each process prints its own `READY` fingerprint and then waits for the other process's 64-character fingerprint on stdin. This example is not the desktop pairing flow and must not be used as persistent identity storage.

## Verify

```powershell
cargo fmt --all -- --check
cargo test --workspace --locked
```

See [PRODUCT.md](PRODUCT.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [PROTOCOL.md](PROTOCOL.md) for scope and wire/security decisions. [TEST_PLAN.md](TEST_PLAN.md) records Phase 2 completion evidence and Phase 3 validation status; [ROADMAP.md](ROADMAP.md) defines the remaining desktop acceptance work.
