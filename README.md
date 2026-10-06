# Internal project codename: ClipBridge

ClipBridge is an internal working codename only. It is not approved for public branding, package identifiers, domains, or releases. This repository describes a privacy-first, local-first clipboard synchronization and lightweight file-sharing project. No account is required; user content is never designed to be stored server-side. The project is currently implementing Phase 2 pairing and identity hardening. The core includes identity/trust models, Windows/Linux secure-store adapters, canonical QR parsing and a Noise-bound pairing state machine. Phase 2 validation remains open; the protocol wrapper has not had an independent security audit.

## Current state

- Rust workspace: `crates/clipcore`
- Prototype transport: TCP over loopback/LAN
- Session protocol: Noise XX with pinned X25519 peer identity
- Prototype identity is generated in memory for each process and discarded at exit.
- The command-line demo requires manual full-fingerprint comparison. It does not implement QR pairing, protected persistent keys, clipboard APIs, files, or a production GUI.
- Pairing and protected-storage APIs are library foundations; the CLI does not yet use them as a production pairing workflow.

## Run the two-process demo

Build with `cargo build --workspace`. In terminal 1:

```powershell
target\debug\clipbridge.exe listen 0.0.0.0:45678 1
```

Copy the `READY` fingerprint shown by the listener. In terminal 2:

```powershell
target\debug\clipbridge.exe send 192.168.1.20:45678 1 "Hello from my other device"
```

Replace the address with the listener's LAN address. Each process prints its own `READY` fingerprint and then waits for the other process's 64-character fingerprint on stdin. Compare the full values out of band, then paste the peer fingerprint into each terminal. The listener should report the received text. A mismatched pin fails closed. Do not use this ephemeral CLI as a persistent identity store.

## Verify

```powershell
cargo fmt --all -- --check
cargo test --workspace --locked
```

See [PRODUCT.md](PRODUCT.md), [ARCHITECTURE.md](ARCHITECTURE.md), and [PROTOCOL.md](PROTOCOL.md) for scope and wire/security decisions. [TEST_PLAN.md](TEST_PLAN.md) records Phase 2 evidence and open gates; [ROADMAP.md](ROADMAP.md) defines the remaining acceptance work before Phase 3.
