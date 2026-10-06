# Test Plan

## Phase 1 acceptance tests
1. Unit: create independent static identities and confirm stable, distinct public fingerprints.
2. Unit: envelope round-trip, malformed/truncated header, unsupported version, oversize payload, invalid UTF-8.
3. Unit/integration: complete Noise XX over TCP with two independent processes and exchange exact UTF-8 text.
4. Negative: incorrect expected fingerprint causes close before any application delivery.
5. Negative: flip an encrypted record bit and require AEAD rejection.
6. Negative: submit the exact previously accepted ciphertext again and require Noise counter/replay rejection; duplicate/out-of-order sequence must fail.
7. Negative: unsupported protocol/prologue or envelope version fails closed.
8. Cross-platform: Windows and Linux debug/release compile; Linux X11/Wayland capability behavior only when adapters exist.

## Later security validation
- Property tests for all lengths, integer boundaries, Unicode names, canonical encoding and state transitions.
- Fuzz frame decoder, envelope decoder, pairing QR decoder, transfer offer/chunk sequencing, filenames and cancellation.
- Fixed vectors for QR canonical encoding, identity fingerprint, exact prologue/transcript and SAS formatting; cross-implementation handshake vectors before compatibility claims.
- Crypto test vectors for all handshake messages and transcript/SAS, duplicate/tampered/reordered records, wrong role, wrong protocol, wrong peer, revocation during active session.
- Pairing directionality: the joiner accepts only the issuer Noise static key encoded in its QR; the issuer derives the joiner identity from Noise XX and must not claim it was QR-pinned. A wrong issuer key fails before trust. Neither side may accept an identity without both local/peer SAS confirmation and authenticated pairing controls.
- Pairing cut-point tests: no QR, stale/previous nonce, expiry, restart invalidation, second attempt/replay, rate limit; before/after each local and peer `PAIR_CONFIRM`/`PAIR_ACK`; cancel, timeout, disconnect, mismatch, SAS rejection, storage failure and final-window loss. Assert each endpoint's local state follows only its validated predicate and no unconfirmed/wrong-key peer becomes trusted. Do not require simultaneous rollback after a peer may already have committed. If a local failure is observed in the final window, assert the UX is incomplete and any local trust is quarantined as `needs_repair`; a subsequent connection to the non-trusting endpoint must reject before application data. Verify recovery requires explicit revoke/re-pair and never silently trusts a replacement key.
- Discovery packet-capture/property checks that LAN/mDNS/BLE/Nearby/public signaling contain only rotating random ephemeral IDs and no device ID, static key, fingerprint, account/name or stable derived value. IDs rotate at session end and no later than 2 minutes in a long session and cannot correlate across generated sessions.
- Route-fallback test: force route failure after handshake starts; assert old Noise state closes and a fresh Noise transcript/ephemeral keys/counters are established on the next route against the pinned identity. Never copy/reuse cipher state or partially sent ciphertext.
- Clipboard-loop tests (future): event ID/origin survives multi-device forwarding; dedup bound 4,096/10 minutes; inbound OS write suppression does not create a new event; identical user content remains allowed as a distinct local event.
- QR parser adversarial corpus: duplicate/out-of-order keys, indefinite maps/arrays/strings, huge declared lengths, truncation, invalid UTF-8, tags, trailing items, unknown keys, non-shortest integers, noncanonical map ordering and endpoint/count overflows. Assert size checks happen before allocations.
- Resource tests at and above max frame/message/session quotas; timeouts, slowloris, buffer pressure, cancellation and cleanup.
- Cross-platform tests for protected keystores; unavailable/locked/unlocked/permission-denied behavior; no plaintext fallback.
- Manual platform matrix: X11 clipboard owner lifetime, Wayland compositors and portals, Android lifecycle/API levels and clipboard feedback, browser-specific PWA permissions.
- Cloud service dry-run/local simulator for token replay, rate caps, disconnect cleanup, no persistent content, TURN budget stop and service errors.
- CI dependency advisory and license checks, SBOM, secret scanning, coverage, release artifact review.

## Phase 2 implementation tests and current results

Implemented tests cover: identity record stability, malformed/mismatched key material and explicit replacement; QR protocol vector and independently generated test-only Python CBOR vector, canonical round-trip, checked-in positive/negative corpus, duplicate/unknown/missing fields, invalid UTF-8, indefinite/non-minimal/trailing data, endpoint bounds and arbitrary-byte no-panic property; invitation expiry/replacement/single-use/throttle; prologue version/nonce and wrong issuer; SAS fixed vector and transcript change; pairing confirmation/ACK ordering, unauthorized trust prevention and local repair cut point; trust database persistence, needs-repair/revocation/session invalidation; Noise-protected tamper/replay/sequence rejection; actual two-process pairing and text exchange; and rejection of an untrusted process peer.

Windows x64 with Rust 1.98.1/Cargo 1.98.1: `cargo test --workspace --locked` passed 28 unit tests and 2 process integration tests (30 passed, 0 failed). The sandboxed run denied loopback socket creation (WinSock 10013); the same command passed after loopback access was approved. `cargo fmt --all -- --check`, strict Clippy and offline locked `cargo check --workspace --locked --offline` passed. The standalone fuzz workspace also passes `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`. Windows debug and release builds passed. `cargo audit` 0.22.2 scanned 170 locked crate dependencies against its loaded advisory database and found no advisories. `cargo deny` 0.20.2 reported advisories, bans, licenses and sources `ok` with configured policy; it emitted duplicate-version and unused-license warnings.

Required quality gates and platform results:

- `cargo fmt --all -- --check`: PASS (Windows Rust 1.98.1).
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: PASS (Windows x64 Rust 1.98.1).
- `cargo test --workspace --locked`: PASS on Windows x64, 30 tests; loopback permission was required.
- offline/locked dependency check: `cargo check --workspace --locked --offline` PASS (Windows x64).
- `cargo audit`: PASS, 170 locked crate dependencies, no reported advisories.
- `cargo deny check`: PASS for configured advisories/bans/licenses/sources; duplicate versions are warnings.
- Windows debug/release builds: PASS (Windows x64, Rust 1.98.1/Cargo 1.98.1).
- GitHub Actions Windows/Linux workflow: NOT RUN. The authenticated GitHub integration identifies the owner account, but its available API tools do not provide repository creation, git push credentials, or workflow dispatch. The local checkout has no remote or commits; `git credential fill` returned no GitHub credential and `gh auth status` reports the local CLI token is invalid. Browser automation was unavailable in this run. Thus no private repository, remote, push, hosted workflow run ID, or CI results exist. `.github/workflows/quality.yml` is configured, but configuration is not execution evidence.
- Windows local quality: debug and release builds, formatting, strict clippy, locked tests and offline locked check passed as above. These are local Windows results, not a GitHub Actions run.
- Linux debug/release builds: NOT EXECUTED. WSL returned `Wsl/E_ACCESSDENIED`; Docker and Podman are absent. `cargo build --workspace --locked --target x86_64-unknown-linux-gnu` failed while building `ring` because `x86_64-linux-gnu-gcc` is unavailable. The workflow defines Ubuntu 24.04 builds but has not run.
- Fuzz target results (Linux runs were not started):
  - `qr`: NOT EXECUTED on Linux. A Windows/MSVC smoke with a 2-second budget failed during `ring`/`libfuzzer-sys` linking (LNK1114/access denied overwriting the libfuzzer archive), before target startup; roughly 15 seconds elapsed to termination; 0 executions; crashes/hangs not evaluated.
  - `envelope`: NOT EXECUTED; duration 0; executions 0; crashes/hangs not evaluated.
  - `pairing_control`: NOT EXECUTED; duration 0; executions 0; crashes/hangs not evaluated.
  - `pairing_events`: NOT EXECUTED; duration 0; executions 0; crashes/hangs not evaluated.
  - No fuzz target completed, so no findings were produced and no corpus files were changed by a fuzz run. This is not a clean fuzz result. The checked-in corpus contains the positive protocol/Python QR vectors, negative QR cases, valid/truncated/max-envelope inputs, and valid/truncated pairing controls. CI is configured for 20-second Linux smoke runs per target.
- SBOM: NOT GENERATED locally. Installing pinned `cargo-cyclonedx 0.5.9` failed because the sandbox could not resolve `index.crates.io`. A CycloneDX generation/upload job is configured, but is unrun.
- Dedicated secret scan: NOT EXECUTED locally; Gitleaks is not installed and dependency download is network-blocked. A Gitleaks Action v3 job is configured, but is unrun.
- Native Credential Manager/Secret Service fault injection: NOT EXECUTED. Windows tests check fixed target, machine-local persistence constant and exact identity-blob validation. Linux unit tests check fixed non-identifying attributes and locked/prompt/unavailable error mapping only; Linux tests have not been executed on Linux.

## Remaining validation gate

Phase 2 remains open. This checkout has no Git remote and the configured GitHub token is invalid, so the workflow could not be dispatched or queried. To close the CI gate, configure a valid remote and credentials, trigger `.github/workflows/quality.yml`, and retain the completed Windows 2022 and Ubuntu 24.04 job results. The required Ubuntu 24.04 debug/release builds, formatting, strict Clippy, and locked workspace tests therefore remain unverified. The four Linux fuzz smoke runs did not start; rerun each with bounded execution and report duration, executions, crashes, hangs, corpus changes, and review any finding. The configured SBOM/Gitleaks jobs also need completed results. Native OS-store fault injection remains explicitly incomplete and must not be described as passed.

These checks do not constitute a security audit, cross-platform release validation, or production readiness. See `ROADMAP.md` for the remaining gates.
