# Test Plan

## Phase 3 desktop foundation verification state

Frontend tests in `apps/desktop/src/App.test.tsx` cover classification, screen navigation, actual QR rendering and cancellation calls, protocol-event SAS confirmation/rejection, repair guidance, explicit clipboard read, and Compose invocation to a selected trusted device/address. The Rust desktop crate tests command validation, settings validation, diagnostics field allowlisting, and metadata-only activity retention. `clipcore` tests QR canonical bounds, pairing controls/state cut points, trust/revocation, identity/store records, Noise tamper/replay protection, and encrypted LAN transfer.

Validation on 2026-10-07 used Windows host build `10.0.26200.0`, `x86_64-pc-windows-msvc`, Rust/Cargo `1.98.1`, Node.js `26.4.0`, npm `12.0.2`, and Tauri WebView2. The real Tauri window launched after correcting a clipboard-plugin configuration error and aligning its JavaScript API/plugin minor versions with their Rust crates. Native UI screenshot review identified and fixed dark-theme heading contrast; the default-width Home layout still appears clipped at the right edge in the captured window and needs another visual pass. Windows app-level pairing/transfer and tray interaction have not been demonstrated; Linux builds/runtime are not executed locally.

Manual application tests still required:

- Windows first identity creation, app restart with the same stable identity, and locked/corrupt secure-store behavior; Ubuntu app launch with Secret Service plus X11/Wayland clipboard behavior.
- Ubuntu 24.04 debug/release/Tauri build matrix and CI workflow completion.
- Two real desktop clients complete QR pairing, compare actual Noise transcript SAS, confirm bilateral controls, persist trust, and exchange encrypted LAN text.
- Revocation terminates an active session and blocks a later connection.
- Privacy Pause blocks transfer after transport integration.
- Activity persists metadata only and retention settings prune records.
- Diagnostics redaction review and clipboard behavior on Windows, X11, and Wayland.
- Native tray open/send-clipboard/compose/pause/quit behavior and start-minimized/close-to-tray behavior.

Core unit/process LAN transfer tests pass, but no two-instance Tauri app E2E result is claimed. Phase 3 remains OPEN until desktop application pairing/send/receive/revoke/Pause, Linux builds/runtime, and native tray behavior have direct evidence.

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

## Phase 2 implementation tests and verified results

The shared Rust core tests cover identity-record validation and replacement, canonical QR v1 vectors and parser rejection cases, invitation lifecycle/rate limits, pairing prologue and issuer-key binding, SAS, bilateral confirmation/ACK ordering and local cut points, trust/revocation/session invalidation, authenticated message tampering/replay/version rejection, separate-process pairing/text exchange, and untrusted-peer rejection.

### Hosted quality run

GitHub Actions run [#13](https://github.com/sajjadka21/secure-handoff-dev/actions/runs/37503106939), commit 2029641939822517b0963599cbc976140629e91f, completed successfully on 2026-10-06.

- Windows Server 2022, x86_64 MSVC, Rust 1.99.0 (b940084d7): formatting, strict Clippy, locked workspace tests, debug build, release build all passed. The test job reported 29 unit tests and 2 process integration tests passed.
- Ubuntu 24.04.5 LTS, x86_64 GNU, Rust 1.99.0 (b940084d7): formatting, strict Clippy, locked workspace tests, debug build, release build all passed. The test job reported 28 unit tests passed and 1 isolated-service test ignored in the ordinary run, plus 2 process integration tests passed.
- Linux Secret Service live integration: passed separately in a disposable D-Bus session with GNOME Keyring. It created a fresh identity in the Secret Service, read and validated the record, deleted it, and verified absence. Test output: 1 passed.
- All five workflow jobs completed successfully: Windows quality, Ubuntu quality, bounded fuzz, dependency policy, and security artifacts.

### Bounded Linux fuzz results

Run #13 used Ubuntu 24.04 and nightly Rust 1.101.0-nightly (282215592), with -max_total_time=20 per target. LibFuzzer reports 21 seconds per target. No crashes, hangs, sanitizer findings, or failure artifacts were reported.

| Target | Duration | Executions | Seed corpus → final in-run corpus |
|---|---:|---:|---:|
| qr | 21 s | 9,733,962 | 13 / 3,015 B → 163 / 17 KiB |
| envelope | 21 s | 17,078,166 | 3 / 155 B → 59 / 2,363 B |
| pairing_control | 21 s | 20,335,402 | 2 / 153 B → 10 / 1,097 B |
| pairing_events | 21 s | 20,845,271 | 2 / 153 B → 10 / 1,097 B |

Corpus growth is the runner-local coverage corpus reported by libFuzzer; these generated corpus files were not committed. A bounded smoke run is not exhaustive fuzzing or security validation.

### Dependency and security artifacts

- cargo audit 0.22.2: passed; checked 170 locked crate dependencies against 1,290 loaded RustSec advisories, with no reported advisory.
- cargo deny check 0.20.2: passed configured advisory, ban, license, and source checks. It emitted duplicate-version warnings (cpufeatures, getrandom, r-efi, syn, windows-sys) and license-metadata-not-encountered warnings; those remain cleanup items.
- CycloneDX 1.5 JSON SBOM: generated and uploaded as artifact phase2-cyclonedx-sbom (22,990 bytes; SHA-256 27a5fc36b14548007c5ed76c36f9bb22746918878c1f45a3628e1cc96a5833c9).
- Gitleaks Action delta scan: passed, scanned approximately 112 bytes, no leaks.
- Pinned Gitleaks v8.24.3 full-history scan: passed, scanned 12 commits / approximately 289.88 KB, no leaks. SARIF artifact gitleaks-full-history was uploaded (artifact ID 11430786925; SHA-256 dc99f5f987115b584a04543f4e70ee593a56a58adbd3cef7ad2e6521e8dc3b66).

### Secure-store validation boundaries

- Windows Credential Manager: the disposable-target integration test ran against the real Windows Credential Manager APIs. It verified missing/read/write/read-back, CRED_PERSIST_LOCAL_MACHINE, malformed record rejection, explicit deletion, and missing-record deletion error. It does not touch the production credential target.
- Linux Secret Service: the isolated live GNOME Keyring round-trip passed as noted above; unit tests also cover fixed non-identifying attributes and locked, prompt-denied, and unavailable error mapping.
- OS-level injected failures for Credential Manager and Secret Service were not injected. Do not describe fault injection as completed. These tests establish adapter/runtime behavior for the exercised cases, not every OS service failure mode.

## Phase 2 status and remaining risks

Phase 2 validation gates are complete for this revision. This is a protocol/core milestone, not a claim of production readiness or a substitute for independent security review.

Remaining risks and follow-up work:

- No third-party protocol/implementation security review has been completed. Review pairing state transitions, Noise wrapper behavior, crypto vectors, and dependency choices before a v1 release claim.
- OS keystore fault injection and non-GNOME Secret Service implementations remain unverified.
- Fuzzing was bounded smoke testing only; continue longer fuzzing and review evolving corpus findings.
- Independent interoperability vectors and cross-implementation pairing checks remain open.
- Android, PWA, UI, clipboard/file integrations, and later transports remain outside Phase 2.

cargo fmt, strict Clippy, locked tests/builds, audit/deny, SBOM, secret scanning, and all four bounded fuzz targets have completed on the hosted run above. No unexecuted job is counted as passing.

## Phase 3 local verification results

- `cargo fmt --all -- --check`: **PASS** (Windows).
- `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings`: **PASS** (Windows).
- `cargo test --workspace --locked --offline`: **PASS** — desktop 4/4, clipcore 31/31, process integration 2/2; all other targets/doc tests passed with zero tests.
- Windows Tauri backend `cargo check --offline`: **PASS**. The Tauri dev app launched and reached its real window after runtime-config fixes; Windows Firewall presented its standard network-access prompt. No firewall allow-rule was accepted as part of this validation.
- Windows Tauri release build `cargo build --manifest-path apps/desktop/src-tauri/Cargo.toml --locked --release --offline`: **PASS**.
- `npm run build`: **PASS** — TypeScript check plus Vite production build.
- `npm test -- --reporter=dot`: **PASS** — 9 frontend tests.
- `npm audit`: **PASS** — 0 vulnerabilities after aligning Tauri JS package versions and updating Vitest.
- Ubuntu 24.04 debug/release/Tauri builds and Linux app launch: **NOT EXECUTED** locally. Hosted Windows/Ubuntu compile and build results are recorded in run #17 below; native Linux app launch and compositor-specific runtime validation remain open.
- Two-instance Tauri app pairing/transfer, actual manual clipboard transfer, tray interaction, native Windows secure-store failure injection, and revocation/Pause runtime behavior: **NOT EXECUTED** end to end.
- Real app screenshot: `apps/desktop/ui-review-home.png`. It was reviewed after the contrast adjustment; headings are now readable. A right-edge layout/cropping issue remains visible at the captured size despite responsive spacing changes. Pairing, SAS, Devices, Settings, diagnostics, and other window-size screenshots remain outstanding.

Phase 3 remains OPEN. Passing core process tests and the local Windows build does not replace the required app-level cross-device and Linux validation.

## Final validation attempt (2026-10-07)

This is a separate revalidation pass; results below do not overwrite the earlier recorded successful Windows checks above.

- `cargo clippy --workspace --all-targets --all-features --offline -- -D warnings`: **PASS** on the Windows host.
- `cargo fmt --all -- --check`: **FAILED TO EXECUTE**; Rust reported parent-path canonicalization warnings followed by Windows `Access is denied (os error 5)`.
- `cargo test --workspace --locked --offline`: **FAILED**; the desktop build script reached `tauri::generate_context!` without `OUT_DIR` set. No workspace test results were produced in this attempt.
- Tauri backend offline check: **FAILED TO EXECUTE**; the custom build script terminated on `Access is denied (os error 5)` during path handling.
- Frontend tests and production build: **FAILED TO EXECUTE**; Vite failed to `realpath` files under `apps/desktop/src` with `EPERM`, before tests/modules could run.
- Tauri dev launch: Rust backend compiled and a process was spawned, but startup logged `identity startup failed: identity_store_error`; no successful identity-startup or usable-window claim is made. The available UI inspection API could not expose the native window, and local browser access to the dev server was unavailable.
- Screenshots: **NONE captured in this pass**. The pre-existing `apps/desktop/ui-review-home.png` was reviewed and shows the prior clipping issue. CSS was adjusted in production styles to remove fixed-width pressure and the grid's right offset, but this correction is not visually verified.
- Two-instance E2E, tray, manual clipboard transfer, revocation/Pause runtime flow: **NOT EXECUTED** in this pass.
- Ubuntu Phase 3 debug/release/Tauri/Secret Service validation: **NOT EXECUTED** locally in this pass; hosted build/integration results are recorded in run #17 below.
- GitHub Actions: **NOT EXECUTED** at the time of this local revalidation. GitHub CLI authentication was invalid in that pass; later hosted runs #16 and #17 are recorded below.
- `git diff --check`: **PASS** after the documentation sweep; Git emitted only line-ending normalization warnings. No CI or end-to-end result is inferred from source inspection.

Phase 3 remains OPEN. That local revalidation attempt did not meet the acceptance criteria for real-app screenshot QA, two-client transfer, tray operation, frontend tests/build, Linux build/runtime, or hosted CI. Hosted run #17 later passed the build, test, and CI gates listed below; it does not close the remaining native runtime/E2E/visual gates.

## Phase 3 hosted validation — GitHub Actions run #17

Run [#17](https://github.com/sajjadka21/secure-handoff-dev/actions/runs/37606419345), commit `ce5fa3fb2de2f9ad4c06496df63043f18e85de76`, completed successfully on 2026-10-07. All seven jobs passed.

- Windows 2022 quality: `cargo fmt`, strict Clippy, locked tests, debug build, and release build passed. Test binaries reported 4 desktop tests, 31 core tests, and 2 process integration tests passing.
- Ubuntu 24.04 quality: the same format, Clippy, locked test, debug, and release gates passed. The ordinary test set reported 30 passed and 1 ignored in the 31-test core binary, plus 2 process integration tests. The separate isolated GNOME Keyring Secret Service test passed (1/1).
- Windows and Ubuntu desktop jobs: `npm ci`, `npm audit` (0 vulnerabilities), frontend tests (9/9), TypeScript/Vite production build, Tauri `cargo check --all-targets`, and Tauri debug build passed on both runners.
- Fuzz: all four targets completed bounded 21-second runs with no job failure or crash. Executions reported: `qr` 4,636,035; `envelope` 8,681,709; `pairing_control` 11,889,036; `pairing_events` 11,535,692. This remains bounded smoke testing, not exhaustive security validation.
- `cargo audit`, `cargo deny check`, CycloneDX SBOM upload, Gitleaks delta scan, and full-history Gitleaks scan passed. The SBOM and Gitleaks reports were uploaded as workflow artifacts. `cargo deny` uses the six documented, targeted unmaintained-advisory exceptions added for the Linux Tauri tray GTK3 dependency chain; other advisory, bans, license, and source checks remain enabled. One unmatched-license-allowance warning remains informational.

The initial Phase 3 run [#16](https://github.com/sajjadka21/secure-handoff-dev/actions/runs/37605899263), commit `876677acba5e05de8b58f497682e4b003b084baa`, passed Windows/Ubuntu quality and desktop jobs, fuzz, and security-artifact jobs, but its dependency-policy job failed on the desktop's unversioned local `clipcore` path dependency, six unmaintained Linux tray transitives, and an Apache/LLVM license expression. These were corrected without removing gates; run #17 is the completed passing rerun.

Hosted CI now verifies cross-platform compilation, tests, frontend, Tauri, fuzz, and dependency/security gates. Phase 3 remains **OPEN**: real two-client pairing/SAS/text and clipboard transfer, trust persistence/revocation/Pause behavior, native tray interaction, fresh real-app screenshot and clipping confirmation, accessibility review, and Linux desktop launch/real compositor behavior have not been demonstrated.
