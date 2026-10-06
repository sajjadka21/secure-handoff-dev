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
