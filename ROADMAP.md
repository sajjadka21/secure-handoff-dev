# Roadmap

## Phase 1 — Foundation and protocol proof (complete)
- [x] Repository layout and architecture/security specifications.
- [x] Shared Rust core skeleton and LAN-only text exchange prototype.
- [x] Execute tests; record results and review scope in `TEST_PLAN.md`.
- Not included: QR image/SAS UI, desktop/mobile clients, clipboard access, file transfer, production interfaces.

## Phase 2 — Pairing and identity core hardening (complete; validation run #13 passed)
The Rust core contains implementation foundations for identity, trust, pairing, QR parsing, and OS secure storage. Required Phase 2 CI, bounded fuzz, dependency, SBOM, and secret-scan gates completed on Windows Server 2022 and Ubuntu 24.04.5 in [GitHub Actions run #13](https://github.com/sajjadka21/secure-handoff-dev/actions/runs/37503106939), commit 2029641939822517b0963599cbc976140629e91f. Remaining release-review risks are kept explicit below.

1. Persistent X25519 identity record abstraction with strict v1 record validation and explicit replacement.
2. Transactional SQLite local trust/revocation database and Windows Credential Manager and Linux Secret Service adapters. They fail closed and have no file fallback. Windows disposable-target API round-trip/corruption/deletion tests and isolated GNOME Keyring Secret Service round-trip both passed. OS-level fault injection was not executed and is not claimed complete.
3. Bounded QR v1 deterministic CBOR codec, checked protocol vector, independently generated test vector and parser property test. All four Linux fuzz targets completed 21-second runs on Ubuntu 24.04 in CI; results and corpus deltas are recorded in TEST_PLAN.md.
4. Volatile issuer nonce lifecycle, injected monotonic time, throttling, and QR/protocol/version/nonce-bound Noise XX prologue.
5. SAS comparison contract and authenticated bilateral `PAIR_CONFIRM` / `PAIR_ACK` state machine. Before an endpoint's local commit predicate passes, failure must create no active trust. Final-window loss may leave asymmetric local trust; an endpoint that observes failure quarantines its local record as `needs_repair`. Unauthorized or unconfirmed peers must never gain active trust. Do not require impossible distributed rollback.
6. Strong revocation and explicit identity replacement/re-pair behavior, including active-session termination.
7. Unit, process, property, adversarial, and cut-point tests for implemented foundations. Bounded QR, envelope, pairing-control, and pairing-event parser/state-machine fuzz runs passed; longer fuzzing and independent interoperability vectors remain open.
8. GitHub Actions run #13 passed Windows 2022 and Ubuntu 24.04.5 formatting, strict Clippy, locked tests, and debug/release builds; the isolated Linux Secret Service integration passed. The four bounded fuzz targets, cargo audit/deny, CycloneDX SBOM generation, Gitleaks delta scan, and full-history Gitleaks scan also completed successfully. Exact evidence is in TEST_PLAN.md. Dependency duplicate/license metadata warnings are recorded there.
9. Independent review of the Rust protocol wrapper/state machine, crypto vectors, dependency advisories, Snow library maintenance/implementation, and a written decision to retain or replace Snow before any v1 release claim.

Acceptance was met for this milestone: pairing negative cases cover unauthorized-trust prevention and endpoint-local cut-point outcomes; tests do not require impossible distributed rollback; locally observed final-window failure quarantines trust as specified; secure-storage error paths fail closed; Windows/Linux builds and required CI/fuzz/security gates passed; and this roadmap matches tested behavior. Phase 2 is complete. OS-level secure-store fault injection, third-party protocol review, and independent interoperability testing remain release-hardening work, not claimed as completed here. Do not include clipboard monitoring, application UI, Android client/storage implementation, file transfer, further transports, cloud deployment, or PWA work in Phase 2.

## Phase 3 — Desktop foundation and guided onboarding
Tauri/TypeScript shell, Windows and Linux LAN receive/send, identity/pairing flows, basic guided onboarding, connection-method explanations, contextual diagnostics/troubleshooting and tray. Then opt-in Windows clipboard monitor and Linux capability-aware integration. Validate Wayland compositor matrix and privacy exclusions before advertising Linux sync.

## Phase 4 — Android
Kotlin/Compose client, Rust core integration, Android secure key storage, Sharesheet and user-triggered Quick Settings send/receive, plus basic onboarding, connection explanations and contextual platform-specific diagnostics. Validate Android version/background/lifecycle constraints; no clipboard polling bypass.

## Phase 5 — Additional transports and files
Transport telemetry/capability model; LAN discovery, platform Nearby route, BLE bootstrap, WebRTC signaling; only then quota-bounded TURN. After reliability validation, implement user-approved bounded file transfers and later evaluate resume.

## Phase 6 — PWA, help illustrations, accessibility, release
Limited foreground PWA with a distinct threat model; complete visual Help & Guide illustrations after the core onboarding/explanations ship in desktop and Android; accessibility, security review, dependency/process hardening, packaging, reproducible builds and release readiness.
