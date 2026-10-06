# Roadmap

## Phase 1 — Foundation and protocol proof (complete)
- [x] Repository layout and architecture/security specifications.
- [x] Shared Rust core skeleton and LAN-only text exchange prototype.
- [x] Execute tests; record results and review scope in `TEST_PLAN.md`.
- Not included: QR image/SAS UI, desktop/mobile clients, clipboard access, file transfer, production interfaces.

## Phase 2 — Pairing and identity core hardening (open; validation gates incomplete)
The Rust core contains implementation foundations for identity, trust, pairing, QR parsing, and OS secure storage. Remaining platform and quality gates are listed below; no unexecuted check is counted as passing.

1. Persistent X25519 identity record abstraction with strict v1 record validation and explicit replacement.
2. Transactional SQLite local trust/revocation database and Windows Credential Manager and Linux Secret Service adapters. They fail closed and have no file fallback; real OS service fault injection/runtime checks remain incomplete.
3. Bounded QR v1 deterministic CBOR codec, checked protocol vector, separately generated test vector and parser property test. Fuzz targets and corpus are present; a bounded fuzz run has not completed on this Windows/MSVC host.
4. Volatile issuer nonce lifecycle, injected monotonic time, throttling, and QR/protocol/version/nonce-bound Noise XX prologue.
5. SAS comparison contract and authenticated bilateral `PAIR_CONFIRM` / `PAIR_ACK` state machine. Before an endpoint's local commit predicate passes, failure must create no active trust. Final-window loss may leave asymmetric local trust; an endpoint that observes failure quarantines its local record as `needs_repair`. Unauthorized or unconfirmed peers must never gain active trust. Do not require impossible distributed rollback.
6. Strong revocation and explicit identity replacement/re-pair behavior, including active-session termination.
7. Unit, process, property, adversarial, and cut-point tests for implemented foundations. Parser/state-machine fuzzing is not yet executed; independent interoperability vectors remain open.
8. Verified local Windows results are recorded in `TEST_PLAN.md`. GitHub Actions has not run: the authenticated GitHub integration does not expose repository creation, git push credentials, or workflow dispatch; this checkout has no remote or commits, and the local CLI credential is invalid. Ubuntu 24.04 debug/release builds, `cargo fmt`, strict Clippy, and locked workspace tests remain unverified. None of the four Linux fuzz targets has completed a run; the Windows QR attempt failed before target startup. SBOM generation and dedicated secret scanning are configured in CI but have no completed results. These gates remain open; an unexecuted job or scan is not a pass.
9. Independent review of the Rust protocol wrapper/state machine, crypto vectors, dependency advisories, Snow library maintenance/implementation, and a written decision to retain or replace Snow before any v1 release claim.

Acceptance requires pairing negative cases to prove no unauthorized trust and to verify each endpoint's safe local outcome at every cut point. Do not require impossible simultaneous rollback when one endpoint may already have durably committed after receiving an ACK; test asymmetric-state detection, quarantine when locally observed, and rejection before application data on the non-trusting side. Secure storage failure must fail closed, cross-platform builds must pass, test corpus/fuzz seeds must be checked in, findings reviewed, and docs must match tested behavior. Phase 2 remains open until all required platform and validation gates have evidence. Do not include clipboard monitoring, application UI, Android client/storage implementation, file transfer, further transports, cloud deployment, or PWA work in Phase 2.

## Phase 3 — Desktop foundation and guided onboarding
Tauri/TypeScript shell, Windows and Linux LAN receive/send, identity/pairing flows, basic guided onboarding, connection-method explanations, contextual diagnostics/troubleshooting and tray. Then opt-in Windows clipboard monitor and Linux capability-aware integration. Validate Wayland compositor matrix and privacy exclusions before advertising Linux sync.

## Phase 4 — Android
Kotlin/Compose client, Rust core integration, Android secure key storage, Sharesheet and user-triggered Quick Settings send/receive, plus basic onboarding, connection explanations and contextual platform-specific diagnostics. Validate Android version/background/lifecycle constraints; no clipboard polling bypass.

## Phase 5 — Additional transports and files
Transport telemetry/capability model; LAN discovery, platform Nearby route, BLE bootstrap, WebRTC signaling; only then quota-bounded TURN. After reliability validation, implement user-approved bounded file transfers and later evaluate resume.

## Phase 6 — PWA, help illustrations, accessibility, release
Limited foreground PWA with a distinct threat model; complete visual Help & Guide illustrations after the core onboarding/explanations ship in desktop and Android; accessibility, security review, dependency/process hardening, packaging, reproducible builds and release readiness.
