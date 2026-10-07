# Contributing

## Development and validation
Rust workspace uses edition 2024 and MSRV 1.89. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, and `cargo test --workspace --locked`. For the desktop, run `npm ci`, `npm test`, `npm run build`, and the platform Tauri checks from `apps/desktop`; Linux additionally needs Tauri's documented WebKitGTK prerequisites and a Secret Service session. CI covers Windows 2022 and Ubuntu 24.04. Keep crypto/protocol changes small, with a short design note, updated protocol version/vectors when wire behavior changes, and positive/negative tests. Do not represent a CI matrix as passed until its run has completed successfully.

## Security-sensitive changes
Never add a custom cryptographic primitive or plaintext fallback. Discuss cryptographic pattern, identity binding, transcript fields, replay behavior, failure behavior, and dependency version before implementation. Update `PROTOCOL.md`, `THREAT_MODEL.md`, `SECURITY.md`, and `TEST_PLAN.md` together. Include dependency review and primary-source links. Do not claim audited/production secure without independent review.

Pairing changes must preserve bilateral user/protocol confirmation: neither side persists active trust before its local commit predicate (local SAS confirmation, authenticated peer confirmation, validated peer ACK, and the required issuer-key check). Cut-point tests must assert each endpoint follows its locally validated state, that wrong/unconfirmed peers never become trusted, and that observed final-window failures quarantine any local trust and fail safely on the next connection. Do not assert impossible rollback of a peer's durable trust after an ACK may already have been received. Route fallback in v1 must create a fresh Noise session and revalidate the pinned key; moving live cipher state between transports is prohibited. Discovery protocols must be tested for stable identity leakage. A release cannot pass the security gate until an independent wrapper/state-machine review, fixed vectors, dependency advisory review, Snow assessment, and written keep/replace decision are recorded.

## Privacy and storage
Do not commit real identity keys, clipboard samples, files, logs with payloads, secrets, or user data. Any fixture keys must be generated for tests and disposable. Server features must not persist payloads or use R2. Logs contain metadata only.

## Platform changes
Document OS version/capability restrictions and test unsupported cases. Do not work around Android privacy restrictions or claim Wayland support without compositor-specific validation. PWA changes require browser-specific user-activation testing.

## Pull requests
Describe scope, acceptance criteria, commands/results, platforms tested, protocol compatibility, docs updated, unresolved risks and migration impact. Add no mock or placeholder behavior that the UI calls completed.
