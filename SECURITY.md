# Security Policy and Engineering Rules

## Status
The Phase 2 identity/pairing foundation and its recorded Windows 2022/Ubuntu 24.04 CI, bounded fuzz, dependency-policy, SBOM, and Gitleaks gates are complete according to the preceding Phase 2 validation record in `TEST_PLAN.md`. The Phase 3 Windows/Linux desktop client is implemented, but Phase 3 remains open: app-level two-instance pairing/transfer, fresh visual QA, native tray behavior, and current Linux runtime/build evidence are not established by this validation pass. Native secure-store fault injection remains incomplete. The project is experimental and not suitable for sensitive production use; no guarantee of security is made.

### Mandatory pre-release review gate
The protocol wrapper and state machine are not independently audited. A v1 release is blocked until an independent reviewer examines the Noise wrapper/state transitions, pairing/confirmation transaction, revocation, QR parser, and platform storage boundary; checked-in fixed vectors and independent interoperability results exist; current dependency advisories and Snow's implementation/maintenance status are reviewed; and maintainers record a written retain/replace decision for Snow. Passing tests or using an established primitive does not close this gate and must not be described as a security audit.

## Rules
- Use established protocols and maintained cryptographic libraries; no custom primitives or ad-hoc crypto.
- Every transport carries application-layer authenticated encryption and authenticates a pinned device key.
- Never log clipboard/file/image bytes, message text, full file names/paths, keys, QR tokens, handshake secrets or unredacted relay metadata.
- Never persist user content on the relay or use Cloudflare R2.
- Fail closed on trust, crypto, protocol, validation, rate/size, protected-store and relay-budget failures.
- Do not store identity secret in plaintext. Production store adapter must expose failure rather than quietly downgrade to file storage. Windows must explicitly use `CRED_PERSIST_LOCAL_MACHINE`, not enterprise/roaming persistence. Android Rust-generated X25519 identity is wrapped at rest by AES-GCM under a Keystore-held key unless direct native X25519 has been proven interoperable and reviewed; no plaintext fallback. Linux Secret Service attributes are lookup metadata that may be unencrypted, so never put secret or device-identifying material in them. The unwrapped Android secret exists in Rust process memory during an active session; memory clearing is best effort.
- Handle secrets with zeroizing buffers where supported; minimize lifetime and copies. Memory zeroization is best-effort, not a guarantee against OS dumps or compromised runtime.
- Run dependency review, `cargo audit`/equivalent advisory checks, license review, SBOM, lockfile checks, fuzz/property tests and platform-specific security tests before release.

## Dependency choices
The core uses `snow` 0.10.x implementing Noise with an explicitly narrowed default resolver (`use-curve25519`, `use-chacha20poly1305`, `use-blake2`, `use-getrandom`) and `x25519-dalek` to derive the public key from an identity secret. `blake3` computes public identity IDs only. `zeroize` clears private buffers on drop on a best-effort basis. `cbor2` 1.1.6 provides canonical CBOR encoding/decoding after a bounded schema preflight. `rusqlite` 0.40.2 with bundled SQLite stores local trust metadata; the database is not encrypted and must be protected by the host profile's file permissions. `uuid` 1.26.1 supplies local record UUIDs. Windows APIs use `windows-sys` 0.61.2; Linux uses `secret-service` 5.1.0. Cargo.lock pins resolved versions. These choices are not independently audited for this product.

The QR parser uses a fixed-shape bounded preflight before `cbor2` allocates owned values; it then rejects duplicate/missing/unknown fields and requires deterministic re-encoding to match the input. The fixed protocol vector is tested. The preceding Phase 2 validation record reports successful bounded Linux fuzz runs for all four targets; longer fuzzing and parser review remain release work, not proof of security.

### Current dependency-policy exception

The Phase 3 Linux system-tray dependency chain currently brings `proc-macro-error` and five `unic-*` crates reported as unmaintained by RustSec; the hosted `cargo deny` output reports no safe upgrade for these transitive crates. `deny.toml` ignores only those six specific unmaintained advisory IDs with this reason, leaving other advisory checks at their existing strict levels. The same run reported a GLib unsoundness advisory as a warning; it is not ignored. Revisit the exceptions when the Tauri/Linux tray dependency chain changes. The desktop's local `clipcore` path dependency declares its matching `0.1.0` package version so the wildcard ban remains enabled. `Apache-2.0 WITH LLVM-exception` is explicitly allowed for the transitive `target-lexicon` crate.

## Internal name
“ClipBridge” is an internal codename only and is not approved for public product branding, package IDs, domains, or releases. The existing v1 protocol prologue/name is a wire identifier and remains unchanged by a product-name decision; any wire-identifier change requires its own protocol compatibility review and version.

## Reporting
Until a private reporting channel exists, use the repository issue tracker only for non-sensitive issues. For suspected vulnerabilities, do not post exploit details publicly; contact maintainers through a verified private channel once configured. Include affected revision, platform, reproduction steps and impact; exclude clipboard/file contents and private keys.
