# Product

## Purpose
ClipBridge is an internal working codename only. Do not use it for public branding, package identifiers, domains, or releases. Select the public name separately; do not change existing protocol identifiers as part of a brand rename without a protocol-version review. The product is a local-first, privacy-first way to move a user-selected text snippet, URL, code sample, photo, or small file among their own explicitly trusted devices. Nearby discovery is only an invitation to verify; it never establishes trust. Accounts and subscriptions are not required.

## Phase 1 scope and acceptance
This milestone writes the architecture/security specifications and creates a Rust core with a two-process desktop CLI prototype. Acceptance means separately generated identities can mutually verify pinned fingerprints, complete a Noise handshake over TCP loopback/LAN, send UTF-8 text, reject a peer whose fingerprint is not pinned, reject altered ciphertext, reject replay/out-of-order data, and fail closed on unsupported versions. This is a protocol foundation, not a GUI or production client.

## Later product shape
- V1 platform priority is Windows ↔ Android first and bidirectional, Windows ↔ iPhone/iPad second where foreground browser APIs permit, and Windows ↔ Windows as a lower-cost secondary pairing. Phase 3 Windows E2E remains OPEN because a genuinely independent second Windows runtime was unavailable; this is an environment limitation, not evidence that the implementation failed.
- Eventual V1 route targets are LAN first, Wi-Fi Direct where reliable, WebRTC direct, then quota-capped TURN. BLE is limited to discovery/bootstrap when it gives real value. iOS PWA support is limited to routes actually supported by WebKit/browser APIs; no BLE or Wi-Fi Direct promise is made. No route changes trust or application-layer encryption requirements.
- Desktop: the Phase 3 Tauri + TypeScript/React Windows/Linux shell is implemented around `clipcore`; current LAN endpoint exchange is manual, and Phase 3 validation remains open. See `TEST_PLAN.md` for verified scope.
- Android: Kotlin/Compose native client with the existing Rust protocol/security core behind a narrow JNI boundary. Windows ↔ Android LAN is the first required cross-platform E2E route; this remains planned until implemented and tested.
- iOS/iPadOS: constrained PWA; clipboard operations remain foreground, user initiated, and browser permission dependent.
- Content is sent only after a user action or an explicitly enabled desktop policy. No default content history, server-side payload storage, automatic file execution, or archive extraction.
- Desktop pairing, diagnostics, basic guided onboarding, manual clipboard and Compose text send are implemented; native tray behavior and cross-device end-to-end validation remain open. Android Sharesheet/Quick Settings and rich visual Help illustrations remain future work.

## Product promises
The UI must distinguish discovered, verifying, trusted, connected, transferring, paused, and failed states. It must show the active route and why it won, with alternatives and their unavailable reasons. It must say when OS policy blocks clipboard access. It must never imply discovery equals trust, or claim security has been audited before independent review.
