# Product

## Purpose
ClipBridge is an internal working codename only. Do not use it for public branding, package identifiers, domains, or releases. Select the public name separately; do not change existing protocol identifiers as part of a brand rename without a protocol-version review. The product is a local-first, privacy-first way to move a user-selected text snippet, URL, code sample, photo, or small file among their own explicitly trusted devices. Nearby discovery is only an invitation to verify; it never establishes trust. Accounts and subscriptions are not required.

## Phase 1 scope and acceptance
This milestone writes the architecture/security specifications and creates a Rust core with a two-process desktop CLI prototype. Acceptance means separately generated identities can mutually verify pinned fingerprints, complete a Noise handshake over TCP loopback/LAN, send UTF-8 text, reject a peer whose fingerprint is not pinned, reject altered ciphertext, reject replay/out-of-order data, and fail closed on unsupported versions. This is a protocol foundation, not a GUI or production client.

## Later product shape
- Desktop: Tauri shell with TypeScript/React and per-OS Rust adapters.
- Android: Kotlin/Compose shell with a Rust protocol library through a narrow FFI boundary.
- iOS/iPadOS: constrained PWA; clipboard operations remain foreground, user initiated, and browser permission dependent.
- Content is sent only after a user action or an explicitly enabled desktop policy. No default content history, server-side payload storage, automatic file execution, or archive extraction.
- Windows tray, Linux capability reporting, Android Sharesheet and Quick Settings entry points, pairing, diagnostics, and basic guided onboarding/connection explanations are planned after core validation. Rich visual Help & Guide illustrations follow after desktop and Android have those foundational explanations.

## Product promises
The UI must distinguish discovered, verifying, trusted, connected, transferring, paused, and failed states. It must show the active route and why it won, with alternatives and their unavailable reasons. It must say when OS policy blocks clipboard access. It must never imply discovery equals trust, or claim security has been audited before independent review.
