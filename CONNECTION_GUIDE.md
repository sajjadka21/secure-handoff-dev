# Connection Guide

## Desktop connection guide status

The desktop currently supports QR-bound pairing and encrypted text transfer over LAN TCP. Add Device creates a real expiring invitation and displays transcript-derived SAS for comparison. Trusted devices remain Offline until a transfer session is active; no discovery is implemented, so the app does not fabricate a Nearby list. WebRTC, Cloudflare signaling, TURN, Bluetooth, and Nearby are unavailable.

`clipcore` provides Noise XX, invitation-bound pairing, QR v1 parsing, transcript SAS, authenticated pairing controls, trust checks, and encrypted text envelopes. The desktop now uses these for pairing and one-shot LAN sessions; each session checks the local trust/revocation database before application data. At present, users share the issuer's displayed LAN address separately and enter the destination address manually. No route fallback is implemented. Relay must remain opt-in, capped, and independent of any assumed free tier when introduced.

Clipboard reading/writing is user initiated using the native clipboard plugin. Linux reports X11 or Wayland from session environment variables; no global Linux clipboard monitoring is implemented or implied. Wayland clipboard operations remain subject to compositor behavior and must surface OS denial. iOS/iPadOS PWA has a separate foreground/user-gesture threat model and is not part of this desktop build.

## Android LAN path (compiled; runtime validation open)

Windows is the pairing issuer in this slice; Android joins by scanning the issuer's actual QR with Google Code Scanner or pasting its hex payload. Rust parses the QR, connects to the first advertised endpoint, verifies the issuer's Noise static key against the QR, derives the SAS, and performs the existing bilateral confirmation/ACK flow after the user confirms. Android is not an invitation issuer yet. Hosted Android ABI/JNI/Kotlin/lint/package checks passed. API 36 emulator instrumentation reached the app but failed protected identity startup/persistence; the targeted atomic-rename correction still awaits a successful rerun. No pairing or transfer E2E is claimed.

For receiving, open Home and choose **Enable receiving** while on a private Wi-Fi/Ethernet LAN. The app displays the current endpoint for manual entry on Windows. The TCP listener is foreground-only and stops when the app leaves the foreground. Sending requires the trusted device and its current address; each text send creates a new Noise-authenticated encrypted session and checks the local trust/revocation database before data. Compose and manually read clipboard text use the same envelope. Received text stays in the active receive surface and is copied only when the user taps **Copy**. Android issuer mode, automatic endpoint discovery, background receive, and routes other than LAN are not implemented.

## Methods and status

| Route | Intended pairings | Current desktop status | Required security |
|---|---|---|---|
| LAN TCP | Windows/Linux desktop on a reachable local network | Implemented in the desktop; endpoint is currently entered/shared manually. Cross-platform app E2E is still pending. | Noise XX + local trust/revocation gate + encrypted envelope |
| LAN TCP | Windows ↔ Android | Android source wires Windows-issued QR pairing, shared trust DB semantics and foreground TCP text transfer; hosted compilation passed, but Android runtime and Windows↔Android E2E remain unverified. Manual endpoints. | Same clipcore Noise, local trust/revocation gate and encrypted envelope |
| Nearby Connections | Android-supported peers | Planned; not implemented | Same Noise session above route |
| Bluetooth/BLE | Native peers where OS APIs and payload needs fit | Planned; not implemented | Same Noise session; BLE is not trust |
| WebRTC DataChannel | Cross-network native/PWA peers | Planned; not implemented | Noise in addition to WebRTC DTLS |
| Cloudflare signaling | WebRTC rendezvous | Planned; no deployment | No content; ephemeral bounded messages |
| Cloudflare TURN | Connectivity fallback | Planned; not implemented | Noise records only; explicit budget cap |

## Desktop pairing and connection

1. On the issuer choose Add device. The issuer creates one random 128-bit nonce held only in process memory, shows a QR for at most 120 seconds on a monotonic clock, and invalidates any prior QR. Restarting the issuer invalidates the QR.
2. The joining device scans and strictly validates canonical CBOR bounds, schema version, and the issuer's key fingerprint. The QR contains the issuer key, not the joiner key. Endpoints and discovered devices remain untrusted hints.
3. The devices establish Noise XX on the selected route. The joining device verifies that the remote Noise static key matches the issuer public key in the QR. The issuer learns the joiner's authenticated static key from Noise XX; it does not verify that key against the QR. The issuer accepts it only after SAS comparison and bilateral user/protocol confirmation.
4. Both show the same transcript-derived verification string. Each person compares it locally and confirms. Both devices then exchange authenticated PAIR_CONFIRM and PAIR_ACK messages.
5. Each device commits trust only after its local validation predicate passes and its local trust transaction succeeds. The two local stores cannot be committed atomically over a failure-prone connection. A failure during the final ACK/commit window can leave temporary asymmetric local trust. If a device observes this failure, show `Pairing incomplete`; disable any local record as `needs_repair` and do not permit content transfer. A local trust record alone does not prove both devices completed pairing.
6. If one device has no active trust, it rejects the next connection before application data. The other device must show a useful recovery error; v1 may require revoking stale local trust and repeating QR pairing. Never silently trust a new key to repair this state.
7. To send text, choose a trusted device, enter its current LAN address, and send. The sender creates a fresh Noise XX session and checks the selected device ID/key before sending. The receiver authorizes the session before parsing/delivering the text envelope. A new secure session is created per transfer; there is no live-session resume or route fallback yet.
7. Discovery never indicates trust. A display-name or identity-key mismatch is rejected and requires explicit revoke/re-pair; never approve a mismatch.

Being discovered does not mean the device is trusted. Never approve a fingerprint or verification string mismatch.

## Platform-specific notes and troubleshooting
- Historical Windows/Linux Phase 1 CLI: use a LAN-reachable TCP address and out-of-band fingerprint pin. The sample process accepts one connection and one text message. Process identities are ephemeral. This is not the current desktop pairing flow; test fixture keys must not be used as persistent app keys.
- Android: from Android 10 (API 29), only the focused app or default IME can read clipboard contents. `getPrimaryClip()` can return null without focus. Background tasks and foreground-service starts are restricted separately; a foreground service does not override clipboard focus restrictions. Use explicit Send Clipboard/Share actions; the app will not poll or bypass system restrictions. Receiving is subject to app lifecycle/platform behavior, and no persistent receiver can be promised before target-version validation. Identity data must be excluded from cloud and device-transfer backup; if the Keystore wrapping key is unavailable after restore, the identity is lost and must re-pair.
- Android LAN: current source targets SDK 36 and uses ordinary foreground TCP sockets; it does not request `NEARBY_WIFI_DEVICES`, which is for nearby Wi-Fi APIs rather than ordinary TCP. Android 16 local-network protections can be enabled for testing. Android 17 requires `ACCESS_LOCAL_NETWORK` for apps targeting API 37+ raw LAN access (or a supported system-mediated picker). Before raising target SDK, implement user-facing rationale and denial/revocation handling and validate both outbound and inbound TCP.
- Linux/X11: the desktop shell and explicit clipboard actions are implemented through the platform clipboard integration, but this pass does not establish compositor-specific runtime validation. X11 selection ownership differs from Wayland.
- Linux/Wayland: clipboard access is compositor-mediated and varies by compositor/session. Data-control/global clipboard monitoring is not a universal Wayland capability. The desktop has no clipboard monitor; explicit actions remain subject to compositor support and must report failures rather than imply universal support.
- iOS/iPadOS PWA: clipboard reads require secure context and browser support/permission/user activation; writes remain user initiated and browser behavior differs. No background sync promise and no native keystore equivalence.

## Help, status and diagnostics contract
The connection screen and Help & Guide use the same route capability identifiers. For each method show (1) platform pairings supported by the design, (2) whether the current endpoint reports it available, (3) selected/unavailable state and plain-language reason, and (4) whether traffic leaves the LAN and its configured relay cost cap. Availability never means trust. For example: “LAN direct — available; lowest-latency eligible route; encrypted session required” or “Wayland clipboard monitoring — unavailable in this compositor session; use Send manually.” Diagnostics are local by default and include route attempt codes/timing buckets only; export is user initiated and previewed. Never export message text, file names, QR nonce, identity secrets or stable discovery IDs.

## V1 priority and route plan
Windows ↔ Android is the first required bidirectional cross-platform pairing and the Android client is the next client under development. Windows ↔ iPhone/iPad follows through the limited foreground PWA where browser APIs permit. Windows ↔ Windows stays secondary while it remains stable and inexpensive. Phase 3 Windows E2E is still OPEN because this host lacked an independent second Windows runtime; the missing environment is not a failed implementation result.

The eventual V1 route target is LAN, Wi-Fi Direct where reliable, WebRTC direct, then cost-capped TURN fallback. BLE is reserved for useful discovery/bootstrap. The Android foundation begins with LAN only. The existing application Noise/trust/session rules are mandatory on every future route. Route selection is never a trust decision. No R2 or persistent server-side payload storage is allowed.

| Pairing | V1 route targets | Current evidence |
|---|---|---|
| Windows ↔ Android | LAN first; later Wi-Fi Direct, WebRTC, capped TURN; BLE bootstrap only if useful | Android implementation and cross-platform E2E are pending until verified in `TEST_PLAN.md` |
| Windows ↔ iPhone/iPad | LAN and WebRTC/TURN only where the PWA/browser actually supports them | Future; no background or native-radio promise |
| Windows ↔ Windows | LAN; other routes only if low-cost to retain | Desktop implementation exists; independent two-client runtime E2E remains open |

## Common error meanings
- `untrusted peer fingerprint`: stop and re-pair/verify; network discovery names/IP do not override the pin.
- `unsupported protocol version`: update both peers; no automatic downgrade.
- `authentication/decrypt failure`: record may be modified or wrong session; connection closes.
- `replayed or out-of-order message`: reject session data and reconnect with fresh ephemeral keys.
- `route unavailable`: explain failed methods and let user retry or select another eligible method. Any fallback still authenticates and encrypts.
- `service quota exceeded`: stop relay usage and report remaining local options; do not incur silent overage. Cloudflare's TURN overview says $0.05 per real-time GB outbound from Cloudflare to the TURN client when not used with Realtime SFU. The TURN FAQ and Realtime pricing page state $0.05/GB and a shared 1,000 GB/month free tier for SFU and TURN. Treat these as provider allowances, not product safety limits: TURN is opt-in/last-resort, hard application/account byte and cost caps always apply, re-check current pricing before deployment, and fail closed at the cap.

## Official platform/service checks (2026-10-06)
- Android clipboard focus restriction: https://developer.android.com/about/versions/10/privacy/changes#limited-access-to-clipboard-data
- Android backup exclusions and data-extraction rules: https://developer.android.com/identity/data/autobackup
- Android LAN access and future runtime permission: https://developer.android.com/privacy-and-security/local-network-permission
- Wayland compositor-mediated data sharing: https://wayland.freedesktop.org/docs/book/Protocol.html
- W3C WebRTC Recommendation and IETF Data Channel protocol: https://www.w3.org/TR/webrtc/ and https://www.rfc-editor.org/rfc/rfc8831
- Cloudflare Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- Cloudflare Durable Objects and WebSocket limits/lifecycle: https://developers.cloudflare.com/durable-objects/api/state/ and https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/
- Cloudflare Realtime TURN overview: https://developers.cloudflare.com/realtime/turn/
- Cloudflare TURN FAQ: https://developers.cloudflare.com/realtime/turn/faq/
- Cloudflare Realtime pricing: https://developers.cloudflare.com/realtime/sfu/platform/pricing/
