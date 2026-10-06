# Connection Guide

## Methods and status

| Route | Intended pairings | Current Phase 1 status | Required security |
|---|---|---|---|
| LAN TCP | Native platforms on reachable network | Implemented only in Phase 1 CLI prototype; loopback tested, not a packaged client | Noise XX + manually pinned identity |
| Nearby Connections | Android-supported peers | Planned; not implemented | Same Noise session above route |
| Bluetooth/BLE | Native peers where OS APIs and payload needs fit | Planned; not implemented | Same Noise session; BLE is not trust |
| WebRTC DataChannel | Cross-network native/PWA peers | Planned; not implemented | Noise in addition to WebRTC DTLS |
| Cloudflare signaling | WebRTC rendezvous | Planned; no deployment | No content; ephemeral bounded messages |
| Cloudflare TURN | Connectivity fallback | Planned; not implemented | Noise records only; explicit budget cap |

## Planned pairing and connection
Production pairing has not yet been implemented; this section defines the expected flow. Phase 1 CLI instead requires manual full-fingerprint pinning and process-lifetime identities.

1. On the issuer choose Add device. The issuer creates one random 128-bit nonce held only in process memory, shows a QR for at most 120 seconds on a monotonic clock, and invalidates any prior QR. Restarting the issuer invalidates the QR.
2. The joining device scans and strictly validates canonical CBOR bounds, schema version, and the issuer's key fingerprint. The QR contains the issuer key, not the joiner key. Endpoints and discovered devices remain untrusted hints.
3. The devices establish Noise XX on the selected route. The joining device verifies that the remote Noise static key matches the issuer public key in the QR. The issuer learns the joiner's authenticated static key from Noise XX; it does not verify that key against the QR. The issuer accepts it only after SAS comparison and bilateral user/protocol confirmation.
4. Both show the same transcript-derived verification string. Each person compares it locally and confirms. Both devices then exchange authenticated PAIR_CONFIRM and PAIR_ACK messages.
5. Each device commits trust only after its local validation predicate passes and its local trust transaction succeeds. The two local stores cannot be committed atomically over a failure-prone connection. A failure during the final ACK/commit window can leave temporary asymmetric local trust. If a device observes this failure, show `Pairing incomplete`; disable any local record as `needs_repair` and do not permit content transfer. A local trust record alone does not prove both devices completed pairing.
6. If one device has no active trust, it rejects the next connection before application data. The other device must show a useful recovery error; v1 may require revoking stale local trust and repeating QR pairing. Never silently trust a new key to repair this state.
7. Discovery never indicates trust. A display-name or identity-key mismatch is rejected and requires explicit revoke/re-pair; never approve a mismatch.

Being discovered does not mean the device is trusted. Never approve a fingerprint or verification string mismatch.

## Platform-specific notes and troubleshooting
- Windows/Linux Phase 1 CLI: use a LAN-reachable TCP address and out-of-band fingerprint pin. The sample process accepts one connection and one text message. Process identities are ephemeral. Key fixture files are only for tests and must not be used as persistent app keys. Protected Windows/Linux identity storage is planned for Phase 2.
- Android: from Android 10 (API 29), only the focused app or default IME can read clipboard contents. `getPrimaryClip()` can return null without focus. Background tasks and foreground-service starts are restricted separately; a foreground service does not override clipboard focus restrictions. Use explicit Send Clipboard/Share actions; the app will not poll or bypass system restrictions. Receiving is subject to app lifecycle/platform behavior, and no persistent receiver can be promised before target-version validation. Identity data must be excluded from cloud and device-transfer backup; if the Keystore wrapping key is unavailable after restore, the identity is lost and must re-pair.
- Linux/X11: classic selections and ownership behavior differ from Wayland; implementation is planned, not currently supported.
- Linux/Wayland: clipboard access is compositor-mediated and varies by compositor/session. Data-control/global clipboard monitoring is not a universal Wayland capability. This Phase 1 build has no clipboard monitor; later builds must detect and report exact capability rather than claim general Wayland support.
- iOS/iPadOS PWA: clipboard reads require secure context and browser support/permission/user activation; writes remain user initiated and browser behavior differs. No background sync promise and no native keystore equivalence.

## Help, status and diagnostics contract
The connection screen and Help & Guide use the same route capability identifiers. For each method show (1) platform pairings supported by the design, (2) whether the current endpoint reports it available, (3) selected/unavailable state and plain-language reason, and (4) whether traffic leaves the LAN and its configured relay cost cap. Availability never means trust. For example: “LAN direct — available; lowest-latency eligible route; encrypted session required” or “Wayland clipboard monitoring — unavailable in this compositor session; use Send manually.” Diagnostics are local by default and include route attempt codes/timing buckets only; export is user initiated and previewed. Never export message text, file names, QR nonce, identity secrets or stable discovery IDs.

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
- Wayland compositor-mediated data sharing: https://wayland.freedesktop.org/docs/book/Protocol.html
- W3C WebRTC Recommendation and IETF Data Channel protocol: https://www.w3.org/TR/webrtc/ and https://www.rfc-editor.org/rfc/rfc8831
- Cloudflare Workers limits: https://developers.cloudflare.com/workers/platform/limits/
- Cloudflare Durable Objects and WebSocket limits/lifecycle: https://developers.cloudflare.com/durable-objects/api/state/ and https://developers.cloudflare.com/durable-objects/concepts/durable-object-lifecycle/
- Cloudflare Realtime TURN overview: https://developers.cloudflare.com/realtime/turn/
- Cloudflare TURN FAQ: https://developers.cloudflare.com/realtime/turn/faq/
- Cloudflare Realtime pricing: https://developers.cloudflare.com/realtime/sfu/platform/pricing/
