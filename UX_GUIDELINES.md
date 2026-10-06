# UX Guidelines

- The primary surface is a clipboard-first Home with explicit Send and Receive actions, a one-click privacy pause, and no content history by default.
- Show states with text + icon: Nearby (untrusted), Verifying, Trusted, Connecting, Connected, Sending, Received, Paused, Failed. Discovery must never look like a trusted/connected state.
- Pair by scan QR, confirm expected device and compare the same short authentication words/numbers on both devices, then explicitly trust. Name and OS are descriptive only. Explain that fingerprint mismatch means stop.
- Connection detail identifies current route, availability, and selection reason, for example “LAN direct: same network, low latency; relay unused.” Keep unavailable alternatives explainable.
- Basic guided onboarding, connection-method explanations and contextual diagnostics are part of the first desktop and Android client slices. The richer illustrated Help & Guide follows after those explanations work in-product. Help content keys off shared route/capability/error identifiers so the guide cannot advertise unsupported behavior.
- For every route, distinguish design support, current runtime availability, and trust state. A detected device/route is only an untrusted candidate; never represent it as trusted or connected until pairing/session checks complete.
- Ask user before receiving a file and before overwriting. Show name, size, sender identity and digest check result. Never automatically open/extract.
- Distinguish an OS limitation from app failure. For Android clipboard reads outside the focused app, and PWA clipboard permission, offer a manual action with steps. For Wayland show detected compositor/protocol capability and fallback.
- Privacy settings include auto-send/auto-sync disabled by default, sensitive-content filters, activity content retention off by default, pause, relay opt-in and data cap.
- Clipboard events use a random event ID and authenticated origin device ID for bounded duplicate suppression. An inbound event written to the local clipboard must not be emitted as a new event. Content equality alone is not a loop-prevention mechanism; never suppress a separately user-copied identical value just because its text matches an earlier event.
- Diagnostics share is explicit, redacted and previewed. Never include clipboard contents.
- Light/dark themes, responsive layouts, semantic headings, keyboard navigation, accessible focus and labels, high contrast, reduced motion and color-independent statuses are requirements.
