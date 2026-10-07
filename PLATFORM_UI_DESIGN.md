# Cross-platform UI design

**Status:** design specification and interactive visual preview. This file does not claim that the Android client or iOS PWA exists. The shipping Windows/Linux shell remains Phase 3 and its known validation gaps remain in `ROADMAP.md`.

## Product and design contract

ClipBridge is a private handoff tool, not a messenger. The main job is to move a user-selected item between devices the user has explicitly verified. Clipboard is the front door, while Compose and future file/photo transfer are distinct handoff actions. There are no chat bubbles or default content history. Discovery is never trust.

The approved visual direction is **Minimal Native + Technical Premium**. Use calm neutral surfaces, native-feeling typography, one clear blue primary action, subtle dividers, compact status labels, and progressive disclosure for technical connection details. Use system/light/dark appearance. Make status readable through text and icon as well as color. Avoid glossy security metaphors, neon, dashboard density, or marketing-style oversized hero layouts.

## Shared interaction model

### Navigation

- Desktop: persistent rail with Home, Devices, Add Device, Activity, Diagnostics, and Settings; Help & Guide is anchored at the bottom. Keep the current device and app readiness in the lower rail.
- Android: four-item bottom navigation for Home, Devices, Activity, and Settings. Add Device is a prominent action on Devices and an optional top-level action from Home. Diagnostics and Help live under Settings > Help & diagnostics, with contextual links from errors.
- iOS PWA: compact bottom navigation for Home, Devices, and Help. Pairing starts from Devices. Settings and diagnostics are accessible from the Home top menu. Keep the page usable inside the browser viewport and account for safe areas and browser chrome.

Navigation labels remain visible; icon-only navigation is not the default. Preserve focus when changing views and return focus to the triggering control when dismissing a dialog/sheet.

### Home: Clipboard and Compose

Clipboard is the initial tab. It begins in **Not read** state and explains that the app has not read the system clipboard. `Read clipboard` is an explicit action. After a successful read, show an in-memory preview, detected type (Text, URL, Code), byte size, destination selector and available actions: Send, Copy, Clear. Do not save the preview as activity or history. Clear removes the in-memory preview. On Android, clipboard access is subject to OS foreground/visibility rules and never polls around them. On iOS, clipboard read is foreground and user initiated and may require browser permission or an OS confirmation.

Compose is a separate direct-send surface. It offers a multiline input, destination selector, Text/URL/Code classification, byte count, Clear and Send. It never becomes a transcript. Desktop supports Ctrl+Enter; mobile shows the platform keyboard action where supported and retains a visible Send button. Send is disabled until the content is non-empty, a trusted destination is selected, LAN is available, and Privacy Pause is off. The frontend state is ephemeral; typed text is not added to logs, diagnostics, activity, browser storage, or application persistence.

Transfer progress uses the shared sequence `Preparing → Connecting → Encrypted → Sending → Sent`; error states map to stable error codes and explain a next action. Show route facts only from runtime: `Encrypted · LAN direct · No relay`. The concept preview labels all sample values as illustrative, not runtime data.

### Trust and connectivity

Trust and connectivity are independent axes. Trust: `Untrusted`, `Verifying`, `Trusted`, `Needs repair`, `Revoked`. Connectivity: `Offline`, `Connecting`, `Connected`, `Failed`. A device can be Trusted + Offline. A Nearby device is Untrusted until pairing completes. Do not offer content sending to `Needs repair` or Revoked records. No peer is accepted by name, IP address, discovery, or route choice.

### Pairing

1. Add Device creates one protocol-backed invitation. Show the real QR payload, monotonic expiry, and Cancel. The QR is issuer-authenticated; the joining device scans/imports it. Manual data entry is a clearly labeled desktop development path, not a replacement for QR verification.
2. After authenticated Noise XX, show the transcript-derived SAS on both devices and explain: “Compare this code on both devices.” Primary action: `Codes match`; destructive action: `Doesn't match`. Only explicit match confirmation proceeds.
3. Show completion only when local pairing state says `PairingCompleteHere`. Show `Pairing incomplete` for final-window ambiguity or `Needs repair`; explain explicit revoke + fresh QR pairing. Never use a local optimistic animation as proof of peer commit.

The concept preview uses sample SAS text only as an annotated static design example. It cannot establish trust.

### Devices, Activity, Diagnostics, Settings and Help

- Devices: compact rows/cards with local label, platform, trust badge, connectivity badge, trusted date, and last route only if known. Detail view shows shortened fingerprint with explicit copy-full action, minimum protocol, trust state and recent route/session metadata. Revoke requires a confirmation dialog naming the local label and explaining that the device will be denied. Re-pair always begins a fresh invitation.
- Activity: metadata only, such as `Text sent`, device label/reference, time, LAN route and sanitized result. Never include content or payload snippets. Retention is off or bounded and configurable; logging is separate from activity.
- Diagnostics: app/core/protocol versions; OS and clipboard capability; identity/store/database health; LAN status; trust status; session encryption state; sanitized error code. A dedicated serializer allowlists fields. Copy is explicit and previews redacted data before clipboard write. No QR nonce, key material, content, raw paths, or historical IP list.
- Settings: Privacy Pause, bounded metadata retention, appearance, app startup/tray (desktop), clipboard behavior explanation, LAN enablement, and advanced protocol/diagnostic actions. Auto-sync and auto-send remain off and absent as working controls. Unsupported routes are described as unavailable; no inert relay controls.
- Help & Guide: short task articles (pair, verify, send, privacy pause), connection explanations, trust/state vocabulary, and platform limitations. Articles deep-link using the same capability/error identifiers as diagnostics.

## Platform specifications

### Windows desktop (Tauri)

**Form factor:** 1040–1440 px typical window, minimum supported layout target 760 px wide. Persistent 232 px navigation rail above 1100 px; at narrower windows collapse to an accessible rail with labels in a navigation drawer. System title bar and native window controls remain visible. Keep an OS-neutral content max-width around 880 px and allow the main column to shrink (`min-width: 0`) so long labels never force clipping.

**Home composition:** header line shows local device and Ready/Paused/Problem state. Main column starts with compact title and Clipboard/Compose segmented control. A single primary content surface contains the input/preview and destination/send row; a small inline connection summary beneath is progressive detail, not a competing card. If no trusted destination exists, replace Send with `Add a device` and one line of explanation. Clipboard begins Not read.

**Native details:** tray has Open, Send Clipboard (opens explicit clipboard action), Compose, Privacy Pause, status and Quit. Tray copy never exposes content. Use Windows Credential Manager availability and clipboard restrictions from actual runtime diagnostics. OS privacy/sync-exclusion signals are respected when clipboard integration lands; no Phase 3 UI implies background monitoring is enabled.

### Linux desktop (Tauri)

Use the same layout, keyboard flow and visual hierarchy as Windows. Vary only where the compositor or desktop environment changes capabilities. Report X11 vs Wayland and each detected clipboard capability separately. Manual read/write controls remain available where the system exposes them; global monitoring is never promised for generic Wayland. Diagnostics should say the exact capability and practical fallback, e.g. `Clipboard read: manual action available` and `Background monitoring: unavailable on this Wayland session`.

Do not change a trust badge because a route is unavailable. Error/help links use the detected compositor/capability code. Native tray support may vary by environment and must not be portrayed as present unless runtime detection succeeds.

### Android native (Jetpack Compose; future client design)

**Form factor:** edge-to-edge, safe-area-aware, 360–480 dp portrait baseline; also support landscape/tablet without stretching the editor. Use Android system font and Material-aligned touch behavior, but keep ClipBridge's restrained neutral/blue token set rather than adding a second brand palette. All primary touch targets are at least 48 dp. Bottom navigation: Home, Devices, Activity, Settings. Help and Diagnostics are Settings subpages and contextual error actions.

**Home:** top app bar displays local device label and a small Ready/Paused state. Tabs for Clipboard and Compose are a top segmented control. Clipboard shows a privacy illustration made from a real icon asset, Not read state, concise explanation and one `Read clipboard` action. After an explicit permitted read, preview and destination selection appear. Compose uses a focused full-width multiline editor; the IME action is Send when valid, while the visible button remains available. Destination selection uses a modal bottom sheet listing trusted devices only, with trust and online state separately stated.

**Android entry points:** Sharesheet receive/send integration and a user-triggered Quick Settings Send Clipboard tile are designed as explicit actions. The Quick Settings tile opens/foregrounds the app for an explicit clipboard operation; it does not bypass Android background clipboard restrictions. When clipboard data is unavailable due to app focus/lifecycle, show `Open ClipBridge and try again` with a direct action. The app never polls in the background to evade platform privacy. Incoming transfer notifications (if later implemented) contain sender label and item type only, never content; receiving UI obeys lifecycle and consent.

**Pairing:** Add Device opens a full-screen guided stepper: invitation QR with visible countdown/cancel; scan QR entry; then high-contrast 4×4 SAS text with large digits and accessible readout; final state is driven by core pairing result. QR camera permission is requested only after the user selects Scan. A no-camera/manual fallback is explicit and keeps all cryptographic verification.

**Devices:** trusted rows show a platform glyph, label, `Trusted` badge, and `Online`/`Offline` separately. Nearby/untrusted candidates, if real LAN discovery is later added, are in a separate section titled `Nearby · not trusted`; no connect-to-send action until pairing.

**Android navigation/deep links:** system Back returns through the task flow (verification to scan, scan to Devices) without silently committing. Privacy Pause is a persistent, easily reachable Settings/Home control. Quick Settings and Sharesheet entry points route into the same Rust-backed validation and visible app state as in-app actions.

### iOS/iPadOS limited PWA (future client design)

**Threat and capability boundary:** Safari-installed web app, foreground and user initiated. It is not a native clipboard daemon, has no guaranteed background clipboard access, and cannot promise uninterrupted transfer while suspended. Clipboard read/write behavior follows current browser permission and gesture rules. No claim of Quick Settings, native share extension, universal clipboard monitoring, persistent local identity protection equivalent to native keychain, or background transfer.

**Form factor:** 320 px minimum responsive width, safe-area inset padding and dynamic viewport sizing. Keep one-column flow, large tap targets (44 pt minimum), a compact top bar, and fixed bottom navigation only when it does not overlap the keyboard/browser chrome. On iPad use a centered column with a modest max width, not desktop sidebar.

**Home:** browser/PWA context is acknowledged once during onboarding, not as a repeated warning banner. Clipboard shows `Read clipboard` and explains that Safari may ask permission. Reading and writing are directly tied to user gestures; denied permission returns a clear manual copy/paste path. Compose is foreground-only and warns before navigating away if unsent text exists, but does not persist the draft automatically.

**Pairing and identity:** show a QR scanner only when a compatible browser API and permission are available; otherwise offer QR image import/paste only if actually implemented, or pair through a currently supported desktop/Android flow. Do not imply iPhone PWA pairing works until the cryptographic implementation and secure persistence strategy have been validated. Clearly label which identity persistence is browser-managed and provide a reset/re-pair action. If the product cannot protect identity material to the required level in a browser storage context, disable pairing rather than storing it in localStorage or claiming native-equivalent protection.

**Navigation:** Home, Devices, Help. Devices contains trust details and user-initiated pairing where supported. Settings/diagnostics are reachable from a top menu. Activity remains metadata-only and optional; PWA suspension may interrupt in-flight work, and no transfer-history promise is made.

## Visual and component rules

The canonical tokens live in `DESIGN_SYSTEM.md`. Each platform can map components to native conventions while sharing semantics:

- Primary button: one per current task; blue fill, clear verb, visible focus/pressed state; disabled state includes explanation.
- Secondary button: neutral outline/soft fill. Destructive revoke/reject uses red text or border and requires confirmation where it changes trust.
- Trust badge and connection badge are separate semantic components. Use label + icon + color; never color alone.
- Inline route detail uses a lock icon + plain-language security statement. Expanded diagnostics list selected route and unavailable route reasons.
- Input/preview surfaces use a neutral filled or outlined region and preserve readable contrast in light/dark themes. Avoid nested cards.
- Dialogs/sheets trap focus, support Escape/Back where expected, announce heading and errors, and return focus on close.
- Reduced motion removes nonessential transitions. No status is conveyed only through animation.

## Responsive and accessibility requirements

- Desktop: test at 760, 1024, 1280 and 1440 px; no horizontal clipping. At narrow width stack destination and send action and reduce sidebar to drawer.
- Mobile: test 320, 360, 390, 430 dp and landscape; account for keyboard, notches, safe areas, and 200% text scaling.
- WCAG 2.2 AA target for PWA/desktop web surfaces: text contrast 4.5:1 (3:1 large text), controls and focus indicators 3:1, full keyboard operation, visible focus, semantic headings/labels, errors associated with fields, minimum 24×24 CSS px WCAG target (design target is 44×44 on web and 48 dp native).
- Dynamic type/text scaling must not truncate SAS, route, trust, or error labels. SAS is selectable/readable but not exposed through notifications or logs.
- Respect OS theme, reduced motion, forced colors/high contrast where available, screen readers, keyboard navigation, and touch operation.
- Accessibility and platform behavior require real-device/assistive-technology testing; a visual preview alone cannot establish compliance.

## Design preview

Open `work/platform-ui-design/index.html` for a responsive, interactive design study covering the four platform shells and Home, Devices, Pairing, Diagnostics, and Settings states. All data in that study is explicitly illustrative; controls switch design states only and do not connect, read the clipboard, pair devices, or send data.
