# ClipBridge visual system

This is the shared cross-platform visual language for the approved **Minimal Native + Technical Premium** direction. Native platform controls and typography should remain familiar; these semantic tokens keep trust, connectivity, privacy, and action priority consistent.

## Tokens

### Primitive palette

| Token | Light value | Dark value | Purpose |
|---|---:|---:|---|
| Blue 700 | `#1D5FBF` | `#8AB7FF` | Primary action, selected navigation |
| Blue 800 | `#174B98` | `#B5D1FF` | Primary hover/pressed emphasis |
| Ink 950 | `#18212B` | `#F1F4F7` | Main text |
| Ink 700 | `#526170` | `#C0CAD4` | Secondary text |
| Surface 0 | `#F5F7F9` | `#14191F` | App canvas |
| Surface 1 | `#FFFFFF` | `#1D242C` | Main content surface |
| Surface 2 | `#EEF2F5` | `#252E38` | Quiet input/selected surface |
| Border | `#D9E0E6` | `#37434F` | Dividers and outlines |
| Green 700 | `#147A52` | `#56C697` | Verified healthy/trusted |
| Amber 700 | `#946000` | `#E9B958` | Paused/degraded/needs repair |
| Red 700 | `#B42332` | `#FF858B` | Failure/revocation/destructive |

### Semantic aliases

`canvas`, `surface`, `surface-muted`, `text-primary`, `text-secondary`, `border-subtle`, `action-primary`, `action-primary-hover`, `state-healthy`, `state-attention`, `state-danger`, `focus-ring`.

Never use raw color as the only state signal. Pair semantic colors with text and, on platforms with an icon library, a familiar icon. Avoid green for “connected” if peer trust is not also clear; trust and connectivity are separate labels.

## Type

- Desktop: system UI font stack; use a restrained type scale: 12/14 px supporting text, 16 px body, 20 px section heading, 26 px page title. Keep uppercase eyebrow labels rare and small.
- Android: Android system sans / Roboto with platform dynamic type; 14 sp supporting, 16 sp body, 20 sp title, 26 sp large title. Keep Compose editor at body size or larger.
- iOS PWA: system UI (`-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, sans-serif), respect browser text zoom and safe areas; never bundle a remote font.
- SAS: monospaced digits with stable grouping, at least 28 px desktop / 30 sp Android / 28 CSS px iOS; do not rely on letter-spacing alone to distinguish groups.

## Spacing, shape and elevation

Use a 4 px base spacing rhythm. Common increments: 4, 8, 12, 16, 24, 32, 40. Desktop content padding 28–32 px, mobile 16–20 dp/px. Compact list row minimum 56 dp native / 56 CSS px; touch actions 48 dp Android and 44 pt iOS. Desktop controls are 36–40 px high.

Use 8 px for controls, 10 px for compact panels, 14 px for primary content surfaces, and pill corners only for small badges/segmented controls. Keep border and shadow subtle; no nested card stacks. Elevation denotes an actual floating sheet/dialog, not decoration.

## Shared components and states

| Component | Required states and behavior |
|---|---|
| Primary action | Default, hover/focus, pressed, disabled with reason, loading with text |
| Trust badge | Untrusted, Verifying, Trusted, Needs repair, Revoked |
| Connectivity badge | Offline, Connecting, Connected, Failed |
| Privacy Pause | Off, On; amber and explicitly blocks new sends/pairing; preserves trust |
| Clipboard surface | Not read, Reading, Available, Empty, Permission denied, Error |
| Compose editor | Empty, editing, over limit, destination missing, paused, sending, sent, failed |
| Pairing stepper | Invitation, Scan/import, SAS pending, confirmation sent, complete here, incomplete/needs repair, aborted |
| Error notice | Stable identifier internally, friendly sentence, one next action, optional technical detail |
| Device row | Label/platform, trust and connectivity as separate text, metadata only if known |
| Dialog/sheet | Labeled heading, clear cancel/confirm, focus management, escape/back, focus restoration |

## Platform mappings

- Windows: Tauri content aligned to familiar desktop spacing, resizable content, native title bar, keyboard accelerators, system tray where runtime supported.
- Linux: same web surface as Windows; capability-dependent wording reflects X11/Wayland/compositor detection. Avoid claiming shell affordances that a desktop environment does not expose.
- Android: Jetpack Compose and Material navigation patterns; native back handling, bottom navigation, bottom sheets, IME action, 48 dp targets, dynamic font scaling.
- iOS: Safari/PWA behavior and WebKit constraints; browser-safe-area CSS, 44 pt targets, no claims of Keychain parity or background access. A PWA-specific capability/insecurity state can block features rather than implying desktop parity.

## Interaction and motion

Keep state transitions short (120–180 ms) and nonessential. Respect reduced motion; status changes must not depend on animation. Prefer instant navigation and a restrained crossfade only for content changes when it helps orientation. Loading states say what is happening. Do not animate a success state before the core confirms the matching protocol state.

## Accessibility

Use semantic controls and logical reading/focus order. Focus rings use a 2 px high-contrast outline with 2 px offset. Contrast target: WCAG 2.2 AA. Text and controls remain usable at 200% browser zoom and platform text scaling. Provide labels for icon-only controls (which should be rare), announce errors and pairing state changes, avoid timeout-only invitation UX (show expiry plus explicit renewal), support screen readers and keyboard navigation. Screen readers must announce SAS as four groups with separators.
