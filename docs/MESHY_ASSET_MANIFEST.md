# Meshy Asset Generation Manifest — Ghost Gate: The Lost Epoch

*Prepared for a future Meshy.ai MCP session. **No generation is authorised yet**: the gameplay must
stay fun and coherent in placeholder form first, and every asset below is already served by a
placeholder interface that generated art can replace without reworking gameplay.*

## How the placeholders are built (the replacement contract)

- Every visual anchor is a fixed-aspect container with a stable CSS class (`data-art` where JS
  needs to address it). Generated art replaces the CONTENT of the container — a `<img>`, `<model>`
  or CSS background — never its layout box.
- Animation hooks are CSS classes already in the game (`lit`, `pale`, `cracked`, `sealing`,
  `opening`, `unlocked`). Generated assets must respect the same class vocabulary; the state
  machine does not change for art.
- 2.5D approach: static scene plates (WebP/AVIF, ≤ 400 KB each) + a small set of animated props
  (GLB, ≤ 1.5 MB each, ≤ 15k triangles). No full 3D scenes — the page must stay instant on a
  mid-range laptop.
- Nothing generated may carry gameplay meaning that CSS/JS does not already express: art is
  presentation, never a signal channel for proof state.

## Assets

| # | Asset | Where it appears | Format / budget | Placeholder today |
|---|---|---|---|---|
| 1 | **Sanctum environment plate** — the vault hub, three doors visible | `#sanctum` background | WebP 1920×1080 + 960×1080 mobile crop | `#fog`/`#vignette` gradients |
| 2 | **Gate A — The Crypt door** (graveyard stone door, cracked) | `#door-crypt .door-visual` | WebP 512×688 + open-state variant | CSS two-leaf door + sigil glyph |
| 3 | **Gate B — The Vault door** (banker's dial door) | `#door-vault .door-visual` | WebP 512×688 + open variant | CSS two-leaf door |
| 4 | **Gate C — The Abyss door** (eye motif) | `#door-abyss .door-visual` | WebP 512×688 + open variant | CSS two-leaf door |
| 5 | **Crypt chamber plate** — graveyard with ledger stones | `#chamber-crypt` background | WebP 1920×900 | flat dark background |
| 6 | **Ledger stone prop** (4 colour variants via CSS filter) | `.stone` cards | WebP 360×280 each | CSS card |
| 7 | **Witness ghost portraits** — Sexton, Bellringer, Payee Ghost | `.witness` cards | 3 × WebP 256×256 (transparent) | `◍` glyph |
| 8 | **The Phantom — bust portrait** | Phantom lines, ending | WebP 512×512, 2 expressions (neutral, laughing) | none (text only) |
| 9 | **The Phantom — full figure**, idle loop | `#chamber-abyss` stage | GLB ≤ 15k tris or sprite sheet 8 frames | `.abyss-eye` CSS |
| 10 | **Chain dial mechanism** — ornate ring frame with rotating gears | `.dial` + `.ring-track` frames | GLB prop or WebP frame + CSS rotation | CSS pill tracks |
| 11 | **Block fragments** (chip faces) | `.chip`, `.chain-block` | WebP 220×120, corrupted variant with 𝕶 burn mark | CSS card |
| 12 | **Echo pads** (4) — sigil stones that light ember/pale | `.echo` buttons | WebP 256×256 × 4 colours, lit/pale states | CSS radial gradients |
| 13 | **Relic artefacts** — Fragment I dossier page, Fragment II chain seal, Fragment III signed oath | reward presentations | 3 × WebP 512×512 | emoji + text card |
| 14 | **Ending cinematic plate** — the epoch sealing, finality washing the vault | `#ending-overlay` | WebP 1920×1080 + slow pan (CSS) | text over dark |
| 15 | **Title screen key art** | `#title-screen` | WebP 1920×1080 | fog gradients |
| 16 | **Ambient loop** — vault drone with occasional bell | Sanctum + chambers | OGG/MP3 ≤ 300 s loop, ≤ 2 MB | none (silent) |
| 17 | **Stingers** — door open, fragment grant, wrong answer, phantom laugh, epoch seal | interaction feedback | 5 × OGG ≤ 150 KB each | none |
| 18 | **Candle/flame set** (retired crypt candles) — reusable for ambient props | decoration | 1 × GLB or sprite | removed with Chapter I |

## Generation order (when authorised)

1. Phantom portrait + bust (character anchor — everything else is tuned to him).
2. Three gate doors (they define the Sanctum's look).
3. Sanctum plate, title key art.
4. Chapter plates + interactive props (stones, chips, pads).
5. Relics + ending plate.
6. Audio last (loops and stingers), mixed against the existing CSS timing.

## Explicitly out of scope for generation

- Anything that replaces the proof-flow UI (`#proof-overlay`) — it must remain plain, legible and
  unambiguous about what the wallet is being asked to do.
- The preview banner, privacy line and footer text — these are load-bearing honesty labels.
- The mobile layout must keep working with art off entirely (art is an enhancement layer; every
  container has a non-art fallback).
