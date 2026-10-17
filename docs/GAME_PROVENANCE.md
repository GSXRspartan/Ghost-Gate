# Game code: archive and provenance

Ghost Gate shipped two games during development. **Neither is part of the contest application.**
The Privacy Lab (the contest submission) contains no game code, no game routes, no game assets.

## What was removed from the active application

| Game | Origin | State in `main` |
| --- | --- | --- |
| The Haunted Vault / "Lost Epoch" | original work by this project (text-driven chapters) | removed from `main` on 2026-10-17; history preserved in the commits that built it (`ea81e61`, `cd2e315`, `ca766ba`) |
| "The Buried Spire" dungeon crawler | **third-party**, reused: `github.com/albader94/maze-game-html` @ `51c928c29b286b3d885493cb724b3af3417e9e06`, MIT, © 2025 Bader K Albader | imported, evaluated, then removed from `main`; the full import is preserved on the branch `archive-games-before-privacy-lab` (commit `dccfe7e`), including upstream `LICENSE`, `README` and `CHANGELOG` |

## Third-party attribution — stated plainly

The Buried Spire import was MIT-licensed and the upstream copyright notice and license file were
copied verbatim into `web/spire/` before the branch was archived. The upstream repository also
ships 20 `.mp3` sound files whose **provenance the upstream project does not document**; those were
carried inside the archived branch together with that uncertainty, and are not part of the contest
submission in any form.

A contest submission containing game code would also have created a licensing question the project
had no reason to take on: the original game was written for this repository, and the imported one
was not. Privacy Lab contains none of it, so the submission is entirely original code under this
repository's own licence.

## Reusable things that came out of the game work (and were KEPT)

Game work was not wasted; these improvements live in the non-game code and remain:

* per-connection read/write timeouts on every bridge connection (the "stalled socket starved the
  whole listener" bug — GG-012 in `docs/SECURITY_FINDINGS.md`),
* the `[hidden]`-authoritative CSS rule and the "no stuck overlay on failure" browser-test pattern,
* `scripts/browser_admin_check.sh` + `scripts/cdp-admin-check.mjs`, the headless-Edge CDP harness
  now used for the admin dashboard,
* origin/Host validation, request-size limits and rate limits in the HTTP layer.

## How to inspect the archive

```bash
git branch --list 'archive-games*'
git show archive-games-before-privacy-lab:web/spire/LICENSE
git ls-tree -r archive-games-before-privacy-lab web/spire | head
```

No branch was rewritten and no commit was deleted: the archive is the ordinary history.
