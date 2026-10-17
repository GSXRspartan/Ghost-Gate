# Changelog

All notable changes to Buried Spire Quest will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.3.3] - 2026-03-27

### Fixed
- Leaderboard score submissions rejected by Firestore security rules — rules only allowed 5 fields but code sends `completionTimeMs` and `deaths`; updated rules to include the extra fields
- Leaderboard deaths counter accumulated across runs instead of tracking per-run deaths — added `runDeaths` counter that resets each new game
- Leaderboard not showing time played for death submissions — now includes elapsed time on both death and victory
- Leaderboard allowing worse scores to overwrite better ones on same floor — now compares time and deaths as tiebreakers before submitting
- Leaderboard current-player highlighting used name matching instead of UID — two players with the same name would both appear highlighted; now uses playerUID for accurate identification

### Added
- Leaderboard name uniqueness check — queries Firestore on name entry to reject names already taken by another player (case-insensitive)

## [2.3.2] - 2026-03-25

### Fixed
- Tutorial not showing on first playthrough — `storyNarration.js` checked `window.TutorialSystem` but `const` declarations don't attach to `window`; tutorial only worked on subsequent plays because an orb popup would set it
- Leaderboard silently dropping score submissions when player's floor equaled their previous best — changed `<=` to `<` so re-completions with different time/deaths are recorded
- Victory screen covering the name entry dialog — name entry now shows before the victory overlay; victory screen appears after name is entered or dismissed
- Bump service worker cache version to force browsers to load fixes

## [2.3.1] - 2026-03-25

### Fixed
- Final floor (50) never spawning the Ancient Pearl — `placeOrbs` ignored the `floorNum` parameter from `generateFloor`, always reading `game.floor` (which defaults to 1 after reset)
- Bump service worker cache version to force browsers to pick up the fix

### Added
- Claude Code skills for live testing, deployment verification, SW hygiene, Firebase diagnostics, config impact tracing, and game system scaffolding

## [2.3.0] - 2026-03-25

### Added
- Leaderboard now tracks completion time and number of deaths
- Score submission triggers on game victory (previously only on death)
- Full leaderboard screen shows TIME and DEATHS columns

### Changed
- Leaderboard data model extended with `completionTimeMs` and `deaths` fields
- Death screen mini-leaderboard shows time and deaths inline

## [2.2.1] - 2026-03-25

### Fixed
- CSP: added `*.firebaseapp.com` to frame-src and `unsafe-inline` to script-src for Firebase auth
- Bump service worker cache version to force browsers to load updated CSP headers
- Leaderboard name entry popup never appearing due to `window.InputManager` being undefined (`const` doesn't create window properties)
- Leaderboard silently failing on Safari due to Firestore streaming fetch being blocked (added `experimentalAutoDetectLongPolling`)
- Leaderboard init failures invisible in production because diagnostic messages used `console.warn` (suppressed); changed to `console.error`

## [2.2.0] - 2026-03-24

### Added
- Pre-commit/push hooks to enforce changelog and release workflow
- Mobile inventory shown in right-side action buttons with orb icons/colors

### Changed
- Difficulty rebalance: Blue orb light restoration reduced from 20% to 15%, Golden orb reduced from 40% to 25%
- Faster light decay rate (0.035%/frame, up from 0.02%)
- Increased ghoul light drain (0.5%/frame, up from 0.3%)
- Reduced floor transition light bonus from +30 to +15
- More aggressive ghoul scaling: count formula changed from 2 + floor/3 to 3 + floor/2
- Faster ghouls: speed range changed from 0.8-1.2 to 1.0-1.6
- Reduced orb spawns per floor from fixed 12 to dynamic 5-10
- In-game messages are now single-line, positioned under the HUD area
- Achievement notifications simplified to icon + title, positioned under minimap
- Story narration skip button moved to top-left corner
- All game messages shortened for conciseness
- Commit & Release Workflow section in CLAUDE.md made mandatory with numbered steps

### Removed
- Save indicator toast ("Saved" notification)
- Bottom inventory bar on mobile (replaced by side buttons)

### Fixed
- Firebase leaderboard CSP error (added apis.google.com to script-src and frame-src)

## [2.1.0] - 2026-03-24

### Added
- Firebase leaderboard with anonymous authentication and Firestore
- Content Security Policy (CSP) hardening for Firebase integration
- XSS-safe rendering for leaderboard names
- Mobile portrait HUD band to prevent UI overlapping game area

### Fixed
- Intro screen overlap on mobile
- Text layering issues on mobile
- Tab overflow on mobile
- Help button positioning on mobile
- Achievements display on mobile
- Duplicate settings button on mobile
- Safe area support for notched devices
- FPS counter cleanup on mobile

### Security
- Added Firestore security rules with field validation, UID enforcement, and write-only-increase constraints
- API key restricted by HTTP referrer and API scope

## [2.0.0] - 2026-03-23

### Added
- Mobile support with virtual joystick and touch action buttons
- Progressive Web App (PWA) with Service Worker for offline play
- App manifest for mobile/desktop installation
- Achievement system with 10 achievements and animated notifications
- Statistics tracking (play time, deaths, distance, ghouls defeated, and more)
- Enhanced settings modal with tabbed interface (Settings, Statistics, Achievements)
- Graphics quality options (Low, Medium, High)
- Audio controls with volume slider
- Touch sensitivity configuration
- Auto-save toggle
- Object pooling for particles, ghouls, and orbs
- Spatial hash grid for optimized collision detection
- Performance monitoring (FPS counter, frame time tracking)
- Comprehensive error handling with graceful recovery
- Global error handlers for unhandled exceptions and promise rejections
- Ghoul defeat mechanism (ghouls flee at 80%+ light)
- Ambient sound system with contextual SFX
- Debug panel and `window.GameDebug` console tools

### Changed
- Canvas rendering is now responsive and adapts to screen size
- UI scales for mobile portrait and landscape orientations
- Improved light decay balance (reduced from 0.05% per frame)
- Enhanced ghoul AI with smoother state transitions

### Fixed
- Wall collision sticking
- Mobile joystick and touch handling across all game states
- Various gameplay bugs and edge cases

## [1.0.0] - 2025-07-08

### Added
- Core game loop at 60 FPS with HTML5 Canvas rendering
- Procedural maze generation using recursive backtracking
- Dynamic light system as primary survival resource
- 7 orb types: Blue, Golden, Purple (phase), Green (regen), White (reveal), Red (lifeline), Light Wisp
- 3-slot inventory system for power orbs
- Ghoul AI with patrol, stalking, and aggressive states
- 50 floors of increasing difficulty
- Checkpoint system every 5 floors
- Death recovery with light wisps at death locations
- Victory sequence with Ancient Pearl on floor 50
- Tutorial system with step-based contextual popups
- Story narration and lore messages
- Minimap with real-time exploration tracking
- Camera system with smooth player following
- Dual canvas rendering (game + minimap)
- Keyboard input (WASD / Arrow Keys)

## [0.1.0] - 2025-06-24

### Added
- Initial working prototype
- Explorer mode with basic maze, player movement, and light mechanics
- Light depletion logic with ghoul drain multiplier
- Basic inventory and pause menu

[Unreleased]: https://github.com/albader94/maze-game-html/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/albader94/maze-game-html/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/albader94/maze-game-html/compare/137e322...14c772f
[2.0.0]: https://github.com/albader94/maze-game-html/compare/8929562...02273d3
[1.0.0]: https://github.com/albader94/maze-game-html/compare/6c2a327...8929562
[0.1.0]: https://github.com/albader94/maze-game-html/compare/da30219...6c2a327
