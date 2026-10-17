/**
 * Ghost Gate's shim for the Buried Spire.
 *
 * Loaded LAST, after the game's own modules, and deliberately small:
 *
 *   - it paints the gate banner (what the bridge serves, and what you proved),
 *   - it adds the Phantom's commentary by WATCHING the game's public state, not by
 *     editing the engine: every floor descent and every few orbs earns one short,
 *     cheap laugh,
 *   - it exposes `window.GhostGateSpire.status()` for the Ghost Gate site.
 *
 * What it never does is decide anything: the game's completion, score, floor count or
 * localStorage carry no authority here. Access is what the BRIDGE answers to
 * /access/check for a real session, and this page has no say in it. In preview — no
 * gate, no session — this page is exactly the upstream game with a banner on top.
 */
(() => {
    'use strict';

    const line = () => document.getElementById('gg-gate-line');
    const sessionLine = () => document.getElementById('gg-session-line');

    // The Phantom: short, dry, never helpful about anything that matters.
    const QUIPS_FLOOR = [
        'Phantom: "Another floor? You turtles and your real estate."',
        'Phantom: "The validators checked your light. It passed. Barely."',
        'Phantom: "Deeper. The mempool remembers everyone who rushed."',
        'Phantom: "I would tell you what is below, but that would spoil the audit."',
        'Phantom: "Your candle flickers. So does your consensus."',
        'Phantom: "Checkpoint saved. The chain never forgets, unfortunately for you."',
    ];
    const QUIPS_ORB = [
        'Phantom: "An orb. The treasury yawns."',
        'Phantom: "Collected. Nothing was moved on chain. I checked."',
        'Phantom: "That one was stealth. You are welcome."',
    ];
    const QUIPS_GHOUL = [
        'Phantom: "A validator approaches. Smile and walk faster."',
        'Phantom: "It only wants to verify you. Aggressively."',
    ];

    let lastFloor = null;
    let lastOrbs = null;
    let lastGhoulCount = null;
    let orbQuipBudget = 0;

    const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

    function say(quip) {
        // Upstream's own message toast; nothing new is invented for this.
        if (typeof Utils !== 'undefined' && Utils.showMessage) {
            Utils.showMessage(quip, 3200);
        }
    }

    function tick() {
        const game = (typeof GameState !== 'undefined' && GameState.game) || null;
        if (!game) return;

        if (game.floor !== lastFloor) {
            if (lastFloor !== null && game.floor < lastFloor) say(pick(QUIPS_FLOOR));
            lastFloor = game.floor;
        }
        const orbs = game.orbsCollected ?? (game.player && game.player.orbsCollected) ?? null;
        if (orbs !== null && orbs !== lastOrbs) {
            if (lastOrbs !== null && orbs > lastOrbs && orbQuipBudget > 0) {
                say(pick(QUIPS_ORB));
                orbQuipBudget -= 1;
            }
            lastOrbs = orbs;
        }
        const ghouls = Array.isArray(game.ghouls) ? game.ghouls.length : null;
        if (ghouls !== null && lastGhoulCount !== null && ghouls > lastGhoulCount) {
            say(pick(QUIPS_GHOUL));
        }
        if (ghouls !== null) lastGhoulCount = ghouls;
    }

    // ---- banner -----------------------------------------------------------------------
    // Phase 2: the page runs standalone (preview). When the bridge assigns this page to a
    // gate, it will inject the assignment here server-side; the shim only ever READS it.
    function banner() {
        const cfg = window.__GG_SPIRE_CONFIG__;
        if (cfg && cfg.gateId) {
            if (line()) {
                line().textContent = `gate ${cfg.gateId} · ${cfg.symbol || ''} ≥ ${cfg.humanThreshold || cfg.threshold} · clear to floor ${cfg.targetFloor} to earn a fresh session`;
            }
        } else if (line()) {
            line().textContent = 'preview — no gate: play freely, no credentials are issued';
        }
    }

    // ---- the one thing the site may ask ----------------------------------------------
    window.GhostGateSpire = {
        /**
         * A COSMETIC read of the game's public state. The site may use this to say "you
         * reached floor N" — and nothing else. It is not proof of anything, the bridge
         * does not accept it, and no token is ever issued from it.
         */
        status() {
            const game = (typeof GameState !== 'undefined' && GameState.game) || {};
            return {
                floor: game.floor ?? null,
                orbs: (typeof lastOrbs === 'number' ? lastOrbs : game.orbsCollected) ?? null,
                state: game.state ?? null,
                victory: !!game.victory,
                preview: !window.__GG_SPIRE_CONFIG__,
            };
        },
    };

    function boot() {
        banner();
        orbQuipBudget = 2; // a couple of orb quips per floor, not one per orb
        setInterval(tick, 1000);
        setInterval(banner, 4000); // the banner catches a late assignment without a reload
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
