/**
 * GHOST GATE — matrix edges (shared)
 *
 * A real digital rain: one small canvas per margin, drawn with requestAnimationFrame.
 * Each frame lays a translucent wash over the strip — that wash is what fades the
 * glyphs already on it into a trail — then drops the next glyph at each column's
 * head, brighter than the trail behind it. Decorative only: no wallet data, no
 * addresses, nothing that leaves this process. Paused when the tab is hidden and
 * never started under prefers-reduced-motion.
 *
 * Shared by the Privacy Lab and the Mainnet page so both carry the same signature
 * background. `rootId` names the centred content box whose gutters the rain fills.
 */
export function startMatrixEdges(rootId = "lab-root") {
    const host = document.getElementById("matrix-edges");
    if (!host) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    // Halfwidth katakana + latin hex-ish set: the classic rain look, Tari green.
    const glyphs = "01ｱｲｳｴｵｶｷｸｹｺｻｼｽｾﾀﾁﾂﾃﾄﾅﾆﾈﾊﾋﾎﾏﾐﾑﾒﾓﾗﾘﾙﾚﾛABCDEF0123456789";
    const SLOT = 14;          // px per glyph column — tighter for denser rain
    const FONT = "600 13px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
    const BG = "rgb(11, 15, 13)";        // --ink, matched to the page
    const HEAD = "rgb(196, 255, 220)";   // brighter than the trail
    const BODY = "rgb(41, 212, 124)";    // --green
    const PAD = 0;           // let the rain reach the edge of the content
    const MIN_STRIP = 32;    // show rain even on narrower screens
    const dpr = Math.min(window.devicePixelRatio || 1, 2);

    // The dashboard is the centred content box. The gutter is whatever is left of
    // that box, measured from its laid-out rect (correct under either box-sizing mode) on load
    // and on resize — not a hard-coded strip.
    const gutterWidth = () => {
        const w = window.innerWidth || document.documentElement.clientWidth;
        const root = document.getElementById(rootId);
        const content = root ? root.getBoundingClientRect().width : 1180;
        return Math.max(0, Math.floor((w - content) / 2));
    };

    for (const side of ["left", "right"]) {
        const canvas = document.createElement("canvas");
        canvas.className = side;
        host.append(canvas);
        const ctx = canvas.getContext("2d", { alpha: false });
        let w = 0, h = 0, drops = [], raf = 0;

        const seedDrop = (slot, count, stagger) => ({
            slot,
            y: stagger === undefined ? -20 - Math.random() * (h || 600) : stagger,
            speed: 0.6 + Math.random() * 1.9,   // px/frame: visibly different speeds
            trail: 8 + Math.floor(Math.random() * 22), // glyphs kept in the streak
            next: 40 + Math.floor(Math.random() * 260), // frames until the next reset
        });

        const resize = () => {
            const g = gutterWidth();
            const strip = Math.max(0, g - PAD);
            canvas.style.display = strip < MIN_STRIP ? "none" : "block";
            w = strip;
            h = canvas.clientHeight || window.innerHeight || 600;
            canvas.width = Math.max(1, Math.round(w * dpr));
            canvas.height = Math.max(1, Math.round(h * dpr));
            canvas.style.width = w + "px";
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            ctx.fillStyle = BG;
            ctx.fillRect(0, 0, Math.max(1, w), h);
            const slots = Math.max(1, Math.floor(w / SLOT));
            // Scatter the drops across every slot and stagger them down the strip so the
            // columns never fall in lockstep: many independent streams, not one line.
            drops = Array.from({ length: slots }, (_, i) => seedDrop(i, slots, (h / slots) * i + Math.random() * 40));
        };

        const frame = () => {
            if (w > 0) {
                // The fade wash: previous glyphs dim rather than vanish, which is the trail.
                ctx.globalAlpha = 0.16;
                ctx.fillStyle = BG;
                ctx.fillRect(0, 0, w, h);
                ctx.globalAlpha = 1;
                ctx.font = FONT;
                ctx.textBaseline = "top";
                for (const d of drops) {
                    const x = d.slot * SLOT + 1;
                    // Trail body first, then the head on top so the head reads bright.
                    ctx.fillStyle = BODY;
                    ctx.globalAlpha = 0.85;
                    for (let t = 1; t <= d.trail; t++) {
                        const ty = d.y - t * 13;
                        if (ty < -13) break;
                        ctx.globalAlpha = 0.85 * (1 - t / (d.trail + 2));
                        ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], x, ty);
                    }
                    ctx.globalAlpha = 1;
                    ctx.fillStyle = HEAD;
                    ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], x, d.y);
                    d.y += d.speed;
                    if (d.y > h + 30 || --d.next <= 0) {
                        d.y = -20 - Math.random() * 60;
                        d.next = 40 + Math.random() * 260;
                        d.speed = 0.6 + Math.random() * 1.9;
                        d.trail = 8 + Math.floor(Math.random() * 22);
                    }
                }
            }
            raf = requestAnimationFrame(frame);
        };

        resize();
        window.addEventListener("resize", resize);
        raf = requestAnimationFrame(frame);

        // A hidden tab animates nobody: stop the loop, restart it on return.
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                if (raf) cancelAnimationFrame(raf);
                raf = 0;
            } else if (!raf) {
                raf = requestAnimationFrame(frame);
            }
        });
    }
}
