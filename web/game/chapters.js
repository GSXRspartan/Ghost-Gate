/**
 * GHOST GATE — THE LOST EPOCH: the three chapters, wired to the page.
 *
 * Each chapter is built once at boot and exposes enter()/leave(). leave() is called for EVERY
 * navigation away — mid-puzzle, after failure, after success, after reward — and must always
 * cancel pending timers (the Phantom does not get to keep flashing pads in a chamber nobody is
 * watching). Navigation never requires a wallet, the localnet, or a proof; doors do, and that is
 * the whole security separation: a PROOF opens a door, a PUZZLE only ever grants a cosmetic
 * fragment of the story.
 *
 * Chapter III runs an explicit input state machine:
 *   IDLE → SHOWING_SEQUENCE → ACCEPTING_INPUT → CHECKING → NEXT_STAGE | RETRY_STAGE | COMPLETE
 * Input is accepted in ACCEPTING_INPUT only, so one physical click is one input and no transition
 * can swallow or duplicate it.
 */

import {
  CHAPTER1_CASE,
  chapter1Violations,
  chapter1AgreeText,
  chapter1WearText,
  CHAPTER2_DIAL,
  chapter2Evaluate,
  CHAPTER3_STAGES,
  chapter3Expectation,
  chapter3WrongReason,
  PHANTOM_WRONG_ECHO,
  PHANTOM_STAGE_DONE,
  PHANTOM_HINTS_2,
} from "./story.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text;
  return n;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ------------------------------------------------------------------ */
/* Chapter I — Crypt of Lost Transactions (investigation)               */
/* ------------------------------------------------------------------ */

export function buildChapter1(api) {
  const stonesHost = $("crypt-stones");
  const witsHost = $("crypt-witnesses");
  const notes = $("crypt-notes");
  const hint = $("crypt-hint");
  const accuseBtn = $("crypt-accuse");
  const targetLbl = $("crypt-accuse-target");
  const examineBtn = $("crypt-examine");
  const intro = $("crypt-intro");
  let selected = null;

  function note(text, cls) {
    const li = el("li", cls, text);
    notes.append(li);
  }

  function renderStones() {
    stonesHost.replaceChildren();
    for (const s of CHAPTER1_CASE.stones) {
      const card = el("button", "stone" + (api.isSolved("crypt") && s.id === CHAPTER1_CASE.forgedId ? " cracked" : ""));
      card.type = "button";
      card.dataset.stone = s.id;
      card.append(
        el("span", "stone-sigil", s.sigil),
        el("span", "stone-name", s.name),
        el("span", "stone-line", `${s.amount.toLocaleString()} LUME · epoch ${s.epoch}`),
      );
      card.addEventListener("click", () => {
        selected = s.id;
        for (const n of stonesHost.children) n.classList.toggle("selected", n.dataset.stone === s.id);
        targetLbl.textContent = `Selected: ${s.name}'s stone.`;
        accuseBtn.disabled = false;
        hint.textContent = chapter1WearText(s.id).startsWith("Fresh scraping")
          ? "This stone bears fresh scraping under its sigil. Examine it. Then accuse it — or think again."
          : "Read the witnesses, then accuse — or think again.";
      });
      stonesHost.append(card);
    }
  }

  function renderWitnesses() {
    witsHost.replaceChildren();
    for (const w of CHAPTER1_CASE.witnesses) {
      const b = el("button", "witness");
      b.type = "button";
      b.dataset.witness = w.id;
      b.append(el("span", "witness-ghost", "◍"), el("span", "witness-name", w.name));
      b.addEventListener("click", () => {
        if (b.dataset.heard) return;
        b.dataset.heard = "1";
        b.classList.add("heard");
        note(`${w.name}: “${w.text}”`);
      });
      witsHost.append(b);
    }
  }

  accuseBtn.addEventListener("click", () => {
    if (!selected) return;
    const violations = chapter1Violations(selected);
    if (violations.length === 0) {
      hint.textContent = chapter1AgreeText(selected);
      api.phantomSay("Wrong grave, detective. That stone agrees with every witness. Do try to keep up.");
      return;
    }
    // The accusation stands: this is the altered stone.
    const stone = CHAPTER1_CASE.stones.find((s) => s.id === selected);
    const card = [...stonesHost.children].find((n) => n.dataset.stone === selected);
    card.classList.add("cracked");
    note(`ACCUSATION — ${stone.name}'s stone:`, "accuse-line");
    for (const v of violations) note(v.reason, "violation");
    note(
      "Under the scraping, the true record shows through: 3,000 LUME, buried after the third watch, sigil unregistered. The grave was settled — someone just wanted it to look forgotten.",
      "reveal",
    );
    api.phantomSay("Fine. FINE. The Stranger's stone. I borrowed the Widow's sigil because mine gives me hives.");
    accuseBtn.disabled = true;
    api.grantFragment("crypt");
  });

  examineBtn.addEventListener("click", () => {
    if (!selected) {
      hint.textContent = "Select a stone first.";
      return;
    }
    note(`Examined — ${CHAPTER1_CASE.stones.find((s) => s.id === selected).name}: ${chapter1WearText(selected)}`);
  });

  return {
    enter() {
      renderStones();
      renderWitnesses();
      selected = null;
      accuseBtn.disabled = true;
      targetLbl.textContent = "No stone selected.";
      notes.replaceChildren();
      if (api.isSolved("crypt")) {
        // The case is closed: seed the notes so a returning player can re-read the deduction.
        for (const w of CHAPTER1_CASE.witnesses) {
          const b = witsHost.querySelector(`[data-witness="${w.id}"]`);
          b.dataset.heard = "1";
          b.classList.add("heard");
          note(`${w.name}: “${w.text}”`);
        }
        note("CASE CLOSED — the Stranger's stone was altered: borrowed sigil, impossible epoch.", "accuse-line");
        hint.textContent = "The case is closed. The fragment is in your file. You may re-read everything.";
      } else {
        hint.textContent =
          "Hear all three witnesses, examine the stones, then accuse the one that contradicts them.";
      }
      intro.textContent = api.store.puzzles.crypt
        ? "The crypt keeps its paperwork. Even the lies are filed."
        : "Four graves. Four records of what was buried with each. Three tell the truth. The Sexton, the Bellringer and the Payee Ghost are happy to swear to it — the dead love an audience.";
    },
    leave() {
      /* nothing pending; the chapter is fully synchronous */
    },
  };
}

/* ------------------------------------------------------------------ */
/* Chapter II — Vault of Forked Epochs (spatial mechanic)               */
/* ------------------------------------------------------------------ */

export function buildChapter2(api) {
  const feedback = $("vault-feedback");
  const hintText = $("vault-hint-text");
  const hintBtn = $("vault-hint");
  const resetBtn = $("vault-reset");
  const windowEl = $("vault-window");
  const rows = [0, 1, 2].map((r) => ({
    track: $(`vault-ring-${r}`),
    back: $(`vault-back-${r}`),
    fwd: $(`vault-fwd-${r}`),
  }));
  const SHELF_NAMES = ["Foundation — height 5", "Middle — height 6", "Tip — height 7"];
  let offsets = [0, 0, 0];
  let hintLevel = 0;
  let sealed = false;

  function renderTracks() {
    rows.forEach((row, r) => {
      row.track.replaceChildren();
      const label = el("span", "shelf-label", SHELF_NAMES[r]);
      row.track.append(label);
      CHAPTER2_DIAL.rings[r].forEach((f, i) => {
        const chip = el(
          "button",
          "chip" + (i === ((offsets[r] % 5) + 5) % 5 ? " active" : "") + (f.corrupt ? " marked" : ""),
        );
        chip.type = "button";
        chip.dataset.id = f.id;
        chip.dataset.h = String(f.h);
        chip.dataset.parent = f.parent;
        chip.dataset.corrupt = f.corrupt ? "true" : "false";
        chip.append(
          el("span", "chip-id", f.id + (f.corrupt ? " 𝕶" : "")),
          el("span", "chip-line", `h${f.h} · parent ${f.parent}`),
        );
        chip.addEventListener("click", () => {
          offsets[r] = i;
          render();
        });
        row.track.append(chip);
      });
      row.back.addEventListener("click", () => {
        offsets[r] = (((offsets[r] - 1) % 5) + 5) % 5;
        render();
      });
      row.fwd.addEventListener("click", () => {
        offsets[r] = (offsets[r] + 1) % 5;
        render();
      });
    });
  }

  const WHY_TEXT = {
    height: (p) => `height ${p.got} does not belong on this shelf (wants ${p.want})`,
    corrupt: () => "sealed under 𝕶 — never sealed at all",
    parent: (p) => `its parent glyph says ${p.parent}, but the block below is ${p.expect}`,
  };

  function renderWindow() {
    windowEl.replaceChildren();
    const { solved, problems, fragments } = chapter2Evaluate(offsets);
    fragments.forEach((f, i) => {
      const block = el(
        "div",
        "chain-block" + (f.corrupt ? " marked" : "") + (sealed ? " sealed" : ""),
      );
      block.append(
        el("span", "block-id", f.id + (f.corrupt ? " 𝕶" : "")),
        el("span", "block-line", `height ${f.h} · parent ${f.parent}`),
      );
      windowEl.append(block);
      if (i < 2) {
        const problem = problems.find((p) => p.link === i && p.why === "parent");
        const link = el("div", "chain-link " + (problem || sealed ? (problem ? "broken" : "") : "good"));
        link.textContent = problem ? `✗ ${WHY_TEXT.parent(problem)}` : "⟶ parent holds";
        windowEl.append(link);
      }
    });
    // Shelf-misplacement and corruption feedback, below the window.
    const shelfProblems = problems.filter((p) => p.why !== "parent");
    if (!solved && (shelfProblems.length || problems.some((p) => p.why === "parent"))) {
      feedback.textContent = shelfProblems.length
        ? shelfProblems.map((p) => `The ${["foundation", "middle", "tip"][p.link]}: ${WHY_TEXT[p.why](p)}.`).join(" ")
        : "The parents do not hold yet. Rotate.";
    } else if (solved) {
      feedback.textContent = sealed
        ? "The spine holds: 5 → 6 → 7, every parent accounted for."
        : "The spine holds. Wait for the seal…";
    }
    return solved;
  }

  function render() {
    renderTracks();
    const solved = renderWindow();
    if (solved && !sealed && !api.isSolved("vault")) {
      sealed = true;
      windowEl.classList.add("sealing");
      api.phantomSay("You found the true spine. Annoying. Do you know how hard it is to fork a chain AND keep the garden tidy?");
      setTimeout(() => {
        windowEl.classList.remove("sealing");
        api.grantFragment("vault");
      }, 1400);
    }
    if (solved && api.isSolved("vault")) sealed = true;
  }

  hintBtn.addEventListener("click", () => {
    hintLevel = Math.min(hintLevel + 1, PHANTOM_HINTS_2.length);
    hintText.textContent = PHANTOM_HINTS_2[hintLevel - 1];
  });

  resetBtn.addEventListener("click", () => {
    if (sealed && api.isSolved("vault")) {
      // Replay is allowed; the fragment is already earned and stays earned.
      sealed = false;
      windowEl.classList.remove("sealing");
    }
    offsets = [0, 0, 0];
    hintLevel = 0;
    hintText.textContent = "";
    render();
  });

  return {
    enter() {
      sealed = api.isSolved("vault");
      render();
      feedback.textContent = sealed
        ? "The spine holds: 5 → 6 → 7, every parent accounted for. (Turn the dial again for the pleasure of it.)"
        : "Reconstruct the Lost Epoch: heights five, six, seven, each block's parent the block below, nothing sealed under 𝕶.";
      hintText.textContent = "";
      hintLevel = 0;
    },
    leave() {
      /* no timers to cancel; the seal timer checks `sealed` */
    },
  };
}

/* ------------------------------------------------------------------ */
/* Chapter III — The Phantom Validator (memory, four stages)            */
/* ------------------------------------------------------------------ */

const S = { IDLE: 0, SHOWING: 1, ACCEPTING: 2, CHECKING: 3, COMPLETE: 4 };

export function buildChapter3(api) {
  const pads = [...document.querySelectorAll("#phantom-pads .echo")];
  const eye = $("phantom-eye");
  const stageLbl = $("phantom-stage");
  const lineEl = $("phantom-line");
  const fbEl = $("phantom-feedback");
  const beginBtn = $("phantom-begin");

  // Bind each pad exactly once, however many times the module boots — duplicate listeners are the
  // classic way one click becomes two inputs.
  for (const pad of pads) {
    if (pad.dataset.bound) continue;
    pad.dataset.bound = "1";
    const i = Number(pad.dataset.i);
    pad.addEventListener("click", () => onPad(i));
  }

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  let state = S.IDLE;
  let stage = 1;
  let seq = [];
  let pos = 0;
  let palePads = [];
  let runToken = 0; // bumped on leave/re-enter: any in-flight demonstration becomes a no-op

  function setStageLabel() {
    stageLbl.textContent =
      state === S.COMPLETE
        ? "The audit is over. You are the auditor now."
        : `Stage ${stage} of 4 — ${CHAPTER3_STAGES[stage - 1].length} echoes` +
          (CHAPTER3_STAGES[stage - 1].reverse ? " · answer in REVERSE" : "") +
          (CHAPTER3_STAGES[stage - 1].decoys ? ` · ${CHAPTER3_STAGES[stage - 1].decoys} pale lie(s)` : "");
  }

  function flash(i, pale) {
    const pad = pads[i];
    if (!pad) return;
    pad.classList.remove("lit", "pale");
    void pad.offsetWidth; // restart the animation
    pad.classList.add(pale ? "pale" : "lit");
    setTimeout(() => pad.classList.remove("lit", "pale"), 460);
  }

  /**
   * Demonstrate a stage. `fresh` regenerates the sequence; a retry replays a NEW sequence for the
   * same stage (the stage is kept — an eight-century-old ghost is many things, but not cruel).
   */
  async function demonstrate(fresh) {
    state = S.SHOWING;
    setStageLabel();
    const my = ++runToken;
    fbEl.textContent = "Watch. Pale echoes are lies.";
    const cfg = CHAPTER3_STAGES[stage - 1];
    if (fresh || seq.length !== cfg.length) {
      seq = Array.from({ length: cfg.length }, () => Math.floor(Math.random() * 4));
    }
    pos = 0;
    palePads = [];
    // Build the demonstration plan: true echoes, with decoy flashes interleaved after them.
    const plan = [];
    let decoys = cfg.decoys;
    for (const s of seq) {
      plan.push({ pad: s, pale: false });
      if (decoys > 0) {
        plan.push({ pad: (s + 1 + Math.floor(Math.random() * 3)) % 4, pale: true });
        decoys--;
      }
    }
    while (decoys-- > 0) plan.push({ pad: Math.floor(Math.random() * 4), pale: true });

    eye.classList.add("listening");
    await sleep(650);
    for (const step of plan) {
      if (my !== runToken) return; // the player left: stop mid-demonstration
      flash(step.pad, step.pale);
      if (step.pale) palePads.push(step.pad);
      await sleep(660);
    }
    if (my !== runToken) return;
    eye.classList.remove("listening");
    state = S.ACCEPTING;
    setStageLabel();
    fbEl.textContent = cfg.reverse ? "Your turn — in REVERSE." : "Your turn.";
    lineEl.textContent = api.store.puzzles.abyss
      ? "Again? I have nothing better to do. I am dead."
      : "The Phantom settles in, entirely too comfortable.";
  }

  function onPad(i) {
    // The gate: input exists only in ACCEPTING. A click during SHOWING, CHECKING, a transition or
    // after completion is ignored — which is exactly what makes one click one input.
    if (state !== S.ACCEPTING) return;
    state = S.CHECKING; // latch: the next click, however fast, is a NEW decision
    flash(i, false);
    const cfg = CHAPTER3_STAGES[stage - 1];
    const expected = chapter3Expectation(seq, pos, cfg.reverse);
    if (i === expected) {
      pos++;
      if (pos >= seq.length) {
        stageCleared();
      } else {
        state = S.ACCEPTING;
      }
      return;
    }
    // Wrong: say WHICH rule was violated, keep the stage, let them retry.
    const reason = chapter3WrongReason(i, palePads, cfg.reverse);
    fbEl.textContent = PHANTOM_WRONG_ECHO[reason];
    lineEl.textContent = "The Phantom makes a note. The note is not flattering.";
    state = S.IDLE;
    setTimeout(() => {
      if (state === S.IDLE) demonstrate(true); // same stage, fresh sequence
    }, 1400);
  }

  function stageCleared() {
    state = S.COMPLETE;
    fbEl.textContent = "The stage holds.";
    lineEl.textContent = PHANTOM_STAGE_DONE[stage - 1];
    if (stage < 4) {
      stage++;
      api.store.puzzles.abyssStage = Math.max(api.store.puzzles.abyssStage || 1, stage);
      api.save();
      beginBtn.textContent = `Face stage ${stage}`;
      state = S.IDLE; // set BEFORE the label, or the banner reads "the audit is over" — wrong: the audit resumes
      setStageLabel();
    } else {
      // The confrontation resolves — the fragment IS the finale.
      api.store.puzzles.abyssStage = 4;
      api.save();
      beginBtn.hidden = true;
      api.grantFragment("abyss"); // opens the ending sequence
    }
  }

  beginBtn.addEventListener("click", () => {
    if (state === S.SHOWING || state === S.ACCEPTING || state === S.CHECKING) return;
    if (stage === 4 && !api.hasFragments(["crypt", "vault"])) {
      lineEl.textContent =
        "THE PHANTOM: “The final audit? You arrive with TWO fragments short of a quorum. Come back " +
        "when your evidence is actual evidence. Two fragments is just a rumour with ambition.”";
      fbEl.textContent = "Recover Fragment I (the Crypt) and Fragment II (the Vault) first.";
      return;
    }
    beginBtn.hidden = true;
    demonstrate(true);
  });

  return {
    enter() {
      runToken++; // any in-flight demonstration from a previous visit dies here
      state = S.IDLE;
      eye.classList.remove("listening");
      for (const p of pads) p.classList.remove("lit", "pale");
      stage = Math.min(Math.max(api.store.puzzles.abyssStage || 1, 1), 4);
      beginBtn.hidden = Boolean(api.store.puzzles.abyss);
      beginBtn.textContent = api.store.puzzles.abyss
        ? "Face the audit again"
        : stage > 1
        ? `Resume at stage ${stage}`
        : "Face the audit";
      fbEl.textContent = api.store.puzzles.abyss
        ? "It stops asking. It still hums, though."
        : "Press “Face the audit” when you are ready. The rules are stated before every stage.";
      setStageLabel();
      lineEl.textContent = api.hasFragments(["crypt", "vault"])
        ? "The Phantom has been dreading this exact appointment."
        : "The Phantom glances at your empty case file and relaxes enormously.";
    },
    leave() {
      runToken++; // abort any demonstration or pending retry
      state = S.IDLE;
      eye.classList.remove("listening");
    },
  };
}
