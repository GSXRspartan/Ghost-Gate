/**
 * GHOST GATE — THE LOST EPOCH: story data and pure puzzle logic.
 *
 * Everything in this file is data or a pure function: no DOM access, so the web unit tests can
 * import it directly and prove that clues and solutions agree. The chapters wire this data to the
 * page; nothing here knows the page exists.
 *
 * Fiction/protocol boundary (docs/SECURITY_RELEASE_GATE.md): the Phantom, the lost epoch, ghost
 * auditors and cursed sigils are INVENTED. Where a line leans on something real — stealth outputs,
 * commitments, validators, finality — it stays faithful to how Ootle actually behaves, and the
 * footer reminds the player that no real chain is haunted.
 */

/* ------------------------------------------------------------------ */
/* The Phantom                                                          */
/* ------------------------------------------------------------------ */

/** Sanctum presence lines — picked at random on entry. Bureaucratic menace. */
export const PHANTOM_TAUNTS = [
  "The Phantom is present. Do not mind the temperature; the temperature is load-bearing.",
  "Ah, visitors. Please sign the guest ledger. Nobody has signed it since the epoch went missing.",
  "I would offer you tea, but the kettle is pending. It has been pending for eight hundred years.",
  "Welcome to the vault. Everything here is final except the atmosphere.",
  "You are about to touch my evidence. I polished it myself. With regret.",
];

/** One line per chapter, spoken on first entry. */
export const PHANTOM_INTRO = {
  crypt:
    "Investigating, are we? How quaint. The vault's records are immaculate — we hired three " +
    "auditors. Two vanished. The third became an NFT. I have their business cards.",
  vault:
    "Careful with the dial. It predates both of us. So does my grudge. Every block on it was " +
    "almost history — some of them were never history at all. I made sure.",
  abyss:
    "Final audit. Repeat my echoes and I shall consider signing. Fail, and I shall consider NOT " +
    "signing — which, I will be honest with you, is my default state.",
};

/** Reactions. */
export const PHANTOM_WRONG_ACCUSE = {
  // Filled per innocent stone id by chapter1Verdict's agreeText; these two cover generic cases.
  generic: "Wrong grave, detective. That stone agrees with every witness. Do try to keep up.",
};

export const PHANTOM_ON_FRAGMENT = {
  crypt:
    "The Stranger's stone? Altered? Obviously. I used the Widow's sigil because mine gives me " +
    "hives. Also I was busy. Being a ghost is mostly admin.",
  vault:
    "You found the true spine. Annoying. Do you know how hard it is to fork a chain AND keep the " +
    "garden tidy?",
  abyss: "", // the ending speaks for itself
};

/** Chapter II hints — progressive, never the answer. */
export const PHANTOM_HINTS_2 = [
  "A chain is built upward: each block's parent glyph must be the block below it, and heights climb by one. The Lost Epoch spans heights five, six and seven.",
  "Anything sealed under the inverted key 𝕶 was never sealed at all. You have met the mark before, detective.",
  "The foundation shelf wants a block of height five whose parent is ♯4 — and only one such block was ever honestly sealed.",
];

/** Chapter III feedback lines, by reason. */
export const PHANTOM_WRONG_ECHO = {
  pale: "That pale echo was one of my lies. I flash them on purpose. It is my only hobby.",
  reverse: "Wrong echo. I echo backwards now; keep up, the rule is the rule.",
  chain: "That echo is not in the true chain. The chain never rang that pad. Neither, for the record, did I.",
};

export const PHANTOM_STAGE_DONE = [
  "Stage one. Fine. Even a cathedral can be walked past.",
  "Stage two, with my lies flashing at you. Rude, but competent.",
  "Backwards AND lying. You are making my eight centuries feel rushed.",
  "Enough. ENOUGH. You win the audit. Do not make it weird.",
];

/* ------------------------------------------------------------------ */
/* Chapter I — Crypt of Lost Transactions (pure case + checker)         */
/* ------------------------------------------------------------------ */

/**
 * The case. Three honest stones and one the Phantom altered.
 *
 * Rules (each stated by a witness the player can hear):
 *   registry — a spender's sigil burns once; the registry lists who owns each sigil, and the
 *              Stranger registered none (he arrived too late).
 *   bell     — the bell rang three watches; valid burial epochs are I, II, III, and the Stranger
 *              was carried in AFTER the last toll, so his stone cannot claim epoch I.
 *   payee    — what each grave was owed: Widow 3,000, Miller 4,000, Sexton 2,000, Stranger 3,000.
 *
 * The forged stone violates exactly two rules (borrowed sigil + impossible epoch); every honest
 * stone violates none. That makes the accusation provable rather than guessable, and the checker
 * below is the SAME data the UI renders — the unit test proves clue and answer cannot drift apart.
 */
export const CHAPTER1_CASE = {
  forgedId: "stranger",
  stones: [
    { id: "widow", name: "Widow Rowan", sigil: "✦", amount: 3000, epoch: "I", wear: "ancient" },
    { id: "miller", name: "Miller Hob", sigil: "❋", amount: 4000, epoch: "II", wear: "ancient" },
    { id: "sexton", name: "The Sexton", sigil: "☾", amount: 2000, epoch: "III", wear: "ancient" },
    { id: "stranger", name: "The Stranger", sigil: "✦", amount: 3000, epoch: "I", wear: "scraped" },
  ],
  witnesses: [
    {
      id: "registry",
      name: "The Sexton's registry of burns",
      text:
        "A spender's sigil burns once and only once — I carve each burn into the registry myself. " +
        "✦ belongs to the Widow's coin. ❋ belongs to the Miller's. ☾ is mine own humble grave. " +
        "The Stranger arrived too late to register any sigil at all.",
    },
    {
      id: "bell",
      name: "The Bellringer",
      text:
        "The bell rang thrice: first, second, third watch — then the ground went quiet. Nothing " +
        "was buried before the first toll. And the Stranger? Carried in AFTER my last toll, poor " +
        "soul. The mourners complained about the overtime.",
    },
    {
      id: "payee",
      name: "The Payee Ghost",
      text:
        "I count what I was owed, never who owed it: the Widow was owed 3,000 LUME, the Miller " +
        "4,000, the Sexton 2,000, and the Stranger — latecomer — 3,000 like the Widow.",
    },
  ],
};

/** The registry the Sexton testifies about, as data. */
export const SIGIL_REGISTRY = { widow: "✦", miller: "❋", sexton: "☾" };
/** The Stranger never registered a sigil. */
export const UNREGISTERED = ["stranger"];
/** Valid epochs per the bell, and when the Stranger was actually buried. */
export const VALID_EPOCHS = ["I", "II", "III"];
export const STRANGER_BURIED = "after III";

/**
 * Every rule a stone must satisfy, with the human reason for each violation. This is the single
 * source of truth shared by the UI and the tests.
 */
export function chapter1Violations(stoneId) {
  const stone = CHAPTER1_CASE.stones.find((s) => s.id === stoneId);
  if (!stone) return [{ rule: "unknown", reason: "There is no such stone." }];
  const out = [];
  const owner = Object.entries(SIGIL_REGISTRY).find(([, sig]) => sig === stone.sigil);
  if (owner && owner[0] !== stone.id) {
    out.push({
      rule: "registry",
      reason: `The sigil ${stone.sigil} is registered to the ${owner[0]}, and a sigil burns only once — yet this stone bears it.`,
    });
  } else if (!owner) {
    out.push({
      rule: "registry",
      reason: `${stone.name} never registered a sigil, yet this stone bears ${stone.sigil}.`,
    });
  }
  if (stone.id === "stranger" && VALID_EPOCHS.includes(stone.epoch)) {
    out.push({
      rule: "bell",
      reason: `The bell rang three watches, and the Stranger was carried in after the last — his grave cannot claim epoch ${stone.epoch}.`,
    });
  }
  return out;
}

/** What the UI says when the player accuses an honest stone. */
export function chapter1AgreeText(stoneId) {
  const stone = CHAPTER1_CASE.stones.find((s) => s.id === stoneId);
  return (
    `${stone.name}'s stone agrees with the registry, the bell, and the payee. ` +
    `The grave is settled. Accuse elsewhere.`
  );
}

/** Wear text for the examine action — quiet environmental corroboration. */
export function chapter1WearText(stoneId) {
  const stone = CHAPTER1_CASE.stones.find((s) => s.id === stoneId);
  return stone.wear === "scraped"
    ? "Fresh scraping under the sigil. The original mark was removed recently — the dust has not even settled."
    : "Ordinary weathering. Nothing chiselled, nothing hidden. Old stone, old grief.";
}

/* ------------------------------------------------------------------ */
/* Chapter II — Vault of Forked Epochs (pure dial + evaluator)          */
/* ------------------------------------------------------------------ */

/**
 * The Chain Dial. Three shelves (foundation / middle / tip). The window reads one fragment per
 * shelf; the Lost Epoch spans heights 5, 6, 7, so a valid window is an ascending parent-linked
 * chain of three uncorrupted blocks. Exactly one combination satisfies every rule — the decoys
 * each fail exactly one, in a legible way:
 *   height   — wrong shelf
 *   parent   — its parent glyph is not the block below it (or names a block that is not here)
 *   corrupt  — sealed under the inverted key 𝕶: never sealed at all
 */
export const CHAPTER2_DIAL = {
  span: [5, 6, 7],
  // The dial starts at offsets [0,0,0], which must NOT be the solution — the true spine sits at
  // offsets [3,4,1]. The decoys still each fail exactly one rule, legibly.
  rings: [
    [
      { id: "♯4", h: 4, parent: "♯3", corrupt: false },
      { id: "♯5", h: 5, parent: "♯4", corrupt: true },
      { id: "♯6", h: 6, parent: "♯5", corrupt: false },
      { id: "♯5", h: 5, parent: "♯4", corrupt: false }, // TRUE (foundation)
      { id: "♯3", h: 3, parent: "♯2", corrupt: false },
    ],
    [
      { id: "♯2", h: 2, parent: "♯1", corrupt: false },
      { id: "♯6", h: 6, parent: "♯4", corrupt: false }, // wrong parent
      { id: "♯6", h: 6, parent: "♯5", corrupt: true },  // right parent, phantom mark
      { id: "♯8", h: 8, parent: "♯7", corrupt: false }, // wrong height
      { id: "♯6", h: 6, parent: "♯5", corrupt: false }, // TRUE (middle)
    ],
    [
      { id: "♯1", h: 1, parent: "♯0", corrupt: false },
      { id: "♯7", h: 7, parent: "♯6", corrupt: false }, // TRUE (tip)
      { id: "♯9", h: 9, parent: "♯8", corrupt: false }, // orphan, wrong height
      { id: "♯7", h: 7, parent: "♯6", corrupt: true },  // right parent, phantom mark
      { id: "♯7", h: 7, parent: "♯5", corrupt: false }, // skips a parent
    ],
  ],
};

/**
 * Evaluate a window selection (offsets per ring). Returns per-link problems with stable machine
 * reasons the UI translates into prose. Foundation = rings[0], then 1, then 2 upward.
 */
export function chapter2Evaluate(offsets) {
  const pick = (r) => CHAPTER2_DIAL.rings[r][((offsets[r] % 5) + 5) % 5];
  const f = [pick(0), pick(1), pick(2)];
  const problems = [];
  for (let i = 0; i < 3; i++) {
    const want = CHAPTER2_DIAL.span[i];
    if (f[i].h !== want) {
      problems.push({ link: i, why: "height", want, got: f[i].h });
    }
    if (f[i].corrupt) {
      problems.push({ link: i, why: "corrupt" });
    }
  }
  // Parent links: block i+1's parent must be block i's id.
  for (let i = 0; i < 2; i++) {
    if (f[i + 1].parent !== f[i].id) {
      problems.push({ link: i, why: "parent", parent: f[i + 1].parent, expect: f[i].id });
    }
  }
  return { solved: problems.length === 0, problems, fragments: f };
}

/* ------------------------------------------------------------------ */
/* Chapter III — The Phantom Validator (stage table + expectation)      */
/* ------------------------------------------------------------------ */

/**
 * Four escalating audits. `length` is the true sequence; `decoys` is how many pale LIES the
 * Phantom flashes during the demonstration; `reverse` means the player answers in reverse order.
 * Rules are stated up front in the stage banner and enforced with specific feedback.
 */
export const CHAPTER3_STAGES = [
  { stage: 1, length: 3, decoys: 0, reverse: false },
  { stage: 2, length: 4, decoys: 1, reverse: false },
  { stage: 3, length: 4, decoys: 1, reverse: true },
  { stage: 4, length: 5, decoys: 2, reverse: true },
];

/** Which pad the player must press next, honouring the reverse rule. */
export function chapter3Expectation(seq, pos, reverse) {
  if (pos < 0 || pos >= seq.length) return null;
  return reverse ? seq[seq.length - 1 - pos] : seq[pos];
}

/** Human reason for a wrong press. */
export function chapter3WrongReason(pressed, palePads, reverse) {
  if (palePads.includes(pressed)) return "pale";
  return reverse ? "reverse" : "chain";
}

/* ------------------------------------------------------------------ */
/* Fragments, secrets, ending                                           */
/* ------------------------------------------------------------------ */

/** The three fragments of evidence. Each body is shown in its own presentation. */
export const FRAGMENTS = {
  crypt: {
    id: "crypt",
    numeral: "I",
    title: "The Altered Ledger",
    kind: "dossier",
    cta: "Add to the case file",
    body: [
      "TRUE RECORD — The Stranger: 3,000 LUME, buried after the third watch, sigil unregistered, grave settled in full.",
      "The forged stone borrowed the Widow's sigil and backdated the burial. Only one resident profits from a settled-looking stranger: whoever fears the epoch's accounting.",
      "The alteration was stamped, not chiselled — pressed in an inverted key-form: 𝕶. Remember the mark. Anything sealed under 𝕶 was never sealed at all.",
    ],
  },
  vault: {
    id: "vault",
    numeral: "II",
    title: "The Missing Parent",
    kind: "chain",
    cta: "Seal it",
    body: [
      "The true spine: ♯5 → ♯6 → ♯7. Heights tell the truth, parents tell the lineage, and the mark 𝕶 tells you who is lying.",
      "And one more thing falls out of the ledger: the Phantom did not refuse to sign out of malice. He refused out of MODESTY.",
      "A signature is a public act, and his position was… considerable. Sign, and the whole chain could count his coins. He chose eight hundred years of pending over one visible balance.",
    ],
  },
  abyss: {
    id: "abyss",
    numeral: "III",
    title: "The Validator's Oath",
    kind: "ending", // not shown as a card — it IS the finale
    cta: "",
    body: [],
  },
};

/** Case-file summaries shown in the Sanctum review. */
export const CASE_FILE_LINES = {
  crypt: "Fragment I — The Altered Ledger: the Stranger's stone was forged under the mark 𝕶.",
  vault: "Fragment II — The Missing Parent: the true spine is 5→6→7, and the Phantom fears disclosure, not defeat.",
  abyss: "Fragment III — The Validator's Oath: signed. The Lost Epoch is final.",
};

/** The ∴ whispers, rewritten for the story. */
export const SECRETS = {
  crypt: {
    title: "Whisper of the scraped stone",
    text:
      "Scratched under the Stranger's ledge, in a hand that shakes: 'he did not steal the coin. " +
      "He stole the CREDIT. Ask any auditor which hurts more.'",
  },
  vault: {
    title: "Whisper behind the dial",
    text:
      "Behind the dial's face, a second dial, motionless. Its pointer points at you. Etched " +
      "beneath: 'every chain is a promise repeated backward from the tip.'",
  },
  abyss: {
    title: "Whisper that was not yours",
    text:
      "The last echo you repeated was not the Phantom's. It was yours, from a room you have not " +
      "entered yet. It sounded, unmistakably, like a signature.",
  },
};

/** The ending, beat by beat. Each beat is one staged paragraph. */
export const ENDING_BEATS = [
  "The three fragments rise from the case file and hang in the air like accused witnesses. The vault holds its breath — 800 years of held breath, and the damp is biblical.",
  "𝕶 burns off the Stranger's stone. The true record settles, plain and honest: 3,000 LUME, buried late, owed in full. The Crypt exhales. Somewhere below, a ledger ticks — once.",
  "The chain snaps taut: five, six, seven. Parents hold. Heights climb. The Lost Epoch has a spine again, and the spine has a PULSE.",
  "THE PHANTOM: \u201cAll right. All RIGHT. I will sign the wretched block.\u201d The eye stops watching. It just… stops.",
  "\u201cDo you know why I never signed? A signature is a PUBLIC act, detective. And my position was… considerable. Sign once, and the whole chain could count my coins for eight hundred years.\u201d",
  "You show him the trick you carried in: a proof that attests a floor — enough to matter, never the amount. The gate learned that you belonged. It never learned what you were worth.",
  "The Phantom reads it twice. Then he laughs — the first sound the vault has made in eight centuries that was not dripping.",
  "\u201cPublic proof. Private purse. Eight hundred years I waited for someone to invent POLITENESS for validators.\u201d",
  "He signs. The epoch seals with a sound like a cathedral clearing its throat. Finality rolls through the vault, gentle as snowfall, and every door in the place unlocks at once — including, you notice, the one you came in by.",
  "THE LOST EPOCH IS FINAL.",
  "Ghost Gate proved you belonged without ever showing your purse. The Phantom waited eight hundred years for that trick. You used it before breakfast.",
];

/** Sanctum intro, shown once per visit under the status. */
export const SANCTUM_INTRO =
  "The Phantom — the validator who refused to sign — has locked an entire epoch in this vault. " +
  "Recover three fragments of evidence and drag the Lost Epoch to a vote.";
