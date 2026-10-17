// Game Messages and Story Content
const MESSAGES = {
    STORY: {
        INTRO: "Your light is your lifeline in these cursed depths.",
        PHASE_ACTIVATED: "Phase active - you can walk through walls!",
        REGENERATION_ACTIVATED: "Regeneration active - energy slowly restoring!",
        REVEAL_ACTIVATED: "Reveal active - the full path is shown!",
        LIFELINE_USED: "Lifeline used - death held at bay!",
        LIFELINE_AUTO: "Lifeline activated - saved from darkness!",
        PHASE_ENDING: "Phase fading - returning to solid form!",
        DARKNESS_CONSUMES: "Darkness closes in... ghouls are coming!",
        INVENTORY_FULL: "Inventory full - cannot carry more orbs!",
        RESPAWN: "Respawned at last checkpoint.",
        VICTORY: "Ancient Pearl found! The curse is broken!"
    },
    
    FLOOR: {
        PROGRESS: (floor) => `Floor ${-floor}: The darkness grows thicker...`,
        CHECKPOINT: (floor) => `Checkpoint saved - Floor ${-floor}`,
        DEEP: (floor) => `Floor ${-floor}: Ancient whispers surround you...`,
        FINAL: `Floor -50: The Ancient Pearl awaits below!`
    },
    
    TUTORIAL: {
        MOVEMENT: "Use WASD or Arrow Keys to move.",
        LIGHT: "Your light fades over time - collect orbs!",
        ORBS: "Orbs restore light and grant abilities.",
        GHOULS: "Avoid ghouls - they drain your light!",
        STAIRS: "Find the stairs to descend deeper.",
        INVENTORY: "Press 1/2/3 to use inventory orbs."
    },
    
    DEATH: {
        LIGHT_DEPLETED: "Your light has been extinguished...",
        SWARM_BEGINS: "Ghouls emerge from the darkness!",
        CONSUMED: "The shadows claimed you...",
        CHECKPOINT_LOST: "Progress lost since last checkpoint."
    },
    
    ORBS: {
        COLLECTED: {
            COMMON: "Blue orb collected - light restored!",
            GOLDEN: "Golden orb - major light restored!",
            PURPLE: "Purple orb - phase energy stored.",
            GREEN: "Green orb - regeneration stored.",
            WHITE: "White orb - reveal power stored.",
            RED: "Red orb - lifeline acquired!",
            WISP: "Wisp collected - light restored.",
            PEARL: "Ancient Pearl found! You are victorious!"
        }
    },
    
    UI: {
        LOADING: "Descending into the buried spire...",
        PAUSED: "Game Paused - The darkness waits...",
        HELP_PROMPT: "Press H for help",
        MENU_RETURN: "Press ESC to return to menu"
    },
    
    ACHIEVEMENTS: {
        FIRST_DEATH: "First Death: The spire claims its first victim.",
        DEEP_EXPLORER: "Deep Explorer: Reached floor -25.",
        LIGHT_MASTER: "Light Master: Maintained 90%+ light for 10 floors.",
        ORB_COLLECTOR: "Orb Collector: Collected 100 orbs.",
        SURVIVOR: "Survivor: Completed the game without dying.",
        SPEED_RUNNER: "Speed Runner: Completed in under 30 minutes."
    },
    
    LORE: {
        BURJ_MUBARAK: "Once a magnificent tower in an ancient utopian civilization, now buried by time and sand.",
        ANCIENT_PEARL: "A legendary black pearl that holds the concentrated light of a lost civilization. It will protect your community from the ghouls that prowl the night.",
        GHOULS: "Cursed spirits that fled the light when the tower fell.",
        LIGHT_ORBS: "Remnants of the tower's former glory, still holding traces of ancient luminous energy.",
        EXPLORER_MODE: "A safer path for those who dare to explore the depths gradually."
    }
};

// Dynamic message generation
const MessageGenerator = {
    // Generate floor-specific messages
    getFloorMessage(floor) {
        if (floor === 1) return MESSAGES.STORY.INTRO;
        if (floor === 50) return MESSAGES.FLOOR.FINAL;
        if (floor % 5 === 0) return MESSAGES.FLOOR.CHECKPOINT(floor);
        if (floor > 30) return MESSAGES.FLOOR.DEEP(floor);
        return MESSAGES.FLOOR.PROGRESS(floor);
    },
    
    // Generate orb collection messages
    getOrbCollectionMessage(orbType) {
        const orbData = ORB_TYPES[orbType];
        if (!orbData) return "You found a mysterious orb...";
        
        if (MESSAGES.ORBS.COLLECTED[orbType.toUpperCase()]) {
            return MESSAGES.ORBS.COLLECTED[orbType.toUpperCase()];
        }
        
        return `You collected a ${orbData.name}!`;
    },
    
    // Generate death messages based on context
    getDeathMessage(cause) {
        switch (cause) {
            case 'light_depleted':
                return MESSAGES.DEATH.LIGHT_DEPLETED;
            case 'swarm':
                return MESSAGES.DEATH.CONSUMED;
            default:
                return MESSAGES.DEATH.CONSUMED;
        }
    },
    
    // Generate tutorial messages
    getTutorialMessage(step) {
        const tutorialSteps = [
            MESSAGES.TUTORIAL.MOVEMENT,
            MESSAGES.TUTORIAL.LIGHT,
            MESSAGES.TUTORIAL.ORBS,
            MESSAGES.TUTORIAL.GHOULS,
            MESSAGES.TUTORIAL.STAIRS,
            MESSAGES.TUTORIAL.INVENTORY
        ];
        
        return tutorialSteps[step % tutorialSteps.length];
    },
    
    // Generate contextual hints
    getHint(game) {
        const hints = [];
        
        if (game.player.light < 30) {
            hints.push("Your light grows dim - seek blue or golden orbs!");
        }
        
        if (game.player.inventory.every(slot => slot === null)) {
            hints.push("Collect power orbs to gain special abilities!");
        }
        
        if (game.ghouls.length > 5) {
            hints.push("Many ghouls roam this floor - be cautious!");
        }
        
        if (game.player.powers.reveal > 0) {
            hints.push("The white orb reveals all - use this knowledge wisely!");
        }
        
        return hints.length > 0 ? hints[Math.floor(Math.random() * hints.length)] : "";
    }
}; 