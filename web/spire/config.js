// Game Configuration
const CONFIG = {
    CANVAS: {
        WIDTH: 800,
        HEIGHT: 600,
        BASE_WIDTH: 800,
        BASE_HEIGHT: 600
    },
    HUD: {
        PORTRAIT_HEIGHT: 195
    },
    MINIMAP: {
        WIDTH: 150,
        HEIGHT: 150
    },
    MAP: {
        WIDTH: 30,
        HEIGHT: 20,
        CELL_SIZE: 40,
        MIN_SIZE: 15 // Minimum map size
    },
    PLAYER: {
        SPEED: 3,
        SIZE: 15, // Player collision radius
        MAX_LIGHT: 100,
        LIGHT: 100, // Starting light level
        LIGHT_RADIUS: 150,
        START_X: 100, // Starting X position (will be corrected by resetPlayerPosition)
        START_Y: 500, // Starting Y position (bottom-left area)
        LIGHT_DECAY_RATE: 0.035, // Base light decay per frame
        LIGHT_DRAIN_FROM_GHOULS: 0.5 // Light drain per frame when near ghouls
    },
    GAME: {
        MAX_FLOORS: 50, // Full game length (50 floors to reach the Ancient Pearl)
        CHECKPOINT_INTERVAL: 5,
        SWARM_DURATION: 180, // 3 seconds at 60fps
        PHASE_DURATION: 300, // 5 seconds
        REGENERATION_DURATION: 600, // 10 seconds
        REVEAL_DURATION: 300 // 5 seconds
    }
};

// Orb Types Configuration
const ORB_TYPES = {
    common: { 
        symbol: 'O', 
        color: '#64b5f6', 
        lightBonus: 15,
        name: 'Blue Orb',
        description: 'Restores 15% light'
    },
    golden: { 
        symbol: '@', 
        color: '#ffeb3b', 
        lightBonus: 25,
        name: 'Golden Orb',
        description: 'Restores 25% light'
    },
    purple: { 
        symbol: 'P', 
        color: '#9c27b0', 
        power: 'phase',
        name: 'Purple Orb',
        description: 'Phase through walls for 5 seconds'
    },
    green: { 
        symbol: 'G', 
        color: '#4caf50', 
        power: 'regeneration',
        name: 'Green Orb',
        description: 'Regenerate light for 10 seconds'
    },
    white: { 
        symbol: 'W', 
        color: '#ffffff', 
        power: 'reveal',
        name: 'White Orb',
        description: 'Reveal entire map for 5 seconds'
    },
    red: { 
        symbol: '♥', 
        color: '#f44336', 
        power: 'lifeline',
        name: 'Red Orb',
        description: 'Auto-revives you at 0% light!'
    },
    wisp: { 
        symbol: '*', 
        color: '#ccccff', 
        lightBonus: 50,
        name: 'Light Wisp',
        description: 'Death marker - Restores 50% light'
    },
    pearl: {
        symbol: '●',
        color: '#1a1a1a',
        outline: '#ffffff',
        power: 'victory',
        name: 'Ancient Pearl',
        description: 'The legendary black pearl that will end the curse and save your people!',
        rare: true,
        finalLevel: true
    }
};

// Note: Game messages are defined in messages.js (MESSAGES and MessageGenerator objects)