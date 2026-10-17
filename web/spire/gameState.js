// Game State Management
const GameState = {
    // Main game object
    game: {
        state: 'menu',
        mode: 'explorer',
        deathScreen: false,
        showHelp: false,
        // Tutorial system
        tutorial: {
            active: false,
            currentStep: 0,
            showingOrbTutorial: false,
            completedSteps: new Set(),
            firstTimeOrbs: new Set(), // Track which orb types have been collected for the first time
            tutorialPopup: null
        },
        player: {
            x: 400,
            y: 300,
            speed: CONFIG.PLAYER.SPEED,
            light: CONFIG.PLAYER.MAX_LIGHT,
            maxLight: CONFIG.PLAYER.MAX_LIGHT,
            lightRadius: CONFIG.PLAYER.LIGHT_RADIUS,
            orbsCollected: 0,
            inventory: [null, null, null],
            selectedSlot: 0,
            powers: {
                phase: 0,
                regeneration: 0,
                reveal: 0
            },
            deathMarkers: [],
            lastPosition: { x: 100, y: 100 }
        },
        camera: {
            x: 0,
            y: 0
        },
        floor: -1,
        checkpoint: -1,
        levelEntryInventory: [null, null, null],
        ghouls: [],
        orbs: [],
        walls: [],
        stairs: null,
        particles: [],
        explored: new Set(),
        gameOver: false,
        victory: false,
        swarming: false,
        swarmTimer: 0,
        darknessFade: 0,
        time: 0,
        mapWidth: CONFIG.MAP.WIDTH,
        mapHeight: CONFIG.MAP.HEIGHT,
        gameStartTime: Date.now(),
        distanceTraveled: 0,
        runDeaths: 0
    },

    // Game statistics
    stats: {
        totalPlayTime: 0,
        gamesPlayed: 0,
        deepestFloor: 0,
        totalOrbsCollected: 0,
        totalDeaths: 0,
        fastestCompletion: null,
        achievements: new Set(),
        sessionStartTime: Date.now(),
        totalDistanceTraveled: 0
    },

    // Achievement definitions
    achievements: {
        'first_death': { name: 'First Steps', description: 'Die for the first time', icon: '💀' },
        'orb_collector': { name: 'Orb Collector', description: 'Collect 10 orbs in a single run', icon: '🔮' },
        'deep_explorer': { name: 'Deep Explorer', description: 'Reach floor -25', icon: '⬇️' },
        'marathon_runner': { name: 'Marathon Runner', description: 'Play for 30 minutes total', icon: '🏃' },
        'speed_runner': { name: 'Speed Runner', description: 'Complete the game in under 10 minutes', icon: '⚡' },
        'survivor': { name: 'Survivor', description: 'Survive for 5 minutes without dying', icon: '🛡️' },
        'explorer': { name: 'Explorer', description: 'Travel 10,000 units total', icon: '🗺️' },
        'persistent': { name: 'Persistent', description: 'Play 10 games', icon: '💪' },
        'completionist': { name: 'Completionist', description: `Reach the final floor (-${CONFIG.GAME.MAX_FLOORS})`, icon: '🏆' }
    },

    // Initialize game state
    init() {
        console.log('🎮 GameState.init() called');
        
        try {
            this.loadStats();
            console.log('✅ Stats loaded');
            
            this.resetGame();
            console.log('✅ Game reset completed');
            
            this.stats.lastPlayed = Date.now();
            this.saveStats();
            console.log('✅ Stats updated and saved');
            
            // Don't auto-start the game, show menu first
            console.log('✅ GameState initialized - showing menu');
            
        } catch (error) {
            console.error('❌ GameState.init() failed:', error);
            // Create a minimal game object as fallback
            this.game = {
                state: 'menu',
                player: { x: 100, y: 100, light: 100 },
                floor: -1,
                ghouls: [],
                orbs: [],
                walls: [],
                particles: [],
                explored: new Set()
            };
            throw error;
        }
    },

    // Reset game to initial state
    resetGame() {
        console.log('🔄 Resetting game state');
        
        // Clear any existing timeouts
        if (Utils.messageTimeout) {
            clearTimeout(Utils.messageTimeout);
            Utils.messageTimeout = null;
        }
        
        this.game = this.createInitialGameState();
        return this.game;
    },

    // Start new game
    startGame() {
        console.log('🚀 Starting new game...');
        
        this.resetGame();
        this.game.state = 'playing'; // Set to playing after reset
        console.log('🎮 Game state set to:', this.game.state);
        
        // Generate the first floor
        if (typeof MapGenerator !== 'undefined' && MapGenerator.generateFloor) {
            try {
                MapGenerator.generateFloor(this.game, 1);
                console.log('✅ First floor generated');
            } catch (error) {
                console.warn('⚠️ Failed to generate first floor:', error);
            }
        } else {
            console.warn('⚠️ MapGenerator not available');
        }
        
        // Set level entry inventory for first level AFTER floor generation
        // This represents what the player has when they enter level 1 (should be empty)
        this.game.levelEntryInventory = [...this.game.player.inventory];
        console.log(`🎒 Initial level entry inventory set for floor ${this.game.floor}:`, this.game.levelEntryInventory);
        
        // Show intro message
        const storyElement = document.getElementById('story');
        if (storyElement) {
            if (typeof MESSAGES !== 'undefined' && MESSAGES.STORY && MESSAGES.STORY.INTRO) {
                Utils.showMessage(MESSAGES.STORY.INTRO, 4000);
            } else {
                Utils.showMessage('Navigate the darkness. Find the stairs to descend.', 4000);
            }
        }
        
        // Don't start tutorial here - it will be started after story narration
        
        // Update inventory display to ensure it shows the correct initial state
        if (typeof InventoryManager !== 'undefined' && InventoryManager.updateDisplay) {
            InventoryManager.updateDisplay();
            console.log(`🎒 Initial inventory display updated`);
        }
        
        // Note: UI elements (ui, minimap, inventory) are rendered on canvas
        // and hidden via CSS !important. Story messages use Utils.showMessage() notifications.
        // The #story element is no longer used for display.
        
        // Set checkpoint with safety check
        const checkpointElement = document.getElementById('checkpoint');
        if (checkpointElement) {
            checkpointElement.textContent = '1';
        }
        
        // Record game start
        this.stats.gamesPlayed++;
        this.stats.sessionStartTime = Date.now();
        this.saveStats();
        
        // Final state check
        console.log('✅ Game started successfully. Final state:', this.game.state);
        console.log('📍 Player position:', this.game.player.x, this.game.player.y);
        console.log('🗺️ Floor:', this.game.floor);
    },

    // Quit to menu
    quitToMenu() {
        // Clean up name entry state and DOM elements
        this.game.showNameEntry = false;
        this.game.pendingScore = null;
        if (window.InputManager && InputManager.hideNameEntryInput) {
            InputManager.hideNameEntryInput();
        }

        this.game.state = 'menu';
        this.game.deathScreen = false;
        this.game.swarming = false;
        this.game.swarmTimer = 0;
        this.game.darknessFade = 0;

        // Stop all sounds when returning to menu
        if (window.SoundManager) {
            SoundManager.stopAll();
        }

        // Hide story element (other UI elements are rendered on canvas and hidden via CSS)
        const storyEl = document.getElementById('story');
        if (storyEl) storyEl.style.display = 'none';
        const powerStatusEl = document.getElementById('powerStatus');
        if (powerStatusEl) powerStatusEl.textContent = '';

        // Reset floor transition effect on renderer
        if (typeof Renderer !== 'undefined') {
            Renderer.lastRenderedFloor = null;
            Renderer.floorTransitionAlpha = 0;
        }
    },

    // Respawn at checkpoint
    respawnAtCheckpoint() {
        console.log(`🔄 Respawning at checkpoint floor ${this.game.checkpoint}...`);

        // Clean up name entry state and DOM elements
        this.game.showNameEntry = false;
        this.game.pendingScore = null;
        if (window.InputManager && InputManager.hideNameEntryInput) {
            InputManager.hideNameEntryInput();
        }

        // Add death marker at current location (store absolute floor for matching in placeDeathMarkers)
        this.game.player.deathMarkers.push({
            x: this.game.player.x,
            y: this.game.player.y,
            floor: Math.abs(this.game.floor)
        });
        
        // Reset to checkpoint floor
        this.game.floor = this.game.checkpoint;
        this.game.player.light = 75; // Give some light at respawn
        
        // IMPORTANT: Clear ALL swarm-related state
        this.game.swarming = false;
        this.game.swarmTimer = 0;
        this.game.darknessFade = 0;
        this.game.deathScreen = false;
        
        // Clear powers and reset player state
        this.game.player.powers = { phase: 0, regeneration: 0, reveal: 0 };
        this.game.player.lightRadius = CONFIG.PLAYER.LIGHT_RADIUS;
        this.game.player.isDead = false;
        
        // Regenerate the checkpoint floor
        if (typeof MapGenerator !== 'undefined' && MapGenerator.generateFloor) {
            try {
                MapGenerator.generateFloor(this.game, this.game.floor);
                
                // Use proper player positioning that validates against walls
                // This will be handled by MapGenerator.generateFloor() -> resetPlayerPosition()
                
                // Reset ALL ghouls to normal state after respawn
                for (const ghoul of this.game.ghouls) {
                    ghoul.state = 'patrol';
                    ghoul.speed = 2; // Reset to normal speed
                }
                
                // Update camera to follow player (instant snap on respawn)
                if (typeof Utils !== 'undefined' && Utils.updateCamera) {
                    Utils.updateCamera(this.game, true);
                }

                console.log(`✅ Respawned at checkpoint floor ${this.game.floor} at position (${this.game.player.x}, ${this.game.player.y})`);
                console.log(`🔄 Reset ${this.game.ghouls.length} ghouls to normal state`);
            } catch (error) {
                console.warn('⚠️ Failed to generate checkpoint floor:', error);
            }
        }
        
        // Update UI
        const checkpointElement = document.getElementById('checkpoint');
        if (checkpointElement) {
            // Calculate and display the correct checkpoint number
            const checkpointNumber = Math.ceil(Math.abs(this.game.checkpoint) / 5);
            checkpointElement.textContent = checkpointNumber;
        }
        
        // Show respawn message
        const storyElement = document.getElementById('story');
        if (storyElement) {
            if (typeof MESSAGES !== 'undefined' && MESSAGES.STORY && MESSAGES.STORY.RESPAWN) {
                Utils.showMessage(MESSAGES.STORY.RESPAWN, 4000);
            } else {
                Utils.showMessage(`Respawned at checkpoint floor ${this.game.floor}.`, 4000);
            }
        }
    },

    // Restart current level with entry inventory
    restartCurrentLevel() {
        console.log(`🔄 Restarting current level ${this.game.floor}...`);
        
        // Store current floor
        const currentFloor = this.game.floor;
        
        // Debug current state before restart
        console.log(`🔍 BEFORE RESTART - Current inventory:`, [...this.game.player.inventory]);
        console.log(`🔍 BEFORE RESTART - Level entry inventory:`, this.game.levelEntryInventory);
        console.log(`🔍 BEFORE RESTART - Floor:`, this.game.floor);
        
        // Get entry inventory - restore what the player had when they ENTERED this level
        let entryInventory;
        
        // If levelEntryInventory exists and is a valid array, use it
        if (this.game.levelEntryInventory && Array.isArray(this.game.levelEntryInventory)) {
            entryInventory = [...this.game.levelEntryInventory];
            console.log(`🎒 Using stored level entry inventory:`, entryInventory);
        } else {
            // If no level entry inventory is set, this means we're on the first level
            // or there was an error - default to empty inventory for first level
            if (currentFloor === -1) {
                entryInventory = [null, null, null];
                console.log(`🎒 Level 1 restart - using empty inventory (starting inventory)`);
            } else {
                // For other levels, this shouldn't happen, but use empty as fallback
                entryInventory = [null, null, null];
                console.log(`⚠️ No level entry inventory found for floor ${currentFloor}, using empty inventory as fallback`);
            }
        }
        
        // Reset player to level entry state
        this.game.player.light = CONFIG.PLAYER.MAX_LIGHT; // Full light at level restart
        this.game.player.powers = { phase: 0, regeneration: 0, reveal: 0 };
        this.game.player.lightRadius = CONFIG.PLAYER.LIGHT_RADIUS;
        this.game.player.inventory = [...entryInventory]; // Restore entry inventory
        
        // Clear swarm-related state
        this.game.swarming = false;
        this.game.swarmTimer = 0;
        this.game.darknessFade = 0;
        this.game.deathScreen = false;
        this.game.player.isDead = false;

        // Player position will be properly set by MapGenerator.generateFloor() -> resetPlayerPosition()
        // This ensures the player spawns in a valid, wall-free location

        // Regenerate the current floor
        if (typeof MapGenerator !== 'undefined' && MapGenerator.generateFloor) {
            try {
                MapGenerator.generateFloor(this.game, currentFloor);
                
                // Reset ALL ghouls to normal state
                for (const ghoul of this.game.ghouls) {
                    ghoul.state = 'patrol';
                    ghoul.speed = 2; // Reset to normal speed
                }
                
                // Update camera to follow player
                if (typeof Utils !== 'undefined' && Utils.updateCamera) {
                    Utils.updateCamera(this.game, true);
                }
                
                console.log(`✅ Level ${currentFloor} restarted successfully`);
                console.log(`🔍 AFTER RESTART - Final inventory:`, [...this.game.player.inventory]);
            } catch (error) {
                console.warn('⚠️ Failed to regenerate current level:', error);
                // Try to recover by ensuring player has valid position
                const cs = CONFIG.MAP.CELL_SIZE || 40;
                this.game.player.x = Math.max(cs, this.game.player.x);
                this.game.player.y = Math.max(cs, this.game.player.y);
            }
        }
        
        // Update inventory display
        if (typeof InventoryManager !== 'undefined' && InventoryManager.updateDisplay) {
            InventoryManager.updateDisplay();
            console.log(`🎒 Inventory display updated`);
        }
        
        // Show restart message
        Utils.showMessage(`Level ${Math.abs(currentFloor)} restarted.`, 3000);
        
        // Debug final state after restart
        console.log(`🔍 RESTART COMPLETE - Player at (${this.game.player.x}, ${this.game.player.y})`);
        console.log(`🔍 RESTART COMPLETE - Light: ${this.game.player.light}`);
        console.log(`🔍 RESTART COMPLETE - Inventory:`, [...this.game.player.inventory]);
    },

    // Update statistics with deltaTime
    updateStats(deltaTime) {
        if (!this.game) {
            console.warn('⚠️ Game object is null/undefined in updateStats');
            return;
        }
        
        this.stats.totalPlayTime += deltaTime;
        
        // Only update survival time when playing
        if (this.game.state === 'playing') {
            this.game.survivalTime += deltaTime;
        }
        
        // Track distance traveled
        const player = this.game.player;
        if (player && player.lastPosition) {
            const lastPos = player.lastPosition;
            const distance = Math.sqrt(
                Math.pow(player.x - lastPos.x, 2) + 
                Math.pow(player.y - lastPos.y, 2)
            );
            
            if (distance > 0) {
                this.stats.totalDistanceTraveled += distance;
                this.game.distanceTraveled += distance;
                player.lastPosition = { x: player.x, y: player.y };
            }
        }
        
        // Update deepest floor (floors are negative, so deeper = more negative)
        if (this.game.floor < this.stats.deepestFloor) {
            this.stats.deepestFloor = this.game.floor;
        }
        
        // Check achievements
        this.checkAchievements();
    },

    // Check and unlock achievements
    checkAchievements() {
        const newAchievements = [];
        
        // First death
        if (this.stats.totalDeaths >= 1 && !this.stats.achievements.has('first_death')) {
            newAchievements.push('first_death');
        }
        
        // Orb collector
        if (this.game.player.orbsCollected >= 10 && !this.stats.achievements.has('orb_collector')) {
            newAchievements.push('orb_collector');
        }
        
        // Deep explorer
        if (this.game.floor <= -25 && !this.stats.achievements.has('deep_explorer')) {
            newAchievements.push('deep_explorer');
        }
        
        // Marathon runner (30 minutes = 1,800,000 ms)
        if (this.stats.totalPlayTime >= 1800000 && !this.stats.achievements.has('marathon_runner')) {
            newAchievements.push('marathon_runner');
        }
        
        // Explorer (10,000 units traveled)
        if (this.stats.totalDistanceTraveled >= 10000 && !this.stats.achievements.has('explorer')) {
            newAchievements.push('explorer');
        }
        
        // Persistent (10 games played)
        if (this.stats.gamesPlayed >= 10 && !this.stats.achievements.has('persistent')) {
            newAchievements.push('persistent');
        }
        
        // Survivor (5 minutes = 300,000 ms)
        if (this.game.survivalTime >= 300000 && !this.stats.achievements.has('survivor')) {
            newAchievements.push('survivor');
        }
        
        // Completionist (floors are negative, so check absolute value)
        if (Math.abs(this.game.floor) >= CONFIG.GAME.MAX_FLOORS && !this.stats.achievements.has('completionist')) {
            newAchievements.push('completionist');
        }
        
        // Unlock new achievements
        newAchievements.forEach(achievementId => {
            this.stats.achievements.add(achievementId);
            this.showAchievementUnlocked(achievementId);
        });
        
        if (newAchievements.length > 0) {
            this.saveStats();
        }
    },

    // Show achievement unlocked notification
    showAchievementUnlocked(achievementId) {
        const achievement = this.achievements[achievementId];
        if (!achievement) return;
        
        const notification = document.createElement('div');
        notification.className = 'achievement-notification';

        notification.innerHTML = `
            <div class="achievement-notification-inner">
                <span class="achievement-notification-icon">${achievement.icon}</span>
                <span class="achievement-notification-name">${achievement.name}</span>
            </div>
        `;
        
        document.body.appendChild(notification);
        
        // Auto-remove after 4 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.style.animation = 'achievementSlide 0.5s ease-in reverse';
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.remove();
                    }
                }, 500);
            }
        }, 4000);
        
        console.log(`🏆 Achievement unlocked: ${achievement.name}`);
    },

    // Record player death
    recordDeath() {
        this.stats.totalDeaths++;
        this.game.runDeaths++;
        this.saveStats();
    },

    // Record orb collection
    recordOrbCollection() {
        this.stats.totalOrbsCollected++;
        this.game.player.orbsCollected++;
    },

    // Record game completion
    recordGameCompletion() {
        const completionTime = Date.now() - this.game.gameStartTime;
        
        if (!this.stats.fastestCompletion || completionTime < this.stats.fastestCompletion) {
            this.stats.fastestCompletion = completionTime;
        }
        
        // Speed runner achievement (10 minutes = 600,000 ms)
        if (completionTime <= 600000 && !this.stats.achievements.has('speed_runner')) {
            this.stats.achievements.add('speed_runner');
            this.showAchievementUnlocked('speed_runner');
        }
        
        this.saveStats();
    },

    // Get formatted statistics
    getFormattedStats() {
        const formatTime = (ms) => {
            const minutes = Math.floor(ms / 60000);
            const seconds = Math.floor((ms % 60000) / 1000);
            return `${minutes}:${seconds.toString().padStart(2, '0')}`;
        };
        
        return {
            totalPlayTime: formatTime(this.stats.totalPlayTime),
            gamesPlayed: this.stats.gamesPlayed,
            deepestFloor: `${Math.abs(this.stats.deepestFloor)}`,
            totalOrbsCollected: this.stats.totalOrbsCollected,
            totalDistanceTraveled: Math.round(this.stats.totalDistanceTraveled),
            totalDeaths: this.stats.totalDeaths,
            fastestCompletion: this.stats.fastestCompletion ? formatTime(this.stats.fastestCompletion) : 'N/A',
            achievementsUnlocked: this.stats.achievements.size,
            totalAchievements: Object.keys(this.achievements).length
        };
    },

    // Load statistics from localStorage
    loadStats() {
        try {
            const saved = localStorage.getItem('buriedSpireStats');
            if (saved) {
                const parsedStats = JSON.parse(saved);
                this.stats = {
                    ...this.stats,
                    ...parsedStats,
                    achievements: new Set(parsedStats.achievements || [])
                };
            }
        } catch (error) {
            console.warn('Failed to load stats:', error);
        }
    },

    // Save statistics to localStorage
    saveStats() {
        try {
            const statsToSave = {
                ...this.stats,
                achievements: Array.from(this.stats.achievements)
            };
            localStorage.setItem('buriedSpireStats', JSON.stringify(statsToSave));
        } catch (error) {
            console.warn('Failed to save stats:', error);
        }
    },

    // Save game state to localStorage
    saveGame() {
        try {
            const gameData = {
                floor: this.game.floor,
                checkpoint: this.game.checkpoint,
                player: {
                    light: this.game.player.light,
                    orbsCollected: this.game.player.orbsCollected,
                    inventory: this.game.player.inventory ? [...this.game.player.inventory] : [],
                    deathMarkers: this.game.player.deathMarkers ? [...this.game.player.deathMarkers] : [],
                    checkpointInventory: this.game.player.checkpointInventory ? [...this.game.player.checkpointInventory] : []
                },
                timestamp: Date.now()
            };
            
            localStorage.setItem('buriedSpireGame', JSON.stringify(gameData));
            console.log('💾 Game saved successfully');
            return true;
        } catch (error) {
            console.error('❌ Failed to save game:', error);
            return false;
        }
    },

    // Load game state from localStorage
    loadGame() {
        try {
            const savedData = localStorage.getItem('buriedSpireGame');
            if (!savedData) return false;
            
            const gameData = JSON.parse(savedData);
            
            // Validate saved data
            if (!gameData.player || typeof gameData.floor !== 'number') {
                console.warn('⚠️ Invalid save data format');
                return false;
            }
            
            // Create fresh game state
            this.game = this.createInitialGameState();
            
            // Restore saved values
            this.game.floor = gameData.floor;
            this.game.checkpoint = gameData.checkpoint || -1;
            this.game.player.light = gameData.player.light || 100;
            this.game.player.orbsCollected = gameData.player.orbsCollected || 0;
            this.game.player.inventory = gameData.player.inventory || [null, null, null];
            this.game.player.deathMarkers = gameData.player.deathMarkers || [];
            this.game.player.checkpointInventory = gameData.player.checkpointInventory || [null, null, null];
            
            // Generate the current floor
            MapGenerator.generateFloor(this.game);
            
            console.log('📂 Game loaded successfully from floor', this.game.floor);
            return true;
        } catch (error) {
            console.error('❌ Failed to load game:', error);
            return false;
        }
    },

    // Get current game state
    getGame() {
        return this.game;
    },

    setGame(gameData) {
        this.game = gameData;
    },

    // Save checkpoint
    saveCheckpoint() {
        this.game.checkpoint = this.game.floor;
        this.saveGame();
        console.log(`Checkpoint saved at floor ${this.game.floor}`);
    },

    // Load game from checkpoint
    loadCheckpoint() {
        try {
            const loaded = this.loadGame();
            if (loaded && this.game.checkpoint) {
                this.game.floor = this.game.checkpoint;
                this.game.player.light = 75; // Restore some light at checkpoint
                MapGenerator.generateFloor(this.game);
                console.log(`Loaded checkpoint at floor ${this.game.floor}`);
            }
        } catch (error) {
            console.error('Failed to load checkpoint:', error);
        }
    },

    // Create initial game state
    createInitialGameState() {
        return {
            state: 'menu',
            mode: 'explorer',
            deathScreen: false,
            showHelp: false,
            tutorial: {
                active: false,
                currentStep: 0,
                showingOrbTutorial: false,
                completedSteps: new Set(),
                firstTimeOrbs: new Set(),
                tutorialPopup: null
            },
            player: {
                x: CONFIG.PLAYER.START_X || 100,
                y: CONFIG.PLAYER.START_Y || 100,
                speed: CONFIG.PLAYER.SPEED || 3,
                light: CONFIG.PLAYER.MAX_LIGHT || 100,
                maxLight: CONFIG.PLAYER.MAX_LIGHT || 100,
                lightRadius: CONFIG.PLAYER.LIGHT_RADIUS || 150,
                size: CONFIG.PLAYER.SIZE || 15,
                orbsCollected: 0,
                inventory: [null, null, null],
                selectedSlot: 0,
                deathMarkers: [],
                lastPosition: { x: 100, y: 100 },
                powers: {
                    phase: 0,
                    regeneration: 0,
                    reveal: 0
                }
            },
            camera: { x: 0, y: 0 },
            floor: -1,
            checkpoint: -1,
            levelEntryInventory: [null, null, null],
            ghouls: [],
            orbs: [],
            walls: [],
            stairs: null,
            particles: [],
            explored: new Set(),
            gameOver: false,
            victory: false,
            swarming: false,
            swarmTimer: 0,
            darknessFade: 0,
            time: 0,
            mapWidth: CONFIG.MAP.WIDTH || 30,
            mapHeight: CONFIG.MAP.HEIGHT || 20,
            gameStartTime: Date.now(),
            distanceTraveled: 0,
            runDeaths: 0,
            survivalTime: 0,
            showNameEntry: false,
            pendingScore: null
        };
    }
};