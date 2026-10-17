// Main Game Initialization and Loop
const Game = {
    lastTime: 0,
    targetFPS: 60,
    frameInterval: 1000 / 60,
    isPaused: false,
    lastAutoSave: 0, // Track last auto-save time to prevent infinite saving
    settings: {
        showFPS: false,
        showDebugInfo: false,
        enableSoundEffects: true,
        graphicsQuality: 'high', // low, medium, high
        autoSave: true,
        touchSensitivity: 1.0,
        volume: 0.7
    },
    
    // Initialize the game
    init() {
        console.log('🎮 Initializing Buried Spire Quest - Explorer Mode');
        
        try {
            // Make Game object globally accessible
            window.Game = this;
            
            // Load settings from localStorage
            this.loadSettings();
            
            // Initialize all game systems
            GameState.init();
            Renderer.init();
            InputManager.init();
            GameLogic.init();
            TutorialSystem.init();
            
            // Initialize sound system (will start on first user interaction)
            SoundManager.init();

            
            // Apply initial settings (including volume)
            this.applySettings();
            
            // Setup development tools
            this.setupDevTools();
            
            // Setup settings UI
            this.setupSettingsUI();
            
            // Start the game loop
            this.startGameLoop();
            
            console.log('✅ Game initialized successfully');
            
        } catch (error) {
            console.error('❌ Failed to initialize game:', error);
            this.showCriticalError(error);
        }
    },

    // Pause/unpause the game
    togglePause() {
        const game = GameState.getGame();
        if (game.state === 'playing' && !game.deathScreen && !game.gameOver && !game.victory) {
            this.isPaused = !this.isPaused;
            if (this.isPaused) {
                this.showPauseMenu();
            } else {
                this.hidePauseMenu();
            }
        }
    },

    // Show pause menu
    showPauseMenu() {
        // Remove existing pause menu if any
        const existingMenu = document.getElementById('pauseMenu');
        if (existingMenu) {
            existingMenu.remove();
        }

        this.showSettingsModal(true); // Pass true to indicate this is a pause menu
    },

    // Hide pause menu
    hidePauseMenu() {
        const pauseMenu = document.getElementById('pauseMenu');
        if (pauseMenu) {
            pauseMenu.remove();
        }
        const settingsModal = document.getElementById('settingsModal');
        if (settingsModal) {
            settingsModal.remove();
        }
    },

    // Setup development tools
    setupDevTools() {
        // Add debug panel
        if (this.settings.showDebugInfo) {
            this.createDebugPanel();
        }
        
        // Setup global debug object
        window.GameDebug = {
            // Game state access
            getGame: () => GameState.getGame(),
            getSettings: () => this.settings,
            
            // Performance tools
            getPerformance: () => Utils.getPerformanceReport(),
            toggleFPS: () => {
                this.settings.showFPS = !this.settings.showFPS;
                this.saveSettings();
            },
            
            // Debug info
            getDebugInfo: () => GameLogic.getDebugInfo(),
            toggleDebugPanel: () => {
                this.settings.showDebugInfo = !this.settings.showDebugInfo;
                this.saveSettings();
                if (this.settings.showDebugInfo) {
                    this.createDebugPanel();
                } else {
                    this.removeDebugPanel();
                }
            },
            
            // Game manipulation
            setPlayerLight: (amount) => {
                const game = GameState.getGame();
                game.player.light = Math.max(0, Math.min(100, amount));
            },
            
            teleportPlayer: (x, y) => {
                const game = GameState.getGame();
                game.player.x = x;
                game.player.y = y;
            },
            
            addOrb: (type) => {
                const game = GameState.getGame();
                const orbConfig = ORB_TYPES[type];
                if (orbConfig) {
                    game.orbs.push({
                        x: game.player.x + 50,
                        y: game.player.y,
                        type: type,
                        color: orbConfig.color,
                        size: 8
                    });
                }
            },
            
            clearGhouls: () => {
                const game = GameState.getGame();
                game.ghouls.length = 0;
            },
            
            // Settings
            updateSetting: (key, value) => {
                this.settings[key] = value;
                this.saveSettings();
                this.applySettings();
            },
            
            // Error testing
            triggerError: (type = 'test') => {
                throw new Error(`Debug error: ${type}`);
            },
            
            // Performance testing
            stressTest: (duration = 5000) => {
                console.log(`Starting ${duration}ms stress test...`);
                const startTime = Date.now();
                const interval = setInterval(() => {
                    const game = GameState.getGame();
                    // Add lots of particles
                    Utils.createParticles(game, 
                        Math.random() * CONFIG.CANVAS.WIDTH,
                        Math.random() * CONFIG.CANVAS.HEIGHT,
                        '#ff0000', 50, 10);
                    
                    if (Date.now() - startTime > duration) {
                        clearInterval(interval);
                        console.log('Stress test completed');
                    }
                }, 100);
            },
            
            // Debug function to test inventory system
            debugInventorySystem: () => {
                const game = GameState.getGame();
                console.log('🔍 INVENTORY DEBUG:');
                console.log('Current player inventory:', [...game.player.inventory]);
                console.log('Level entry inventory:', game.levelEntryInventory);
                console.log('Current floor:', game.floor);
                console.log('Checkpoint floor:', game.checkpoint);
                
                // Add some test orbs to inventory if empty
                if (!game.player.inventory.some(item => item !== null)) {
                    console.log('🧪 Adding test orbs to inventory...');
                    game.player.inventory = ['common', 'golden', 'purple'];
                    if (typeof InventoryManager !== 'undefined' && InventoryManager.updateDisplay) {
                        InventoryManager.updateDisplay();
                    }
                }
            },
            
            addTestOrbs: () => {
                const game = GameState.getGame();
                game.player.inventory = ['common', 'golden', 'purple'];
                if (typeof InventoryManager !== 'undefined' && InventoryManager.updateDisplay) {
                    InventoryManager.updateDisplay();
                }
                console.log('🧪 Added test orbs to inventory');
            },
            
            showInventoryState: () => {
                const game = GameState.getGame();
                console.log('🔍 INVENTORY STATE:');
                console.log('Current inventory:', [...game.player.inventory]);
                console.log('Level entry inventory:', game.levelEntryInventory);
                console.log('Floor:', game.floor);
                console.log('Checkpoint:', game.checkpoint);
            },
            
            simulateFloorTransition: () => {
                const game = GameState.getGame();
                console.log('🚪 Simulating floor transition...');
                console.log('Before - Current inventory:', [...game.player.inventory]);
                console.log('Before - Level entry inventory:', game.levelEntryInventory);
                
                // Simulate stairs interaction
                game.levelEntryInventory = [...game.player.inventory];
                game.floor++;
                
                console.log('After - Level entry inventory stored:', game.levelEntryInventory);
                console.log('After - New floor:', game.floor);
            },
            
            testRestartLevel: () => {
                console.log('🔄 Testing level restart...');
                GameState.restartCurrentLevel();
            },
            
            testInventoryScenarios: () => {
                const game = GameState.getGame();
                console.log('🧪 TESTING INVENTORY SCENARIOS:');
                
                // Scenario 1: Test restart on level 1 (should have empty inventory)
                console.log('\\n--- Scenario 1: Level 1 Restart (Empty Inventory) ---');
                game.floor = 1;
                game.levelEntryInventory = [null, null, null]; // Level 1 entry inventory
                game.player.inventory = ['blue', 'gold', 'purple']; // Current inventory
                console.log('1. Before restart - Current inventory:', [...game.player.inventory]);
                console.log('1. Before restart - Level entry inventory:', game.levelEntryInventory);
                GameState.restartCurrentLevel();
                console.log('1. After restart - Final inventory:', [...game.player.inventory]);
                console.log('1. Expected: [null, null, null] - Should be empty');
                
                // Scenario 2: Test with level entry inventory containing items
                console.log('\\n--- Scenario 2: Level with Entry Inventory ---');
                game.floor = 5;
                game.levelEntryInventory = ['blue', null, 'green']; // Had blue and green when entering level 5
                game.player.inventory = ['blue', 'gold', 'purple']; // Current inventory (different)
                console.log('2. Before restart - Current inventory:', [...game.player.inventory]);
                console.log('2. Before restart - Level entry inventory:', game.levelEntryInventory);
                GameState.restartCurrentLevel();
                console.log('2. After restart - Final inventory:', [...game.player.inventory]);
                console.log('2. Expected: ["blue", null, "green"] - Should match entry inventory');
                
                // Scenario 3: Test level entry inventory tracking when using stairs
                console.log('\\n--- Scenario 3: Level Entry Inventory Tracking ---');
                game.floor = 3;
                game.player.inventory = ['gold', 'purple', null]; // Current inventory before stairs
                console.log('3. Before using stairs - Current inventory:', [...game.player.inventory]);
                
                // Simulate using stairs (this should set levelEntryInventory for the NEW floor)
                game.floor = 4; // Simulate going to floor 4
                game.levelEntryInventory = [...game.player.inventory]; // This is what checkStairs does
                console.log('3. After using stairs to floor 4 - Level entry inventory set to:', game.levelEntryInventory);
                console.log('3. This should be: ["gold", "purple", null]');
                
                // Now test restart on floor 4
                game.player.inventory = ['blue', 'red', 'white']; // Player collected different items
                console.log('3. Player then collected different items:', [...game.player.inventory]);
                GameState.restartCurrentLevel();
                console.log('3. After restart - Final inventory:', [...game.player.inventory]);
                console.log('3. Expected: ["gold", "purple", null] - Should match what player had when entering floor 4');
                
                console.log('\\n🧪 INVENTORY TEST COMPLETE');
            },
            
            testLevelEntryTracking: () => {
                const game = GameState.getGame();
                console.log('🔍 TESTING LEVEL ENTRY INVENTORY TRACKING:');
                
                // Reset to known state
                game.floor = 1;
                game.player.inventory = [null, null, null];
                game.levelEntryInventory = [null, null, null];
                
                console.log('\\nStarting at floor 1 with empty inventory');
                console.log('Floor 1 - Entry inventory:', game.levelEntryInventory);
                console.log('Floor 1 - Current inventory:', [...game.player.inventory]);
                
                // Simulate collecting items on floor 1
                game.player.inventory = ['blue', null, 'green'];
                console.log('\\nCollected items on floor 1:', [...game.player.inventory]);
                
                // Simulate going to floor 2 (this should set entry inventory for floor 2)
                console.log('\\nUsing stairs to go to floor 2...');
                game.floor = 2;
                game.levelEntryInventory = [...game.player.inventory]; // What checkStairs does
                console.log('Floor 2 - Entry inventory set to:', game.levelEntryInventory);
                
                // Simulate collecting more items on floor 2
                game.player.inventory = ['blue', 'gold', 'green'];
                console.log('\\nCollected more items on floor 2:', [...game.player.inventory]);
                
                // Test restart on floor 2
                console.log('\\nRestarting floor 2...');
                GameState.restartCurrentLevel();
                console.log('After restart - Inventory should be entry inventory:', [...game.player.inventory]);
                console.log('Expected: ["blue", null, "green"] (what player had when entering floor 2)');
                
                console.log('\\n🔍 LEVEL ENTRY TRACKING TEST COMPLETE');
            },
            
            simulateProperLevelTransition: () => {
                const game = GameState.getGame();
                console.log('🚪 SIMULATING PROPER LEVEL TRANSITION:');
                
                // Start fresh
                game.floor = 1;
                game.player.inventory = [null, null, null];
                game.levelEntryInventory = [null, null, null]; // Empty when starting level 1
                console.log('\n📍 Level 1 - Entry inventory (empty):', game.levelEntryInventory);
                
                // Player collects items on level 1
                game.player.inventory = ['blue', 'gold', null];
                console.log('🎒 Player collected items on level 1:', [...game.player.inventory]);
                
                // Player uses stairs to go to level 2
                console.log('\n🚪 Using stairs from level 1 to level 2...');
                game.floor = 2;
                // This is what checkStairs() does - set entry inventory for NEW level
                game.levelEntryInventory = [...game.player.inventory];
                console.log('📍 Level 2 - Entry inventory set to:', game.levelEntryInventory);
                console.log('📍 This means: when player entered level 2, they had:', game.levelEntryInventory);
                
                // Player collects different items on level 2
                game.player.inventory = ['blue', 'gold', 'purple'];
                console.log('\n🎒 Player collected more items on level 2:', [...game.player.inventory]);
                
                // Now test restart - should restore level 2 entry inventory
                console.log('\n🔄 Player restarts level 2...');
                GameState.restartCurrentLevel();
                console.log('✅ After restart - Player inventory:', [...game.player.inventory]);
                console.log('✅ Expected: ["blue", "gold", null] (what they had when entering level 2)');
                
                console.log('\n🚪 LEVEL TRANSITION SIMULATION COMPLETE');
            },
            
            // Test the exact scenario the user reported
            testUserScenario: () => {
                const game = GameState.getGame();
                console.log('🧪 TESTING USER SCENARIO: Level 2 with purple, green, purple');
                
                // Set up level 1 first
                game.floor = 1;
                game.player.inventory = [null, null, null];
                game.levelEntryInventory = [null, null, null]; // Level 1 starts empty
                console.log('\n📍 Level 1 - Starting with empty inventory');
                
                // Player collects purple, green, purple on level 1
                game.player.inventory = ['purple', 'green', 'purple'];
                console.log('🎒 Player collected on level 1:', [...game.player.inventory]);
                
                // Player goes to level 2 (simulate stairs)
                console.log('\n🚪 Player uses stairs to go to level 2...');
                game.floor = 2;
                game.levelEntryInventory = [...game.player.inventory]; // Set entry inventory for level 2
                console.log('📍 Level 2 - Entry inventory set to:', game.levelEntryInventory);
                
                // Player does something on level 2 (maybe collects more items or uses items)
                game.player.inventory = ['purple', 'green', null]; // Maybe used one purple
                console.log('🎒 Player inventory changed on level 2:', [...game.player.inventory]);
                
                // Player restarts level 2
                console.log('\n🔄 Player restarts level 2...');
                console.log('Before restart - Current inventory:', [...game.player.inventory]);
                console.log('Before restart - Level entry inventory:', game.levelEntryInventory);
                
                GameState.restartCurrentLevel();
                
                console.log('After restart - Final inventory:', [...game.player.inventory]);
                console.log('Expected: ["purple", "green", "purple"] (what they had entering level 2)');
                
                if (JSON.stringify(game.player.inventory) === JSON.stringify(['purple', 'green', 'purple'])) {
                    console.log('✅ TEST PASSED: Inventory correctly restored');
                } else {
                    console.log('❌ TEST FAILED: Inventory not correctly restored');
                    console.log('Expected: ["purple", "green", "purple"]');
                    console.log('Actual:', [...game.player.inventory]);
                }
                
                console.log('\n🧪 USER SCENARIO TEST COMPLETE');
            },
            
            testInventorySystem: () => {
                const game = GameState.getGame();
                console.log('🧪 TESTING COMPLETE INVENTORY SYSTEM:');
                
                // Test 1: Fresh game start
                console.log('\\n📍 TEST 1: Fresh Game Start');
                GameState.startGame(); // This should set levelEntryInventory to [null, null, null]
                console.log('Level 1 entry inventory:', game.levelEntryInventory);
                console.log('Player inventory:', [...game.player.inventory]);
                
                // Test 2: Collect items on level 1
                console.log('\\n📍 TEST 2: Collecting Items on Level 1');
                game.player.inventory = ['purple', 'green', 'blue'];
                console.log('Player collected items:', [...game.player.inventory]);
                console.log('Level entry inventory (should still be empty):', game.levelEntryInventory);
                
                // Test 3: Transition to level 2 (simulate stairs)
                console.log('\\n📍 TEST 3: Transitioning to Level 2');
                const originalFloor = game.floor;
                
                // Simulate the stairs transition logic from gameLogic.js
                game.floor++;
                game.levelEntryInventory = [...game.player.inventory]; // This is what the fix does
                console.log(`Transitioned from floor ${originalFloor} to floor ${game.floor}`);
                console.log('Level entry inventory for level 2:', game.levelEntryInventory);
                console.log('Player inventory:', [...game.player.inventory]);
                
                // Test 4: Player uses/loses items on level 2
                console.log('\\n📍 TEST 4: Player Uses Items on Level 2');
                game.player.inventory[2] = null; // Used blue orb
                console.log('Player used blue orb, current inventory:', [...game.player.inventory]);
                console.log('Level entry inventory (should be unchanged):', game.levelEntryInventory);
                
                // Test 5: Restart level 2
                console.log('\\n📍 TEST 5: Restart Level 2');
                GameState.restartCurrentLevel();
                console.log('After restart - Player inventory:', [...game.player.inventory]);
                console.log('After restart - Level entry inventory:', game.levelEntryInventory);
                
                console.log('\\n✅ INVENTORY SYSTEM TEST COMPLETE');
                console.log('Expected: Player inventory should be restored to ["purple", "green", "blue"]');
            }
        };
        
        console.log('🔧 Debug tools available via window.GameDebug');
    },

    // Create debug panel
    createDebugPanel() {
        if (document.getElementById('debugPanel')) return;
        
        const panel = document.createElement('div');
        panel.id = 'debugPanel';
        panel.className = 'debug-panel';
        
        document.body.appendChild(panel);
        
        // Update debug info every second
        this.debugUpdateInterval = setInterval(() => {
            this.updateDebugPanel();
        }, 1000);
    },

    // Remove debug panel
    removeDebugPanel() {
        const panel = document.getElementById('debugPanel');
        if (panel) {
            panel.remove();
        }
        
        if (this.debugUpdateInterval) {
            clearInterval(this.debugUpdateInterval);
        }
    },

    // Update debug panel content
    updateDebugPanel() {
        const panel = document.getElementById('debugPanel');
        if (!panel) return;
        
        const debugInfo = GameLogic.getDebugInfo();
        const game = GameState.getGame();
        
        panel.innerHTML = `
            <div class="debug-label">🔍 DEBUG INFO</div>
            <div>FPS: ${debugInfo.performance.fps}</div>
            <div>Frame: ${debugInfo.performance.frameTime}ms</div>
            <div>Render: ${debugInfo.performance.renderTime}ms</div>
            <div>Update: ${debugInfo.performance.updateTime}ms</div>
            <div>---</div>
            <div>Floor: ${game.floor}</div>
            <div>Light: ${Math.round(game.player.light)}%</div>
            <div>Pos: ${Math.round(game.player.x)}, ${Math.round(game.player.y)}</div>
            <div>Ghouls: ${game.ghouls.length}</div>
            <div>Orbs: ${game.orbs.length}</div>
            <div>Particles: ${game.particles.length}</div>
            <div>---</div>
            <div>Errors: ${debugInfo.errors.errorCount}</div>
            <div>Pool Size: ${debugInfo.performance.particlePoolSize}</div>
            <div>Spatial Cells: ${debugInfo.performance.spatialGridCells}</div>
            <div>---</div>
            <div>Device: ${debugInfo.device.isMobile ? 'Mobile' : 'Desktop'}</div>
            <div>Screen: ${debugInfo.device.screenSize}</div>
            <div>Orientation: ${debugInfo.device.orientation}</div>
        `;
    },

    // Show confirmation dialog
    showConfirmationDialog(title, message, onConfirm, onCancel) {
        // Create overlay
        const overlay = document.createElement('div');
        overlay.className = 'confirm-overlay';

        // Create dialog
        const dialog = document.createElement('div');
        dialog.className = 'confirm-dialog';
        
        // Add corner decorations
        const corners = ['top-left', 'top-right', 'bottom-left', 'bottom-right'];
        corners.forEach(corner => {
            const decoration = document.createElement('div');
            decoration.className = 'confirm-corner confirm-corner--' + corner;
            dialog.appendChild(decoration);
        });
        
        // Title
        const titleElement = document.createElement('h2');
        titleElement.className = 'confirm-title';
        titleElement.textContent = title;

        // Message
        const messageElement = document.createElement('div');
        messageElement.className = 'confirm-message';
        // Build message content safely using DOM methods instead of innerHTML.
        // `message` is an array of objects describing content parts:
        //   { text: 'string' }        - plain text node
        //   { bold: 'string' }        - <strong> element
        //   { br: true }              - <br> line break
        //   { items: ['a', 'b'] }     - list of text lines separated by <br>
        if (Array.isArray(message)) {
            message.forEach(part => {
                if (part.text != null) {
                    messageElement.appendChild(document.createTextNode(part.text));
                } else if (part.bold != null) {
                    const strong = document.createElement('strong');
                    strong.textContent = part.bold;
                    messageElement.appendChild(strong);
                } else if (part.br) {
                    messageElement.appendChild(document.createElement('br'));
                } else if (part.items) {
                    part.items.forEach((item, index) => {
                        messageElement.appendChild(document.createTextNode(item));
                        if (index < part.items.length - 1) {
                            messageElement.appendChild(document.createElement('br'));
                        }
                    });
                }
            });
        } else {
            // Fallback for plain text strings
            messageElement.textContent = message;
        }
        
        // Button container
        const buttonContainer = document.createElement('div');
        buttonContainer.className = 'confirm-buttons';

        // Confirm button
        const confirmButton = document.createElement('button');
        confirmButton.textContent = 'CONFIRM';
        confirmButton.className = 'confirm-btn confirm-btn--ok';

        // Cancel button
        const cancelButton = document.createElement('button');
        cancelButton.textContent = 'CANCEL';
        cancelButton.className = 'confirm-btn confirm-btn--cancel';
        
        // Add hover effects
        confirmButton.addEventListener('mouseenter', () => {
            confirmButton.style.transform = 'translateY(-2px)';
            confirmButton.style.boxShadow = '0 6px 20px rgba(76, 175, 80, 0.4)';
        });
        confirmButton.addEventListener('mouseleave', () => {
            confirmButton.style.transform = 'translateY(0)';
            confirmButton.style.boxShadow = '0 4px 15px rgba(76, 175, 80, 0.3)';
        });
        
        cancelButton.addEventListener('mouseenter', () => {
            cancelButton.style.transform = 'translateY(-2px)';
            cancelButton.style.boxShadow = '0 6px 20px rgba(244, 67, 54, 0.4)';
        });
        cancelButton.addEventListener('mouseleave', () => {
            cancelButton.style.transform = 'translateY(0)';
            cancelButton.style.boxShadow = '0 4px 15px rgba(244, 67, 54, 0.3)';
        });
        
        // Event listeners (click + touch for mobile)
        this.addMobileFriendlyListener(confirmButton, () => {
            if (overlay.parentNode) document.body.removeChild(overlay);
            if (onConfirm) onConfirm();
        });

        this.addMobileFriendlyListener(cancelButton, () => {
            if (overlay.parentNode) document.body.removeChild(overlay);
            if (onCancel) onCancel();
        });
        
        // Escape key to cancel
        const escapeHandler = (e) => {
            if (e.key === 'Escape') {
                // Safety check to ensure overlay exists before removing
                if (overlay && overlay.parentNode) {
                    document.body.removeChild(overlay);
                }
                document.removeEventListener('keydown', escapeHandler);
                if (onCancel) onCancel();
            }
        };
        document.addEventListener('keydown', escapeHandler);
        
        // Assemble dialog
        buttonContainer.appendChild(confirmButton);
        buttonContainer.appendChild(cancelButton);
        dialog.appendChild(titleElement);
        dialog.appendChild(messageElement);
        dialog.appendChild(buttonContainer);
        overlay.appendChild(dialog);
        document.body.appendChild(overlay);
        
        // Focus confirm button
        confirmButton.focus();
    },

    // Setup settings UI
    setupSettingsUI() {
        // Create settings button
        const settingsBtn = document.createElement('button');
        settingsBtn.textContent = '⚙️';
        settingsBtn.id = 'settingsButton';
        settingsBtn.className = 'settings-btn';
        // Settings button now acts like ESC key - shows pause menu if in game
        const settingsAction = () => {
            const game = GameState.getGame();
            if (game && game.state === 'playing') {
                this.togglePause();
            } else {
                this.showSettingsModal();
            }
        };
        settingsBtn.addEventListener('click', settingsAction);
        settingsBtn.addEventListener('touchend', (e) => {
            e.preventDefault();
            settingsAction();
        }, { passive: false });
        document.body.appendChild(settingsBtn);
    },

    // Show settings modal
    showSettingsModal(isPauseMenu = false) {
        // Remove existing modal if present
        const existingModal = document.getElementById('settingsModal');
        if (existingModal) {
            existingModal.remove();
        }

        const stats = GameState.getFormattedStats();
        
        // Generate achievements list with all achievements visible
        let achievementsList = '';
        const unlockedAchievements = GameState.stats.achievements;

        Object.entries(GameState.achievements).forEach(([id, achievement]) => {
            const isUnlocked = unlockedAchievements.has(id);
            const stateClass = isUnlocked ? 'unlocked' : 'locked';

            achievementsList += `
                <div class="achievement-item achievement-item--${stateClass}">
                    <div class="achievement-icon">${achievement.icon}</div>
                    <div class="achievement-info">
                        <div class="achievement-name--${stateClass}">${achievement.name}</div>
                        <div class="achievement-desc--${stateClass}">${achievement.description}</div>
                        <div class="achievement-status--${stateClass}">${isUnlocked ? '✓ UNLOCKED' : '🔒 LOCKED'}</div>
                    </div>
                </div>
            `;
        });

        const modal = document.createElement('div');
        modal.id = 'settingsModal';
        modal.className = 'settings-modal-overlay';

        modal.innerHTML = `
            <div class="settings-modal-content">
                <!-- Golden corner decorations -->
                <div class="settings-corner settings-corner--tl"></div>
                <div class="settings-corner settings-corner--tr"></div>
                <div class="settings-corner settings-corner--bl"></div>
                <div class="settings-corner settings-corner--br"></div>

                <div class="settings-header">
                    <h2 class="settings-title">
                        ${isPauseMenu ? '⚜ QUEST PAUSED ⚜' : '⚙ SACRED SETTINGS ⚙'}
                    </h2>
                    <button id="closeModal" class="settings-close-btn">✕</button>
                </div>

                ${isPauseMenu ? `
                <div class="pause-actions">
                    <button id="resumeGame" class="pause-btn pause-btn--resume">♦ RESUME</button>
                    <button id="restartGame" class="pause-btn pause-btn--restart">♠ RESTART</button>
                    <button id="replayFromCheckpoint" class="pause-btn pause-btn--checkpoint">♣ CHECKPOINT</button>
                    <button id="quitToMenu" class="pause-btn pause-btn--quit">♥ MENU</button>
                </div>
                ` : ''}

                <div class="tab-bar">
                    <button id="settingsTab" class="tab-btn active">⚙️ SETTINGS</button>
                    <button id="statsTab" class="tab-btn">📊 STATS</button>
                    <button id="achievementsTab" class="tab-btn">🏆 ACHIEVEMENTS</button>
                    <button id="helpTab" class="tab-btn">❓ HELP</button>
                </div>

                <!-- Settings Panel -->
                <div id="settingsPanel" class="tab-panel">
                    <div class="settings-grid">
                        <h3 class="settings-section-title">⚙️ Game Settings</h3>

                        <div class="settings-sub-grid">
                            <div class="settings-card">
                                <label class="settings-label">Graphics Quality:</label>
                                <select id="graphicsQuality" class="settings-select">
                                    <option value="low">Low (Better Performance)</option>
                                    <option value="medium">Medium (Balanced)</option>
                                    <option value="high">High (Best Quality)</option>
                                </select>
                            </div>

                            <div class="settings-checkbox-grid">
                                <label class="settings-checkbox-label">
                                    <input type="checkbox" id="showFPS" class="settings-checkbox">
                                    <span class="settings-bold">Show FPS Counter</span>
                                </label>
                                <label class="settings-checkbox-label">
                                    <input type="checkbox" id="showDebugInfo" class="settings-checkbox">
                                    <span class="settings-bold">Debug Information</span>
                                </label>
                                <label class="settings-checkbox-label">
                                    <input type="checkbox" id="enableSoundEffects" class="settings-checkbox">
                                    <span class="settings-bold">Sound Effects</span>
                                </label>
                                <label class="settings-checkbox-label">
                                    <input type="checkbox" id="autoSave" class="settings-checkbox">
                                    <span class="settings-bold">Auto Save</span>
                                </label>
                            </div>

                            <div class="settings-card">
                                <label class="settings-label--inline">Volume: <span id="volumeValue" class="settings-value">${Math.round(this.settings.volume * 100)}%</span></label>
                                <input type="range" id="volume" min="0" max="1" step="0.1" value="${this.settings.volume}" class="settings-range">
                            </div>

                            <div class="settings-card">
                                <label class="settings-label--inline">Touch Sensitivity: <span id="touchSensitivityValue" class="settings-value">${this.settings.touchSensitivity}x</span></label>
                                <input type="range" id="touchSensitivity" min="0.5" max="2" step="0.1" value="${this.settings.touchSensitivity}" class="settings-range">
                            </div>
                        </div>

                        <div class="settings-action-row">
                            <button id="applySettings" class="settings-apply-btn">✅ APPLY SETTINGS</button>
                            <button id="resetSettings" class="settings-reset-btn">🔄 RESET DEFAULTS</button>
                        </div>

                        <div id="settingsMessage" class="settings-message">
                            ✅ Settings have been applied successfully!
                        </div>
                    </div>
                </div>

                <!-- Statistics Panel -->
                <div id="statsPanel" class="tab-panel tab-panel--hidden">
                    <div class="stats-grid">
                        <h3 class="settings-section-title">📊 Game Statistics</h3>
                        <div class="stats-cards">
                            <div class="stats-card"><strong>Total Play Time:</strong><br><span>${stats.totalPlayTime}</span></div>
                            <div class="stats-card"><strong>Games Played:</strong><br><span>${stats.gamesPlayed}</span></div>
                            <div class="stats-card"><strong>Deepest Floor:</strong><br><span>${stats.deepestFloor}</span></div>
                            <div class="stats-card"><strong>Total Deaths:</strong><br><span>${stats.totalDeaths}</span></div>
                            <div class="stats-card"><strong>Orbs Collected:</strong><br><span>${stats.totalOrbsCollected}</span></div>
                            <div class="stats-card"><strong>Distance Traveled:</strong><br><span>${stats.totalDistanceTraveled}</span></div>
                            <div class="stats-card"><strong>Fastest Completion:</strong><br><span>${stats.fastestCompletion}</span></div>
                            <div class="stats-card"><strong>Achievements:</strong><br><span>${stats.achievementsUnlocked}/${stats.totalAchievements}</span></div>
                        </div>
                        <div class="stats-progress-section">
                            <div class="stats-progress-header">
                                <strong>Achievement Progress</strong>
                                <span>${Math.round((stats.achievementsUnlocked / stats.totalAchievements) * 100)}%</span>
                            </div>
                            <div class="stats-progress-bar">
                                <div class="stats-progress-fill" data-width="${(stats.achievementsUnlocked / stats.totalAchievements) * 100}"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Achievements Panel -->
                <div id="achievementsPanel" class="tab-panel tab-panel--hidden">
                    <h3 class="achievements-title">🏆 Achievements</h3>
                    <div class="achievements-scroll">
                        ${achievementsList || '<div class="achievements-empty">No achievements data available!</div>'}
                    </div>
                    <div class="achievements-tip">
                        💡 <strong>Tip:</strong> Unlocked achievements glow with golden light, while locked achievements remain in shadow. Explore the depths to unlock them all!
                    </div>
                </div>

                <!-- Help Panel -->
                <div id="helpPanel" class="tab-panel tab-panel--hidden">
                    <div class="help-scroll">
                        <h3 class="settings-section-title">❓ Game Help & Guide</h3>

                        <div class="help-section">
                            <h4>🎯 Mission</h4>
                            <p class="help-text">
                                Descend through the mysterious Buried Spire to reach floor -${CONFIG.GAME.MAX_FLOORS} and find the legendary Ancient Pearl. Navigate through dark corridors of the ancient Burj Mubarak while managing your light and avoiding the lurking ghouls.
                            </p>
                        </div>

                        <div class="help-section">
                            <h4>🎮 Controls</h4>
                            <div class="help-controls">
                                <strong>Movement:</strong> WASD or Arrow Keys<br>
                                <strong>Use Orbs:</strong> Press 1, 2, or 3 keys<br>
                                <strong>Help:</strong> Press H to toggle help overlay<br>
                                <strong>Pause:</strong> Press ESC to pause the game<br>
                                <strong>Settings:</strong> Click ⚙️ button (top-right)
                            </div>
                        </div>

                        <div class="help-section">
                            <h4 class="help-orb-title">🔮 Orb Types</h4>
                            <div class="help-orb-grid">
                                <div class="help-orb-item help-orb-item--blue">
                                    <span class="help-orb-symbol help-orb-symbol--blue">O</span>
                                    <span><strong class="help-orb-name--blue">Blue Orb:</strong> Restores 15% light - collect immediately</span>
                                </div>
                                <div class="help-orb-item help-orb-item--gold">
                                    <span class="help-orb-symbol help-orb-symbol--gold">@</span>
                                    <span><strong class="help-orb-name--gold">Golden Orb:</strong> Restores 25% light - collect immediately</span>
                                </div>
                                <div class="help-orb-item help-orb-item--purple">
                                    <span class="help-orb-symbol help-orb-symbol--purple">P</span>
                                    <span><strong class="help-orb-name--purple">Purple Orb:</strong> Phase through walls for 5 seconds</span>
                                </div>
                                <div class="help-orb-item help-orb-item--green">
                                    <span class="help-orb-symbol help-orb-symbol--green">G</span>
                                    <span><strong class="help-orb-name--green">Green Orb:</strong> Regenerate light for 10 seconds</span>
                                </div>
                                <div class="help-orb-item help-orb-item--white">
                                    <span class="help-orb-symbol help-orb-symbol--white">W</span>
                                    <span><strong class="help-orb-name--white">White Orb:</strong> Reveal entire map for 5 seconds</span>
                                </div>
                                <div class="help-orb-item help-orb-item--red">
                                    <span class="help-orb-symbol help-orb-symbol--red">♥</span>
                                    <span><strong class="help-orb-name--red">Red Orb:</strong> Auto-revives you when light reaches 0%</span>
                                </div>
                                <div class="help-orb-item help-orb-item--wisp">
                                    <span class="help-orb-symbol help-orb-symbol--wisp">*</span>
                                    <span><strong class="help-orb-name--wisp">Light Wisp:</strong> Death marker - Restores 50% light</span>
                                </div>
                            </div>
                        </div>

                        <div class="help-section">
                            <h4>👻 Ghouls & Survival</h4>
                            <div class="help-survival">
                                • <strong>Ghouls flee from bright light</strong> - stay near the center of your light radius<br>
                                • <strong>Ghouls stalk you in dim light</strong> - they increase light depletion when near<br>
                                • <strong>When light reaches 0%</strong> - ghouls swarm! Use a lifeline orb or face death<br>
                                • <strong>Checkpoints every 5 floors</strong> - you'll respawn at the last checkpoint<br>
                                • <strong>Light radius shrinks</strong> as your light depletes - manage it carefully!
                            </div>
                        </div>

                        <div class="help-section--tips">
                            <h4>💡 Pro Tips</h4>
                            <div class="help-tips-text">
                                • Collect blue orbs immediately - they don't take inventory space<br>
                                • Save red lifeline orbs for emergencies - they auto-activate at 0% light<br>
                                • Use purple phase orbs to escape tight situations or find shortcuts<br>
                                • Green regeneration orbs are great for long-term light management<br>
                                • White reveal orbs help you navigate efficiently and find stairs quickly
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // Set dynamic widths via JS (CSP-safe)
        const progressFill = modal.querySelector('.stats-progress-fill');
        if (progressFill) {
            progressFill.style.width = progressFill.dataset.width + '%';
        }

        // Setup tab switching
        this.setupTabSwitching(modal);
        
        // Setup event listeners
        this.setupSettingsEventListeners(modal, isPauseMenu);
        
        // Load current settings
        this.loadSettingsIntoModal();
    },

    // Setup tab switching functionality
    setupTabSwitching(modal) {
        const tabs = modal.querySelectorAll('.tab-btn');
        const panels = modal.querySelectorAll('.tab-panel');
        
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                // Remove active class from all tabs and panels
                tabs.forEach(t => {
                    t.classList.remove('active');
                    t.style.background = '';
                    t.style.color = '';
                    t.style.textShadow = '';
                });
                panels.forEach(p => p.classList.add('tab-panel--hidden'));

                // Add active class to clicked tab
                tab.classList.add('active');
                
                // Show corresponding panel
                const panelId = tab.id.replace('Tab', 'Panel');
                const panel = modal.querySelector(`#${panelId}`);
                if (panel) {
                    panel.classList.remove('tab-panel--hidden');
                }
            });
        });
    },

    // Add both click and touch handlers for mobile compatibility
    addMobileFriendlyListener(element, handler) {
        if (!element) return;
        element.addEventListener('click', handler);
        element.addEventListener('touchend', (e) => {
            e.preventDefault();
            handler(e);
        }, { passive: false });
    },

    // Setup settings event listeners
    setupSettingsEventListeners(modal, isPauseMenu) {
        // Pause menu buttons (only if this is a pause menu)
        if (isPauseMenu) {
            this.addMobileFriendlyListener(document.getElementById('resumeGame'), () => {
                this.isPaused = false;
                this.hidePauseMenu();
            });
            
            this.addMobileFriendlyListener(document.getElementById('restartGame'), () => {
                const game = GameState.getGame();
                const currentFloor = Math.abs(game.floor);
                
                // Create inventory summary
                const inventoryItems = [];
                for (let i = 0; i < game.player.inventory.length; i++) {
                    const orb = game.player.inventory[i];
                    if (orb) {
                        if (typeof ORB_TYPES !== 'undefined' && ORB_TYPES[orb]) {
                            inventoryItems.push(`${ORB_TYPES[orb].symbol} ${ORB_TYPES[orb].name}`);
                        } else {
                            inventoryItems.push(`${orb} orb`);
                        }
                    }
                }
                const inventoryParts = inventoryItems.length > 0 ?
                    [{ br: true }, { br: true }, { bold: 'Your current inventory:' }, { br: true }, { items: inventoryItems }] :
                    [{ br: true }, { br: true }, { bold: 'Your inventory is empty.' }];

                this.showConfirmationDialog(
                    '\u{1F504} RESTART LEVEL',
                    [
                        { text: `Are you sure you want to restart Floor ${currentFloor}?` },
                        { br: true }, { br: true },
                        { text: 'You will restart this level with the inventory you had when you first entered it.' },
                        ...inventoryParts
                    ],
                    () => {
                        this.isPaused = false;
                        this.hidePauseMenu();
                        GameState.restartCurrentLevel();
                    }
                );
            });
            
            this.addMobileFriendlyListener(document.getElementById('replayFromCheckpoint'), () => {
                const game = GameState.getGame();
                const checkpointFloor = Math.abs(game.checkpoint);
                const checkpointNumber = Math.ceil(checkpointFloor / 5);
                
                // Create inventory summary
                const inventoryItems = [];
                for (let i = 0; i < game.player.inventory.length; i++) {
                    const orb = game.player.inventory[i];
                    if (orb) {
                        if (typeof ORB_TYPES !== 'undefined' && ORB_TYPES[orb]) {
                            inventoryItems.push(`${ORB_TYPES[orb].symbol} ${ORB_TYPES[orb].name}`);
                        } else {
                            inventoryItems.push(`${orb} orb`);
                        }
                    }
                }
                const inventoryParts = inventoryItems.length > 0 ?
                    [{ br: true }, { br: true }, { bold: 'Your current inventory will be retained:' }, { br: true }, { items: inventoryItems }] :
                    [{ br: true }, { br: true }, { bold: 'Your inventory is currently empty.' }];

                this.showConfirmationDialog(
                    '\u{1F4CD} RETURN TO CHECKPOINT',
                    [
                        { text: `Are you sure you want to return to Checkpoint ${checkpointNumber}?` },
                        { br: true }, { br: true },
                        { text: `You will be taken to Floor ${checkpointFloor} and retain your current inventory.` },
                        ...inventoryParts
                    ],
                    () => {
                        this.isPaused = false;
                        this.hidePauseMenu();
                        GameState.respawnAtCheckpoint();
                    }
                );
            });
            
            this.addMobileFriendlyListener(document.getElementById('quitToMenu'), () => {
                this.isPaused = false;
                this.hidePauseMenu();
                GameState.quitToMenu();
            });
        }

        // Volume slider
        const volumeSlider = document.getElementById('volume');
        const volumeValue = document.getElementById('volumeValue');
        volumeSlider.addEventListener('input', (e) => {
            volumeValue.textContent = `${Math.round(e.target.value * 100)}%`;
            // Apply volume change immediately for testing
            if (window.SoundManager) {
                SoundManager.setVolume(parseFloat(e.target.value));
            }
        });
        
        // Touch sensitivity slider
        const touchSlider = document.getElementById('touchSensitivity');
        const touchValue = document.getElementById('touchSensitivityValue');
        touchSlider.addEventListener('input', (e) => {
            touchValue.textContent = `${e.target.value}x`;
        });
        
        // Apply settings button
        this.addMobileFriendlyListener(document.getElementById('applySettings'), () => {
            this.applySettingsFromModal();
            // Show confirmation message
            const message = document.getElementById('settingsMessage');
            if (message) {
                message.style.display = 'block';
                setTimeout(() => {
                    message.style.display = 'none';
                }, 3000);
            }
        });

        // Reset settings button
        this.addMobileFriendlyListener(document.getElementById('resetSettings'), () => {
            this.resetSettings();
            this.loadSettingsIntoModal();
        });

        // Close button
        this.addMobileFriendlyListener(document.getElementById('closeModal'), () => {
            if (isPauseMenu) {
                this.isPaused = false;
                this.hidePauseMenu();
            } else {
                modal.remove();
            }
        });

        // Close on outside click/touch
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                if (isPauseMenu) {
                    this.isPaused = false;
                    this.hidePauseMenu();
                } else {
                    modal.remove();
                }
            }
        });
        modal.addEventListener('touchend', (e) => {
            if (e.target === modal) {
                e.preventDefault();
                if (isPauseMenu) {
                    this.isPaused = false;
                    this.hidePauseMenu();
                } else {
                    modal.remove();
                }
            }
        }, { passive: false });
    },

    // Apply settings from modal
    applySettingsFromModal() {
        this.settings.graphicsQuality = document.getElementById('graphicsQuality').value;
        this.settings.showFPS = document.getElementById('showFPS').checked;
        this.settings.showDebugInfo = document.getElementById('showDebugInfo').checked;
        this.settings.enableSoundEffects = document.getElementById('enableSoundEffects').checked;
        this.settings.autoSave = document.getElementById('autoSave').checked;
        this.settings.volume = parseFloat(document.getElementById('volume').value);
        this.settings.touchSensitivity = parseFloat(document.getElementById('touchSensitivity').value);
        
        this.saveSettings();
        this.applySettings();
    },

    // Apply current settings
    applySettings() {
        // Clean up FPS display when disabled
        if (!this.settings.showFPS) {
            const fpsDisplay = document.getElementById('fpsDisplay');
            if (fpsDisplay) fpsDisplay.remove();
        }

        // Apply debug panel setting
        if (this.settings.showDebugInfo) {
            this.createDebugPanel();
        } else {
            this.removeDebugPanel();
        }
        
        // Apply audio settings
        if (window.SoundManager) {
            SoundManager.setVolume(this.settings.volume);
            SoundManager.setEnabled(this.settings.enableSoundEffects);
        }
        
        // Apply touch sensitivity
        if (InputManager.touchControls) {
            InputManager.touchControls.sensitivity = this.settings.touchSensitivity;
        }
        
        // Apply graphics quality
        this.applyGraphicsQuality();
        
        console.log('Settings applied:', this.settings);
    },

    // Apply graphics quality settings
    applyGraphicsQuality() {
        const quality = this.settings.graphicsQuality;

        switch (quality) {
            case 'low':
                CONFIG.GRAPHICS = {
                    quality: 'low',
                    particleMultiplier: 0.3,
                    particles: false,
                    vignette: false,
                    wallGradients: false,
                    lightFlicker: false
                };
                break;
            case 'medium':
                CONFIG.GRAPHICS = {
                    quality: 'medium',
                    particleMultiplier: 0.7,
                    particles: true,
                    vignette: true,
                    wallGradients: true,
                    lightFlicker: true
                };
                break;
            case 'high':
                CONFIG.GRAPHICS = {
                    quality: 'high',
                    particleMultiplier: 1.0,
                    particles: true,
                    vignette: true,
                    wallGradients: true,
                    lightFlicker: true
                };
                break;
        }
    },

    // Load settings from localStorage
    loadSettings() {
        try {
            const saved = localStorage.getItem('buriedSpireSettings');
            if (saved) {
                const parsedSettings = JSON.parse(saved);
                this.settings = { ...this.settings, ...parsedSettings };
                console.log('Settings loaded from localStorage');
            }
        } catch (error) {
            console.warn('Failed to load settings:', error);
        }
    },

    // Save settings to localStorage
    saveSettings() {
        try {
            localStorage.setItem('buriedSpireSettings', JSON.stringify(this.settings));
        } catch (error) {
            console.warn('Failed to save settings:', error);
        }
    },

    // Reset settings to default
    resetSettings() {
        this.settings = {
            showFPS: false,
            showDebugInfo: false,
            enableSoundEffects: true,
            graphicsQuality: 'high',
            autoSave: true,
            touchSensitivity: 1.0,
            volume: 0.7
        };
        this.saveSettings();
        this.applySettings();
    },

    // Show critical error
    showCriticalError(error) {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'critical-error';
        
        const heading = document.createElement('h2');
        heading.textContent = '\u274C Critical Error';
        const desc = document.createElement('p');
        desc.textContent = 'The game failed to initialize properly.';
        const errorP = document.createElement('p');
        const strong = document.createElement('strong');
        strong.textContent = 'Error: ';
        errorP.appendChild(strong);
        errorP.appendChild(document.createTextNode(error.message));
        const reloadBtn = document.createElement('button');
        reloadBtn.textContent = 'Reload Game';
        reloadBtn.className = 'critical-error-btn';
        reloadBtn.addEventListener('click', () => location.reload());
        errorDiv.appendChild(heading);
        errorDiv.appendChild(desc);
        errorDiv.appendChild(errorP);
        errorDiv.appendChild(reloadBtn);
        
        document.body.appendChild(errorDiv);
    },

    // Start the main game loop
    startGameLoop() {
        const gameLoop = (currentTime) => {
            try {
                // Calculate delta time
                const deltaTime = currentTime - this.lastTime;
                this.lastTime = currentTime;
                
                // Skip frame if delta time is too large (tab was inactive)
                if (deltaTime > 100) {
                    requestAnimationFrame(gameLoop);
                    return;
                }
                
                // Skip updates if game is paused, but still render
                const isTutorialPaused = TutorialSystem.shouldPauseGame();
                if (!this.isPaused && !isTutorialPaused) {
                    // Update game logic
                    Utils.startPerformanceTimer('update');
                    GameLogic.update(deltaTime);
                    Utils.endPerformanceTimer('update');
                    
                    // Update performance metrics
                    Utils.updatePerformanceMetrics(deltaTime);
                } else {
                    // When paused, still update performance metrics but with 0 delta
                    Utils.updatePerformanceMetrics(0);
                }
                
                // Always render (even when paused to show pause overlay)
                Utils.startPerformanceTimer('render');
                const game = GameState.getGame();
                if (game) {
                    Renderer.render(game);
                    
                    // Show pause overlay if paused
                    if (this.isPaused && game.state === 'playing') {
                        this.renderPauseOverlay();
                    }
                }
                Utils.endPerformanceTimer('render');
                
                // Show FPS if enabled
                if (this.settings.showFPS) {
                    this.showFPS(deltaTime);
                }
                
                // Update mobile UI visibility
                if (typeof InputManager !== 'undefined' && InputManager.updateMobileUI) {
                    InputManager.updateMobileUI();
                }

                // Auto-save periodically (only when not paused)
                if (!this.isPaused && this.settings.autoSave) {
                    this.autoSave();
                }

            } catch (error) {
                console.error('❌ Game loop error:', error);
                this.showCriticalError(error);
                return; // Stop the game loop on critical error
            }
            
            // Continue the loop
            requestAnimationFrame(gameLoop);
        };
        
        // Start the loop
        this.lastTime = performance.now();
        requestAnimationFrame(gameLoop);
    },

    // Render pause overlay on canvas
    renderPauseOverlay() {
        const canvas = document.getElementById('gameCanvas');
        const ctx = canvas.getContext('2d');

        // Semi-transparent overlay
        ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
        ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // Pause text
        ctx.fillStyle = '#87CEEB';
        ctx.font = 'bold 48px monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('⏸️ PAUSED', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2 - 40);

        ctx.fillStyle = '#B0C4DE';
        ctx.font = '24px monospace';
        const isMobilePause = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        if (isMobilePause) {
            ctx.fillText('Tap pause button to resume', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2 + 20);
        } else {
            ctx.fillText('Press ESC to resume or open settings', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2 + 20);
        }

        // Reset text properties to avoid affecting subsequent rendering
        ctx.textBaseline = 'alphabetic';
        ctx.textAlign = 'left';
    },

    // Show FPS counter
    showFPS(deltaTime) {
        let fpsDisplay = document.getElementById('fpsDisplay');
        if (!fpsDisplay) {
            fpsDisplay = document.createElement('div');
            fpsDisplay.id = 'fpsDisplay';
            fpsDisplay.className = 'fps-display';
            document.body.appendChild(fpsDisplay);
        }
        
        const fps = Math.round(1000 / deltaTime);
        const color = fps >= 50 ? '#00ff00' : fps >= 30 ? '#ffff00' : '#ff0000';
        fpsDisplay.style.color = color;
        fpsDisplay.textContent = `${fps} FPS`;
    },

    // Auto-save game progress
    autoSave() {
        try {
            const game = GameState.getGame();
            if (game.state === 'playing' && !game.deathScreen && !game.victory) {
                // Only save every 10 seconds to avoid infinite save loop
                const now = Date.now();
                if (!this.lastAutoSave || (now - this.lastAutoSave) >= 10000) {
                    this.lastAutoSave = now;
                    GameState.saveGame();
                    
                    // Show save indicator
                    this.showSaveIndicator();
                }
            }
        } catch (error) {
            console.warn('Auto-save failed:', error);
        }
    },

    // Show save indicator
    showSaveIndicator() {
        // Save indicator removed - no need to notify player
    },

    // Load settings into modal
    loadSettingsIntoModal() {
        // Set current values
        document.getElementById('graphicsQuality').value = this.settings.graphicsQuality;
        document.getElementById('showFPS').checked = this.settings.showFPS;
        document.getElementById('showDebugInfo').checked = this.settings.showDebugInfo;
        document.getElementById('enableSoundEffects').checked = this.settings.enableSoundEffects;
        document.getElementById('autoSave').checked = this.settings.autoSave;
        document.getElementById('volume').value = this.settings.volume;
        document.getElementById('touchSensitivity').value = this.settings.touchSensitivity;
        
        // Update display values
        document.getElementById('volumeValue').textContent = `${Math.round(this.settings.volume * 100)}%`;
        document.getElementById('touchSensitivityValue').textContent = `${this.settings.touchSensitivity}x`;
    }
};

// Handle page visibility changes (pause/resume)
document.addEventListener('visibilitychange', () => {
    try {
        const game = GameState.getGame();
        if (game && game.state) {
            if (document.hidden) {
                game.paused = true;
                console.log('Game paused (tab hidden)');
            } else {
                game.paused = false;
                console.log('Game resumed (tab visible)');
            }
        }
    } catch (error) {
        console.warn('Failed to handle visibility change:', error);
    }
});

// Handle beforeunload for auto-save
window.addEventListener('beforeunload', (e) => {
    if (Game.settings && Game.settings.autoSave) {
        try {
            GameState.saveGame();
        } catch (error) {
            console.warn('Failed to save on page unload:', error);
        }
    }
});

// Initialize game when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing game...');
    
    // Check for required elements
    const requiredElements = [
        'gameCanvas',
        'minimap',
        'ui',
        'inventory',
        'story'
    ];
    
    let missingElements = [];
    for (const elementId of requiredElements) {
        if (!document.getElementById(elementId)) {
            missingElements.push(elementId);
        }
    }
    
    if (missingElements.length > 0) {
        console.error('Missing required DOM elements:', missingElements);
        alert('Game cannot start - missing required elements: ' + missingElements.join(', '));
        return;
    }
    
    // Initialize the game
    try {
        Game.init();
        console.log('✅ Game initialized successfully');
    } catch (error) {
        console.error('❌ Failed to initialize game:', error);
        alert('Failed to initialize game: ' + error.message);
    }
});

// Note: Window resize is handled by InputManager.setupResponsiveCanvas()
// Note: Global error handler is set up in GameLogic.init()

console.log('Main game script loaded. Game will initialize when DOM is ready.');
console.log('Debug commands available in console via window.GameDebug');