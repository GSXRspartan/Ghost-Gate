// Input Management
const InputManager = {
    keys: {},
    touchControls: {
        active: false,
        startX: 0,
        startY: 0,
        currentX: 0,
        currentY: 0,
        deadzone: 15,
        sensitivity: 1.0,
        identifier: null
    },
    isMobile: false,
    hasTouchSupport: false,
    canvasScale: null,

    // Initialize input handlers
    init() {
        this.detectMobile();
        this.setupKeyboardEvents();
        this.setupMouseEvents();
        this.setupResponsiveCanvas();

        // Setup mobile UI and touch events if touch-capable device
        if (this.isMobile || this.hasTouchSupport) {
            this.setupMobileUI();
            // Touch events are set up AFTER mobile UI creates the DOM elements
            this.setupTouchEvents();
            this.setupCanvasTouchEvents();
        }
    },

    // Detect mobile devices and touch support
    detectMobile() {
        this.hasTouchSupport = ('ontouchstart' in window) ||
                               (navigator.maxTouchPoints && navigator.maxTouchPoints > 0);
        this.isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent) ||
                        (this.hasTouchSupport && (window.innerWidth <= 1024));
    },

    // Setup responsive canvas
    setupResponsiveCanvas() {
        const canvas = document.getElementById('gameCanvas');
        const container = document.getElementById('gameContainer');

        const resizeCanvas = () => {
            const containerWidth = container.clientWidth || window.innerWidth;
            const containerHeight = container.clientHeight || window.innerHeight;
            const screenWidth = window.innerWidth;
            const screenHeight = window.innerHeight;
            const isPortrait = screenHeight > screenWidth;

            let newWidth, newHeight;

            if (this.isMobile && isPortrait) {
                // Portrait mobile: fill the available screen below safe area (status bar/notch)
                const safeAreaTop = parseInt(getComputedStyle(document.body).paddingTop) || 0;
                newWidth = screenWidth;
                newHeight = screenHeight - safeAreaTop;

                // Calculate new internal canvas dimensions that match portrait aspect ratio
                // Keep the base width (800) and scale height proportionally to the screen
                const portraitAspect = newHeight / newWidth;
                const newCanvasWidth = CONFIG.CANVAS.BASE_WIDTH;
                const newCanvasHeight = Math.round(newCanvasWidth * portraitAspect);

                // Update the internal canvas coordinate system if dimensions changed
                if (CONFIG.CANVAS.WIDTH !== newCanvasWidth || CONFIG.CANVAS.HEIGHT !== newCanvasHeight) {
                    CONFIG.CANVAS.WIDTH = newCanvasWidth;
                    CONFIG.CANVAS.HEIGHT = newCanvasHeight;
                    // Reinitialize the canvas buffer to match new internal dimensions
                    if (typeof Renderer !== 'undefined' && Renderer.updateCanvasBuffer) {
                        Renderer.updateCanvasBuffer();
                    }
                }
            } else if (this.isMobile) {
                // Landscape mobile: use full screen with base aspect ratio
                const baseAspectRatio = CONFIG.CANVAS.BASE_WIDTH / CONFIG.CANVAS.BASE_HEIGHT;
                newWidth = screenWidth;
                newHeight = screenHeight;

                // Maintain the landscape aspect ratio
                if (newWidth / newHeight > baseAspectRatio) {
                    newWidth = newHeight * baseAspectRatio;
                } else {
                    newHeight = newWidth / baseAspectRatio;
                }

                // Restore base canvas dimensions for landscape
                if (CONFIG.CANVAS.WIDTH !== CONFIG.CANVAS.BASE_WIDTH || CONFIG.CANVAS.HEIGHT !== CONFIG.CANVAS.BASE_HEIGHT) {
                    CONFIG.CANVAS.WIDTH = CONFIG.CANVAS.BASE_WIDTH;
                    CONFIG.CANVAS.HEIGHT = CONFIG.CANVAS.BASE_HEIGHT;
                    if (typeof Renderer !== 'undefined' && Renderer.updateCanvasBuffer) {
                        Renderer.updateCanvasBuffer();
                    }
                }
            } else {
                // Desktop: maintain fixed size or scale down if needed
                const baseAspectRatio = CONFIG.CANVAS.BASE_WIDTH / CONFIG.CANVAS.BASE_HEIGHT;
                newWidth = Math.min(CONFIG.CANVAS.BASE_WIDTH, containerWidth);
                newHeight = Math.min(CONFIG.CANVAS.BASE_HEIGHT, containerHeight);

                if (newWidth / newHeight > baseAspectRatio) {
                    newWidth = newHeight * baseAspectRatio;
                } else {
                    newHeight = newWidth / baseAspectRatio;
                }

                // Ensure desktop always uses base dimensions
                if (CONFIG.CANVAS.WIDTH !== CONFIG.CANVAS.BASE_WIDTH || CONFIG.CANVAS.HEIGHT !== CONFIG.CANVAS.BASE_HEIGHT) {
                    CONFIG.CANVAS.WIDTH = CONFIG.CANVAS.BASE_WIDTH;
                    CONFIG.CANVAS.HEIGHT = CONFIG.CANVAS.BASE_HEIGHT;
                    if (typeof Renderer !== 'undefined' && Renderer.updateCanvasBuffer) {
                        Renderer.updateCanvasBuffer();
                    }
                }
            }

            canvas.style.width = `${newWidth}px`;
            canvas.style.height = `${newHeight}px`;

            // Update canvas scale factor for input calculations
            this.canvasScale = {
                x: CONFIG.CANVAS.WIDTH / newWidth,
                y: CONFIG.CANVAS.HEIGHT / newHeight
            };
        };

        window.addEventListener('resize', resizeCanvas);
        window.addEventListener('orientationchange', () => {
            setTimeout(resizeCanvas, 150);
        });

        // Also handle visual viewport changes (iOS keyboard, etc.)
        if (window.visualViewport) {
            window.visualViewport.addEventListener('resize', resizeCanvas);
        }

        resizeCanvas();
    },

    // Setup mobile UI elements
    setupMobileUI() {
        // Prevent duplicate setup
        if (document.getElementById('virtualJoystick')) return;

        // Create virtual joystick
        const joystick = document.createElement('div');
        joystick.id = 'virtualJoystick';
        joystick.innerHTML = `
            <div class="joystick-outer">
                <div class="joystick-inner" id="joystickInner"></div>
            </div>
        `;
        document.body.appendChild(joystick);

        // Create mobile action buttons (right side)
        const actionButtons = document.createElement('div');
        actionButtons.id = 'mobileActions';
        actionButtons.innerHTML = `
            <button class="mobile-btn mobile-pause-btn" data-action="pause">| |</button>
            <button class="mobile-btn orb-btn" id="mobileOrbBtn1" data-action="orb1">&middot;</button>
            <button class="mobile-btn orb-btn" id="mobileOrbBtn2" data-action="orb2">&middot;</button>
            <button class="mobile-btn orb-btn" id="mobileOrbBtn3" data-action="orb3">&middot;</button>
        `;
        document.body.appendChild(actionButtons);

        // Create a mobile help/close button (for help screen and game-over)
        const helpBtn = document.createElement('button');
        helpBtn.id = 'mobileHelpBtn';
        helpBtn.className = 'mobile-btn';
        helpBtn.dataset.action = 'help';
        helpBtn.textContent = '?';
        helpBtn.classList.add('mobile-help-btn');
        document.body.appendChild(helpBtn);

        // Add mobile-specific CSS
        this.addMobileStyles();

        // Setup mobile button events
        this.setupMobileButtons();
    },

    // Mobile-specific styles are now in the external stylesheet (ui.css)
    addMobileStyles() {
        // No-op: styles moved to src/css/ui.css for CSP compliance
    },

    // Setup mobile button events
    setupMobileButtons() {
        const buttons = document.querySelectorAll('.mobile-btn');
        buttons.forEach(btn => {
            // Use touchstart for immediate response
            btn.addEventListener('touchstart', (e) => {
                e.preventDefault();
                e.stopPropagation();
                btn.classList.add('active');
                const action = btn.dataset.action;
                if (action) {
                    this.handleMobileAction(action);
                }

                // Enable audio on first user interaction
                if (window.SoundManager) {
                    SoundManager.handleUserInteraction();
                }
            }, { passive: false });

            btn.addEventListener('touchend', (e) => {
                e.preventDefault();
                btn.classList.remove('active');
            }, { passive: false });

            // Fallback click for non-touch
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const action = btn.dataset.action;
                if (action) {
                    this.handleMobileAction(action);
                }
            });
        });
    },

    // Handle mobile button actions
    handleMobileAction(action) {
        const game = GameState.getGame();

        switch (action) {
            case 'pause':
                if (game.state === 'playing' && !game.deathScreen && !game.victory) {
                    if (window.Game) {
                        window.Game.togglePause();
                    }
                }
                break;
            case 'help':
                if (game.state === 'playing' && !game.deathScreen && !game.victory) {
                    game.showHelp = !game.showHelp;
                }
                break;
            case 'orb1':
            case 'orb2':
            case 'orb3':
                if (game.state === 'playing' && !game.deathScreen && !game.showHelp && !game.victory) {
                    const slot = parseInt(action.slice(-1)) - 1;
                    if (typeof InventoryManager !== 'undefined') {
                        InventoryManager.useOrb(slot);
                    }
                }
                break;
        }
    },

    // Setup keyboard event listeners
    setupKeyboardEvents() {
        window.addEventListener('keydown', (e) => {
            this.keys[e.key.toLowerCase()] = true;
            this.handleKeyDown(e);

            // Enable audio on first user interaction
            if (window.SoundManager) {
                SoundManager.handleUserInteraction();
            }
        });

        window.addEventListener('keyup', (e) => {
            this.keys[e.key.toLowerCase()] = false;
        });
    },

    // Setup mouse event listeners
    setupMouseEvents() {
        const canvas = document.getElementById('gameCanvas');
        canvas.addEventListener('click', (e) => {
            this.handleCanvasInteraction(e.clientX, e.clientY);

            // Enable audio on first user interaction
            if (window.SoundManager) {
                SoundManager.handleUserInteraction();
            }
        });
    },

    // Setup touch events for the virtual joystick
    setupTouchEvents() {
        const joystickOuter = document.querySelector('.joystick-outer');
        const joystickInner = document.getElementById('joystickInner');

        if (!joystickOuter || !joystickInner) {
            console.warn('Joystick elements not found, skipping touch event setup');
            return;
        }

        // Helper to get dynamic joystick dimensions (adapts to CSS changes like landscape mode)
        const getJoystickDimensions = () => {
            const rect = joystickOuter.getBoundingClientRect();
            return {
                outerRadius: rect.width / 2,
                maxKnobTravel: rect.width * 0.29 // ~35px for 120px, scales proportionally
            };
        };

        const updateKnobVisual = (deltaX, deltaY, distance) => {
            const dims = getJoystickDimensions();
            let displayX, displayY;
            if (distance > dims.maxKnobTravel) {
                const angle = Math.atan2(deltaY, deltaX);
                displayX = Math.cos(angle) * dims.maxKnobTravel;
                displayY = Math.sin(angle) * dims.maxKnobTravel;
            } else {
                displayX = deltaX;
                displayY = deltaY;
            }
            joystickInner.style.left = `${dims.outerRadius + displayX}px`;
            joystickInner.style.top = `${dims.outerRadius + displayY}px`;
            joystickInner.style.transform = 'translate(-50%, -50%)';
        };

        const resetKnobVisual = () => {
            joystickInner.style.left = '50%';
            joystickInner.style.top = '50%';
            joystickInner.style.transform = 'translate(-50%, -50%)';
        };

        joystickOuter.addEventListener('touchstart', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const touch = e.changedTouches[0];
            this.touchControls.active = true;
            this.touchControls.identifier = touch.identifier;
            const rect = joystickOuter.getBoundingClientRect();
            this.touchControls.startX = rect.left + rect.width / 2;
            this.touchControls.startY = rect.top + rect.height / 2;
            this.touchControls.currentX = touch.clientX;
            this.touchControls.currentY = touch.clientY;

            // Enable audio on first touch
            if (window.SoundManager) {
                SoundManager.handleUserInteraction();
            }
        }, { passive: false });

        joystickOuter.addEventListener('touchmove', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!this.touchControls.active) return;

            // Find the correct touch by identifier
            let touch = null;
            for (let i = 0; i < e.touches.length; i++) {
                if (e.touches[i].identifier === this.touchControls.identifier) {
                    touch = e.touches[i];
                    break;
                }
            }
            if (!touch) return;

            this.touchControls.currentX = touch.clientX;
            this.touchControls.currentY = touch.clientY;

            // Calculate delta from center of joystick
            const deltaX = this.touchControls.currentX - this.touchControls.startX;
            const deltaY = this.touchControls.currentY - this.touchControls.startY;
            const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);

            updateKnobVisual(deltaX, deltaY, distance);
        }, { passive: false });

        const endTouch = (e) => {
            // Check if the ended touch matches our tracked one
            if (e.changedTouches) {
                for (let i = 0; i < e.changedTouches.length; i++) {
                    if (e.changedTouches[i].identifier === this.touchControls.identifier) {
                        this.touchControls.active = false;
                        this.touchControls.identifier = null;
                        resetKnobVisual();
                        break;
                    }
                }
            }
        };

        joystickOuter.addEventListener('touchend', (e) => {
            e.preventDefault();
            endTouch(e);
        }, { passive: false });

        joystickOuter.addEventListener('touchcancel', (e) => {
            e.preventDefault();
            endTouch(e);
        }, { passive: false });

        // Document-level fallback: if a joystick touch moves/ends outside the element,
        // some browsers may not deliver the event to the original target.
        // These fallbacks ensure the joystick state stays in sync.
        document.addEventListener('touchmove', (e) => {
            if (!this.touchControls.active || this.touchControls.identifier === null) return;

            for (let i = 0; i < e.touches.length; i++) {
                if (e.touches[i].identifier === this.touchControls.identifier) {
                    this.touchControls.currentX = e.touches[i].clientX;
                    this.touchControls.currentY = e.touches[i].clientY;

                    const deltaX = this.touchControls.currentX - this.touchControls.startX;
                    const deltaY = this.touchControls.currentY - this.touchControls.startY;
                    const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);
                    updateKnobVisual(deltaX, deltaY, distance);
                    return;
                }
            }
        }, { passive: true });

        document.addEventListener('touchend', (e) => {
            if (!this.touchControls.active || this.touchControls.identifier === null) return;
            endTouch(e);
        }, { passive: true });

        document.addEventListener('touchcancel', (e) => {
            if (!this.touchControls.active || this.touchControls.identifier === null) return;
            endTouch(e);
        }, { passive: true });

        console.log('Virtual joystick touch events initialized');
    },

    // Setup touch events on the canvas for menu/UI interactions
    setupCanvasTouchEvents() {
        const canvas = document.getElementById('gameCanvas');

        // Prevent all default touch behaviors on canvas
        canvas.addEventListener('touchstart', (e) => {
            e.preventDefault();

            // Enable audio on first touch
            if (window.SoundManager) {
                SoundManager.handleUserInteraction();
            }
        }, { passive: false });

        canvas.addEventListener('touchmove', (e) => {
            e.preventDefault();
        }, { passive: false });

        canvas.addEventListener('touchend', (e) => {
            e.preventDefault();
            // Use the last changed touch position as a "click"
            if (e.changedTouches && e.changedTouches.length > 0) {
                const touch = e.changedTouches[0];
                this.handleCanvasInteraction(touch.clientX, touch.clientY);
            }
        }, { passive: false });
    },

    // Unified handler for canvas interactions (both click and touch)
    handleCanvasInteraction(clientX, clientY) {
        const canvas = document.getElementById('gameCanvas');
        const rect = canvas.getBoundingClientRect();
        let x = clientX - rect.left;
        let y = clientY - rect.top;

        // Apply canvas scaling if responsive
        if (this.canvasScale) {
            x *= this.canvasScale.x;
            y *= this.canvasScale.y;
        }

        const game = GameState.getGame();

        // Suppress clicks when name entry input is active
        if (game.showNameEntry) {
            return;
        }

        if (game.state === 'menu') {
            this.handleMenuClick(x, y);
        } else if (game.state === 'leaderboard') {
            this.handleLeaderboardClick(x, y);
        } else if (game.deathScreen) {
            this.handleDeathScreenClick(x, y);
        } else if (game.gameOver && !game.victory) {
            // Game over screen: treat any tap as "R" key (return to menu)
            GameState.quitToMenu();
        } else if (game.showHelp) {
            // Tap anywhere to dismiss help screen on mobile
            game.showHelp = false;
        }
    },

    // Handle key down events
    handleKeyDown(e) {
        const game = GameState.getGame();

        // Suppress keyboard input when name entry is active (handled by the input element)
        if (game.showNameEntry) {
            return;
        }

        // ESC key handling
        if (e.key === 'Escape') {
            e.preventDefault();
            if (game.state === 'leaderboard') {
                GameState.game.state = 'menu';
            } else if (game.state === 'playing' && !game.deathScreen && !game.gameOver && !game.victory) {
                if (window.Game) {
                    window.Game.togglePause();
                }
            }
            return;
        }

        // Direct orb usage (1-3 keys)
        if (e.key >= '1' && e.key <= '3' && game.state === 'playing' && !game.deathScreen && !game.showHelp && !game.victory) {
            const slot = parseInt(e.key) - 1;
            if (typeof InventoryManager !== 'undefined') {
                InventoryManager.useOrb(slot);
            }
        }

        // Help toggle
        if (e.key.toLowerCase() === 'h') {
            if (game.state === 'playing' && !game.deathScreen && !game.victory) {
                game.showHelp = !game.showHelp;
            }
        }

        // Return to menu from game over/victory
        if (e.key.toLowerCase() === 'r' && (game.gameOver || game.victory)) {
            GameState.quitToMenu();
        }

        // Start game from menu (but not if story narration is playing)
        if (e.key === ' ' && game.state === 'menu' && !(window.StoryNarration && window.StoryNarration.isPlaying)) {
            e.preventDefault();
            GameState.startGame();
        }
    },

    // Handle mouse clicks (legacy - now uses handleCanvasInteraction)
    handleClick(e) {
        this.handleCanvasInteraction(e.clientX, e.clientY);
    },

    // Handle menu clicks
    handleMenuClick(x, y) {
        const centerX = CONFIG.CANVAS.WIDTH / 2;
        const isMobileBtn = this.isMobile || this.hasTouchSupport;
        const buttonWidth = 300;
        const buttonHeight = isMobileBtn ? 56 : 45;
        const buttonSpacing = isMobileBtn ? 65 : 55;
        // Match portrait offset from renderMenu/renderMenuButtons
        const isPortraitCanvas = CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT;
        const menuOffsetY = isPortraitCanvas ? Math.round((CONFIG.CANVAS.HEIGHT - CONFIG.CANVAS.BASE_HEIGHT) / 3) : 0;
        const startY = 200 + menuOffsetY;

        const buttons = [
            { text: 'NEW GAME', y: startY, action: 'newGame' },
            { text: 'SETTINGS', y: startY + buttonSpacing * 2, action: 'settings' }
        ];

        // Check which button was clicked/tapped
        for (const button of buttons) {
            if (x >= centerX - buttonWidth/2 && x <= centerX + buttonWidth/2 &&
                y >= button.y && y <= button.y + buttonHeight) {
                this.handleMenuAction(button.action);
                break;
            }
        }
    },

    // Handle menu button actions
    handleMenuAction(action) {
        // Play button select sound
        if (window.SoundManager) {
            SoundManager.playButtonSelect();
        }

        switch (action) {
            case 'newGame':
                // Start story narration first, which will then start the game
                if (window.StoryNarration) {
                    StoryNarration.start();
                } else {
                    // Fallback if story system not available
                    GameState.startGame();
                }
                break;
            case 'leaderboards':
                // The upstream Firebase leaderboard was removed. Keep the action defined so an old
                // save or a stray click cannot fall through to unknown code.
                break;
                break;
            case 'settings':
                if (window.Game && window.Game.showSettingsModal) {
                    window.Game.showSettingsModal(false);
                }
                break;
        }
    },

    // Handle leaderboard screen clicks
    handleLeaderboardClick(x, y) {
        const centerX = CONFIG.CANVAS.WIDTH / 2;
        const isMobileBtn = this.isMobile || this.hasTouchSupport;
        const btnWidth = isMobileBtn ? 200 : 180;
        const btnHeight = isMobileBtn ? 58 : 50;
        const btnY = CONFIG.CANVAS.HEIGHT - 100;

        // BACK button
        if (x >= centerX - btnWidth / 2 && x <= centerX + btnWidth / 2 &&
            y >= btnY && y <= btnY + btnHeight) {
            if (window.SoundManager) {
                SoundManager.playButtonSelect();
            }
            GameState.game.state = 'menu';
        }
    },

    // Show the HTML name entry input element over the canvas
    showNameEntryInput() {
        // Remove any existing input first
        this.hideNameEntryInput();

        const canvas = document.getElementById('gameCanvas');
        const rect = canvas.getBoundingClientRect();

        // Calculate where the input field should be positioned based on renderer layout
        // Renderer draws: panelWidth = 420, panelHeight = 220, centered
        // Input area: panelX + 50, panelY + 115, panelWidth - 100 (320px), height 36
        const panelWidth = 420;
        const panelHeight = 220;
        const centerX = CONFIG.CANVAS.WIDTH / 2;
        const centerY = CONFIG.CANVAS.HEIGHT / 2;
        const panelX = centerX - panelWidth / 2;
        const panelY = centerY - panelHeight / 2;
        const inputX = panelX + 50;
        const inputY = panelY + 115;
        const inputW = panelWidth - 100;
        const inputH = 36;

        // Convert canvas coordinates to screen coordinates
        const scaleX = rect.width / CONFIG.CANVAS.WIDTH;
        const scaleY = rect.height / CONFIG.CANVAS.HEIGHT;

        const screenX = rect.left + (inputX * scaleX);
        const screenY = rect.top + (inputY * scaleY);
        const screenW = inputW * scaleX;
        const screenH = inputH * scaleY;

        const input = document.createElement('input');
        input.type = 'text';
        input.id = 'nameEntryInput';
        input.maxLength = 20;
        input.placeholder = 'Enter your name...';
        input.autocomplete = 'off';
        input.spellcheck = false;
        input.style.position = 'fixed';
        input.style.left = screenX + 'px';
        input.style.top = screenY + 'px';
        input.style.width = screenW + 'px';
        input.style.height = screenH + 'px';
        input.style.background = 'rgba(15, 8, 4, 0.9)';
        input.style.color = '#DAA520';
        input.style.border = '1px solid #654321';
        input.style.fontFamily = 'serif';
        input.style.fontSize = Math.max(14, 16 * scaleY) + 'px';
        input.style.textAlign = 'center';
        input.style.outline = 'none';
        input.style.zIndex = '10000';
        input.style.boxSizing = 'border-box';
        input.style.padding = '0 8px';

        input.addEventListener('keydown', (e) => {
            e.stopPropagation(); // Prevent game key handlers from firing

            if (e.key === 'Enter') {
                e.preventDefault();
                this.hideNameEntryInput();
                GameState.game.showNameEntry = false;
                GameState.game.pendingScore = null;
                this._showDeferredVictoryScreen();
            } else if (e.key === 'Escape') {
                e.preventDefault();
                this.hideNameEntryInput();
                GameState.game.showNameEntry = false;
                GameState.game.pendingScore = null;
                this._showDeferredVictoryScreen();
            }
        });

        input.addEventListener('blur', () => {
            setTimeout(() => {
                if (document.getElementById('nameEntryInput')) {
                    input.focus();
                }
            }, 100);
        });

        // Create a full-screen transparent backdrop behind the input.
        // Tapping this backdrop cancels the name entry (same as Escape).
        const backdrop = document.createElement('div');
        backdrop.id = 'nameEntryBackdrop';
        backdrop.className = 'name-entry-backdrop';
        backdrop.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.hideNameEntryInput();
            GameState.game.showNameEntry = false;
            GameState.game.pendingScore = null;
            this._showDeferredVictoryScreen();
        });
        backdrop.addEventListener('touchend', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.hideNameEntryInput();
            GameState.game.showNameEntry = false;
            GameState.game.pendingScore = null;
            this._showDeferredVictoryScreen();
        }, { passive: false });

        document.body.appendChild(backdrop);
        document.body.appendChild(input);

        // Store resize handler for cleanup
        this._nameEntryResizeHandler = () => {
            const input = document.getElementById('nameEntryInput');
            if (!input) return;
            const canvas = document.getElementById('gameCanvas');
            if (!canvas) return;
            const rect = canvas.getBoundingClientRect();
            const scaleX = rect.width / CONFIG.CANVAS.WIDTH;
            const scaleY = rect.height / CONFIG.CANVAS.HEIGHT;
            const panelWidth = 420;
            const panelHeight = 220;
            const panelX = (CONFIG.CANVAS.WIDTH - panelWidth) / 2;
            const panelY = (CONFIG.CANVAS.HEIGHT - panelHeight) / 2;
            const inputX = panelX + 50;
            const inputY = panelY + 115;
            const inputW = panelWidth - 100;
            const inputH = 36;
            input.style.left = (rect.left + inputX * scaleX) + 'px';
            input.style.top = (rect.top + inputY * scaleY) + 'px';
            input.style.width = (inputW * scaleX) + 'px';
            input.style.height = (inputH * scaleY) + 'px';
        };
        window.addEventListener('resize', this._nameEntryResizeHandler);

        // Focus the input after a brief delay to ensure it's rendered
        setTimeout(() => {
            input.focus();
        }, 50);
    },

    // Remove the HTML name entry input element and backdrop
    hideNameEntryInput() {
        if (this._nameEntryResizeHandler) {
            window.removeEventListener('resize', this._nameEntryResizeHandler);
            this._nameEntryResizeHandler = null;
        }
        const existing = document.getElementById('nameEntryInput');
        if (existing) {
            existing.remove();
        }
        const backdrop = document.getElementById('nameEntryBackdrop');
        if (backdrop) {
            backdrop.remove();
        }
    },

    // Show victory screen that was deferred while name entry was active
    _showDeferredVictoryScreen() {
        const game = GameState.game;
        if (game && game._pendingVictoryScreen) {
            game._pendingVictoryScreen = false;
            if (typeof EntityManager !== 'undefined') {
                EntityManager.showVictoryScreen(game);
            }
        }
    },

    // The upstream score-submission flow (name entry -> Firebase) was removed with the
    // leaderboard. A run ends in its own victory screen; Ghost Gate records progress
    // server-side via spire/ghostgate.js, never through a third-party service.
    handleScoreSubmission(floor, orbsCollected, extra) {
        return false;
    },

    // Handle death screen clicks
    handleDeathScreenClick(x, y) {
        const isMobileDeath = this.isMobile || this.hasTouchSupport;
        const btnY = CONFIG.CANVAS.HEIGHT - 140;
        const btnWidth = isMobileDeath ? 200 : 180;
        const btnHeight = isMobileDeath ? 58 : 50;
        const btnGap = isMobileDeath ? 24 : 20;
        const centerX = CONFIG.CANVAS.WIDTH / 2;

        // Respawn button
        if (x >= centerX - btnWidth - btnGap &&
            x <= centerX - btnGap &&
            y >= btnY && y <= btnY + btnHeight) {
            GameState.respawnAtCheckpoint();
        }

        // Quit button (starts at center + btnGap, width btnWidth)
        if (x >= centerX + btnGap &&
            x <= centerX + btnGap + btnWidth &&
            y >= btnY && y <= btnY + btnHeight) {
            GameState.quitToMenu();
        }
    },

    // Check if key is pressed
    isKeyPressed(key) {
        return this.keys[key.toLowerCase()] || false;
    },

    // Get movement input (supports both keyboard and touch)
    getMovementInput() {
        const movement = { x: 0, y: 0 };

        // Keyboard input
        if (this.isKeyPressed('arrowup') || this.isKeyPressed('w')) movement.y = -1;
        if (this.isKeyPressed('arrowdown') || this.isKeyPressed('s')) movement.y = 1;
        if (this.isKeyPressed('arrowleft') || this.isKeyPressed('a')) movement.x = -1;
        if (this.isKeyPressed('arrowright') || this.isKeyPressed('d')) movement.x = 1;

        // Touch input (virtual joystick) - overrides keyboard when active
        if (this.touchControls.active) {
            const deltaX = this.touchControls.currentX - this.touchControls.startX;
            const deltaY = this.touchControls.currentY - this.touchControls.startY;
            const distance = Math.sqrt(deltaX * deltaX + deltaY * deltaY);

            if (distance > this.touchControls.deadzone) {
                // Use dynamic max range based on actual joystick size
                const joystickEl = document.querySelector('.joystick-outer');
                const maxRange = joystickEl ? joystickEl.getBoundingClientRect().width / 2 : 60;
                const magnitude = Math.min((distance - this.touchControls.deadzone) / (maxRange - this.touchControls.deadzone), 1.0);
                const angle = Math.atan2(deltaY, deltaX);

                movement.x = Math.cos(angle) * magnitude * this.touchControls.sensitivity;
                movement.y = Math.sin(angle) * magnitude * this.touchControls.sensitivity;
            }
        }

        return movement;
    },

    // Update mobile orb buttons to reflect current inventory contents
    updateMobileOrbButtons() {
        if (!this.isMobile && !this.hasTouchSupport) return;

        const game = GameState.getGame();
        if (!game || !game.player) return;

        for (let i = 0; i < 3; i++) {
            const btn = document.getElementById(`mobileOrbBtn${i + 1}`);
            if (!btn) continue;

            const orbType = game.player.inventory[i];
            if (orbType && typeof ORB_TYPES !== 'undefined' && ORB_TYPES[orbType]) {
                const orb = ORB_TYPES[orbType];
                btn.textContent = orb.symbol;
                btn.style.background = orb.color.replace(')', ', 0.35)').replace('rgb(', 'rgba(');
                // Handle hex colors
                if (orb.color.startsWith('#')) {
                    const hex = orb.color.slice(1);
                    const r = parseInt(hex.substring(0, 2), 16);
                    const g = parseInt(hex.substring(2, 4), 16);
                    const b = parseInt(hex.substring(4, 6), 16);
                    btn.style.background = `rgba(${r}, ${g}, ${b}, 0.35)`;
                }
                btn.style.color = orb.color;
                btn.style.borderColor = orb.color;
                btn.style.textShadow = `0 0 8px ${orb.color}`;
            } else {
                btn.textContent = '\u00B7'; // middle dot
                btn.style.background = 'rgba(0, 0, 0, 0.7)';
                btn.style.color = 'rgba(255, 255, 255, 0.3)';
                btn.style.borderColor = 'rgba(255, 255, 255, 0.15)';
                btn.style.textShadow = 'none';
            }
        }
    },

    // Update mobile UI visibility based on game state
    updateMobileUI() {
        if (!this.isMobile && !this.hasTouchSupport) return;

        const game = GameState.getGame();
        if (!game) return;

        const isPlaying = game.state === 'playing' && !game.deathScreen && !game.showHelp && !game.victory && !game.gameOver;
        const isPaused = window.Game && window.Game.isPaused;
        const isTutorialShowing = game.tutorial && game.tutorial.tutorialPopup !== null;

        if (isPlaying && !isPaused && !isTutorialShowing) {
            document.body.classList.add('mobile-active');
            document.body.classList.remove('mobile-menu');
        } else {
            document.body.classList.remove('mobile-active');
            document.body.classList.add('mobile-menu');
        }
    },

    // Get device info
    getDeviceInfo() {
        return {
            isMobile: this.isMobile,
            hasTouchSupport: this.hasTouchSupport,
            touchSupport: 'ontouchstart' in window,
            screenSize: `${window.innerWidth}x${window.innerHeight}`,
            pixelRatio: window.devicePixelRatio || 1,
            orientation: window.innerWidth > window.innerHeight ? 'landscape' : 'portrait'
        };
    }
};

// Make InputManager globally accessible
window.InputManager = InputManager;