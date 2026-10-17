// Tutorial System
const TutorialSystem = {
    // Initialize tutorial system
    init() {
        console.log('🎓 Tutorial system initialized');
    },

    // Check if player is in tutorial levels (floors -1 to -5)
    isInTutorial(floor) {
        return floor >= -5 && floor <= -1;
    },

    // Start tutorial for new players
    startTutorial() {
        const game = GameState.getGame();
        if (!game) return;

        game.tutorial.active = true;
        game.tutorial.currentStep = 0;
        console.log('🎓 Tutorial started');
        
        // Show first tutorial message
        this.showTutorialStep(0);
    },

    // Show specific tutorial step
    showTutorialStep(step) {
        const game = GameState.getGame();
        if (!game) return;

        const isMobileDevice = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const moveInstruction = isMobileDevice
            ? "Use the joystick on the left side of the screen to move around."
            : "Use WASD or Arrow Keys to move around.";
        const orbInstruction = isMobileDevice
            ? "Look for glowing orbs throughout the maze to restore light and gain powers."
            : "Look for glowing orbs throughout the maze to restore light and gain powers.";

        const tutorialSteps = [
            {
                title: "Welcome to the Buried Spire",
                message: `Welcome, explorer! You stand at the entrance to the ancient Burj Mubarak, now buried beneath the shifting sands of time. Your mission is to descend ${CONFIG.GAME.MAX_FLOORS} floors to find the legendary Ancient Pearl.`,
                instruction: moveInstruction
            },
            {
                title: "Your Light is Life",
                message: "Your light is your most precious resource. It slowly depletes as you explore, and when it reaches 0%, the ghouls will swarm you! Watch the light bar in the top-left corner.",
                instruction: "Your light slowly decreases over time - keep an eye on it!"
            },
            {
                title: "Collecting Orbs",
                message: "Orbs scattered throughout the spire can restore your light or grant special powers. Blue orbs restore light immediately, while other orbs go to your inventory for later use.",
                instruction: orbInstruction
            },
            {
                title: "Avoiding the Ghouls",
                message: "Dark spirits called ghouls roam these halls. They flee from bright light but will stalk you in dim areas. If they get too close, they'll drain your light faster!",
                instruction: "Stay in the center of your light radius to keep ghouls at bay."
            },
            {
                title: "Finding the Stairs",
                message: "To progress deeper, you must find the stairs (▼) on each floor. They're usually hidden in the maze, so explore thoroughly. Every 5 floors, you'll reach a checkpoint.",
                instruction: "Find the stairs (▼) to descend to the next floor."
            }
        ];

        if (step < tutorialSteps.length) {
            // Set the current step BEFORE showing the popup so the step counter is correct
            game.tutorial.currentStep = step;
            
            const stepData = tutorialSteps[step];
            this.showTutorialPopup(stepData.title, stepData.message, stepData.instruction);
        }
    },

    // Show tutorial popup that pauses the game
    showTutorialPopup(title, message, instruction = null, isOrbTutorial = false) {
        const game = GameState.getGame();
        if (!game) return;

        // Pause the game
        game.tutorial.showingOrbTutorial = isOrbTutorial;
        
        // Remove existing popup
        this.hideTutorialPopup();

        // Use the explicit parameter to determine popup type
        const isTutorialStep = !isOrbTutorial && game.tutorial.active;
        const currentStep = game.tutorial.currentStep;
        const totalSteps = 5;

        // Create tutorial popup
        const popup = document.createElement('div');
        popup.id = 'tutorialPopup';
        popup.className = 'tutorial-overlay';

        popup.innerHTML = `
            <div class="tutorial-dialog">
                <!-- Golden inner border -->
                <div class="tutorial-inner-border"></div>

                <!-- Gothic corner decorations -->
                <div class="tutorial-corner tutorial-corner--tl">╔</div>
                <div class="tutorial-corner tutorial-corner--tr">╗</div>
                <div class="tutorial-corner tutorial-corner--bl">╚</div>
                <div class="tutorial-corner tutorial-corner--br">╝</div>

                ${isTutorialStep ? `
                <div class="tutorial-step-counter">
                    Lesson ${currentStep + 1} of ${totalSteps}
                </div>
                ` : ''}

                <h2 class="tutorial-title">
                    ⚜ ${title}
                </h2>

                <div class="tutorial-message-box">
                    <p class="tutorial-message-text">
                        ${message}
                    </p>
                </div>

                ${instruction ? `
                <div class="tutorial-instruction-box">
                    <p class="tutorial-instruction-text">
                        ♦ ${instruction}
                    </p>
                </div>
                ` : ''}

                <div class="tutorial-actions">
                    <button id="tutorialContinue" class="tutorial-continue-btn tutorial-hover-btn">
                        ♦ Continue
                    </button>

                    ${isTutorialStep ? `
                    <button id="tutorialSkip" class="tutorial-skip-btn tutorial-hover-btn">
                        ♠ Skip Lessons
                    </button>
                    ` : ''}
                </div>

                <div class="tutorial-dismiss-hint">
                    ${(typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport)) ? 'Tap Continue or press ESC to dismiss' : 'Press ESC to dismiss'}
                </div>
            </div>
        `;

        document.body.appendChild(popup);
        game.tutorial.tutorialPopup = popup;

        // Attach hover effects via addEventListener (CSP-safe, no inline handlers)
        popup.querySelectorAll('.tutorial-hover-btn').forEach(btn => {
            btn.addEventListener('mouseover', function() { this.style.transform = 'scale(1.05)'; });
            btn.addEventListener('mouseout', function() { this.style.transform = 'scale(1)'; });
        });

        // Debug: Log the actual HTML to see if buttons are created
        console.log('🔍 Generated HTML contains Continue button:', popup.innerHTML.includes('tutorialContinue'));
        console.log('🔍 Generated HTML contains Skip button:', popup.innerHTML.includes('tutorialSkip'));

        // Debug: Log that popup was created with programmatic event listeners
        console.log('🔍 Tutorial popup created with programmatic event listeners');
        
        // Test if TutorialSystem is accessible globally
        console.log('🔍 TutorialSystem accessible globally?', typeof window.TutorialSystem !== 'undefined');
        console.log('🔍 TutorialSystem object:', TutorialSystem);
        
        // Make TutorialSystem globally accessible for event listeners
        window.TutorialSystem = TutorialSystem;
        
        // Add event handlers to the tutorial buttons after they're in the DOM
        setTimeout(() => {
            const continueBtn = document.getElementById('tutorialContinue');
            const skipBtn = document.getElementById('tutorialSkip');

            console.log('Looking for buttons after DOM insert:');
            console.log('  Continue button found:', !!continueBtn);
            console.log('  Skip button found:', !!skipBtn);

            if (continueBtn) {
                // Click handler for desktop
                continueBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    TutorialSystem.handleTutorialContinue();
                });
                // Touch handler for mobile - use touchend so it doesn't conflict
                continueBtn.addEventListener('touchend', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    TutorialSystem.handleTutorialContinue();
                }, { passive: false });
            }

            if (skipBtn) {
                skipBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    TutorialSystem.skipTutorial();
                });
                skipBtn.addEventListener('touchend', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    TutorialSystem.skipTutorial();
                }, { passive: false });
            }
        }, 100); // Wait 100ms for DOM to settle
        
        // Tutorial popup is now ready with working event handlers
        console.log('✅ Tutorial popup created with working event handlers');

        // Also allow ESC to close
        const escapeHandler = (e) => {
            if (e.key === 'Escape') {
                this.hideTutorialPopup();
                document.removeEventListener('keydown', escapeHandler);
            }
        };
        document.addEventListener('keydown', escapeHandler);

        console.log(`📚 Showing ${isOrbTutorial ? 'orb tutorial' : 'main tutorial step ' + currentStep}: ${title}`);
    },

    // Hide tutorial popup and resume game
    hideTutorialPopup() {
        // Always remove the popup from DOM first to prevent stuck pause state
        const popup = document.getElementById('tutorialPopup');
        if (popup) {
            popup.remove();
        }

        const game = GameState.getGame();
        if (game) {
            game.tutorial.showingOrbTutorial = false;
            game.tutorial.tutorialPopup = null;
        }
        console.log('📚 Tutorial popup hidden, game resumed');
    },

    // Show first-time orb tutorial
    showOrbTutorial(orbType) {
        const game = GameState.getGame();
        if (!game || game.tutorial.firstTimeOrbs.has(orbType)) {
            return; // Already seen this orb type
        }

        // Mark this orb type as seen
        game.tutorial.firstTimeOrbs.add(orbType);

        const orbData = ORB_TYPES[orbType];
        if (!orbData) return;

        const isMobileDevice = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const activateText = isMobileDevice
            ? "Tap buttons 1, 2, or 3 on the right side of the screen to activate it based on which slot it's in."
            : "Press keys 1, 2, or 3 to activate it based on which slot it's in.";
        const activateTextShort = isMobileDevice
            ? "You can also tap buttons 1, 2, or 3 for full light restoration."
            : "You can also manually activate it with keys 1, 2, or 3 for full light restoration.";

        let title, message, instruction;

        switch (orbType) {
            case 'common':
                title = "Blue Orb - Light Restoration";
                message = "You've found a Blue Orb! These orbs restore 15% of your light immediately when collected. They don't take up inventory space, so collect them whenever you see them.";
                instruction = "Blue orbs are consumed instantly - perfect for emergency light restoration!";
                break;

            case 'golden':
                title = "Golden Orb - Powerful Light";
                message = "A Golden Orb! This powerful orb restores 25% of your light immediately when collected, just like the blue orb but with greater power. It doesn't take up inventory space.";
                instruction = "Golden orbs are consumed instantly - perfect for major light restoration!";
                break;

            case 'purple':
                title = "Purple Orb - Phase Power";
                message = "You've discovered a Purple Orb! This mystical orb grants you the power to phase through walls for 5 seconds. It goes into your inventory and can be activated manually.";
                instruction = `The Purple Orb goes into your inventory (slots 1-3). ${activateText} When activated, you can walk through walls for 5 seconds - perfect for escaping danger or finding shortcuts!`;
                break;

            case 'green':
                title = "Green Orb - Regeneration";
                message = "A Green Orb! This nature-powered orb slowly regenerates your light over 10 seconds. It goes into your inventory and can be activated manually when needed.";
                instruction = `The Green Orb goes into your inventory (slots 1-3). ${activateText} Perfect for long-term light management during exploration!`;
                break;

            case 'white':
                title = "White Orb - Map Revelation";
                message = "You've found a White Orb! This illuminating orb reveals the entire floor layout for 5 seconds, showing walls, orbs, ghouls, and most importantly - the stairs! It goes into your inventory for manual activation.";
                instruction = `The White Orb goes into your inventory (slots 1-3). ${activateText} Use it strategically to quickly navigate and find the stairs!`;
                break;

            case 'red':
                title = "Red Orb - Lifeline";
                message = "A rare Red Orb! This goes into your inventory and serves as your lifeline. It will automatically activate when your light reaches 0%, fully restoring your light and saving you from the ghoul swarm.";
                instruction = `The Red Orb goes into your inventory (slots 1-3) and auto-activates at 0% light to save you! ${activateTextShort} Keep it safe - it's your lifeline!`;
                break;

            case 'wisp':
                title = "Light Wisp - Death Echo";
                message = "A Light Wisp appears where you previously died. These ethereal remnants of your past self restore 50% light when collected, helping you recover from setbacks.";
                instruction = "Wisps mark your death locations and provide substantial light restoration.";
                break;

            default:
                return; // Unknown orb type
        }

        this.showTutorialPopup(title, message, instruction, true);
    },

    // Update tutorial based on game state
    update(game) {
        if (!game || !game.tutorial.active) return;

        // Check tutorial progression for first 5 floors
        if (this.isInTutorial(game.floor)) {
            this.checkTutorialProgress(game);
        } else if (game.floor < -5) {
            // End tutorial after floor -5
            this.endTutorial();
        }
    },

    // Check if tutorial objectives are met
    checkTutorialProgress(game) {
        const step = game.tutorial.currentStep;
        
        // Only check for specific trigger conditions, don't auto-advance
        switch (step) {
            case 0: // Movement tutorial
                // Check if player has moved
                if (game.player.x !== (CONFIG.PLAYER.START_X || 100) || 
                    game.player.y !== (CONFIG.PLAYER.START_Y || 100)) {
                    // Player has moved, but don't auto-advance - wait for Continue button
                    // Just update the instruction text to acknowledge movement
                    const popup = document.getElementById('tutorialPopup');
                    if (popup) {
                        const instructionDiv = popup.querySelector('.tutorial-instruction-box');
                        if (instructionDiv) {
                            instructionDiv.innerHTML = `
                                <p class="tutorial-success-text">
                                    ✅ Great! You're moving around. Click Continue when ready to proceed.
                                </p>
                            `;
                        }
                    }
                }
                break;
                
            case 1: // Light tutorial
                // No automatic advancement - user must click Continue
                break;
                
            case 2: // Orb collection tutorial
                // This will be completed when first orb is collected via handleOrbCollection
                break;
                
            case 3: // Ghoul tutorial
                // No automatic advancement - user must click Continue
                break;
                
            case 4: // Stairs tutorial
                // Check if player has used stairs
                if (game.floor < -1) {
                    // Player has progressed, but tutorial is ending anyway
                    this.endTutorial();
                }
                break;
        }
    },

    // Complete a tutorial step (now only called by handleTutorialContinue)
    completeTutorialStep(nextStep) {
        const game = GameState.getGame();
        if (!game) return;

        // This function is now primarily used by handleOrbCollection
        // for the orb collection step completion
        if (game.tutorial.currentStep === 2 && nextStep === 3) {
            // Orb collection completed, show next step
            game.tutorial.completedSteps.add(2);
            setTimeout(() => {
                this.showTutorialStep(3);
            }, 1000);
        } else {
            console.log('🎓 Tutorial step completed');
        }
    },

    // End tutorial system
    endTutorial() {
        const game = GameState.getGame();
        if (!game) return;

        game.tutorial.active = false;
        this.hideTutorialPopup();
        
        // Show completion message
        Utils.showMessage("Tutorial complete! Good luck, explorer!", 5000);
        
        console.log('🎓 Tutorial system ended');
    },

    // Check if game should be paused for tutorial
    shouldPauseGame() {
        const game = GameState.getGame();
        if (!game) return false;
        
        // Check if any tutorial popup is currently showing
        const tutorialPopup = document.getElementById('tutorialPopup');
        const hasActivePopup = tutorialPopup !== null;
        
        // Also check the game state flags
        const showingTutorial = game.tutorial.showingOrbTutorial || hasActivePopup;
        
        // Debug logging (can be removed later)
        if (showingTutorial) {
            console.log('🎓 Tutorial pause active:', {
                hasActivePopup,
                showingOrbTutorial: game.tutorial.showingOrbTutorial,
                tutorialActive: game.tutorial.active
            });
        }
        
        return showingTutorial;
    },

    // Handle orb collection for tutorial
    handleOrbCollection(orbType) {
        const game = GameState.getGame();
        if (!game) return;

        // Show first-time orb tutorial
        this.showOrbTutorial(orbType);

        // If this is step 2 (orb collection tutorial), advance
        if (game.tutorial.active && game.tutorial.currentStep === 2) {
            this.completeTutorialStep(3);
        }
    },

    // Handle tutorial continue button
    handleTutorialContinue() {
        const game = GameState.getGame();
        if (!game) {
            console.log('❌ No game state found in handleTutorialContinue');
            // Still try to remove popup from DOM to prevent stuck state
            const popup = document.getElementById('tutorialPopup');
            if (popup) popup.remove();
            return;
        }

        console.log('🎓 Tutorial continue clicked - Step:', game.tutorial.currentStep);

        // Save the orb tutorial flag BEFORE hideTutorialPopup resets it
        const wasOrbTutorial = game.tutorial.showingOrbTutorial;

        // Hide current popup
        this.hideTutorialPopup();

        // Check if this is an orb tutorial or main tutorial
        if (wasOrbTutorial) {
            // For orb tutorials, just hide the popup and resume game
            console.log('🎓 Orb tutorial completed');
            return;
        }

        // If this is a main tutorial step, advance to next step
        if (game.tutorial.active) {
            const currentStep = game.tutorial.currentStep;
            
            // Mark current step as completed
            game.tutorial.completedSteps.add(currentStep);
            
            // Check if there's a next step
            if (currentStep < 4) { // Steps 0-4 (5 total steps)
                // Advance to next step
                game.tutorial.currentStep = currentStep + 1;
                console.log(`🎓 Advancing to tutorial step ${game.tutorial.currentStep}`);
                setTimeout(() => {
                    this.showTutorialStep(game.tutorial.currentStep);
                }, 500); // Small delay for better UX
            } else {
                // Tutorial completed
                console.log('🎓 All tutorial steps completed');
                this.endTutorial();
            }
        } else {
            console.log('🎓 Not advancing tutorial - tutorial not active');
        }
    },

    // Skip entire tutorial
    skipTutorial() {
        const game = GameState.getGame();
        if (!game) return;

        // Mark all steps as completed
        for (let i = 0; i < 5; i++) {
            game.tutorial.completedSteps.add(i);
        }

        // End tutorial
        this.endTutorial();
        
        console.log('⏭️ Tutorial skipped by user');
    }
}; 