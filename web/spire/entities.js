// Entity Management
const EntityManager = {
    // Collect an orb
    collectOrb(game, orb) {
        orb.collected = true;

        const orbType = ORB_TYPES[orb.type];
        if (!orbType) return;

        // Show tutorial for first-time orb collection
        if (typeof TutorialSystem !== 'undefined') {
            TutorialSystem.handleOrbCollection(orb.type);
        }

        if (orbType.lightBonus) {
            // Light restoration orbs - always collectible
            game.player.light = Math.min(game.player.light + orbType.lightBonus, game.player.maxLight);
            if (orb.type !== 'wisp') {
                game.player.orbsCollected++;
            }
        } else if (orb.type === 'pearl') {
            // Special handling for the Ancient Pearl - triggers victory!
            console.log('Ancient Pearl collected! Victory achieved!');
            game.victory = true;
            game.pearlCollected = true;
            game.pearlPosition = { x: orb.x, y: orb.y }; // Store Pearl position for animation

            // Make all ghouls flee in terror
            for (const ghoul of game.ghouls) {
                ghoul.state = 'fleeing';
                ghoul.speed = 6; // Make them run away fast
                ghoul.fleeStartTime = Date.now();
            }

            // Start the dramatic white light animation sequence
            this.startVictoryLightAnimation(game, orb.x, orb.y);

        } else if (orbType.power) {
            // Power orbs - add to inventory only if space available
            let added = false;
            for (let i = 0; i < 3; i++) {
                if (!game.player.inventory[i]) {
                    game.player.inventory[i] = orb.type;
                    added = true;
                    InventoryManager.updateDisplay();
                    Utils.showMessage(`${orbType.name} added to inventory!`, 2500);
                    break;
                }
            }

            if (!added) {
                // Inventory is full - don't collect the orb
                Utils.showMessage(MESSAGES.STORY.INVENTORY_FULL, 2000);
                orb.collected = false;
                return false; // Indicate collection failed
            }
        }

        // Play orb collection sound only on successful pickup
        if (window.SoundManager) {
            SoundManager.playOrbCollection(orb.type);
        }

        // Create collection particle effect only if successfully collected
        Utils.createParticles(game, orb.x, orb.y, orbType.color, 10, 4);
        return true; // Indicate collection succeeded
    },

    // Start the white light animation from Pearl position
    startVictoryLightAnimation(game, pearlX, pearlY) {
        console.log('Starting victory light animation...');

        // Initialize animation state
        game.victoryAnimation = {
            active: true,
            startTime: Date.now(),
            pearlX: pearlX,
            pearlY: pearlY,
            lightRadius: 0,
            phase: 'expanding', // 'expanding' -> 'complete'
            duration: 3000 // 3 seconds total animation
        };

        // Pause normal game updates during animation
        game.animatingVictory = true;
    },

    // Update victory light animation
    updateVictoryAnimation(game) {
        if (!game.victoryAnimation || !game.victoryAnimation.active) return;

        const animation = game.victoryAnimation;
        const elapsed = Date.now() - animation.startTime;
        const progress = Math.min(elapsed / animation.duration, 1);

        if (animation.phase === 'expanding') {
            // Exponential expansion of white light
            const maxRadius = Math.max(window.innerWidth, window.innerHeight) * 1.5;
            animation.lightRadius = maxRadius * (progress * progress); // Quadratic easing

            if (progress >= 1) {
                // Animation complete - trigger victory screen
                animation.active = false;
                game.animatingVictory = false;
                this.triggerVictorySequence(game);
            }
        }
    },

    // Render the victory light animation
    renderVictoryAnimation(game, ctx, canvas) {
        if (!game.victoryAnimation || !game.victoryAnimation.active) return;

        const animation = game.victoryAnimation;

        // Save context
        ctx.save();

        // Convert world coordinates to screen coordinates
        const camera = game.camera || { x: 0, y: 0 };
        const hudHeight = (CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT) ? (CONFIG.HUD?.PORTRAIT_HEIGHT || 0) : 0;
        const screenX = animation.pearlX - camera.x;
        const screenY = animation.pearlY - camera.y + hudHeight;

        // Create radial gradient for expanding light
        const gradient = ctx.createRadialGradient(
            screenX, screenY, 0,
            screenX, screenY, animation.lightRadius
        );

        // Bright white center fading to transparent
        gradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
        gradient.addColorStop(0.3, 'rgba(255, 255, 255, 0.9)');
        gradient.addColorStop(0.6, 'rgba(255, 255, 255, 0.5)');
        gradient.addColorStop(1, 'rgba(255, 255, 255, 0)');

        // Fill the entire canvas with the expanding light
        ctx.globalCompositeOperation = 'screen'; // Additive blending for bright effect
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // Add intense bright flash at center
        if (animation.lightRadius > 50) {
            const centerGradient = ctx.createRadialGradient(
                screenX, screenY, 0,
                screenX, screenY, 100
            );
            centerGradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
            centerGradient.addColorStop(1, 'rgba(255, 255, 255, 0)');

            ctx.fillStyle = centerGradient;
            ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);
        }

        // Restore context
        ctx.restore();
    },

    // Trigger victory sequence when Pearl is collected
    triggerVictorySequence(game) {
        console.log('Triggering victory sequence...');

        // Pause the game
        game.state = 'victory';

        // Submit score to leaderboard on victory
        let needsNameEntry = false;
        if (window.InputManager && InputManager.handleScoreSubmission) {
            const completionTimeMs = Date.now() - game.gameStartTime;
            needsNameEntry = InputManager.handleScoreSubmission(
                game.floor,
                game.player.orbsCollected,
                { completionTimeMs: completionTimeMs, deaths: game.runDeaths }
            );
        }

        if (needsNameEntry) {
            // Defer victory screen until name entry completes
            game._pendingVictoryScreen = true;
        } else {
            // Show victory screen immediately
            this.showVictoryScreen(game);
        }
    },

    // Show the victory screen
    showVictoryScreen(game) {
        // Create victory overlay
        const victoryOverlay = document.createElement('div');
        victoryOverlay.id = 'victory-overlay';
        victoryOverlay.className = 'victory-overlay';

        const victoryContent = `
            <div class="victory-content">
                <h1 class="victory-title">⚜ TRIUMPH ⚜</h1>

                <h2 class="victory-subtitle">The Sacred Pearl is Reclaimed!</h2>

                <div class="victory-story-box">
                    <p class="victory-story-text">
                        Through courage and determination, you have retrieved the <strong>Sacred Pearl</strong>
                        from the cursed depths of the Buried Spire! Its divine radiance shall protect your realm
                        from the shadow beasts that haunt the darkness.
                    </p>
                    <br>
                    <p class="victory-story-epilogue">
                        The ancient curse is shattered. The creatures of the void retreat in terror
                        before the Pearl's holy light, and your people shall know peace once more.
                    </p>
                </div>

                <div class="victory-stats">
                    <p><strong>⚔ Conqueror</strong> - You descended all ${Math.abs(game.floor)} treacherous floors!</p>
                    <p><strong>💎 Seeker</strong> - You gathered ${game.player.orbsCollected || 0} mystical orbs!</p>
                    <p><strong>⚜ Champion</strong> - Your valor has saved an entire realm!</p>
                </div>

                <button id="victory-menu-btn" class="victory-menu-btn victory-hover-btn">
                    ♦ Return to Sanctum
                </button>
            </div>
        `;

        victoryOverlay.innerHTML = victoryContent;
        document.body.appendChild(victoryOverlay);

        // Attach hover effects via addEventListener (CSP-safe, no inline handlers)
        victoryOverlay.querySelectorAll('.victory-hover-btn').forEach(btn => {
            btn.addEventListener('mouseover', function() { this.style.transform = 'scale(1.05)'; });
            btn.addEventListener('mouseout', function() { this.style.transform = 'scale(1)'; });
        });

        // Add event listener for menu button (both click and touch)
        const victoryMenuBtn = document.getElementById('victory-menu-btn');
        if (victoryMenuBtn) {
            victoryMenuBtn.addEventListener('click', () => {
                window.location.reload();
            });
            victoryMenuBtn.addEventListener('touchend', (e) => {
                e.preventDefault();
                window.location.reload();
            }, { passive: false });
        }

        console.log('Victory screen displayed!');
    }
};