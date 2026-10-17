// Rendering System
const Renderer = {
    canvas: null,
    ctx: null,
    minimapCanvas: null,
    minimapCtx: null,
    floorTransitionAlpha: 0, // For floor transition fade effect
    lastRenderedFloor: null, // Track floor changes for transition effect

    // Initialize renderer
    init() {
        this.canvas = document.getElementById('gameCanvas');
        this.ctx = this.canvas.getContext('2d');
        this.minimapCanvas = document.getElementById('minimap');
        this.minimapCtx = this.minimapCanvas.getContext('2d');
        this.hudHeight = 0;

        this.updateCanvasBuffer();
    },

    // Update canvas buffer dimensions (called on init and orientation/resize changes)
    updateCanvasBuffer() {
        const dpr = window.devicePixelRatio || 1;
        this.canvas.width = CONFIG.CANVAS.WIDTH * dpr;
        this.canvas.height = CONFIG.CANVAS.HEIGHT * dpr;
        this.ctx.setTransform(1, 0, 0, 1, 0, 0); // Reset transform before re-scaling
        this.ctx.scale(dpr, dpr);

        this.minimapCanvas.width = CONFIG.MINIMAP.WIDTH * dpr;
        this.minimapCanvas.height = CONFIG.MINIMAP.HEIGHT * dpr;
        this.minimapCtx.setTransform(1, 0, 0, 1, 0, 0);
        this.minimapCtx.scale(dpr, dpr);
    },

    // Helper function to draw rounded rectangles
    drawRoundedRect(x, y, width, height, radius, fillColor = null, strokeColor = null, lineWidth = 1) {
        this.ctx.beginPath();
        this.ctx.moveTo(x + radius, y);
        this.ctx.lineTo(x + width - radius, y);
        this.ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
        this.ctx.lineTo(x + width, y + height - radius);
        this.ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
        this.ctx.lineTo(x + radius, y + height);
        this.ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
        this.ctx.lineTo(x, y + radius);
        this.ctx.quadraticCurveTo(x, y, x + radius, y);
        this.ctx.closePath();
        
        if (fillColor) {
            this.ctx.fillStyle = fillColor;
            this.ctx.fill();
        }
        
        if (strokeColor) {
            this.ctx.strokeStyle = strokeColor;
            this.ctx.lineWidth = lineWidth;
            this.ctx.stroke();
        }
    },

    // Format milliseconds to mm:ss string
    formatTime(ms) {
        const totalSeconds = Math.floor(ms / 1000);
        const minutes = Math.floor(totalSeconds / 60);
        const seconds = totalSeconds % 60;
        return `${minutes}:${seconds.toString().padStart(2, '0')}`;
    },

    // Main render function
    render(game) {
        // Safety check for game object
        if (!game) {
            console.warn('⚠️ Renderer.render() called with undefined game object');
            return;
        }

        // Reset canvas state to prevent leakage between frames
        this.ctx.globalAlpha = 1;
        this.ctx.globalCompositeOperation = 'source-over';
        this.ctx.shadowBlur = 0;
        this.ctx.shadowColor = 'transparent';
        this.ctx.textAlign = 'left';
        this.ctx.textBaseline = 'alphabetic';
        this.ctx.lineWidth = 1;
        this.ctx.setLineDash([]);

        // Manage sounds based on game state
        if (window.SoundManager) {
            const isPaused = window.Game && window.Game.isPaused;
            if (game.state === 'menu' || game.deathScreen || game.victory || game.showHelp || game.gameOver || isPaused) {
                // Pause sounds in menus
                SoundManager.pauseAll();
            } else if (game.state === 'playing' && SoundManager.isPaused) {
                // Resume sounds when playing
                SoundManager.resumeAll();
            }
        }
        
        // Dark underground atmosphere
        this.ctx.fillStyle = '#0a0a0a';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        if (game.state === 'menu') {
            this.renderMenu();
            return;
        }

        if (game.state === 'leaderboard') {
            this.renderLeaderboardScreen();
            return;
        }

        const isPortrait = CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT;
        const hudHeight = isPortrait ? (CONFIG.HUD?.PORTRAIT_HEIGHT || 0) : 0;
        this.hudHeight = hudHeight;

        this.ctx.save();
        if (hudHeight > 0) {
            this.ctx.beginPath();
            this.ctx.rect(0, hudHeight, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT - hudHeight);
            this.ctx.clip();
        }
        this.ctx.translate(-game.camera.x, -game.camera.y + hudHeight);

        // Render game world (order matters for correct z-layering)
        this.renderFloorTiles(game);
        this.renderWalls(game);
        this.renderStairs(game);
        this.renderOrbs(game);
        this.renderGhouls(game);
        this.renderParticles(game);
        this.renderLightEffect(game);  // Light before player so player isn't washed out
        this.renderPlayer(game);       // Player on top of light effect

        this.ctx.restore();

        // Render victory light animation (before UI overlays for dramatic effect)
        if (game.victoryAnimation && game.victoryAnimation.active) {
            EntityManager.renderVictoryAnimation(game, this.ctx, this.canvas);
        }

        // Draw HUD band background in portrait mode
        if (hudHeight > 0) {
            this.ctx.fillStyle = 'rgba(10, 8, 6, 0.95)';
            this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, hudHeight);
            this.ctx.strokeStyle = '#3a2a1a';
            this.ctx.lineWidth = 1;
            this.ctx.beginPath();
            this.ctx.moveTo(0, hudHeight);
            this.ctx.lineTo(CONFIG.CANVAS.WIDTH, hudHeight);
            this.ctx.stroke();
        }

        // Render UI overlays (behind help/death screens)
        this.renderVignette();
        this.renderDarknessFade(game);
        this.renderGameUI(game);
        this.renderMinimap(game);
        this.renderInventory(game);

        // Floor transition fade effect
        if (game.state === 'playing') {
            if (this.lastRenderedFloor !== null && this.lastRenderedFloor !== game.floor) {
                this.floorTransitionAlpha = 1.0; // Trigger fade
            }
            this.lastRenderedFloor = game.floor;
        }
        if (this.floorTransitionAlpha > 0) {
            this.ctx.fillStyle = `rgba(0, 0, 0, ${this.floorTransitionAlpha})`;
            this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);
            this.floorTransitionAlpha = Math.max(0, this.floorTransitionAlpha - 0.04);
        }

        // Render modal overlays (on top of everything)
        this.renderHelpScreen(game);
        this.renderDeathScreen(game);
        this.renderGameOverScreen(game);

        // Name entry overlay (on top of all other overlays)
        if (game.showNameEntry) {
            this.renderNameEntryOverlay();
        }
    },

    // Render floor tiles
    renderFloorTiles(game) {
        const startX = Math.floor(game.camera.x / CONFIG.MAP.CELL_SIZE);
        const endX = Math.ceil((game.camera.x + CONFIG.CANVAS.WIDTH) / CONFIG.MAP.CELL_SIZE);
        const startY = Math.floor(game.camera.y / CONFIG.MAP.CELL_SIZE);
        const endY = Math.ceil((game.camera.y + CONFIG.CANVAS.HEIGHT) / CONFIG.MAP.CELL_SIZE);
        
        // Very dark underground floor grid lines (subtly visible near player)
        this.ctx.strokeStyle = '#1a1510';
        for (let x = startX; x <= endX; x++) {
            for (let y = startY; y <= endY; y++) {
                const tileX = x * CONFIG.MAP.CELL_SIZE;
                const tileY = y * CONFIG.MAP.CELL_SIZE;
                const dist = Utils.distance({ x: tileX + 20, y: tileY + 20 }, game.player);
                
                if (dist < game.player.lightRadius * 1.5 || game.player.powers.reveal > 0) {
                    this.ctx.globalAlpha = game.player.powers.reveal > 0 ? 0.5 : 
                                         Math.max(0, 1 - (dist / (game.player.lightRadius * 1.5)));
                    this.ctx.strokeRect(tileX, tileY, CONFIG.MAP.CELL_SIZE, CONFIG.MAP.CELL_SIZE);
                }
            }
        }
        this.ctx.globalAlpha = 1;
    },

    // Render walls
    renderWalls(game) {
        // Very dark underground wall color
        this.ctx.fillStyle = '#111';
        const useGradients = !CONFIG.GRAPHICS || CONFIG.GRAPHICS.wallGradients !== false;
        for (const wall of game.walls) {
            const dist = Utils.distance(wall, game.player);
            if (dist < game.player.lightRadius * 1.5 || game.player.powers.reveal > 0) {
                this.ctx.globalAlpha = Math.max(0.3, 1 - (dist / (game.player.lightRadius * 2)));

                if (useGradients) {
                    // Sandstone wall with texture gradient
                    const wallGradient = this.ctx.createLinearGradient(wall.x - 15, wall.y - 15, wall.x + 15, wall.y + 15);
                    wallGradient.addColorStop(0, '#9b8365'); // Lighter sandstone
                    wallGradient.addColorStop(0.5, '#8b7355'); // Base sandstone
                    wallGradient.addColorStop(1, '#7b6345'); // Darker shadow
                    this.ctx.fillStyle = wallGradient;
                    this.ctx.fillRect(wall.x - 15, wall.y - 15, 30, 30);

                    // Subtle weathered edge
                    this.ctx.strokeStyle = '#6b5335';
                    this.ctx.lineWidth = 1;
                    this.ctx.strokeRect(wall.x - 15, wall.y - 15, 30, 30);
                } else {
                    // Simple flat color for low quality
                    this.ctx.fillStyle = '#8b7355';
                    this.ctx.fillRect(wall.x - 15, wall.y - 15, 30, 30);
                }
            }
        }
        this.ctx.globalAlpha = 1;
    },

    // Render stairs with Gothic design
    renderStairs(game) {
        if (!game.stairs) return;
        
        const dist = Utils.distance(game.stairs, game.player);
        if (dist < game.player.lightRadius * 1.5 || game.player.powers.reveal > 0 || dist < 100) {
            const time = game.time || 0; // Default to 0 if time is undefined
            const pulseSize = Math.sin(time * 0.08) * 3;
            const glowIntensity = 0.5 + Math.sin(time * 0.06) * 0.3;
            
            // Mystical glow background
            this.ctx.globalAlpha = glowIntensity * 0.6;
            const glowGradient = this.ctx.createRadialGradient(
                game.stairs.x, game.stairs.y, 0,
                game.stairs.x, game.stairs.y, 50 + pulseSize * 2
            );
            // Mystical Gothic glow
            glowGradient.addColorStop(0, 'rgba(218, 165, 32, 0.8)'); // Golden glow
            glowGradient.addColorStop(0.5, 'rgba(139, 69, 19, 0.4)'); // Gothic brown
            glowGradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
            this.ctx.fillStyle = glowGradient;
            this.ctx.fillRect(game.stairs.x - 60, game.stairs.y - 60, 120, 120);
            this.ctx.globalAlpha = 1;
            
            // Main Gothic platform with rounded corners
            const platformSize = 35;

            // Outer platform with Gothic gradient (use world coordinates)
            const outerGradient = this.ctx.createLinearGradient(
                game.stairs.x - platformSize, game.stairs.y - platformSize,
                game.stairs.x + platformSize, game.stairs.y + platformSize
            );
            outerGradient.addColorStop(0, '#654321'); // Gothic brown
            outerGradient.addColorStop(0.5, '#8B4513'); // Medium brown
            outerGradient.addColorStop(1, '#2A1810'); // Dark brown

            // Draw outer platform with rounded corners
            this.drawRoundedRect(
                game.stairs.x - platformSize,
                game.stairs.y - platformSize,
                platformSize * 2,
                platformSize * 2,
                8,
                outerGradient
            );
            
            // Inner platform with weathered stone
            const innerSize = platformSize - 6;
            const innerGradient = this.ctx.createLinearGradient(
                game.stairs.x - innerSize, 
                game.stairs.y - innerSize, 
                game.stairs.x + innerSize, 
                game.stairs.y + innerSize
            );
            innerGradient.addColorStop(0, '#2A1810'); // Dark Gothic
            innerGradient.addColorStop(0.5, '#1A0F08'); // Deeper shadow
            innerGradient.addColorStop(1, '#654321'); // Medium Gothic
            
            this.drawRoundedRect(
                game.stairs.x - innerSize,
                game.stairs.y - innerSize,
                innerSize * 2,
                innerSize * 2,
                6,
                innerGradient
            );
            
            this.ctx.save();
            this.ctx.translate(game.stairs.x, game.stairs.y);
            
            // Gothic stair steps with golden color
            this.ctx.strokeStyle = '#DAA520';
            this.ctx.lineWidth = 2;
            for (let i = 0; i < 3; i++) {
                this.ctx.beginPath();
                this.ctx.moveTo(-20 + i * 6, -10 + i * 6);
                this.ctx.lineTo(20 - i * 2, -10 + i * 6);
                this.ctx.stroke();
            }
            
            // Gothic down arrow
            this.ctx.fillStyle = '#DAA520';
            this.ctx.font = 'bold 28px serif';
            this.ctx.textAlign = 'center';
            this.ctx.fillText('⬇', 0, 8);
            
            // EXIT text with Gothic styling
            this.ctx.fillStyle = '#8B4513';
            this.ctx.font = 'bold 11px serif';
            this.ctx.fillText('EXIT', 0, -22);
            
            this.ctx.restore();
            
            // Pulsing ancient golden border
            this.ctx.globalAlpha = glowIntensity;
            this.drawRoundedRect(
                game.stairs.x - platformSize - 2, 
                game.stairs.y - platformSize - 2, 
                (platformSize + 2) * 2, 
                (platformSize + 2) * 2, 
                10,
                null,
                '#FFD700',
                3
            );
            
            // Inner sandy glow border
            this.drawRoundedRect(
                game.stairs.x - platformSize + 2, 
                game.stairs.y - platformSize + 2, 
                (platformSize - 2) * 2, 
                (platformSize - 2) * 2, 
                6,
                null,
                '#FFE4B5',
                1
            );
            this.ctx.globalAlpha = 1;
        }
    },

    // Render orbs
    renderOrbs(game) {
        for (const orb of game.orbs) {
            if (orb.collected) continue;
            
            // Validate orb position
            if (typeof orb.x !== 'number' || typeof orb.y !== 'number' || 
                !isFinite(orb.x) || !isFinite(orb.y)) {
                console.warn('Invalid orb position, skipping render:', orb);
                continue;
            }
            
            const dist = Utils.distance(orb, game.player);
            if (dist < game.player.lightRadius * 1.5 || game.player.powers.reveal > 0) {
                const pulseSize = Math.sin(orb.pulse) * 3;
                
                try {
                    if (orb.type === 'wisp') {
                        // Death marker wisp
                        this.ctx.globalAlpha = 0.6 + Math.sin(game.time * 0.05) * 0.3;
                        const wispGlow = this.ctx.createRadialGradient(orb.x, orb.y, 0, orb.x, orb.y, 30);
                        wispGlow.addColorStop(0, 'rgba(200, 200, 255, 0.8)');
                        wispGlow.addColorStop(1, 'rgba(100, 100, 255, 0)');
                        this.ctx.fillStyle = wispGlow;
                        this.ctx.fillRect(orb.x - 30, orb.y - 30, 60, 60);
                    } else if (orb.type === 'pearl') {
                        // Special rendering for the Ancient Pearl
                        this.ctx.globalAlpha = 0.8;
                        
                        // Larger, more dramatic glow for the Pearl
                        const pearlGlow = this.ctx.createRadialGradient(orb.x, orb.y, 0, orb.x, orb.y, 40 + pulseSize * 2);
                        pearlGlow.addColorStop(0, 'rgba(255, 255, 255, 0.8)');
                        pearlGlow.addColorStop(0.3, 'rgba(255, 235, 59, 0.6)');
                        pearlGlow.addColorStop(1, 'rgba(0, 0, 0, 0)');
                        this.ctx.fillStyle = pearlGlow;
                        this.ctx.fillRect(orb.x - 50, orb.y - 50, 100, 100);
                        
                        // Additional mystical aura
                        this.ctx.globalAlpha = 0.3;
                        const aura = this.ctx.createRadialGradient(orb.x, orb.y, 20, orb.x, orb.y, 60 + pulseSize * 3);
                        aura.addColorStop(0, 'rgba(255, 235, 59, 0.4)');
                        aura.addColorStop(1, 'rgba(156, 39, 176, 0)');
                        this.ctx.fillStyle = aura;
                        this.ctx.fillRect(orb.x - 70, orb.y - 70, 140, 140);
                    } else {
                        // Regular orbs
                        this.ctx.globalAlpha = 0.5;
                        const glowGradient = this.ctx.createRadialGradient(orb.x, orb.y, 0, orb.x, orb.y, 20 + pulseSize);
                        glowGradient.addColorStop(0, ORB_TYPES[orb.type].color);
                        glowGradient.addColorStop(1, 'rgba(0,0,0,0)');
                        this.ctx.fillStyle = glowGradient;
                        this.ctx.fillRect(orb.x - 30, orb.y - 30, 60, 60);
                    }
                    
                    this.ctx.globalAlpha = 1;
                    
                    if (orb.type === 'pearl') {
                        // Draw the Pearl with special styling
                        const pearlSize = 12 + pulseSize;
                        
                        // Main Pearl body (black)
                        this.ctx.fillStyle = ORB_TYPES.pearl.color;
                        this.ctx.beginPath();
                        this.ctx.arc(orb.x, orb.y, pearlSize, 0, Math.PI * 2);
                        this.ctx.fill();
                        
                        // White outline
                        this.ctx.strokeStyle = ORB_TYPES.pearl.outline;
                        this.ctx.lineWidth = 3;
                        this.ctx.beginPath();
                        this.ctx.arc(orb.x, orb.y, pearlSize, 0, Math.PI * 2);
                        this.ctx.stroke();
                        
                        // Inner mystical glow
                        this.ctx.globalAlpha = 0.8;
                        this.ctx.fillStyle = 'rgba(255, 235, 59, 0.6)';
                        this.ctx.beginPath();
                        this.ctx.arc(orb.x - 2, orb.y - 2, 4, 0, Math.PI * 2);
                        this.ctx.fill();
                        
                        // Reset line width
                        this.ctx.lineWidth = 1;
                    } else {
                        // Regular orb rendering
                        this.ctx.fillStyle = ORB_TYPES[orb.type].color;
                        this.ctx.beginPath();
                        this.ctx.arc(orb.x, orb.y, 8 + pulseSize, 0, Math.PI * 2);
                        this.ctx.fill();
                        
                        // Inner shine
                        this.ctx.fillStyle = '#fff';
                        this.ctx.beginPath();
                        this.ctx.arc(orb.x - 3, orb.y - 3, 3, 0, Math.PI * 2);
                        this.ctx.fill();
                    }
                } catch (error) {
                    console.error('Error rendering orb:', error, orb);
                    // Reset alpha in case of error
                    this.ctx.globalAlpha = 1;
                }
            }
        }
        this.ctx.globalAlpha = 1;
    },

    // Render ghouls
    renderGhouls(game) {
        for (const ghoul of game.ghouls) {
            const dist = Utils.distance(ghoul, game.player);
            
            if (dist < game.player.lightRadius * 2 || game.player.powers.reveal > 0 || game.swarming) {
                let alpha = 1;
                if (!game.swarming && dist < game.player.lightRadius * 0.6) {
                    alpha = 0.3;
                } else if (!game.swarming && dist < game.player.lightRadius) {
                    alpha = 0.6;
                }
                
                this.ctx.globalAlpha = alpha;
                
                // Ghoul body
                this.ctx.fillStyle = ghoul.state === 'stunned' ? '#111' : '#200';
                this.ctx.fillRect(ghoul.x - 12, ghoul.y - 20, 24, 35);
                
                // Ghoul cloak
                this.ctx.fillStyle = '#100';
                this.ctx.beginPath();
                this.ctx.moveTo(ghoul.x - 15, ghoul.y - 20);
                this.ctx.lineTo(ghoul.x + 15, ghoul.y - 20);
                this.ctx.lineTo(ghoul.x + 20, ghoul.y + 15);
                this.ctx.lineTo(ghoul.x - 20, ghoul.y + 15);
                this.ctx.closePath();
                this.ctx.fill();
                
                // Ghoul eyes
                this.ctx.fillStyle = game.swarming ? '#ff0' : (ghoul.state === 'stalking' ? '#f00' : '#800');
                this.ctx.shadowBlur = game.swarming ? 20 : 10;
                this.ctx.shadowColor = game.swarming ? '#ff0' : '#f00';
                this.ctx.beginPath();
                this.ctx.arc(ghoul.x - 5, ghoul.y - 10, game.swarming ? 4 : 3, 0, Math.PI * 2);
                this.ctx.arc(ghoul.x + 5, ghoul.y - 10, game.swarming ? 4 : 3, 0, Math.PI * 2);
                this.ctx.fill();
                this.ctx.shadowBlur = 0;
            }
        }
        this.ctx.globalAlpha = 1;
    },

    // Render particles
    renderParticles(game) {
        if (CONFIG.GRAPHICS && CONFIG.GRAPHICS.particles === false) {
            return;
        }
        for (const particle of game.particles) {
            this.ctx.globalAlpha = particle.life / 30;
            this.ctx.fillStyle = particle.color;
            this.ctx.fillRect(particle.x - 2, particle.y - 2, 4, 4);
        }
        this.ctx.globalAlpha = 1;
    },

    // Render player
    renderPlayer(game) {
        // Calculate player visibility based on light level
        const lightPercent = game.player.light / 100;
        const minVisibility = 0.6; // Never go below 60% visibility
        const playerAlpha = Math.max(minVisibility, 0.4 + (lightPercent * 0.6));
        
        // Ghost Gate: the player is a small green turtle. Same circle collision body as upstream —
        // only the drawing changed, so every rule (movement, collision, ghouls) still sees the
        // identical shape.
        const shell = game.player.powers.phase > 0
            ? `rgba(200, 200, 200, ${0.5 * playerAlpha})`
            : `rgba(34, 122, 58, ${playerAlpha})`;   // turtle shell green
        const shellRim = game.player.powers.phase > 0
            ? `rgba(255, 255, 255, ${0.5 * playerAlpha})`
            : `rgba(120, 200, 140, ${playerAlpha})`; // pale rim
        this.ctx.fillStyle = shell;
        this.ctx.beginPath();
        this.ctx.arc(game.player.x, game.player.y, 10, 0, Math.PI * 2);
        this.ctx.fill();
        // Shell rim + the head poking out in the direction of travel (upstream draws motion
        // elsewhere; a static nub reads as a turtle without inventing new state).
        this.ctx.strokeStyle = shellRim;
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.arc(game.player.x, game.player.y, 10, 0, Math.PI * 2);
        this.ctx.stroke();
        this.ctx.fillStyle = shellRim;
        this.ctx.beginPath();
        this.ctx.arc(game.player.x + 8, game.player.y - 8, 4, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Phase effect
        if (game.player.powers.phase > 0) {
            this.ctx.strokeStyle = '#9c27b0';
            this.ctx.lineWidth = 2;
            this.ctx.setLineDash([5, 5]);
            this.ctx.beginPath();
            this.ctx.arc(game.player.x, game.player.y, 14, 0, Math.PI * 2);
            this.ctx.stroke();
            this.ctx.setLineDash([]);
        }
        
        // Player light ring
        this.ctx.strokeStyle = '#ffeb3b';
        this.ctx.globalAlpha = 0.5;
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.arc(game.player.x, game.player.y, 20, 0, Math.PI * 2);
        this.ctx.stroke();
        this.ctx.globalAlpha = 1;
    },

    // Render light effect
    renderLightEffect(game) {
        try {
            // Validate player and light radius values
            if (!game.player || 
                typeof game.player.x !== 'number' || 
                typeof game.player.y !== 'number' || 
                typeof game.player.lightRadius !== 'number' ||
                !isFinite(game.player.x) || 
                !isFinite(game.player.y) || 
                !isFinite(game.player.lightRadius) ||
                game.player.lightRadius <= 0) {
                console.warn('Invalid light effect values:', {
                    playerX: game.player?.x,
                    playerY: game.player?.y,
                    lightRadius: game.player?.lightRadius
                });
                return; // Skip rendering light effect
            }
            
            // Additional validation for extreme values
            if (game.player.lightRadius > 10000 || 
                Math.abs(game.player.x) > 100000 || 
                Math.abs(game.player.y) > 100000) {
                console.warn('Light effect values too extreme, skipping render');
                return;
            }
            
            // Add subtle flicker effect using time and light level
            const useFlicker = !CONFIG.GRAPHICS || CONFIG.GRAPHICS.lightFlicker !== false;
            let flickeredRadius;

            if (useFlicker) {
                const time = game.time || 0;
                const lightPercent = game.player.light / 100;
                const flickerIntensity = 0.04; // Subtle flicker
                const flicker = 1 + Math.sin(time * 0.08) * flickerIntensity + Math.sin(time * 0.17) * flickerIntensity * 0.6;

                // Adjust flicker based on light level - more flicker when light is low
                const lowLightFlicker = Math.max(0, (1 - lightPercent) * 0.08);
                const totalFlicker = flicker + lowLightFlicker;

                flickeredRadius = game.player.lightRadius * totalFlicker;
            } else {
                flickeredRadius = game.player.lightRadius;
            }
            
            const gradient = this.ctx.createRadialGradient(
                game.player.x, game.player.y, 0,
                game.player.x, game.player.y, flickeredRadius
            );
            
            // Warm torch fire light effect with flicker intensity
            const intensityScale = useFlicker ? (flickeredRadius / game.player.lightRadius) : 1;
            const baseIntensity = 0.5 * intensityScale;
            const midIntensity = 0.3 * intensityScale;
            const edgeIntensity = 0.15 * intensityScale;
            
            gradient.addColorStop(0, `rgba(255, 200, 100, ${baseIntensity})`); // Bright warm center
            gradient.addColorStop(0.3, `rgba(255, 150, 50, ${midIntensity})`); // Orange glow
            gradient.addColorStop(0.7, `rgba(255, 100, 0, ${edgeIntensity})`); // Red-orange fade
            gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
            
            this.ctx.globalCompositeOperation = 'lighter';
            this.ctx.fillStyle = gradient;
            this.ctx.fillRect(
                game.player.x - flickeredRadius, 
                game.player.y - flickeredRadius,
                flickeredRadius * 2, 
                flickeredRadius * 2
            );
            this.ctx.globalCompositeOperation = 'source-over';
        } catch (error) {
            console.error('Error in renderLightEffect:', error);
            // Reset composite operation in case of error
            this.ctx.globalCompositeOperation = 'source-over';
        }
    },

    // Render darkness vignette
    renderVignette() {
        if (CONFIG.GRAPHICS && CONFIG.GRAPHICS.vignette === false) {
            return;
        }
        try {
            const vignetteRadius = Math.max(CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT) / 2;
            const vignette = this.ctx.createRadialGradient(
                CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2, 0,
                CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2, vignetteRadius
            );
            // Dark underground vignette effect
            vignette.addColorStop(0, 'rgba(0,0,0,0)');
            vignette.addColorStop(0.6, 'rgba(0,0,0,0.2)');
            vignette.addColorStop(0.8, 'rgba(0,0,0,0.4)');
            vignette.addColorStop(1, 'rgba(0,0,0,0.7)');
            this.ctx.fillStyle = vignette;
            this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);
        } catch (error) {
            console.error('Error in renderVignette:', error);
        }
    },

    // Render darkness fade during swarm
    renderDarknessFade(game) {
        if (game.darknessFade > 0) {
            // Black fade during swarm for dramatic darkness effect
            this.ctx.fillStyle = `rgba(0, 0, 0, ${game.darknessFade})`;
            this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);
        }
    },

    // Render game UI elements on canvas
    renderGameUI(game) {
        if (game.state !== 'playing') return;

        // Scale up UI in portrait mode for readability
        const isPortrait = CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT;
        const isMobileStats = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const uiScale = isPortrait ? 1.6 : 1;
        const baseFontSize = isMobileStats ? 14 : 13;

        // UI background panel with proper spacing
        const uiX = 10;
        const uiWidth = 200 * uiScale;
        const uiHeight = 115 * uiScale;
        const uiY = this.hudHeight > 0 ? Math.round((this.hudHeight - uiHeight) / 2) : 10;

        // Gothic UI background with rounded corners
        this.drawRoundedRect(uiX, uiY, uiWidth, uiHeight, 10 * uiScale, 'rgba(42, 24, 16, 0.9)', '#8B4513', 2);

        // Inner golden border with rounded corners
        this.drawRoundedRect(uiX + 2, uiY + 2, uiWidth - 4, uiHeight - 4, 8 * uiScale, null, '#DAA520', 1);

        // Text styling
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = `${Math.round(baseFontSize * uiScale)}px serif`;
        this.ctx.textAlign = 'left';

        let textY = uiY + 20 * uiScale;
        const lineHeight = (isMobileStats ? 18 : 16) * uiScale;

        // Floor info (use CONFIG for max floors)
        this.ctx.fillText(`Floor: ${game.floor} / -${CONFIG.GAME.MAX_FLOORS}`, uiX + 10 * uiScale, textY);
        textY += lineHeight;

        // Light percentage
        const lightPercent = Math.round(game.player.light);
        this.ctx.fillText(`Light: ${lightPercent}%`, uiX + 10 * uiScale, textY);
        textY += lineHeight;

        // Light bar
        const barX = uiX + 10 * uiScale;
        const barY = textY;
        const barWidth = 170 * uiScale;
        const barHeight = 12 * uiScale;

        // Light bar background
        this.ctx.fillStyle = '#1a0f08';
        this.ctx.fillRect(barX, barY, barWidth, barHeight);

        // Light bar border
        this.ctx.strokeStyle = '#654321';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(barX, barY, barWidth, barHeight);

        // Light bar fill (clamped to bar bounds)
        const fillWidth = Math.min(barWidth - 2, Math.max(0, game.player.light / 100) * (barWidth - 2));
        if (fillWidth > 0) {
            const gradient = this.ctx.createLinearGradient(barX, barY, barX + barWidth, barY);
            gradient.addColorStop(0, '#DAA520');
            gradient.addColorStop(1, '#8B4513');
            this.ctx.fillStyle = gradient;
            this.ctx.fillRect(barX + 1, barY + 1, fillWidth, barHeight - 2);
        }

        textY += lineHeight + 12 * uiScale; // Extra space after light bar

        // Checkpoint
        const checkpointNum = Math.ceil(Math.abs(game.checkpoint || game.floor) / 5);
        this.ctx.fillStyle = '#DAA520';
        this.ctx.fillText(`Checkpoint: ${checkpointNum}`, uiX + 10 * uiScale, textY);
        textY += lineHeight;

        // Power status
        if (game.player.powers.phase > 0) {
            this.ctx.fillStyle = '#9c27b0';
            this.ctx.fillText('♦ PHASE ACTIVE', uiX + 10 * uiScale, textY);
        } else if (game.player.powers.regeneration > 0) {
            this.ctx.fillStyle = '#4caf50';
            this.ctx.fillText('♦ REGENERATING', uiX + 10 * uiScale, textY);
        } else if (game.player.powers.reveal > 0) {
            this.ctx.fillStyle = '#ffffff';
            this.ctx.fillText('♦ MAP REVEALED', uiX + 10 * uiScale, textY);
        }

        // Ensure consistent bottom padding (match top padding)
        // The UI height should accommodate the content with equal top/bottom spacing
    },
    
    // Render inventory on canvas (matching reference image)
    renderInventory(game) {
        if (game.state !== 'playing') return;

        const isMobileInv = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);

        // On mobile, skip the canvas inventory bar — the mobile orb buttons serve as inventory
        if (isMobileInv) return;

        const slotSize = 48;
        const slotGap = 8;
        const orbFontSize = 22;
        const keyFontSize = 11;
        const totalSlotsWidth = (slotSize * 3) + (slotGap * 2);

        // Position inventory at bottom center, moved down
        const invX = (CONFIG.CANVAS.WIDTH - totalSlotsWidth) / 2;
        const invY = CONFIG.CANVAS.HEIGHT - 70;

        // Render each inventory slot individually (like in reference image)
        for (let i = 0; i < 3; i++) {
            const slotX = invX + (i * (slotSize + slotGap));
            const slotY = invY;

            // Slot background with Gothic styling
            this.drawRoundedRect(
                slotX, slotY, slotSize, slotSize,
                10,
                'rgba(26, 15, 8, 0.8)',
                '#654321',
                2
            );

            // Inner slot border for depth
            this.drawRoundedRect(
                slotX + 2, slotY + 2, slotSize - 4, slotSize - 4,
                8,
                null,
                '#8B4513',
                1
            );

            // Active slot highlighting (only when explicitly selected and has an item)
            if (game.player.selectedSlot === i && game.player.inventory[i]) {
                this.drawRoundedRect(
                    slotX, slotY, slotSize, slotSize,
                    10,
                    null,
                    '#DAA520',
                    2
                );

                // Subtle inner glow for active slot
                this.ctx.shadowBlur = 8;
                this.ctx.shadowColor = '#DAA520';
                this.drawRoundedRect(
                    slotX + 1, slotY + 1, slotSize - 2, slotSize - 2,
                    9,
                    null,
                    '#DAA520',
                    1
                );
                this.ctx.shadowBlur = 0;
            }

            // Key indicator above slot - sand colored
            this.ctx.fillStyle = '#d4a574';
            this.ctx.font = `bold ${keyFontSize}px serif`;
            this.ctx.textAlign = 'center';
            this.ctx.fillText(String(i + 1), slotX + slotSize / 2, slotY - 6);

            // Orb in slot
            const orbType = game.player.inventory[i];
            if (orbType && ORB_TYPES[orbType]) {
                const orb = ORB_TYPES[orbType];
                this.ctx.fillStyle = orb.color;
                this.ctx.font = `bold ${orbFontSize}px serif`;
                this.ctx.textAlign = 'center';

                // Add subtle glow to orb
                this.ctx.shadowBlur = 8;
                this.ctx.shadowColor = orb.color;
                this.ctx.fillText(orb.symbol, slotX + slotSize / 2, slotY + slotSize / 2 + 8);
                this.ctx.shadowBlur = 0;
            }
        }
    },

    // Render minimap on main canvas
    renderMinimap(game) {
        if (game.state !== 'playing') return;
        
        // Calculate actual map dimensions
        const mapWorldWidth = game.mapWidth * CONFIG.MAP.CELL_SIZE;
        const mapWorldHeight = game.mapHeight * CONFIG.MAP.CELL_SIZE;
        const mapAspectRatio = mapWorldWidth / mapWorldHeight;

        // Scale up minimap in portrait mode for readability
        const isPortrait = CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT;
        const uiScale = isPortrait ? 1.6 : 1;

        // Set minimap size (scaled for portrait)
        const mapHeight = 115 * uiScale;
        const mapWidth = mapHeight * mapAspectRatio;

        const mapX = CONFIG.CANVAS.WIDTH - mapWidth - 10;
        // Settings button is hidden on mobile, so minimap can sit at the top
        const mapY = this.hudHeight > 0 ? Math.round((this.hudHeight - mapHeight) / 2) : 10;
        
        // Minimap background with rounded corners and extra padding
        this.drawRoundedRect(mapX, mapY, mapWidth, mapHeight, 12, 'rgba(42, 24, 16, 0.9)', '#8B4513', 3);
        
        // Inner content area with more padding
        const contentPadding = 8;
        const contentWidth = mapWidth - (contentPadding * 2);
        const contentHeight = mapHeight - (contentPadding * 2);
        const contentX = mapX + contentPadding;
        const contentY = mapY + contentPadding;
        
        // Very dark underground background for minimap
        this.ctx.fillStyle = '#0a0a0a';
        this.ctx.fillRect(contentX, contentY, contentWidth, contentHeight);

        // Clip minimap content to its bounds so nothing leaks out
        this.ctx.save();
        this.ctx.beginPath();
        this.ctx.rect(contentX, contentY, contentWidth, contentHeight);
        this.ctx.clip();

        const scaleX = contentWidth / mapWorldWidth;
        const scaleY = contentHeight / mapWorldHeight;

        // Draw explored areas
        this.ctx.fillStyle = '#0f0f0f';
        for (const coord of game.explored) {
            const [x, y] = coord.split(',').map(Number);
            if (!isNaN(x) && !isNaN(y)) {
                this.ctx.fillRect(
                    contentX + (x * CONFIG.MAP.CELL_SIZE * scaleX), 
                    contentY + (y * CONFIG.MAP.CELL_SIZE * scaleY), 
                    CONFIG.MAP.CELL_SIZE * scaleX, 
                    CONFIG.MAP.CELL_SIZE * scaleY
                );
            }
        }
        
        // Draw walls
        this.ctx.fillStyle = '#222';
        for (const wall of game.walls) {
            const tileX = Math.floor(wall.x / CONFIG.MAP.CELL_SIZE);
            const tileY = Math.floor(wall.y / CONFIG.MAP.CELL_SIZE);
            if (game.explored.has(`${tileX},${tileY}`) || game.player.powers.reveal > 0) {
                this.ctx.fillRect(
                    contentX + ((wall.x - 15) * scaleX), 
                    contentY + ((wall.y - 15) * scaleY), 
                    30 * scaleX, 
                    30 * scaleY
                );
            }
        }
        
        // Draw stairs with Gothic styling
        if (game.stairs) {
            const stairTileX = Math.floor(game.stairs.x / CONFIG.MAP.CELL_SIZE);
            const stairTileY = Math.floor(game.stairs.y / CONFIG.MAP.CELL_SIZE);
            if (game.explored.has(`${stairTileX},${stairTileY}`) || game.player.powers.reveal > 0) {
                const stairX = contentX + ((game.stairs.x - 15) * scaleX);
                const stairY = contentY + ((game.stairs.y - 15) * scaleY);
                const stairSize = 30;
                
                // Golden stairs
                this.ctx.fillStyle = '#ff0';
                this.ctx.fillRect(stairX, stairY, stairSize * scaleX, stairSize * scaleY);
                
                // Pulsing Gothic border
                if ((game.time || 0) % 60 < 30) {
                    this.ctx.strokeStyle = '#fff';
                    this.ctx.lineWidth = Math.max(1, 2 * scaleX);
                    this.ctx.strokeRect(stairX, stairY, stairSize * scaleX, stairSize * scaleY);
                }
            }
        }
        
        // Draw player
        this.ctx.fillStyle = '#fff';
        this.ctx.fillRect(
            contentX + ((game.player.x - 5) * scaleX),
            contentY + ((game.player.y - 5) * scaleY),
            10 * scaleX,
            10 * scaleY
        );
        
        // Draw camera bounds
        this.ctx.strokeStyle = '#666';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(
            contentX + (game.camera.x * scaleX),
            contentY + (game.camera.y * scaleY),
            CONFIG.CANVAS.WIDTH * scaleX,
            CONFIG.CANVAS.HEIGHT * scaleY
        );

        // Restore context to remove minimap clipping
        this.ctx.restore();
    },

    // Render menu
    renderMenu() {
        // Dark mystical background
        this.ctx.fillStyle = '#0a0505';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // Dark red vignette effect for mystical atmosphere
        const menuVignetteRadius = Math.max(CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT) / 2;
        const gradient = this.ctx.createRadialGradient(
            CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2, 0,
            CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2, menuVignetteRadius
        );
        gradient.addColorStop(0, 'rgba(20, 5, 0, 0)');
        gradient.addColorStop(0.6, 'rgba(30, 10, 5, 0.3)');
        gradient.addColorStop(1, 'rgba(15, 0, 0, 0.7)');
        this.ctx.fillStyle = gradient;
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // In portrait mode, offset menu content vertically to center it
        // Menu content spans ~265px (from title at y=90 to last button bottom at ~355)
        // Center that content block in the available space (above the footer)
        const isPortraitCanvas = CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT;
        const menuOffsetY = isPortraitCanvas ? Math.round((CONFIG.CANVAS.HEIGHT - CONFIG.CANVAS.BASE_HEIGHT) / 3) : 0;

        // Main title with Gothic styling
        this.ctx.textAlign = 'center';
        this.ctx.shadowBlur = 15;
        this.ctx.shadowColor = '#8B0000'; // Dark red shadow
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = 'bold 52px serif';
        this.ctx.fillText('THE BURIED SPIRE', CONFIG.CANVAS.WIDTH / 2, 90 + menuOffsetY);

        // Subtitle with mystical glow
        this.ctx.shadowBlur = 10;
        this.ctx.shadowColor = '#654321'; // Gothic brown shadow
        this.ctx.fillStyle = '#8B4513'; // Gothic brown
        this.ctx.font = 'italic 22px serif';
        this.ctx.fillText('Quest Into the Depths', CONFIG.CANVAS.WIDTH / 2, 120 + menuOffsetY);
        this.ctx.shadowBlur = 0;

        // Atmospheric flavor text
        this.ctx.fillStyle = '#654321'; // Gothic brown
        this.ctx.font = '14px serif';
        this.ctx.fillText('Ancient depths await the brave...', CONFIG.CANVAS.WIDTH / 2, 150 + menuOffsetY);

        // Desert decorative elements
        this.ctx.fillStyle = '#a68654';
        this.ctx.font = '16px serif';
        this.ctx.fillText('☥ ═══════════════════════════════════ ☥', CONFIG.CANVAS.WIDTH / 2, 175 + menuOffsetY);

        // Menu buttons (pass offset for portrait centering)
        this.renderMenuButtons(menuOffsetY);

        // Gothic footer with mystical symbols (positioned relative to bottom)
        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = '11px serif';
        const isMobileMenu = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        if (isMobileMenu) {
            this.ctx.fillText('⚔ Joystick: Move • Buttons: Use Orb ⚔', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT - 80);
        } else {
            this.ctx.fillText('⚔ WASD: Move • 1-3: Use Orb • ESC: Pause ⚔', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT - 80);
        }

        // Build info with gothic styling
        this.ctx.fillStyle = '#654321';
        this.ctx.font = '9px serif';
        this.ctx.fillText('Ancient Codex v1.0 • Forged in Darkness', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT - 55);

        this.ctx.textAlign = 'left';
    },
    
    // Render main menu buttons
    renderMenuButtons(offsetY = 0) {
        const centerX = CONFIG.CANVAS.WIDTH / 2;
        const isMobileBtn = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const buttonWidth = 300;
        const buttonHeight = isMobileBtn ? 56 : 45;
        const buttonSpacing = isMobileBtn ? 65 : 55;
        const buttonFontSize = isMobileBtn ? 22 : 18;
        const iconFontSize = isMobileBtn ? 24 : 20;
        const textCenterY = isMobileBtn ? 34 : 28;
        const startY = 200 + offsetY;

        const buttons = [
            { text: 'NEW GAME', y: startY, icon: '♦' },
            { text: 'LEADERBOARDS', y: startY + buttonSpacing, icon: '♠' },
            { text: 'SETTINGS', y: startY + buttonSpacing * 2, icon: '♣' }
        ];

        for (let i = 0; i < buttons.length; i++) {
            const button = buttons[i];
            const isHovered = false; // Could add hover logic later

            // Dark Gothic button background
            const buttonGradient = this.ctx.createLinearGradient(
                centerX - buttonWidth/2, button.y,
                centerX + buttonWidth/2, button.y + buttonHeight
            );
            buttonGradient.addColorStop(0, '#654321'); // Gothic brown
            buttonGradient.addColorStop(0.5, '#2A1810'); // Dark brown
            buttonGradient.addColorStop(1, '#1A0F08'); // Darkest brown
            this.ctx.fillStyle = buttonGradient;
            this.ctx.fillRect(centerX - buttonWidth/2, button.y, buttonWidth, buttonHeight);

            // Dark Gothic border styling
            this.ctx.strokeStyle = '#8B4513'; // Gothic brown
            this.ctx.lineWidth = 2;
            this.ctx.strokeRect(centerX - buttonWidth/2, button.y, buttonWidth, buttonHeight);

            // Inner golden highlight
            this.ctx.strokeStyle = '#DAA520'; // Golden
            this.ctx.lineWidth = 1;
            this.ctx.strokeRect(centerX - buttonWidth/2 + 3, button.y + 3, buttonWidth - 6, buttonHeight - 6);

            // Button icon with golden glow
            this.ctx.shadowBlur = 6;
            this.ctx.shadowColor = '#DAA520';
            this.ctx.fillStyle = '#DAA520';
            this.ctx.font = `${iconFontSize}px serif`;
            this.ctx.textAlign = 'center';
            this.ctx.fillText(button.icon, centerX - 80, button.y + textCenterY);
            this.ctx.shadowBlur = 0;

            // Button text with Gothic styling
            this.ctx.fillStyle = '#DAA520'; // Golden for readability
            this.ctx.font = `bold ${buttonFontSize}px serif`;
            this.ctx.fillText(button.text, centerX + 10, button.y + textCenterY);

            // Add mystical corner decorations
            this.ctx.fillStyle = '#8B4513';
            this.ctx.font = '12px serif';
            this.ctx.fillText('╔', centerX - buttonWidth/2 + 5, button.y + 12);
            this.ctx.fillText('╗', centerX + buttonWidth/2 - 12, button.y + 12);
            this.ctx.fillText('╚', centerX - buttonWidth/2 + 5, button.y + buttonHeight - 5);
            this.ctx.fillText('╝', centerX + buttonWidth/2 - 12, button.y + buttonHeight - 5);
        }

        // Add mystical glow effect around buttons
        this.ctx.shadowBlur = 3;
        this.ctx.shadowColor = '#8B0000';
        this.ctx.strokeStyle = '#4a1a0a';
        this.ctx.lineWidth = 1;
        for (let i = 0; i < buttons.length; i++) {
            const button = buttons[i];
            this.ctx.strokeRect(centerX - buttonWidth/2 - 2, button.y - 2, buttonWidth + 4, buttonHeight + 4);
        }
        this.ctx.shadowBlur = 0;

        this.ctx.textAlign = 'left';
    },


    // Render help screen
    renderHelpScreen(game) {
        if (!game.showHelp) return;

        const isMobileDevice = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const bodyFont = isMobileDevice ? 16 : 14;
        const headerFont = isMobileDevice ? 20 : 18;

        // Dark background overlay
        this.ctx.fillStyle = 'rgba(42, 24, 16, 0.95)';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // Decorative Gothic border
        this.ctx.strokeStyle = '#8B4513';
        this.ctx.lineWidth = 3;
        this.ctx.strokeRect(50, 30, CONFIG.CANVAS.WIDTH - 100, CONFIG.CANVAS.HEIGHT - 60);

        // Inner golden border
        this.ctx.strokeStyle = '#DAA520';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(55, 35, CONFIG.CANVAS.WIDTH - 110, CONFIG.CANVAS.HEIGHT - 70);

        // Title with gothic styling
        this.ctx.shadowBlur = 8;
        this.ctx.shadowColor = '#8B0000';
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = 'bold 28px serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText('⚜ ADVENTURER\'S GUIDE ⚜', CONFIG.CANVAS.WIDTH / 2, 70);
        this.ctx.shadowBlur = 0;

        // Section headers with bronze styling
        this.ctx.fillStyle = '#CD853F';
        this.ctx.font = `bold ${headerFont}px serif`;
        this.ctx.fillText('SACRED QUEST', CONFIG.CANVAS.WIDTH / 2, 110);
        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = `${bodyFont}px serif`;
        this.ctx.fillText(`Descend the cursed tower to floor -${CONFIG.GAME.MAX_FLOORS}`, CONFIG.CANVAS.WIDTH / 2, 130);
        this.ctx.fillText('Seek the Ancient Pearl to break the curse', CONFIG.CANVAS.WIDTH / 2, 150);

        // Controls section
        this.ctx.fillStyle = '#CD853F';
        this.ctx.font = `bold ${headerFont}px serif`;
        this.ctx.fillText('MYSTIC CONTROLS', CONFIG.CANVAS.WIDTH / 2, 190);
        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = `${bodyFont}px serif`;
        if (isMobileDevice) {
            this.ctx.fillText('Virtual Joystick: Navigate the darkness', CONFIG.CANVAS.WIDTH / 2, 210);
            this.ctx.fillText('Buttons 1-3: Channel orb powers from inventory', CONFIG.CANVAS.WIDTH / 2, 230);
            this.ctx.fillText('Pause button: Open settings', CONFIG.CANVAS.WIDTH / 2, 250);
        } else {
            this.ctx.fillText('Arrow Keys / WASD: Navigate the darkness', CONFIG.CANVAS.WIDTH / 2, 210);
            this.ctx.fillText('1-3: Channel orb powers from inventory', CONFIG.CANVAS.WIDTH / 2, 230);
            this.ctx.fillText('H: Summon this guide', CONFIG.CANVAS.WIDTH / 2, 250);
        }

        // Orb guide
        this.renderHelpOrbGuide(isMobileDevice);

        // Footer (positioned relative to bottom)
        this.ctx.textAlign = 'center';
        this.ctx.fillStyle = '#654321';
        this.ctx.font = '16px serif';
        if (isMobileDevice) {
            this.ctx.fillText('Tap anywhere to dismiss this guide', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT - 80);
        } else {
            this.ctx.fillText('Press H to dismiss this guide', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT - 80);
        }
        this.ctx.textAlign = 'left';
    },

    // Render orb guide in help screen
    renderHelpOrbGuide(isMobileDevice) {
        const headerFont = isMobileDevice ? 20 : 18;
        const bodyFont = isMobileDevice ? 16 : 14;

        this.ctx.fillStyle = '#CD853F';
        this.ctx.font = `bold ${headerFont}px serif`;
        this.ctx.textAlign = 'center';
        this.ctx.fillText('MYSTICAL ORBS', CONFIG.CANVAS.WIDTH / 2, 290);

        this.ctx.textAlign = 'left';
        const orbX = 180;
        this.ctx.font = `${bodyFont}px serif`;

        // Light orbs section
        this.ctx.fillStyle = '#8B4513';
        this.ctx.fillText('Light Restoration:', orbX, 320);
        this.ctx.fillStyle = '#64b5f6';
        this.ctx.fillText('O  Blue Orb: Restores 15% illumination', orbX + 20, 340);
        this.ctx.fillStyle = '#ffeb3b';
        this.ctx.fillText('@  Golden Orb: Restores 25% illumination', orbX + 20, 360);
        this.ctx.fillStyle = '#ccccff';
        this.ctx.fillText('*  Light Wisp: Soul marker - Restores 50% illumination', orbX + 20, 380);

        // Power orbs section
        this.ctx.fillStyle = '#8B4513';
        this.ctx.fillText('Arcane Powers:', orbX, 410);
        this.ctx.fillStyle = '#9c27b0';
        this.ctx.fillText('P  Purple Orb: Ethereal form - pass through walls', orbX + 20, 430);
        this.ctx.fillStyle = '#4caf50';
        this.ctx.fillText('G  Green Orb: Regenerative aura - restore light over time', orbX + 20, 450);
        this.ctx.fillStyle = '#fff';
        this.ctx.fillText('W  White Orb: Divine sight - reveal the entire floor', orbX + 20, 470);
        this.ctx.fillStyle = '#f44336';
        this.ctx.fillText('♥  Crimson Orb: Soul anchor - defies death itself!', orbX + 20, 490);
    },

    // Render death screen
    renderDeathScreen(game) {
        if (!game.deathScreen) return;

        // Vertical offset for portrait mode centering
        const isPortraitCanvas = CONFIG.CANVAS.HEIGHT > CONFIG.CANVAS.BASE_HEIGHT;
        const deathOffsetY = isPortraitCanvas ? Math.round((CONFIG.CANVAS.HEIGHT - CONFIG.CANVAS.BASE_HEIGHT) / 3) : 0;

        // Dark death screen background
        this.ctx.fillStyle = 'rgba(42, 24, 16, 0.98)';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // Gothic decorative border
        this.ctx.strokeStyle = '#8B4513';
        this.ctx.lineWidth = 3;
        this.ctx.strokeRect(30, 30, CONFIG.CANVAS.WIDTH - 60, CONFIG.CANVAS.HEIGHT - 60);

        // Inner golden border
        this.ctx.strokeStyle = '#DAA520';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(35, 35, CONFIG.CANVAS.WIDTH - 70, CONFIG.CANVAS.HEIGHT - 70);

        // Title with gothic styling
        this.ctx.shadowBlur = 12;
        this.ctx.shadowColor = '#8B0000';
        this.ctx.fillStyle = '#DC143C';
        this.ctx.font = 'bold 40px serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText('⚜ CLAIMED BY THE VOID ⚜', CONFIG.CANVAS.WIDTH / 2, 100 + deathOffsetY);
        this.ctx.shadowBlur = 0;

        // Stats with gothic styling
        this.ctx.fillStyle = '#CD853F';
        this.ctx.font = 'bold 20px serif';
        this.ctx.fillText('⚰ MORTAL CHRONICLE ⚰', CONFIG.CANVAS.WIDTH / 2, 160 + deathOffsetY);

        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = '16px serif';
        this.ctx.textAlign = 'left';
        const statsX = CONFIG.CANVAS.WIDTH / 2 - 160;
        this.ctx.fillText(`⚔ Final Depth: Floor ${-game.floor}`, statsX, 200 + deathOffsetY);
        this.ctx.fillText(`⚜ Last Sanctuary: Floor ${-game.checkpoint}`, statsX, 220 + deathOffsetY);
        this.ctx.fillText(`💎 Orbs Gathered: ${game.player.orbsCollected}`, statsX, 240 + deathOffsetY);
        this.ctx.fillText(`💀 Deaths This Quest: ${GameState.game.runDeaths}`, statsX, 260 + deathOffsetY);
        this.ctx.fillText(`🏆 Deepest Descent: Floor ${-GameState.stats.deepestFloor}`, statsX, 280 + deathOffsetY);

        // Leaderboard with gothic theme
        this.ctx.textAlign = 'center';
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = 'bold 18px serif';
        this.ctx.fillText('⚔ HALL OF LEGENDS ⚔', CONFIG.CANVAS.WIDTH / 2, 330 + deathOffsetY);

        // Get scores from LeaderboardService (sync read of cached data)
        const scores = (window.LeaderboardService && LeaderboardService.isReady())
            ? LeaderboardService.getCachedScores()
            : [];

        const rankSymbols = ['♦', '♠', '♣', '♥', '♤'];

        if (scores.length > 0) {
            // Show top 3 scores
            scores.slice(0, 3).forEach((score, i) => {
                const symbol = rankSymbols[i] || '♦';
                this.ctx.fillStyle = i === 0 ? '#FFD700' : (i === 1 ? '#C0C0C0' : '#CD7F32');
                this.ctx.font = '14px serif';
                let details = `Floor ${score.deepestFloor}`;
                if (score.completionTimeMs) {
                    details += ` | ${this.formatTime(score.completionTimeMs)}`;
                }
                if (score.deaths != null) {
                    details += ` | ${score.deaths}☠`;
                }
                this.ctx.fillText(
                    `${symbol} ${score.name} - ${details}`,
                    CONFIG.CANVAS.WIDTH / 2,
                    355 + (i * 20) + deathOffsetY
                );
            });
            // Always show player's entry at the bottom
            this.ctx.fillStyle = '#654321';
            this.ctx.fillText(
                `♥ Your Legacy - Floor ${-GameState.stats.deepestFloor}`,
                CONFIG.CANVAS.WIDTH / 2,
                355 + (Math.min(scores.length, 3) * 20) + deathOffsetY
            );
        } else {
            // Fallback when leaderboard unavailable
            this.ctx.fillStyle = '#654321';
            this.ctx.font = '14px serif';
            this.ctx.fillText('No legends recorded yet...', CONFIG.CANVAS.WIDTH / 2, 355 + deathOffsetY);
            this.ctx.fillText(
                `♥ Your Legacy - Floor ${-GameState.stats.deepestFloor}`,
                CONFIG.CANVAS.WIDTH / 2,
                375 + deathOffsetY
            );
        }
        
        // Buttons
        this.renderDeathScreenButtons();
        
        this.ctx.textAlign = 'left';
    },

    // Render death screen buttons
    renderDeathScreenButtons() {
        const isMobileDeath = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const btnY = CONFIG.CANVAS.HEIGHT - 140;
        const btnWidth = isMobileDeath ? 200 : 180;
        const btnHeight = isMobileDeath ? 58 : 50;
        const btnGap = isMobileDeath ? 24 : 20;
        const btnFontSize = isMobileDeath ? 20 : 18;
        const btnTextY = btnY + Math.round(btnHeight / 2 + btnFontSize / 3);

        // Respawn button with gothic styling
        const gradient1 = this.ctx.createLinearGradient(CONFIG.CANVAS.WIDTH / 2 - btnWidth - btnGap, btnY, CONFIG.CANVAS.WIDTH / 2 - btnGap, btnY + btnHeight);
        gradient1.addColorStop(0, '#8B4513');
        gradient1.addColorStop(1, '#654321');
        this.ctx.fillStyle = gradient1;
        this.ctx.fillRect(CONFIG.CANVAS.WIDTH / 2 - btnWidth - btnGap, btnY, btnWidth, btnHeight);
        this.ctx.strokeStyle = '#DAA520';
        this.ctx.lineWidth = 2;
        this.ctx.strokeRect(CONFIG.CANVAS.WIDTH / 2 - btnWidth - btnGap, btnY, btnWidth, btnHeight);

        this.ctx.fillStyle = '#FFD700';
        this.ctx.font = `bold ${btnFontSize}px serif`;
        this.ctx.textAlign = 'center';
        this.ctx.fillText('♦ RISE AGAIN', CONFIG.CANVAS.WIDTH / 2 - btnWidth / 2 - btnGap, btnTextY);

        // Quit button with gothic styling
        const gradient2 = this.ctx.createLinearGradient(CONFIG.CANVAS.WIDTH / 2 + btnGap, btnY, CONFIG.CANVAS.WIDTH / 2 + btnWidth + btnGap, btnY + btnHeight);
        gradient2.addColorStop(0, '#654321');
        gradient2.addColorStop(1, '#3d2817');
        this.ctx.fillStyle = gradient2;
        this.ctx.fillRect(CONFIG.CANVAS.WIDTH / 2 + btnGap, btnY, btnWidth, btnHeight);
        this.ctx.strokeStyle = '#8B4513';
        this.ctx.strokeRect(CONFIG.CANVAS.WIDTH / 2 + btnGap, btnY, btnWidth, btnHeight);

        this.ctx.fillStyle = '#CD853F';
        this.ctx.fillText('♠ RETREAT', CONFIG.CANVAS.WIDTH / 2 + btnWidth / 2 + btnGap, btnTextY);
    },

    // Render game over screen (victory has its own overlay)
    renderGameOverScreen(game) {
        if (!game.gameOver || game.victory) return; // Skip if victory (has its own overlay)
        
        // Desert sand game over background
        this.ctx.fillStyle = 'rgba(61, 43, 31, 1)';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);
        
        // Desert game over styling
        this.ctx.shadowBlur = 15;
        this.ctx.shadowColor = '#8b5a2b'; // Sandy brown shadow
        this.ctx.fillStyle = '#DC143C';
        this.ctx.font = 'bold 52px serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText('☥ QUEST FAILED ☥', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2);
        this.ctx.shadowBlur = 0;
        
        this.ctx.font = '18px serif';
        this.ctx.fillStyle = '#d4a574'; // Light sand
        const isMobileGameOver = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        if (isMobileGameOver) {
            this.ctx.fillText('Tap to retreat to the sanctum', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2 + 50);
        } else {
            this.ctx.fillText('Press R to retreat to the sanctum', CONFIG.CANVAS.WIDTH / 2, CONFIG.CANVAS.HEIGHT / 2 + 50);
        }
        this.ctx.textAlign = 'left';
    },

    // Render full leaderboard screen
    renderLeaderboardScreen() {
        const centerX = CONFIG.CANVAS.WIDTH / 2;

        // Dark gothic background
        this.ctx.fillStyle = 'rgba(61, 43, 31, 1)';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        // Gothic decorative border
        this.ctx.strokeStyle = '#8B4513';
        this.ctx.lineWidth = 3;
        this.ctx.strokeRect(30, 30, CONFIG.CANVAS.WIDTH - 60, CONFIG.CANVAS.HEIGHT - 60);

        // Inner golden border
        this.ctx.strokeStyle = '#DAA520';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(35, 35, CONFIG.CANVAS.WIDTH - 70, CONFIG.CANVAS.HEIGHT - 70);

        // Title
        this.ctx.shadowBlur = 12;
        this.ctx.shadowColor = '#8B0000';
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = 'bold 28px serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText('⚔ HALL OF LEGENDS ⚔', centerX, 80);
        this.ctx.shadowBlur = 0;

        // Decorative divider
        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = '14px serif';
        this.ctx.fillText('═══════════════════════════════════', centerX, 105);

        // Check if LeaderboardService is available and configured
        const serviceReady = window.LeaderboardService && LeaderboardService.isReady();
        const serviceExists = window.LeaderboardService;
        const scores = serviceReady ? LeaderboardService.getCachedScores() : [];

        if (!serviceExists) {
            // Leaderboard not configured at all
            this.ctx.fillStyle = '#CD853F';
            this.ctx.font = '18px serif';
            this.ctx.fillText('Leaderboard not configured', centerX, CONFIG.CANVAS.HEIGHT / 2 - 30);
            this.ctx.fillStyle = '#8B4513';
            this.ctx.font = '14px serif';
            this.ctx.fillText('Set up LeaderboardService to enable online rankings.', centerX, CONFIG.CANVAS.HEIGHT / 2);
            this.ctx.fillText('See project documentation for configuration details.', centerX, CONFIG.CANVAS.HEIGHT / 2 + 25);
        } else if (scores.length === 0) {
            // Service exists but no scores yet
            this.ctx.fillStyle = '#CD853F';
            this.ctx.font = '20px serif';
            this.ctx.fillText('No legends recorded yet...', centerX, CONFIG.CANVAS.HEIGHT / 2 - 15);
            this.ctx.fillStyle = '#8B4513';
            this.ctx.font = '16px serif';
            this.ctx.fillText('Be the first!', centerX, CONFIG.CANVAS.HEIGHT / 2 + 15);
        } else {
            // Column headers
            this.ctx.fillStyle = '#CD853F';
            this.ctx.font = 'bold 13px serif';
            const headerY = 135;
            this.ctx.textAlign = 'left';
            this.ctx.fillText('RANK', 55, headerY);
            this.ctx.fillText('ADVENTURER', 110, headerY);
            this.ctx.textAlign = 'right';
            this.ctx.fillText('FLOOR', CONFIG.CANVAS.WIDTH - 280, headerY);
            this.ctx.fillText('TIME', CONFIG.CANVAS.WIDTH - 185, headerY);
            this.ctx.fillText('DEATHS', CONFIG.CANVAS.WIDTH - 95, headerY);
            this.ctx.textAlign = 'center';

            // Divider below headers
            this.ctx.fillStyle = '#654321';
            this.ctx.font = '10px serif';
            this.ctx.fillText('────────────────────────────────────────────────────', centerX, headerY + 12);

            // Get current player UID for highlighting
            const currentPlayerUID = (window.LeaderboardService && LeaderboardService.playerUID)
                ? LeaderboardService.playerUID
                : null;

            // Show top 10 scores
            const rankSymbols = ['♦', '♠', '♣', '♥', '♤', '♧', '♢', '♡', '⚜', '☥'];
            const top10 = scores.slice(0, 10);
            const rowHeight = 32;
            const startY = 170;

            top10.forEach((score, i) => {
                const rowY = startY + (i * rowHeight);
                const isCurrentPlayer = currentPlayerUID && score.playerUID === currentPlayerUID;

                // Row highlight for current player
                if (isCurrentPlayer) {
                    this.ctx.fillStyle = 'rgba(65, 105, 225, 0.15)';
                    this.ctx.fillRect(60, rowY - 16, CONFIG.CANVAS.WIDTH - 120, rowHeight);
                }

                // Color based on rank
                if (isCurrentPlayer) {
                    this.ctx.fillStyle = '#4169E1'; // Royal blue for current player
                } else if (i === 0) {
                    this.ctx.fillStyle = '#FFD700'; // Gold
                } else if (i === 1) {
                    this.ctx.fillStyle = '#C0C0C0'; // Silver
                } else if (i === 2) {
                    this.ctx.fillStyle = '#CD7F32'; // Bronze
                } else {
                    this.ctx.fillStyle = '#654321'; // Standard brown
                }

                const symbol = rankSymbols[i] || '♦';
                this.ctx.font = '15px serif';

                // Rank
                this.ctx.textAlign = 'left';
                this.ctx.fillText(`${symbol} ${i + 1}`, 55, rowY);

                // Player name (truncate if too long)
                const displayName = score.name && score.name.length > 14
                    ? score.name.substring(0, 12) + '...'
                    : (score.name || 'Unknown');
                this.ctx.fillText(displayName, 110, rowY);

                // Floor depth
                this.ctx.textAlign = 'right';
                this.ctx.fillText(`${score.deepestFloor || 0}`, CONFIG.CANVAS.WIDTH - 280, rowY);

                // Completion time
                const timeStr = score.completionTimeMs ? this.formatTime(score.completionTimeMs) : '--:--';
                this.ctx.fillText(timeStr, CONFIG.CANVAS.WIDTH - 185, rowY);

                // Deaths
                const deathStr = score.deaths != null ? `${score.deaths}` : '-';
                this.ctx.fillText(deathStr, CONFIG.CANVAS.WIDTH - 95, rowY);
            });

            this.ctx.textAlign = 'center';
        }

        // BACK button at bottom
        const isMobileBtn = typeof InputManager !== 'undefined' && (InputManager.isMobile || InputManager.hasTouchSupport);
        const btnWidth = isMobileBtn ? 200 : 180;
        const btnHeight = isMobileBtn ? 58 : 50;
        const btnY = CONFIG.CANVAS.HEIGHT - 100;
        const btnFontSize = isMobileBtn ? 20 : 18;

        // Button background gradient
        const btnGradient = this.ctx.createLinearGradient(
            centerX - btnWidth / 2, btnY,
            centerX + btnWidth / 2, btnY + btnHeight
        );
        btnGradient.addColorStop(0, '#654321');
        btnGradient.addColorStop(1, '#3d2817');
        this.ctx.fillStyle = btnGradient;
        this.ctx.fillRect(centerX - btnWidth / 2, btnY, btnWidth, btnHeight);

        // Button border
        this.ctx.strokeStyle = '#DAA520';
        this.ctx.lineWidth = 2;
        this.ctx.strokeRect(centerX - btnWidth / 2, btnY, btnWidth, btnHeight);

        // Inner golden border
        this.ctx.strokeStyle = '#8B4513';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(centerX - btnWidth / 2 + 3, btnY + 3, btnWidth - 6, btnHeight - 6);

        // Button text
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = `bold ${btnFontSize}px serif`;
        this.ctx.textAlign = 'center';
        this.ctx.fillText('♦ BACK', centerX, btnY + Math.round(btnHeight / 2 + btnFontSize / 3));

        this.ctx.textAlign = 'left';
    },

    // Render name entry overlay (canvas background for HTML input overlay)
    renderNameEntryOverlay() {
        // Semi-transparent dark overlay
        this.ctx.fillStyle = 'rgba(10, 5, 0, 0.85)';
        this.ctx.fillRect(0, 0, CONFIG.CANVAS.WIDTH, CONFIG.CANVAS.HEIGHT);

        const centerX = CONFIG.CANVAS.WIDTH / 2;
        const centerY = CONFIG.CANVAS.HEIGHT / 2;

        // Overlay panel background
        const panelWidth = 420;
        const panelHeight = 220;
        const panelX = centerX - panelWidth / 2;
        const panelY = centerY - panelHeight / 2;

        // Dark brown panel
        this.ctx.fillStyle = 'rgba(42, 24, 16, 0.98)';
        this.ctx.fillRect(panelX, panelY, panelWidth, panelHeight);

        // Gothic decorative border
        this.ctx.strokeStyle = '#8B4513';
        this.ctx.lineWidth = 3;
        this.ctx.strokeRect(panelX, panelY, panelWidth, panelHeight);

        // Inner golden border
        this.ctx.strokeStyle = '#DAA520';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(panelX + 4, panelY + 4, panelWidth - 8, panelHeight - 8);

        // Title
        this.ctx.shadowBlur = 10;
        this.ctx.shadowColor = '#8B0000';
        this.ctx.fillStyle = '#DAA520';
        this.ctx.font = 'bold 22px serif';
        this.ctx.textAlign = 'center';
        this.ctx.fillText('Enter Your Name, Adventurer', centerX, panelY + 50);
        this.ctx.shadowBlur = 0;

        // Decorative divider
        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = '12px serif';
        this.ctx.fillText('═══════════════════════════', centerX, panelY + 70);

        // Subtitle / instruction text
        this.ctx.fillStyle = '#CD853F';
        this.ctx.font = '14px serif';
        this.ctx.fillText('Your name shall be etched in the Hall of Legends', centerX, panelY + 100);

        // Input field placeholder area (the actual HTML input is positioned on top)
        this.ctx.fillStyle = 'rgba(15, 8, 4, 0.8)';
        this.ctx.fillRect(panelX + 50, panelY + 115, panelWidth - 100, 36);
        this.ctx.strokeStyle = '#654321';
        this.ctx.lineWidth = 1;
        this.ctx.strokeRect(panelX + 50, panelY + 115, panelWidth - 100, 36);

        // Corner decorations
        this.ctx.fillStyle = '#8B4513';
        this.ctx.font = '14px serif';
        this.ctx.fillText('╔', panelX + 10, panelY + 18);
        this.ctx.fillText('╗', panelX + panelWidth - 16, panelY + 18);
        this.ctx.fillText('╚', panelX + 10, panelY + panelHeight - 8);
        this.ctx.fillText('╝', panelX + panelWidth - 16, panelY + panelHeight - 8);

        // Footer hint
        this.ctx.fillStyle = '#654321';
        this.ctx.font = '12px serif';
        this.ctx.fillText('Press Enter to confirm', centerX, panelY + panelHeight - 25);

        this.ctx.textAlign = 'left';
    }
};