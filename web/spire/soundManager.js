// Sound Manager for Buried Spire Quest
const SoundManager = {
    sounds: {},
    ambientSounds: [],
    currentAmbient: null,
    crossfadeStarted: false,
    nextAmbient: null,
    currentBackground: null,
    backgroundCrossfadeStarted: false,
    nextBackground: null,
    ghoulDetectionPlayed: new Set(),
    volume: 0.7,
    ambientVolume: 0.15,  // Reduced for subtlety
    sfxVolume: 0.3,      // Reduced for less intrusive SFX
    initialized: false,
    isPaused: false,
    muted: false,
    enabled: true, // Controlled by settings enableSoundEffects
    audioUnlocked: false, // Track whether user gesture has unlocked audio

    // Initialize sound system
    init() {
        if (this.initialized) return;

        console.log('Initializing Sound Manager');

        // Load all sounds with correct paths relative to public/index.html
        // Load underground ambience
        this.loadSound('ambient', 'sound/Underground_ambience.mp3');
        this.loadSound('background', 'sound/backfround-sound.mp3');

        // Load wind sounds
        this.loadSound('wind1', 'sound/wind-passage-1.mp3');
        this.loadSound('wind2', 'sound/wind-passage-2.mp3');

        // Load game event sounds
        this.loadSound('death', 'sound/Death_sound_Ominous.mp3');
        this.loadSound('orb_collection', 'sound/Orb_collection.mp3');
        this.loadSound('button_select', 'sound/Button_selection.mp3');
        this.loadSound('footsteps', 'sound/Footsteps_Stone.mp3');
        this.loadSound('stalking', 'sound/stalking.mp3');

        // Load individual orb sounds
        this.loadSound('blue_orb', 'sound/blue-orb.mp3');
        this.loadSound('gold_orb', 'sound/gold-orb.mp3');
        this.loadSound('green_orb', 'sound/green-orb.mp3');
        this.loadSound('purple_orb', 'sound/purple-orb.mp3');
        this.loadSound('white_orb', 'sound/white-orb.mp3');
        this.loadSound('red_orb', 'sound/red-orb.mp3');

        // Load ghoul tension sounds
        this.loadSound('ghoul_detection', 'sound/ghoul-detection.mp3');

        this.initialized = true;

        // Don't start ambient sounds automatically - wait for user interaction
    },
    
    // Load individual sound
    loadSound(name, path) {
        try {
            const audio = new Audio(path);
            audio.preload = 'auto';
            audio.addEventListener('error', () => {
                // Graceful fallback: mark sound as failed so we don't try to play it
                console.warn(`Failed to load sound: ${name} from ${path}`);
                delete this.sounds[name];
            });
            this.sounds[name] = audio;
        } catch (error) {
            // Graceful fallback: audio constructor failed (e.g., no audio support)
            console.warn(`Error loading sound ${name}:`, error);
        }
    },
    
    // Play a sound effect
    playSFX(soundName, volume = null) {
        if (!this.initialized || !this.enabled || this.muted || !this.audioUnlocked) return;
        if (!this.sounds[soundName]) {
            // Graceful fallback: sound not loaded, skip silently
            return;
        }

        try {
            const sound = this.sounds[soundName].cloneNode();
            sound.volume = (volume !== null ? volume : this.sfxVolume) * this.volume;
            sound.play().catch(e => {
                // Silently handle play failures (common on mobile before interaction)
            });
        } catch (error) {
            // Graceful fallback: do not crash on audio errors
        }
    },

    // Play button selection sound
    playButtonSelect() {
        this.playSFX('button_select', 0.3);
    },
    
    
    
    // Start ambient sound loop
    startAmbientSounds() {
        if (!this.initialized || !this.enabled || this.muted || !this.audioUnlocked) return;

        // Start with underground ambience
        this.playAmbientLoop();

        // Start background music
        this.playBackgroundLoop();

        // Occasionally play wind sounds
        this.scheduleWindSounds();
    },
    
    // Play looping ambient sound - crossfade to handle fade-out
    playAmbientLoop() {
        if (this.sounds.ambient && !this.currentAmbient && this.enabled && !this.muted && this.audioUnlocked) {
            try {
                // Clone the audio to avoid issues
                this.currentAmbient = this.sounds.ambient.cloneNode();
                this.currentAmbient.volume = this.ambientVolume * this.volume;
                this.currentAmbient.loop = false; // Don't use native loop due to fade-out
                
                // Preload to avoid gaps
                this.currentAmbient.preload = 'auto';
                
                // Handle crossfade before track ends (account for fade-out)
                this.currentAmbient.addEventListener('timeupdate', () => {
                    if (this.currentAmbient) {
                        const timeLeft = this.currentAmbient.duration - this.currentAmbient.currentTime;
                        // Start crossfade 2 seconds before end (during fade-out)
                        if (timeLeft <= 2 && timeLeft > 0 && !this.crossfadeStarted) {
                            this.crossfadeStarted = true;
                            this.startAmbientCrossfade();
                        }
                    }
                });
                
                this.currentAmbient.addEventListener('ended', () => {
                    this.currentAmbient = null;
                    this.crossfadeStarted = false;
                    // Start next loop if not paused
                    if (!this.isPaused) {
                        this.playAmbientLoop();
                    }
                });
                
                this.currentAmbient.play().catch(() => {
                    // Silently handle - audio may not be allowed yet
                });
            } catch (error) {
                // Graceful fallback
            }
        }
    },
    
    
    // Start crossfade for ambient sound to handle fade-out
    startAmbientCrossfade() {
        if (this.sounds.ambient && !this.nextAmbient) {
            try {
                // Create next ambient sound
                this.nextAmbient = this.sounds.ambient.cloneNode();
                this.nextAmbient.volume = 0; // Start silent
                this.nextAmbient.preload = 'auto';
                
                // Start playing the next sound
                this.nextAmbient.play().catch(() => {});
                
                // Crossfade: fade out current, fade in next
                const fadeInterval = setInterval(() => {
                    if (this.currentAmbient && this.nextAmbient) {
                        // Fade out current
                        this.currentAmbient.volume = Math.max(0, this.currentAmbient.volume - 0.05);
                        // Fade in next
                        this.nextAmbient.volume = Math.min(this.ambientVolume * this.volume, this.nextAmbient.volume + 0.05);
                        
                        // When crossfade complete
                        if (this.currentAmbient.volume <= 0 && this.nextAmbient.volume >= this.ambientVolume * this.volume) {
                            clearInterval(fadeInterval);
                            // Switch to next sound
                            if (this.currentAmbient) {
                                this.currentAmbient.pause();
                            }
                            this.currentAmbient = this.nextAmbient;
                            this.nextAmbient = null;
                            this.crossfadeStarted = false;
                            
                            // Setup next crossfade
                            this.currentAmbient.addEventListener('timeupdate', () => {
                                if (this.currentAmbient) {
                                    const timeLeft = this.currentAmbient.duration - this.currentAmbient.currentTime;
                                    if (timeLeft <= 2 && timeLeft > 0 && !this.crossfadeStarted) {
                                        this.crossfadeStarted = true;
                                        this.startAmbientCrossfade();
                                    }
                                }
                            });
                        }
                    } else {
                        clearInterval(fadeInterval);
                    }
                }, 100); // Crossfade every 100ms
            } catch (error) {
                // Graceful fallback
            }
        }
    },
    
    // Play death sound effect
    playDeathSound() {
        this.playSFX('death', 0.6);
    },
    
    // Play orb collection sound effect based on orb type
    playOrbCollection(orbType) {
        if (orbType === 'common') {
            this.playSFX('blue_orb', 0.4);
        } else if (orbType === 'golden') {
            this.playSFX('gold_orb', 0.4);
        } else {
            // For purple, green, white, red orbs - play generic collection sound
            this.playSFX('orb_collection', 0.3); // Slightly quieter as requested
        }
    },
    
    // Play orb usage sound effect
    playOrbUsage(orbType) {
        switch(orbType) {
            case 'regeneration':
                this.playSFX('green_orb', 0.4);
                break;
            case 'phase':
                this.playSFX('purple_orb', 0.4);
                break;
            case 'reveal':
                this.playSFX('white_orb', 0.4);
                break;
            case 'flame':
                this.playSFX('red_orb', 0.4);
                break;
            default:
                // Fallback for any other orb types
                this.playSFX('orb_collection', 0.3);
        }
    },
    
    // Play ghoul detection sound (one-time alert when ghoul spots player)
    playGhoulDetection(ghoulId) {
        if (!this.ghoulDetectionPlayed.has(ghoulId)) {
            this.ghoulDetectionPlayed.add(ghoulId);
            this.playSFX('ghoul_detection', 0.3); // Subtle volume
        }
    },
    
    
    // Update ghoul tension sounds based on their states
    updateGhoulTension(ghoulStates) {
        let hasStalkingGhouls = false;
        
        // Check for stalking ghouls and new detections
        ghoulStates.forEach(ghoulInfo => {
            if (ghoulInfo.state === 'stalking') {
                hasStalkingGhouls = true;
                
                // Play detection sound when ghoul first starts stalking
                if (ghoulInfo.justStartedStalking) {
                    this.playGhoulDetection(ghoulInfo.id);
                }
            }
        });
        
        // No stalking sound - only detection alerts
        
        // Clean up detection tracking for ghouls no longer nearby
        const currentGhoulIds = new Set(ghoulStates.map(g => g.id));
        for (const ghoulId of this.ghoulDetectionPlayed) {
            if (!currentGhoulIds.has(ghoulId)) {
                this.ghoulDetectionPlayed.delete(ghoulId);
            }
        }
    },
    
    // Schedule random wind sounds (only during gameplay)
    scheduleWindSounds() {
        const playWind = () => {
            // Only play wind if game is in playing state and not paused
            if (window.GameState && window.GameState.getGame) {
                const game = window.GameState.getGame();
                const isPaused = window.Game && window.Game.isPaused;
                
                if (game.state === 'playing' && !isPaused && !game.deathScreen && !game.gameOver && !game.victory) {
                    if (Math.random() < 0.1) { // 10% chance
                        const windSounds = ['wind1', 'wind2'];
                        const randomWind = windSounds[Math.floor(Math.random() * windSounds.length)];
                        this.playSFX(randomWind, 0.2);
                    }
                }
            }
            
            // Schedule next wind check (15-45 seconds)
            setTimeout(playWind, 15000 + Math.random() * 30000);
        };
        
        // Start first wind sound after 10-30 seconds
        setTimeout(playWind, 10000 + Math.random() * 20000);
    },
    
    // Play looping background music with crossfade for seamless loop
    playBackgroundLoop() {
        if (this.sounds.background && !this.currentBackground && this.enabled && !this.muted && this.audioUnlocked) {
            try {
                this.currentBackground = this.sounds.background.cloneNode();
                this.currentBackground.volume = 0.25 * this.volume; // Slightly louder than ambient
                this.currentBackground.loop = false; // Handle looping manually for crossfade
                
                this.currentBackground.preload = 'auto';
                
                // Handle crossfade before track ends (start crossfade 3 seconds before end for abrupt ending)
                this.currentBackground.addEventListener('timeupdate', () => {
                    if (this.currentBackground) {
                        const timeLeft = this.currentBackground.duration - this.currentBackground.currentTime;
                        // Start crossfade 3 seconds before end to handle abrupt ending
                        if (timeLeft <= 3 && timeLeft > 0 && !this.backgroundCrossfadeStarted) {
                            this.backgroundCrossfadeStarted = true;
                            this.startBackgroundCrossfade();
                        }
                    }
                });
                
                this.currentBackground.addEventListener('ended', () => {
                    this.currentBackground = null;
                    this.backgroundCrossfadeStarted = false;
                    // Start next loop if not paused
                    if (!this.isPaused) {
                        this.playBackgroundLoop();
                    }
                });
                
                this.currentBackground.play().catch(() => {});
            } catch (error) {
                // Graceful fallback
            }
        }
    },
    
    // Start crossfade for background music to handle abrupt ending
    startBackgroundCrossfade() {
        if (this.sounds.background && !this.nextBackground) {
            try {
                // Create next background sound
                this.nextBackground = this.sounds.background.cloneNode();
                this.nextBackground.volume = 0; // Start silent
                this.nextBackground.preload = 'auto';
                
                // Start playing the next sound
                this.nextBackground.play().catch(() => {});
                
                // Crossfade: fade out current, fade in next over 3 seconds
                const fadeStep = 0.02; // Smaller steps for smoother fade
                const fadeInterval = setInterval(() => {
                    if (this.currentBackground && this.nextBackground) {
                        // Fade out current
                        this.currentBackground.volume = Math.max(0, this.currentBackground.volume - fadeStep);
                        // Fade in next
                        this.nextBackground.volume = Math.min(0.25 * this.volume, this.nextBackground.volume + fadeStep);
                        
                        // When crossfade complete
                        if (this.currentBackground.volume <= 0 && this.nextBackground.volume >= 0.25 * this.volume) {
                            clearInterval(fadeInterval);
                            // Switch to next sound
                            if (this.currentBackground) {
                                this.currentBackground.pause();
                            }
                            this.currentBackground = this.nextBackground;
                            this.nextBackground = null;
                            this.backgroundCrossfadeStarted = false;
                            
                            // Setup next crossfade
                            this.currentBackground.addEventListener('timeupdate', () => {
                                if (this.currentBackground) {
                                    const timeLeft = this.currentBackground.duration - this.currentBackground.currentTime;
                                    if (timeLeft <= 3 && timeLeft > 0 && !this.backgroundCrossfadeStarted) {
                                        this.backgroundCrossfadeStarted = true;
                                        this.startBackgroundCrossfade();
                                    }
                                }
                            });
                        }
                    } else {
                        clearInterval(fadeInterval);
                    }
                }, 50); // Crossfade every 50ms for smooth transition
            } catch (error) {
                // Graceful fallback
            }
        }
    },
    
    
    // Set master volume
    setVolume(volume) {
        this.volume = Math.max(0, Math.min(1, volume));
        
        // Update current sound volumes
        if (this.currentAmbient) {
            this.currentAmbient.volume = this.ambientVolume * this.volume;
        }
        if (this.currentBackground) {
            this.currentBackground.volume = 0.25 * this.volume;
        }
    },
    
    // Pause all sounds (for menus)
    pauseAll() {
        if (this.currentAmbient) {
            this.currentAmbient.pause();
        }
        if (this.nextAmbient) {
            this.nextAmbient.pause();
        }
        if (this.currentBackground) {
            this.currentBackground.pause();
        }
        if (this.nextBackground) {
            this.nextBackground.pause();
        }
        this.isPaused = true;
    },
    
    // Resume all sounds (when returning to game)
    resumeAll() {
        if (!this.isPaused) return;
        if (!this.enabled || this.muted || !this.audioUnlocked) return;

        this.isPaused = false;

        // If sounds were playing, resume them
        if (this.currentAmbient) {
            this.currentAmbient.play().catch(() => {});
        }

        if (this.nextAmbient) {
            this.nextAmbient.play().catch(() => {});
        }

        if (this.currentBackground) {
            this.currentBackground.play().catch(() => {});
        }

        if (this.nextBackground) {
            this.nextBackground.play().catch(() => {});
        }
    },
    
    // Stop all sounds completely
    stopAll() {
        if (this.currentAmbient) {
            this.currentAmbient.pause();
            this.currentAmbient = null;
        }
        if (this.nextAmbient) {
            this.nextAmbient.pause();
            this.nextAmbient = null;
        }
        if (this.currentBackground) {
            this.currentBackground.pause();
            this.currentBackground = null;
        }
        if (this.nextBackground) {
            this.nextBackground.pause();
            this.nextBackground = null;
        }
        this.backgroundCrossfadeStarted = false;
        this.ghoulDetectionPlayed.clear();
        this.crossfadeStarted = false;
        this.isPaused = false;
    },
    
    // Toggle mute on/off
    toggleMute() {
        this.muted = !this.muted;
        if (this.muted) {
            this.pauseAll();
        } else if (this.enabled && this.audioUnlocked) {
            this.resumeAll();
        }
        return this.muted;
    },

    // Set enabled state (from settings)
    setEnabled(enabled) {
        this.enabled = enabled;
        if (!enabled) {
            this.stopAll();
        } else if (this.audioUnlocked && !this.muted) {
            // Restart ambient sounds if audio was previously unlocked
            if (!this.currentAmbient) {
                this.startAmbientSounds();
            }
        }
    },

    // Handle user interaction to enable audio (browsers require user gesture)
    handleUserInteraction() {
        if (!this.initialized) {
            this.init();
        }

        // Mark audio as unlocked by user gesture
        if (!this.audioUnlocked) {
            this.audioUnlocked = true;
        }

        // Start ambient sounds on first interaction if not already playing
        if (!this.currentAmbient && this.initialized && this.enabled && !this.muted) {
            this.startAmbientSounds();
        }
    }
};

// Make globally accessible
window.SoundManager = SoundManager;