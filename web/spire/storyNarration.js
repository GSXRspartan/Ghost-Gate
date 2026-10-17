// Story Narration System - Text-based with manual navigation
const StoryNarration = {
    currentPart: 0,
    isPlaying: false,
    skipPressed: false,
    completed: false,
    transitioning: false,
    narrationTexts: [
        // Part 1
        "In the heart of an ancient desert, where the sun's rage turns sand to glass, lies a secret buried for millennia. The Spire of Shadows - a cursed monument that descends deep into the earth's forgotten depths.",

        // Part 2
        "You are an explorer, drawn by whispers of untold treasures and mystical orbs of power. But as you descended the spiral stairs, the entrance collapsed behind you. Now, only one path remains... down.",

        // Part 3
        "Light is life in these depths. The darkness hungers, and ancient guardians stalk the shadows. Gather the orbs, preserve your flame, and descend ever deeper. For at the bottom of this buried spire, legend speaks of the Ancient Pearl - your only escape from this tomb of shadows.",

        // Part 4
        "Remember, brave soul: when your light fades, the darkness consumes all. Begin your descent."
    ],

    // Start the story narration
    start() {
        if (this.isPlaying) return;

        this.isPlaying = true;
        this.currentPart = 0;
        this.skipPressed = false;
        this.completed = false;
        this.transitioning = false;

        // Create story overlay
        this.createStoryOverlay();

        // Show the first part after overlay fades in
        setTimeout(() => {
            this.showPart(0);
        }, 500);
    },

    // Create the black overlay with text and navigation
    createStoryOverlay() {
        // Create overlay container
        const overlay = document.createElement('div');
        overlay.id = 'storyOverlay';
        overlay.className = 'story-overlay';

        // Create text container
        const textContainer = document.createElement('div');
        textContainer.id = 'storyText';
        textContainer.className = 'story-text';

        // Create navigation container
        const navContainer = document.createElement('div');
        navContainer.id = 'storyNav';
        navContainer.className = 'story-nav';

        // Create Prev button
        const prevButton = document.createElement('button');
        prevButton.id = 'storyPrev';
        prevButton.textContent = 'Prev';
        prevButton.className = 'story-btn';
        this.attachButtonEvents(prevButton, () => this.goToPart(this.currentPart - 1));

        // Create Next / Begin button
        const nextButton = document.createElement('button');
        nextButton.id = 'storyNext';
        nextButton.textContent = 'Next';
        nextButton.className = 'story-btn';
        this.attachButtonEvents(nextButton, () => {
            if (this.currentPart >= this.narrationTexts.length - 1) {
                this.complete();
            } else {
                this.goToPart(this.currentPart + 1);
            }
        });

        // Create Skip button
        const skipButton = document.createElement('button');
        skipButton.id = 'storySkip';
        skipButton.textContent = 'Skip';
        skipButton.className = 'story-btn story-skip-btn';
        this.attachButtonEvents(skipButton, () => this.skip());

        navContainer.appendChild(prevButton);
        navContainer.appendChild(nextButton);

        overlay.appendChild(textContainer);
        overlay.appendChild(navContainer);
        overlay.appendChild(skipButton);
        document.body.appendChild(overlay);

        // Fade in overlay
        setTimeout(() => {
            overlay.style.opacity = '1';
        }, 100);

        // Listen for keyboard input
        this.keyHandler = (e) => {
            if (e.key === 'Escape') {
                e.stopImmediatePropagation();
                this.skip();
            } else if (e.key === 'ArrowRight' || e.key === 'Enter') {
                e.stopImmediatePropagation();
                if (this.currentPart >= this.narrationTexts.length - 1) {
                    this.complete();
                } else {
                    this.goToPart(this.currentPart + 1);
                }
            } else if (e.key === 'ArrowLeft') {
                e.stopImmediatePropagation();
                if (this.currentPart > 0) {
                    this.goToPart(this.currentPart - 1);
                }
            }
        };
        document.addEventListener('keydown', this.keyHandler);
    },

    // Helper to attach hover and click/touch events to a button
    attachButtonEvents(button, action) {
        button.addEventListener('mouseover', () => { button.style.opacity = '1'; });
        button.addEventListener('mouseout', () => { button.style.opacity = '0.7'; });
        button.addEventListener('click', (e) => { e.preventDefault(); action(); });
        button.addEventListener('touchend', (e) => {
            e.preventDefault();
            e.stopPropagation();
            action();
        }, { passive: false });
    },

    // Show a specific part with fade transition
    showPart(partIndex) {
        if (partIndex < 0 || partIndex >= this.narrationTexts.length) return;

        const textElement = document.getElementById('storyText');
        if (!textElement) return;

        this.currentPart = partIndex;

        // Update text content and fade in
        textElement.textContent = this.narrationTexts[this.currentPart];
        setTimeout(() => {
            textElement.style.opacity = '1';
        }, 100);

        // Update navigation buttons
        this.updateNavButtons();
    },

    // Navigate to a specific part with fade transition
    goToPart(partIndex) {
        if (this.transitioning) return;
        if (partIndex < 0 || partIndex >= this.narrationTexts.length) return;

        const textElement = document.getElementById('storyText');
        if (!textElement) return;

        this.transitioning = true;

        // Fade out current text and clear it immediately
        textElement.style.opacity = '0';
        textElement.textContent = '';

        setTimeout(() => {
            this.currentPart = partIndex;
            textElement.textContent = this.narrationTexts[this.currentPart];

            // Fade in new text
            setTimeout(() => {
                textElement.style.opacity = '1';
                this.transitioning = false;
            }, 50);

            // Update navigation buttons
            this.updateNavButtons();
        }, 900); // Wait for fade out to complete
    },

    // Update visibility and labels of navigation buttons
    updateNavButtons() {
        const prevButton = document.getElementById('storyPrev');
        const nextButton = document.getElementById('storyNext');
        const skipButton = document.getElementById('storySkip');

        if (prevButton) {
            // Hide Prev on first part
            prevButton.style.visibility = this.currentPart === 0 ? 'hidden' : 'visible';
        }

        if (nextButton) {
            const isLastPart = this.currentPart >= this.narrationTexts.length - 1;
            // Show "Begin" on last part, "Next" otherwise
            nextButton.textContent = isLastPart ? 'Begin' : 'Next';
        }

        if (skipButton) {
            // Hide Skip on last part since Begin serves the same purpose
            const isLastPart = this.currentPart >= this.narrationTexts.length - 1;
            skipButton.style.visibility = isLastPart ? 'hidden' : 'visible';
        }
    },

    // Skip the narration
    skip() {
        this.skipPressed = true;
        this.complete();
    },

    // Complete the narration and start the game
    complete() {
        // Guard against being called multiple times
        if (this.completed) return;
        this.completed = true;

        // Remove keyboard handler immediately to prevent re-entry
        document.removeEventListener('keydown', this.keyHandler);

        // Mark narration as no longer playing
        this.isPlaying = false;

        // Start the game BEFORE removing overlay so state is 'playing'
        // while the overlay fades out (prevents menu from rendering underneath)
        console.log('Story complete - calling GameState.startGame()...');

        // Call the official startGame method
        GameState.startGame();

        // Verify the game started
        const game = GameState.getGame();
        console.log('Game state after startGame:', game.state);

        // Start tutorial after game loads
        setTimeout(() => {
            if (typeof TutorialSystem !== 'undefined' && TutorialSystem.startTutorial) {
                TutorialSystem.startTutorial();
            }
        }, 500);

        // Now fade out and remove the overlay
        const overlay = document.getElementById('storyOverlay');
        if (overlay) {
            overlay.style.opacity = '0';
            // Immediately stop blocking touch events during fadeout
            overlay.style.pointerEvents = 'none';

            setTimeout(() => {
                overlay.remove();
            }, 1000);
        }
    }
};

// Make globally accessible
window.StoryNarration = StoryNarration;
