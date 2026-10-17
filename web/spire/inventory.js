// Inventory Management
const InventoryManager = {
    // Use orb from specific slot
    useOrb(slot) {
        const game = GameState.getGame();
        const orb = game.player.inventory[slot];
        if (!orb) return;
        
        switch (orb) {
            case 'purple':
                game.player.powers.phase = CONFIG.GAME.PHASE_DURATION;
                Utils.showMessage(MESSAGES.STORY.PHASE_ACTIVATED, 2500);
                if (window.SoundManager) {
                    SoundManager.playOrbUsage('phase');
                }
                break;
                
            case 'green':
                game.player.powers.regeneration = CONFIG.GAME.REGENERATION_DURATION;
                Utils.showMessage(MESSAGES.STORY.REGENERATION_ACTIVATED, 2500);
                if (window.SoundManager) {
                    SoundManager.playOrbUsage('regeneration');
                }
                break;
                
            case 'white':
                game.player.powers.reveal = CONFIG.GAME.REVEAL_DURATION;
                Utils.showMessage(MESSAGES.STORY.REVEAL_ACTIVATED, 2500);
                if (window.SoundManager) {
                    SoundManager.playOrbUsage('reveal');
                }
                break;
                
            case 'red':
                // Manual use of lifeline
                game.player.light = 100;
                Utils.showMessage(MESSAGES.STORY.LIFELINE_USED, 3000);
                // Create revival effect
                Utils.createCircularParticles(game, game.player.x, game.player.y, '#f44336', 20, 6);
                if (window.SoundManager) {
                    SoundManager.playOrbUsage('flame');
                }
                break;
        }
        
        game.player.inventory[slot] = null;
        this.updateDisplay();
    },

    // Update inventory display
    updateDisplay() {
        const game = GameState.getGame();
        
        for (let i = 0; i < 3; i++) {
            const slot = document.getElementById(`slot${i + 1}`);
            const orb = game.player.inventory[i];
            
            slot.setAttribute('data-key', i + 1);
            
            if (orb && ORB_TYPES[orb]) {
                slot.textContent = ORB_TYPES[orb].symbol;
                slot.style.color = ORB_TYPES[orb].color;
                slot.style.borderColor = '#666';
                slot.title = ORB_TYPES[orb].description;
            } else {
                slot.textContent = '';
                slot.style.color = '';
                slot.style.borderColor = '#444';
                slot.title = '';
            }
        }

        // Update mobile orb buttons to match inventory
        if (typeof InputManager !== 'undefined' && InputManager.updateMobileOrbButtons) {
            InputManager.updateMobileOrbButtons();
        }
    },

    // Check if inventory has specific orb type
    hasOrb(orbType) {
        const game = GameState.getGame();
        return game.player.inventory.includes(orbType);
    },

    // Get count of specific orb type in inventory
    getOrbCount(orbType) {
        const game = GameState.getGame();
        return game.player.inventory.filter(item => item === orbType).length;
    },

    // Check if inventory is full
    isFull() {
        const game = GameState.getGame();
        return game.player.inventory.every(slot => slot !== null);
    },

    // Get first empty slot index
    getFirstEmptySlot() {
        const game = GameState.getGame();
        for (let i = 0; i < game.player.inventory.length; i++) {
            if (!game.player.inventory[i]) {
                return i;
            }
        }
        return -1; // No empty slots
    },

    // Clear all inventory slots
    clear() {
        const game = GameState.getGame();
        game.player.inventory = [null, null, null];
        this.updateDisplay();
    }
}; 