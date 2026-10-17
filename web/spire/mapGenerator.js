// Map Generation
const MapGenerator = {
    // Generate a new floor
    generateFloor(game, floorNum = null) {
        // Use the game's floor number if not provided
        if (floorNum === null) {
            floorNum = Math.abs(game.floor);
        } else {
            floorNum = Math.abs(floorNum);
        }
        
        // Clear existing floor data
        game.walls = [];
        game.orbs = [];
        game.ghouls = [];
        game.particles = [];
        game.explored.clear();
        
        const cellSize = CONFIG.MAP.CELL_SIZE;
        const grid = this.createGrid(game.mapWidth, game.mapHeight);
        
        // Generate maze structure
        this.generateMaze(grid, game.mapWidth, game.mapHeight);
        
        // Add rooms for variety
        this.addRooms(grid, game.mapWidth, game.mapHeight, floorNum);
        
        // Find empty spaces for entities
        const emptySpaces = this.findEmptySpaces(grid, game.mapWidth, game.mapHeight, cellSize);
        
        // Only place stairs if this is NOT the final level
        if (floorNum < CONFIG.GAME.MAX_FLOORS) {
            this.placeStairs(game, emptySpaces);
            // Clear walls around stairs position (3x3 area)
            if (game.stairs) {
                const stairGridX = Math.floor(game.stairs.x / cellSize);
                const stairGridY = Math.floor(game.stairs.y / cellSize);
                
                // Clear a 3x3 area around the stairs
                for (let dy = -1; dy <= 1; dy++) {
                    for (let dx = -1; dx <= 1; dx++) {
                        const clearX = stairGridX + dx;
                        const clearY = stairGridY + dy;
                        if (clearX >= 0 && clearX < game.mapWidth && 
                            clearY >= 0 && clearY < game.mapHeight) {
                            grid[clearY][clearX] = 0; // Clear wall
                        }
                    }
                }
            }
        } else {
            // Final level has no stairs - only the Pearl can complete the game
            console.log(`🔮 Final level ${floorNum}: No stairs placed - Pearl is the only exit`);
            game.stairs = null; // Ensure no stairs object exists
        }
        
        // Convert grid to walls (after stairs area is cleared)
        this.createWalls(grid, game, cellSize);
        
        // Place game entities
        this.placeDeathMarkers(game, floorNum);
        this.placeOrbs(game, emptySpaces, floorNum);
        this.placeGhouls(game, emptySpaces, floorNum);
        
        // Reset player position using the same empty spaces
        this.resetPlayerPosition(game, cellSize, emptySpaces);
        
        Utils.updateCamera(game, true);
        
        console.log('Floor generated:', floorNum, 'Ghouls placed:', game.ghouls.length, 'Stairs at:', game.stairs);
    },

    // Create initial grid
    createGrid(width, height) {
        const grid = [];
        for (let y = 0; y < height; y++) {
            grid[y] = [];
            for (let x = 0; x < width; x++) {
                grid[y][x] = 1; // 1 = wall, 0 = empty
            }
        }
        return grid;
    },

    // Generate maze using recursive backtracking
    generateMaze(grid, width, height) {
        const stack = [];
        // Start from position (2,2) instead of (1,1) to create 2-cell border
        const startCell = { x: 2, y: height - 3 };
        grid[startCell.y][startCell.x] = 0;
        stack.push(startCell);
        
        const directions = [
            { dx: 0, dy: -2 },  // Up
            { dx: 2, dy: 0 },   // Right
            { dx: 0, dy: 2 },   // Down
            { dx: -2, dy: 0 }   // Left
        ];
        
        while (stack.length > 0) {
            const current = stack[stack.length - 1];
            const neighbors = [];
            
            // Find valid neighbors - keep 2-cell border by using bounds (2, width-3) and (2, height-3)
            for (const dir of directions) {
                const nx = current.x + dir.dx;
                const ny = current.y + dir.dy;
                
                if (nx >= 2 && nx <= width - 3 && ny >= 2 && ny <= height - 3 && grid[ny][nx] === 1) {
                    neighbors.push({ x: nx, y: ny, dx: dir.dx / 2, dy: dir.dy / 2 });
                }
            }
            
            if (neighbors.length > 0) {
                const next = Utils.randomElement(neighbors);
                grid[next.y][next.x] = 0;
                grid[current.y + next.dy][current.x + next.dx] = 0;
                stack.push(next);
            } else {
                stack.pop();
            }
        }
    },

    // Add rooms to make the maze more interesting
    addRooms(grid, width, height, floorNum) {
        const numRooms = 3 + Math.floor(floorNum / 10);
        
        for (let i = 0; i < numRooms; i++) {
            // Keep rooms within the 2-cell border
            const roomX = 3 + Math.floor(Math.random() * (width - 8));
            const roomY = 3 + Math.floor(Math.random() * (height - 8));
            const roomW = 2 + Math.floor(Math.random() * 3);
            const roomH = 2 + Math.floor(Math.random() * 3);
            
            // Create room
            for (let ry = 0; ry < roomH; ry++) {
                for (let rx = 0; rx < roomW; rx++) {
                    if (roomX + rx < width - 2 && roomY + ry < height - 2) {
                        grid[roomY + ry][roomX + rx] = 0;
                    }
                }
            }
        }
    },

    // Convert grid to wall objects
    createWalls(grid, game, cellSize) {
        for (let y = 0; y < game.mapHeight; y++) {
            for (let x = 0; x < game.mapWidth; x++) {
                if (grid[y][x] === 1) {
                    game.walls.push({
                        x: x * cellSize + cellSize / 2,
                        y: y * cellSize + cellSize / 2
                    });
                }
            }
        }
    },

    // Find all empty spaces in the grid
    findEmptySpaces(grid, width, height, cellSize) {
        const emptySpaces = [];
        // Use 2-cell border: start from 2, end at width-3 and height-3
        for (let y = 2; y < height - 2; y++) {
            for (let x = 2; x < width - 2; x++) {
                if (grid[y][x] === 0) {
                    emptySpaces.push({ 
                        x: x * cellSize + cellSize / 2, 
                        y: y * cellSize + cellSize / 2 
                    });
                }
            }
        }
        return emptySpaces;
    },

    // Place death markers from previous attempts
    placeDeathMarkers(game, floorNum) {
        // Ensure deathMarkers array exists
        if (!game.player.deathMarkers || !Array.isArray(game.player.deathMarkers)) {
            console.warn('Player deathMarkers array not initialized, skipping death marker placement');
            return;
        }
        
        for (const marker of game.player.deathMarkers) {
            if (marker.floor === floorNum) {
                game.orbs.push({
                    x: marker.x,
                    y: marker.y,
                    type: 'wisp',
                    collected: false,
                    pulse: 0,
                    size: 8, // Add size property for collision detection
                    color: ORB_TYPES.wisp.color
                });
            }
        }
    },

    // Place orbs on the floor
    placeOrbs(game, emptySpaces, floorNum) {
        floorNum = floorNum != null ? Math.abs(floorNum) : Math.abs(game.floor);
        const availableSpaces = [...emptySpaces];
        
        // Special handling for final level - place only the Pearl
        if (floorNum === CONFIG.GAME.MAX_FLOORS) {
            // Find the center of the map for Pearl placement
            const centerX = (game.mapWidth * (CONFIG.MAP.CELL_SIZE || 40)) / 2;
            const centerY = (game.mapHeight * (CONFIG.MAP.CELL_SIZE || 40)) / 2;
            
            // Find the space closest to center
            let bestSpace = availableSpaces[0];
            let minDistance = Infinity;
            
            for (const space of availableSpaces) {
                const distance = Math.sqrt(
                    Math.pow(space.x - centerX, 2) + Math.pow(space.y - centerY, 2)
                );
                if (distance < minDistance) {
                    minDistance = distance;
                    bestSpace = space;
                }
            }
            
            // Place the Ancient Pearl at the center
            game.orbs.push({
                x: bestSpace.x,
                y: bestSpace.y,
                type: 'pearl',
                collected: false,
                pulse: Math.random() * Math.PI * 2,
                size: 12, // Larger size for the Pearl
                color: ORB_TYPES.pearl.color,
                isVictoryOrb: true
            });
            
            console.log(`🔮 Ancient Pearl placed at center position (${bestSpace.x}, ${bestSpace.y})`);
            return; // Only place the Pearl on final level
        }
        
        // Normal orb placement for other levels
        const orbCount = Math.min(5 + Math.floor(floorNum / 5), 10);
        
        // Place guaranteed introduction orb if this is a new orb introduction floor
        this.placeIntroductionOrb(game, availableSpaces, floorNum);
        
        for (let i = 0; i < Math.min(orbCount, availableSpaces.length - 2); i++) {
            const idx = Math.floor(Math.random() * availableSpaces.length);
            const space = availableSpaces.splice(idx, 1)[0];
            
            const orbType = this.getRandomOrbType(floorNum);
            
            game.orbs.push({
                x: space.x,
                y: space.y,
                type: orbType,
                collected: false,
                pulse: Math.random() * Math.PI * 2,
                size: 8, // Add size property for collision detection
                color: ORB_TYPES[orbType].color
            });
        }
    },

    // Place a guaranteed introduction orb near the player when new orb types are introduced
    placeIntroductionOrb(game, availableSpaces, floorNum) {
        let introOrbType = null;
        
        // Determine if this floor introduces a new orb type
        if (floorNum === 1) {
            introOrbType = 'common'; // Blue orb
        } else if (floorNum === 2) {
            introOrbType = 'golden'; // Golden/Yellow orb
        } else if (floorNum === 6) {
            introOrbType = 'purple';
        } else if (floorNum === 11) {
            introOrbType = 'green';
        } else if (floorNum === 16) {
            introOrbType = 'white';
        } else if (floorNum === 21) {
            introOrbType = 'red';
        }
        
        if (introOrbType && availableSpaces.length > 0) {
            // Find the player's starting position (we know it will be in bottom-left)
            const playerStartX = 2 * CONFIG.MAP.CELL_SIZE + CONFIG.MAP.CELL_SIZE / 2;
            const playerStartY = (game.mapHeight - 3) * CONFIG.MAP.CELL_SIZE + CONFIG.MAP.CELL_SIZE / 2;
            
            // Find empty spaces near the player's starting area
            const nearbySpaces = availableSpaces.filter(space => {
                const distance = Math.sqrt(
                    Math.pow(space.x - playerStartX, 2) + 
                    Math.pow(space.y - playerStartY, 2)
                );
                // Within about 3-5 cells of the player start
                return distance >= 80 && distance <= 200;
            });
            
            // If we have nearby spaces, use one of them, otherwise use any available space
            const targetSpaces = nearbySpaces.length > 0 ? nearbySpaces : availableSpaces;
            
            if (targetSpaces.length > 0) {
                // Choose the space closest to being directly in front of the player
                // (slightly up and to the right from bottom-left start)
                let bestSpace = targetSpaces[0];
                let bestScore = -Infinity;
                
                for (const space of targetSpaces) {
                    // Prefer spaces that are up and to the right of player start
                    const deltaX = space.x - playerStartX;
                    const deltaY = playerStartY - space.y; // Y is inverted (up is negative)
                    
                    // Score based on being in the "forward" direction from player start
                    const score = deltaX + deltaY - Math.abs(deltaX - deltaY) * 0.5;
                    
                    if (score > bestScore) {
                        bestScore = score;
                        bestSpace = space;
                    }
                }
                
                // Remove the chosen space from available spaces
                const spaceIndex = availableSpaces.indexOf(bestSpace);
                if (spaceIndex !== -1) {
                    availableSpaces.splice(spaceIndex, 1);
                }
                
                // Place the introduction orb
                game.orbs.push({
                    x: bestSpace.x,
                    y: bestSpace.y,
                    type: introOrbType,
                    collected: false,
                    pulse: Math.random() * Math.PI * 2,
                    size: 8,
                    color: ORB_TYPES[introOrbType].color,
                    isIntroduction: true // Mark this as an introduction orb for potential special effects
                });
                
                console.log(`Placed introduction ${introOrbType} orb at floor ${floorNum} near player start`);
            }
        }
    },

    // Get random orb type based on floor progression and rarity
    getRandomOrbType(floorNum) {
        // Progressive orb introduction:
        // Floor 1: Blue (common) orbs only
        // Floor 2+: Add Golden orbs
        // Floor 6+: Add Purple orbs
        // Floor 11+: Add Green orbs  
        // Floor 16+: Add White orbs
        // Floor 21+: Add Red orbs
        // Floor 50: Ancient Pearl (victory orb)
        // Light Wisp: Only appears as death markers (handled separately)
        
        // Special case: Final floor gets the Ancient Pearl
        if (floorNum === CONFIG.GAME.MAX_FLOORS) {
            return 'pearl';
        }
        
        const availableOrbs = [];
        
        // Blue orbs available from floor 1
        if (floorNum >= 1) {
            availableOrbs.push({ type: 'common', weight: 30 }); // Blue orb - most common
        }
        
        // Golden orbs introduced at floor 2
        if (floorNum >= 2) {
            availableOrbs.push({ type: 'golden', weight: 15 }); // Golden orb - common
        }
        
        // Purple orbs introduced at floor 6
        if (floorNum >= 6) {
            availableOrbs.push({ type: 'purple', weight: 15 });
        }
        
        // Green orbs introduced at floor 11
        if (floorNum >= 11) {
            availableOrbs.push({ type: 'green', weight: 15 });
        }
        
        // White orbs introduced at floor 16
        if (floorNum >= 16) {
            availableOrbs.push({ type: 'white', weight: 10 });
        }
        
        // Red orbs introduced at floor 21 (very rare)
        if (floorNum >= 21) {
            availableOrbs.push({ type: 'red', weight: 5 });
        }
        
        // Calculate total weight
        const totalWeight = availableOrbs.reduce((sum, orb) => sum + orb.weight, 0);
        
        // Select random orb based on weighted probability
        let randomValue = Math.random() * totalWeight;
        
        for (const orb of availableOrbs) {
            randomValue -= orb.weight;
            if (randomValue <= 0) {
                return orb.type;
            }
        }
        
        // Fallback to common orb if something goes wrong
        return 'common';
    },

    // Place ghouls on the floor
    placeGhouls(game, emptySpaces, floorNum) {
        const ghoulCount = 3 + Math.floor(floorNum / 2);
        const availableSpaces = [...emptySpaces];
        
        for (let i = 0; i < Math.min(ghoulCount, availableSpaces.length); i++) {
            const idx = Math.floor(Math.random() * availableSpaces.length);
            const space = availableSpaces.splice(idx, 1)[0];
            
            game.ghouls.push({
                x: space.x,
                y: space.y,
                speed: 1.0 + Math.random() * 0.6,
                state: 'patrol',
                size: 15, // Add size property for collision detection
                patrolTarget: { 
                    x: Math.random() * game.mapWidth * CONFIG.MAP.CELL_SIZE, 
                    y: Math.random() * game.mapHeight * CONFIG.MAP.CELL_SIZE 
                }
            });
        }
    },

    // Place stairs to next floor with randomized positioning
    placeStairs(game, emptySpaces) {
        if (emptySpaces.length === 0) {
            // Fallback position if no empty spaces
            game.stairs = {
                x: (game.mapWidth - 2) * CONFIG.MAP.CELL_SIZE,
                y: 2 * CONFIG.MAP.CELL_SIZE
            };
            return;
        }

        // Filter out spaces that are too close to the player spawn area (bottom-left)
        const cellSize = CONFIG.MAP.CELL_SIZE || 40;
        const validStairSpaces = emptySpaces.filter(space => {
            const gridX = Math.floor((space.x - cellSize/2) / cellSize);
            const gridY = Math.floor((space.y - cellSize/2) / cellSize);
            
            // Exclude bottom-left quadrant to avoid placing stairs too close to spawn
            const isBottomLeft = gridX < game.mapWidth / 2 && gridY >= game.mapHeight / 2;
            
            // Also ensure minimum distance from typical spawn position (2, mapHeight-3)
            const spawnX = 2;
            const spawnY = game.mapHeight - 3;
            const distanceFromSpawn = Math.abs(gridX - spawnX) + Math.abs(gridY - spawnY);
            const minDistance = 8; // Minimum Manhattan distance from spawn
            
            return !isBottomLeft && distanceFromSpawn >= minDistance;
        });
        
        // If we have valid spaces away from spawn, use those
        if (validStairSpaces.length > 0) {
            // Randomize exit position from valid spaces
            const stairSpace = Utils.randomElement(validStairSpaces);
            game.stairs = { x: stairSpace.x, y: stairSpace.y };
            console.log(`🚪 Exit placed at grid position (${Math.floor((stairSpace.x - cellSize/2) / cellSize)}, ${Math.floor((stairSpace.y - cellSize/2) / cellSize)})`);
        } else {
            // Fallback: use any space that's not in the immediate spawn area
            const fallbackSpaces = emptySpaces.filter(space => {
                const gridX = Math.floor((space.x - cellSize/2) / cellSize);
                const gridY = Math.floor((space.y - cellSize/2) / cellSize);
                
                // Just avoid the immediate spawn corner (3x3 area around spawn)
                const spawnX = 2;
                const spawnY = game.mapHeight - 3;
                const isNearSpawn = Math.abs(gridX - spawnX) <= 1 && Math.abs(gridY - spawnY) <= 1;
                
                return !isNearSpawn;
            });
            
            if (fallbackSpaces.length > 0) {
                const stairSpace = Utils.randomElement(fallbackSpaces);
                game.stairs = { x: stairSpace.x, y: stairSpace.y };
                console.log(`🚪 Exit placed at fallback position (${Math.floor((stairSpace.x - cellSize/2) / cellSize)}, ${Math.floor((stairSpace.y - cellSize/2) / cellSize)})`);
            } else {
                // Last resort: random position
                const stairSpace = Utils.randomElement(emptySpaces);
                game.stairs = { x: stairSpace.x, y: stairSpace.y };
                console.log(`🚪 Exit placed at random position (emergency fallback)`);
            }
        }
    },

    // Reset player to starting position
    resetPlayerPosition(game, cellSize, emptySpaces) {
        // Always place player in bottom-left area, but find a safe empty space
        if (emptySpaces.length > 0) {
            // Filter empty spaces to only those in the bottom-left quadrant
            const bottomLeftSpaces = emptySpaces.filter(space => {
                const gridX = Math.floor((space.x - cellSize/2) / cellSize);
                const gridY = Math.floor((space.y - cellSize/2) / cellSize);
                
                // Bottom-left quadrant: left half of map width, bottom half of map height
                return gridX < game.mapWidth / 2 && gridY >= game.mapHeight / 2;
            });
            
            if (bottomLeftSpaces.length > 0) {
                // Find the space closest to bottom-left corner (2, mapHeight-3)
                const targetX = 2;
                const targetY = game.mapHeight - 3;
                
                let bestSpace = bottomLeftSpaces[0];
                let bestDistance = Infinity;
                
                for (const space of bottomLeftSpaces) {
                    const gridX = Math.floor((space.x - cellSize/2) / cellSize);
                    const gridY = Math.floor((space.y - cellSize/2) / cellSize);
                    const distance = Math.abs(gridX - targetX) + Math.abs(gridY - targetY);
                    
                    if (distance < bestDistance) {
                        bestDistance = distance;
                        bestSpace = space;
                    }
                }
                
                game.player.x = bestSpace.x;
                game.player.y = bestSpace.y;
            } else {
                // Fallback: find any empty space in the left half of the map
                const leftHalfSpaces = emptySpaces.filter(space => {
                    const gridX = Math.floor((space.x - cellSize/2) / cellSize);
                    return gridX < game.mapWidth / 2;
                });
                
                if (leftHalfSpaces.length > 0) {
                    game.player.x = leftHalfSpaces[0].x;
                    game.player.y = leftHalfSpaces[0].y;
                } else {
                    // Final fallback: use any empty space
                    game.player.x = emptySpaces[0].x;
                    game.player.y = emptySpaces[0].y;
                }
            }
        } else {
            // Ultimate fallback to original fixed position if no empty spaces found (shouldn't happen)
            this.setFallbackPosition(game, cellSize);
        }
        
        // Final validation - ensure player position is safe
        if (!this.validateSpawnPosition(game, game.player.x, game.player.y)) {
            console.warn('⚠️ Player spawn position validation failed, attempting emergency repositioning');
            this.emergencyRepositioning(game, cellSize);
        }
        
        console.log(`✅ Player positioned at (${game.player.x}, ${game.player.y})`);
    },
    
    // Validate that a spawn position is safe (no wall collisions)
    // Uses AABB collision consistent with GameLogic.isValidPosition
    validateSpawnPosition(game, x, y) {
        // Check bounds
        const mapWidth = game.mapWidth * (CONFIG.MAP.CELL_SIZE || 40);
        const mapHeight = game.mapHeight * (CONFIG.MAP.CELL_SIZE || 40);
        const margin = 20;

        if (x < margin || x > mapWidth - margin || y < margin || y > mapHeight - margin) {
            return false;
        }

        // Check wall collisions using AABB (circle vs rectangle)
        const playerRadius = game.player.size || 15;
        const halfCell = (CONFIG.MAP.CELL_SIZE || 40) / 2;

        for (const wall of game.walls) {
            // Find closest point on wall rectangle to the test position
            const closestX = Math.max(wall.x - halfCell, Math.min(x, wall.x + halfCell));
            const closestY = Math.max(wall.y - halfCell, Math.min(y, wall.y + halfCell));

            const dx = x - closestX;
            const dy = y - closestY;

            if (dx * dx + dy * dy < playerRadius * playerRadius) {
                return false;
            }
        }

        return true;
    },
    
    // Find a safe spawn position from a list of candidates
    findSafeSpawnPosition(game, candidates) {
        for (const candidate of candidates) {
            if (this.validateSpawnPosition(game, candidate.x, candidate.y)) {
                return candidate;
            }
        }
        return null;
    },
    
    // Set fallback position with validation
    setFallbackPosition(game, cellSize) {
        const fallbackX = 2 * cellSize + cellSize / 2;
        const fallbackY = (game.mapHeight - 3) * cellSize + cellSize / 2;
        
        if (this.validateSpawnPosition(game, fallbackX, fallbackY)) {
            game.player.x = fallbackX;
            game.player.y = fallbackY;
        } else {
            this.emergencyRepositioning(game, cellSize);
        }
    },
    
    // Emergency repositioning when all else fails
    emergencyRepositioning(game, cellSize) {
        console.warn('🚨 Emergency repositioning triggered');
        
        // Try positions in a spiral pattern from the center
        const centerX = (game.mapWidth * cellSize) / 2;
        const centerY = (game.mapHeight * cellSize) / 2;
        
        for (let radius = cellSize; radius < game.mapWidth * cellSize / 2; radius += cellSize) {
            for (let angle = 0; angle < 360; angle += 45) {
                const x = centerX + radius * Math.cos(angle * Math.PI / 180);
                const y = centerY + radius * Math.sin(angle * Math.PI / 180);
                
                if (this.validateSpawnPosition(game, x, y)) {
                    game.player.x = x;
                    game.player.y = y;
                    console.log(`🔧 Emergency position found at (${x}, ${y})`);
                    return;
                }
            }
        }
        
        // If we get here, something is very wrong - use center position
        console.error('🚨 Critical: Could not find any safe spawn position');
        game.player.x = centerX;
        game.player.y = centerY;
    }
}; 