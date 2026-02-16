require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const User = require('./models/User'); 

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'exodus_prime_secret_key_change_me';

// --- SECURITY MIDDLEWARE (HELMET) ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'"],
            "script-src-attr": ["'unsafe-inline'"],
            "img-src": ["'self'", "data:", "*"],
        },
    },
}));

// --- МОДЕЛЬ ДЛЯ ЛОГОВ ---
const ActionLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
    username: { type: String },
    action: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    ip: { type: String },
    details: { type: Object }
});
const ActionLog = mongoose.model('ActionLog', ActionLogSchema);

// --- HELPER: FIRE AND FORGET LOGGING ---
// Мы не ждем выполнения этой функции в основном потоке
const logAction = async (action, userId, username, req, details = {}) => {
    // Получаем IP сразу, так как req может быть очищен garbage collector'ом
    // если ответ уйдет очень быстро (редкий кейс, но хорошая практика)
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

    try {
        const newLog = new ActionLog({
            action,
            userId,
            username,
            ip,
            details
        });
        await newLog.save();
        // Опционально: можно убрать console.log для продакшена, чтобы не засорять вывод
        console.log(`[LOG] Action: ${action} | User: ${username || 'Guest'}`); 
    } catch (err) {
        // Важно: так как мы не используем await при вызове, ошибки здесь
        // не должны всплывать выше, иначе будет UnhandledPromiseRejection
        console.error('Logging Error (Background):', err.message);
    }
};

// --- RATE LIMITING ---
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: { msg: 'Too many requests from this IP, please try again later' }
});
app.use(globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 20, 
    message: { msg: 'Too many login attempts, please try again later' }
});
app.use('/api/auth', authLimiter); 

// Middleware
app.use(express.json({ limit: '500kb' }));
app.use(cors());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/exodus_prime')
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error('MongoDB Error:', err));

// --- AUTH MIDDLEWARE ---
const auth = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) return res.status(401).json({ msg: 'No token, authorization denied' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded.user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// --- ROUTES ---

// 1. Register
app.post('/api/auth/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await User.findOne({ username });
        if (user) {
            // FIRE AND FORGET: Нет await
            logAction('REGISTER_FAIL_EXISTS', null, username, req);
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({ username, password });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        user.gameState = {}; 
        
        await user.save();

        // FIRE AND FORGET: Нет await
        logAction('REGISTER_SUCCESS', user.id, username, req);

        const payload = { user: { id: user.id } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// 2. Login
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        let user = await User.findOne({ username });
        if (!user) {
            // FIRE AND FORGET: Нет await
            logAction('LOGIN_FAIL_USER', null, username, req);
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            // FIRE AND FORGET: Нет await
            logAction('LOGIN_FAIL_PASSWORD', user.id, username, req);
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        // FIRE AND FORGET: Нет await
        logAction('LOGIN_SUCCESS', user.id, username, req);

        const payload = { user: { id: user.id } };
        jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
            if (err) throw err;
            res.json({ token, gameState: user.gameState });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// 3. Load Game (Protected)
app.get('/api/game/load', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');

        // FIRE AND FORGET: Нет await (клиент получит сохранение быстрее)
        logAction('GAME_LOAD', user.id, user.username, req);

        res.setHeader('x-server-time', Date.now());
        res.json(user.gameState);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// 4. Save Game (Protected) with Anti-Cheat
app.post('/api/game/save', auth, async (req, res) => {
    try {
        const { gameState, clientTime } = req.body;
        const newState = gameState; 
        const serverNow = Date.now();

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        const oldState = user.gameState || {}; 
        let timeSinceLastSave = 0;

        // --- ANTI-CHEAT CHECKS ---

        // 1. Time Check
        if (clientTime) {
            const timeDifference = Math.abs(serverNow - clientTime);
            const maxAllowedDifference = 5 * 60 * 1000; 

            if (timeDifference > maxAllowedDifference) {
                // FIRE AND FORGET
                logAction('CHEAT_ATTEMPT_TIME', user.id, user.username, req, { clientTime, serverNow });
                return res.status(400).json({ msg: 'Time manipulation detected or device clock out of sync. Please sync your clock.' });
            }
        }

        // 2. Frequency Check
        if (user.lastSaveTime) {
            timeSinceLastSave = serverNow - new Date(user.lastSaveTime).getTime();
            if (timeSinceLastSave < 1000) { 
                return res.status(429).json({ msg: 'Saving too frequently. Slow down.' });
            }
        } else {
            timeSinceLastSave = 30000;
        }

        // 3. Power & Battery Check
        if (newState.power && newState.power.batteries) {
            const batteries = newState.power.batteries;
            const BATTERY_CAP = 33.33;
            const MAX_ALLOWED_CHARGE = BATTERY_CAP + 2.0; 
            const MAX_GEN_PER_SEC = 0.5; 
            
            let totalNewCharge = 0;
            let totalOldCharge = 0;

            for (let bat of batteries) {
                if (bat.charge > MAX_ALLOWED_CHARGE) {
                    // FIRE AND FORGET
                    logAction('CHEAT_BATTERY_OVERCHARGE', user.id, user.username, req, {
                        batId: bat.id,
                        charge: bat.charge,
                        limit: BATTERY_CAP
                    });
                    return res.status(400).json({ msg: 'Game integrity error: Battery charge exceeds physical capacity.' });
                }
                totalNewCharge += (bat.charge || 0);
            }

            if (oldState.power && oldState.power.batteries) {
                oldState.power.batteries.forEach(b => totalOldCharge += (b.charge || 0));
                
                const chargeDelta = totalNewCharge - totalOldCharge;
                const elapsedSeconds = timeSinceLastSave / 1000;
                const maxPossibleGain = (elapsedSeconds * MAX_GEN_PER_SEC) + 10.0; 

                if (chargeDelta > maxPossibleGain) {
                    // FIRE AND FORGET
                      logAction('CHEAT_POWER_GENERATION', user.id, user.username, req, {
                        delta: chargeDelta,
                        maxAllowed: maxPossibleGain,
                        elapsedTime: elapsedSeconds
                    });
                    return res.status(400).json({ msg: 'Game integrity error: Abnormal power generation detected.' });
                }
            }
        }

        // 4. Stamina Check
        if (newState.stamina) {
            const MAX_STAMINA_LIMIT = 100;

            if (newState.stamina.val > MAX_STAMINA_LIMIT || newState.stamina.max > MAX_STAMINA_LIMIT) {
                // FIRE AND FORGET
                logAction('CHEAT_STAMINA_CAP', user.id, user.username, req, { 
                    val: newState.stamina.val, 
                    max: newState.stamina.max 
                });
                return res.status(400).json({ msg: 'Game integrity error: Stamina values exceed allowable limits.' });
            }

            if (oldState.stamina && oldState.inventory && newState.inventory) {
                const oldVal = parseFloat(oldState.stamina.val) || 0;
                const newVal = parseFloat(newState.stamina.val) || 0;
                const staminaDiff = newVal - oldVal;

                if (staminaDiff > 0) {
                    const foodItems = ['Snack', 'Meal', 'Feast', 'Energy Bar', 'Energy Isotonic'];
                    let hasConsumedFood = false;

                    for (const item of foodItems) {
                        const oldQty = oldState.inventory[item] || 0;
                        const newQty = newState.inventory[item] || 0;
                        if (newQty < oldQty) {
                            hasConsumedFood = true;
                            break;
                        }
                    }

                    if (!hasConsumedFood && staminaDiff > 0.5) {
                        // FIRE AND FORGET
                        logAction('CHEAT_STAMINA_NO_CONSUME', user.id, user.username, req, { 
                            oldStamina: oldVal, 
                            newStamina: newVal,
                            diff: staminaDiff,
                            details: "Stamina increased without inventory consumption"
                        });
                        return res.status(400).json({ msg: 'Game integrity error: Stamina increased without food consumption.' });
                    }
                }
            }
        }

        // 5. Scavenging & Resources Check
        let dScrap = 0;
        
        if (oldState.inventory && newState.inventory) {
            const dRegolith = (newState.inventory.Regolith || 0) - (oldState.inventory.Regolith || 0);
            const dIce = (newState.inventory["Ice water"] || 0) - (oldState.inventory["Ice water"] || 0);
            dScrap = (newState.inventory.Scrap || 0) - (oldState.inventory.Scrap || 0);

            const SCAV_DURATION_MS = 5000;
            const MAX_REG_PER_SCAV = 10;
            const MAX_ICE_PER_SCAV = 3;
            const MAX_SCRAP_PER_SCAV = 10;

            const maxActionsPossible = Math.ceil(timeSinceLastSave / SCAV_DURATION_MS) + 2;
            const SHIP_BUFFER = 100;

            if (dScrap > (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20) {
                // FIRE AND FORGET
                  logAction('CHEAT_RESOURCE_SCRAP', user.id, user.username, req, { 
                    delta: dScrap, 
                    maxAllowed: (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20,
                    timeElapsed: timeSinceLastSave 
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Scrap increase detected.' });
            }

            if (dIce > ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)) {
                // FIRE AND FORGET
                  logAction('CHEAT_RESOURCE_ICE', user.id, user.username, req, { 
                    delta: dIce,
                    maxAllowed: ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Ice increase detected.' });
            }

            if (dRegolith > ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)) {
                // FIRE AND FORGET
                  logAction('CHEAT_RESOURCE_REGOLITH', user.id, user.username, req, { 
                    delta: dRegolith, 
                    maxAllowed: ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Regolith increase detected.' });
            }

            // 6. Food & Harvest Check
            const dSnack = (newState.inventory.Snack || 0) - (oldState.inventory.Snack || 0);
            const dMeal = (newState.inventory.Meal || 0) - (oldState.inventory.Meal || 0);
            const dFeast = (newState.inventory.Feast || 0) - (oldState.inventory.Feast || 0);
            const dIsotonic = (newState.inventory["Energy Isotonic"] || 0) - (oldState.inventory["Energy Isotonic"] || 0);
            
            const dFood = (newState.inventory.Food || 0) - (oldState.inventory.Food || 0);
            const dAmaranth = (newState.inventory.Amaranth || 0) - (oldState.inventory.Amaranth || 0);
            const dGuarana = (newState.inventory.Guarana || 0) - (oldState.inventory.Guarana || 0);

            let impliedFoodCost = 0;
            if (dSnack > 0) impliedFoodCost += dSnack * 30; 
            if (dMeal > 0) impliedFoodCost += dMeal * 60;    
            if (dFeast > 0) impliedFoodCost += dFeast * 90; 

            const MAX_FOOD_HARVEST_BUFFER = 1200; 
            
            if ((dFood + impliedFoodCost) > MAX_FOOD_HARVEST_BUFFER) {
                // FIRE AND FORGET
                logAction('CHEAT_RESOURCE_FOOD_BALANCE', user.id, user.username, req, {
                    dFood, 
                    impliedFoodCost, 
                    netGain: dFood + impliedFoodCost,
                    limit: MAX_FOOD_HARVEST_BUFFER
                });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Food/Ration production balance.' });
            }

            if (dAmaranth > 300) {
                // FIRE AND FORGET
                logAction('CHEAT_CROP_AMARANTH', user.id, user.username, req, { delta: dAmaranth });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Amaranth harvest.' });
            }
            if (dGuarana > 400) {
                // FIRE AND FORGET
                logAction('CHEAT_CROP_GUARANA', user.id, user.username, req, { delta: dGuarana });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Guarana harvest.' });
            }

            if (dIsotonic > 25) {
                // FIRE AND FORGET
                logAction('CHEAT_RESOURCE_ISOTONIC', user.id, user.username, req, { delta: dIsotonic });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Energy Isotonic increase.' });
            }
            
            // 7. Seeds Check
            const seedTypes = ['Seeds: Sprouts', 'Seeds: Potato', 'Seeds: Maize', 'Seeds: Amaranth', 'Seeds: Guarana'];
            const MAX_SEEDS_DROP_BUFFER = 50;

            for (const seedName of seedTypes) {
                const oldSeedQty = oldState.inventory[seedName] || 0;
                const newSeedQty = newState.inventory[seedName] || 0;
                const dSeed = newSeedQty - oldSeedQty;

                if (dSeed > 0) {
                    if (dScrap >= 0 && dSeed > MAX_SEEDS_DROP_BUFFER) {
                          // FIRE AND FORGET
                          logAction('CHEAT_RESOURCE_SEEDS', user.id, user.username, req, {
                            seedType: seedName,
                            delta: dSeed,
                            limit: MAX_SEEDS_DROP_BUFFER,
                            dScrap: dScrap
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal increase in ${seedName} detected without purchase.` });
                    }
                }
            }

            // 8. Ores & Smelting Check
            const oreTypes = [
                { key: "Iron Ore", maxPerSmelt: 15 },       
                { key: "Aluminium Ore", maxPerSmelt: 15 },
                { key: "Copper Ore", maxPerSmelt: 15 },
                { key: "Titanium Ore", maxPerSmelt: 15 },
                { key: "Raw silicon", maxPerSmelt: 5 },     
                { key: "Steel", maxPerSmelt: 15 }
            ];

            const hasMiner = (newState.hangar && newState.hangar.miner > 0) || (newState.hangar && newState.hangar.hauler > 0);
            const SHIP_CARGO_BUFFER = 150; 
            
            for (const ore of oreTypes) {
                const oldQty = oldState.inventory[ore.key] || 0;
                const newQty = newState.inventory[ore.key] || 0;
                const dQty = newQty - oldQty;

                if (dQty > 0) {
                    let allowedGain = ore.maxPerSmelt * 2; 

                    if (hasMiner) {
                        allowedGain += SHIP_CARGO_BUFFER;
                    }

                    const SAFETY_MARGIN = 20; 
                    const finalLimit = allowedGain + SAFETY_MARGIN;

                    if (dQty > finalLimit) {
                          // FIRE AND FORGET
                          logAction(`CHEAT_RESOURCE_${ore.key.toUpperCase().replace(' ', '_')}`, user.id, user.username, req, {
                            resource: ore.key,
                            delta: dQty,
                            limit: finalLimit,
                            hasMiner: hasMiner
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal increase in ${ore.key}.` });
                    }
                }
            }

            // 9. CAD Gases Check
            const cadGases = [
                { key: "CO2", maxPerRun: 15 }, 
                { key: "Nitrogen", maxPerRun: 2 },
                { key: "Argon", maxPerRun: 2 },
                { key: "Neon", maxPerRun: 2 },
                { key: "Krypton", maxPerRun: 2 },
                { key: "Xenon", maxPerRun: 2 }
            ];

            const MAX_CAD_SLOTS = 2; 
            const CAD_SAFETY_BUFFER = 5; 

            for (const gas of cadGases) {
                const oldQty = oldState.inventory[gas.key] || 0;
                const newQty = newState.inventory[gas.key] || 0;
                const dQty = newQty - oldQty;

                if (dQty > 0) {
                    const limit = (gas.maxPerRun * MAX_CAD_SLOTS) + CAD_SAFETY_BUFFER;

                    if (dQty > limit) {
                        // FIRE AND FORGET
                        logAction(`CHEAT_RESOURCE_${gas.key.toUpperCase()}`, user.id, user.username, req, {
                            resource: gas.key,
                            delta: dQty,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal increase in ${gas.key} (CAD violation).` });
                    }
                }
            }

            // 10. Water Filter Check
            const dWater = (newState.inventory.Water || 0) - (oldState.inventory.Water || 0);

            if (dWater > 0) {
                const FILTER_SLOTS = 2;
                const WATER_PER_SLOT = 25;
                const WATER_BUFFER = 10; 
                const maxWaterGain = (FILTER_SLOTS * WATER_PER_SLOT) + WATER_BUFFER;

                if (dWater > maxWaterGain) {
                      // FIRE AND FORGET
                      logAction('CHEAT_RESOURCE_WATER_FILTER', user.id, user.username, req, {
                        delta: dWater,
                        limit: maxWaterGain
                    });
                    return res.status(400).json({ msg: 'Game integrity error: Abnormal Water increase (Filter violation).' });
                }
            }

            // 11. Fermentation Check
            const dFermGuarana = (newState.inventory["Fermented Guarana"] || 0) - (oldState.inventory["Fermented Guarana"] || 0);
            const dFermAmaranth = (newState.inventory["Fermented Amaranth"] || 0) - (oldState.inventory["Fermented Amaranth"] || 0);

            const totalFermGain = Math.max(0, dFermGuarana) + Math.max(0, dFermAmaranth);

            if (totalFermGain > 0) {
                const FERM_SLOTS = 2;
                const FERM_PER_SLOT = 37; 
                const FERM_BUFFER = 3; 
                const maxFermGain = (FERM_SLOTS * FERM_PER_SLOT) + FERM_BUFFER;

                if (totalFermGain > maxFermGain) {
                    // FIRE AND FORGET
                    logAction('CHEAT_RESOURCE_FERMENTATION', user.id, user.username, req, {
                        dFermGuarana,
                        dFermAmaranth,
                        totalGain: totalFermGain,
                        limit: maxFermGain
                    });
                    return res.status(400).json({ msg: 'Game integrity error: Abnormal Fermentation output detected.' });
                }
            }

            // 11.5. Kitchen Chain Check (Roasting, Grinding, Brewing) - NEW ADDITION
            const kitchenItems = [
                // Roasting: 2 slots, max ~20 output per slot. Limit = 45
                { key: "Roasted Guarana", maxPerSlot: 20, slots: 2, buffer: 5 },
                // Grinding: 2 slots, max ~13 output per slot. Limit = 31
                { key: "Ground Guarana", maxPerSlot: 13, slots: 2, buffer: 5 },
                // Brewing: 2 slots, max ~5 output per slot. Limit = 13
                { key: "Energy Isotonic", maxPerSlot: 5, slots: 2, buffer: 3 }
            ];

            for (const item of kitchenItems) {
                const oldQ = oldState.inventory[item.key] || 0;
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;

                if (delta > 0) {
                    const limit = (item.maxPerSlot * item.slots) + item.buffer;

                    if (delta > limit) {
                        // FIRE AND FORGET
                        logAction(`CHEAT_KITCHEN_${item.key.toUpperCase().replace(' ', '_')}`, user.id, user.username, req, {
                            resource: item.key,
                            delta: delta,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal Kitchen output for ${item.key}.` });
                    }
                }
            }

            // 12. Chemical Lab Check
            const chemItems = [
                { key: "PVC", maxPerSlot: 12 },
                { key: "Perchlorate", maxPerSlot: 3 },
                { key: "PLA", maxPerSlot: 10 },
                { key: "Empty Battery", maxPerSlot: 3 },
                { key: "Electric silicon", maxPerSlot: 3 }
            ];

            const CHEM_SLOTS = 4;
            const CHEM_BUFFER = 5; 

            for (const item of chemItems) {
                const oldQ = oldState.inventory[item.key] || 0;
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;

                if (delta > 0) {
                    const limit = (item.maxPerSlot * CHEM_SLOTS) + CHEM_BUFFER;
                    
                    if (delta > limit) {
                        // FIRE AND FORGET
                        logAction(`CHEAT_CHEMLAB_${item.key.toUpperCase().replace(' ', '_')}`, user.id, user.username, req, {
                            resource: item.key,
                            delta: delta,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal Chemical Lab output for ${item.key}.` });
                    }
                }
            }
            
            // 13. Factory Check (Metalworks, Machine Parts, Printer)
            const factoryItems = [
                // Metalworks (3 слота, максимум база 5 + бонус 5 = 10 на слот)
                { key: "Aluminium Plate", maxPerSlot: 10, slots: 3, buffer: 5 },
                { key: "Titanium Plate", maxPerSlot: 10, slots: 3, buffer: 5 },
                // Machine Parts (3 слота, максимум база 3 + бонус 2 = 5 на слот)
                { key: "Machined Parts", maxPerSlot: 5, slots: 3, buffer: 5 },
                { key: "Moving Parts", maxPerSlot: 5, slots: 3, buffer: 5 },
                // Printer (2 слота)
                { key: "Structural Part", maxPerSlot: 2, slots: 2, buffer: 2 }, // Фиксировано 2
                { key: "PVC Pipe", maxPerSlot: 5, slots: 2, buffer: 3 }, // Максимум 5
                { key: "Electronic Parts", maxPerSlot: 3, slots: 2, buffer: 2 } // Максимум 3
            ];

            for (const item of factoryItems) {
                const oldQ = oldState.inventory[item.key] || 0;
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;

                if (delta > 0) {
                    const limit = (item.maxPerSlot * item.slots) + item.buffer;

                    if (delta > limit) {
                        // FIRE AND FORGET
                        logAction(`CHEAT_FACTORY_${item.key.toUpperCase().replace(/ /g, '_')}`, user.id, user.username, req, {
                            resource: item.key,
                            delta: delta,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal Factory output for ${item.key}.` });
                    }
                }
            }

            // 14. Fuel Factory Check
            const fuelItems = [
                { key: "Liquid CH4", maxPerSlot: 20, slots: 4, buffer: 2 },
                { key: "Liquid O2", maxPerSlot: 20, slots: 4, buffer: 2 },
                { key: "Rocket Fuel", maxPerSlot: 40, slots: 4, buffer: 4 }
            ];

            for (const item of fuelItems) {
                const oldQ = oldState.inventory[item.key] || 0;
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;

                if (delta > 0) {
                    const limit = (item.maxPerSlot * item.slots) + item.buffer;

                    if (delta > limit) {
                        // FIRE AND FORGET
                        logAction(`CHEAT_FUEL_${item.key.toUpperCase().replace(/ /g, '_')}`, user.id, user.username, req, {
                            resource: item.key,
                            delta: delta,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal Fuel Factory output for ${item.key}.` });
                    }
                }
            }
        }

        // --- SUCCESSFUL SAVE ---
        user.gameState = gameState;
        user.lastSaveTime = serverNow;
        await user.save(); // Ждем сохранения юзера (критично)

        // FIRE AND FORGET (Лог сохранения)
        logAction('GAME_SAVE', req.user.id, user.username, req, {
            savedAt: serverNow
        });

        res.json({ msg: 'Game Saved', serverTime: serverNow }); 
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
