require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
// --- НАСТРОЙКА ДОВЕРИЯ ПРОКСИ (ВАЖНО ДЛЯ RENDER/VPN) ---
app.set('trust proxy', 1);

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

// --- HONEYPOT CONFIGURATION (ЛОВУШКА) ---
const HONEYPOT_KEYS = [
    'admin', 'isAdmin', 'is_admin', 
    'god_mode', 'godMode', 
    'cheats', 'cheat_enabled',
    'bypass', 'bypass_validation',
    'dev_tools', 'debug_mode',
    'unlimited_resources'
];

// --- DATABASE MODELS & SCHEMAS (VALIDATION ADDED) ---

// 1. Sub-Schemas for Game State Validation

// Battery Structure
const BatterySchema = new mongoose.Schema({
    id: { type: String, required: true },
    charge: { type: Number, default: 0, min: 0 },
    wear: { type: Number, default: 0, min: 0, max: 100 },
    loc: { type: String, enum: ['grid', 'inventory', 'warehouse'], default: 'inventory' }
}, { _id: false });

// Generic Machine Slot (Refinery, Factory, etc.)
const SlotSchema = new mongoose.Schema({
    id: { type: Number, default: 0 }, 
    active: { type: Boolean, default: false },
    startTime: { type: Number, default: 0 },
    duration: { type: Number, default: 0 },
    mode: { type: String, default: null },
    status: { type: String }, 
    crop: { type: String, default: null }
}, { _id: false });

// Skill Structure
const SkillSchema = new mongoose.Schema({
    lvl: { type: Number, default: 1, min: 1 },
    xp: { type: Number, default: 0, min: 0 },
    next: { type: Number, default: 100 },
    locked: { type: Boolean, default: false }
}, { _id: false });

// Active Ship Structure
const ShipSchema = new mongoose.Schema({
    type: { type: String, required: true },
    targetId: { type: Number },
    phase: { type: String, enum: ['outbound', 'mining', 'return', 'orbit'], default: 'outbound' },
    duration: { type: Number, default: 0 },
    progress: { type: Number, default: 0 },
    lastTick: { type: Number, default: Date.now },
    startPos: { x: Number, y: Number },
    lastPos: { x: Number, y: Number },
    cargoItem: { type: String, default: null },
    cargoAmount: { type: Number, default: 0 },
    mineStart: { type: Number, default: 0 },
    spec: { type: Object } 
}, { _id: false });

// Celestial Body (Map Object)
const BodySchema = new mongoose.Schema({
    id: Number,
    name: String,
    dist: Number,
    speed: Number,
    color: String,
    size: Number,
    type: String,
    angle: Number,
    scanned: { type: Boolean, default: false },
    res: [String]
}, { _id: false });

// MAIN GAME STATE SCHEMA
const GameStateSchema = new mongoose.Schema({
    camera: { 
        x: { type: Number, default: 0 }, 
        y: { type: Number, default: 0 } 
    },
    zoom: { type: Number, default: 0.8 },
    inventory: {
        type: Map,
        of: Number,
        default: {}
    },
    stamina: {
        val: { type: Number, default: 100, min: 0 },
        max: { type: Number, default: 100 }
    },
    cooldowns: {
        type: Map,
        of: Number,
        default: {}
    },
    lastDailyClaim: { type: Number, default: 0 },
    skills: {
        scavenging: { type: SkillSchema, default: () => ({}) },
        agriculture: { type: SkillSchema, default: () => ({}) },
        metallurgy: { type: SkillSchema, default: () => ({}) },
        chemistry: { type: SkillSchema, default: () => ({}) },
        planetary_exploration: { type: SkillSchema, default: () => ({}) },
        engineering: { type: SkillSchema, default: () => ({}) }
    },
    hangar: {
        probe: { type: Number, default: 1 },
        miner: { type: Number, default: 0 },
        hauler: { type: Number, default: 0 },
        gas: { type: Number, default: 0 }
    },
    power: {
        batteries: [BatterySchema],
        productionRate: { type: Number, default: 0 },
        consumptionRate: { type: Number, default: 0 },
        gridStatus: { type: String, default: 'ONLINE' }
    },
    scavenging: {
        active: { type: Boolean, default: false },
        timer: { type: Number, default: 0 },
        duration: { type: Number, default: 5000 }
    },
    cad: { slots: [SlotSchema] },
    metalworks: { slots: [SlotSchema] },
    machineParts: { slots: [SlotSchema] },
    printer: { slots: [SlotSchema] },
    refinery: {
        waterSlots: [SlotSchema],
        sabatierSlots: [SlotSchema],
        smelterSlots: [SlotSchema],
        fermenterSlot: { type: SlotSchema, default: () => ({ id: 0, active: false }) }
    },
    fuelFactory: { slots: [SlotSchema] },
    chemlab: { slots: [SlotSchema] },
    kitchen: {
        roasterSlots: [SlotSchema],
        grinderSlots: [SlotSchema],
        brewerSlots: [SlotSchema]
    },
    greenhouse: { 
        slots: [SlotSchema], 
        selectedSlot: { type: Number, default: null } 
    },
    composter: { slots: [SlotSchema] },
    ships: [ShipSchema],
    bodies: [BodySchema],
    buildQueue: [{
        type: { type: String },
        progress: { type: Number },
        totalDuration: { type: Number }
    }],
    components: { type: Map, of: Number, default: {} },
    environment: {
        flux: { type: Number, default: 0.15 }
    },
    market: { 
        offers: { type: Array, default: [] } 
    }
}, { _id: false, strict: true });

// 2. User Model
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    gameState: { type: GameStateSchema, default: () => ({}) },
    lastSaveTime: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// 3. Action Log Model
const ActionLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
    username: { type: String },
    action: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    ip: { type: String },
    details: { type: Object }
});
const ActionLog = mongoose.model('ActionLog', ActionLogSchema);

// 4. Market Offer Model
const MarketOfferSchema = new mongoose.Schema({
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sellerName: { type: String, required: true },
    sellerIp: { type: String, required: true },
    item: { type: String, required: true },
    qty: { type: Number, required: true, min: 1 },
    price: { type: Number, required: true, min: 1 },
    currency: { type: String, default: 'HELIUM3' },
    postedAt: { type: Date, default: Date.now }
});
const MarketOffer = mongoose.model('MarketOffer', MarketOfferSchema);

// --- HELPER: FIRE AND FORGET LOGGING ---
const logAction = async (action, userId, username, req, details = {}) => {
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
        console.log(`[LOG] Action: ${action} | User: ${username || 'Guest'}`);
    } catch (err) {
        console.error('Logging Error (Background):', err.message);
    }
};

// --- SECURITY HELPER: NEGATIVE VALUE PREVENTION ---
/**
 * Sanitizes a number, enforcing boundaries and preventing NaN/Infinity/Null.
 * @param {any} val - The input value.
 * @param {number} defaultVal - Fallback if input is invalid (default 0).
 * @param {number} min - Minimum allowed value (default 0).
 * @param {number} max - Maximum allowed value (default Infinity).
 * @returns {number} A safe, valid number.
 */
const sanitizeNumber = (val, defaultVal = 0, min = 0, max = Infinity) => {
    // Check for null, undefined, or non-finite values (Infinity, NaN)
    if (val === null || val === undefined || typeof val !== 'number' || !Number.isFinite(val) || isNaN(val)) {
        return defaultVal;
    }
    // Clamp values
    if (val < min) return min;
    if (val > max) return max;
    return val;
};

/**
 * Deep sanitization of the Game State object to prevent injection of malicious types.
 */
const secureGameState = (state) => {
    if (!state) return {};

    // 1. Sanitize Inventory (No negatives, no NaNs)
    if (state.inventory) {
        // If it's a plain object (from JSON body)
        for (const key in state.inventory) {
            state.inventory[key] = sanitizeNumber(state.inventory[key], 0, 0);
        }
    }

    // 2. Sanitize Stamina (0-100)
    if (state.stamina) {
        state.stamina.val = sanitizeNumber(state.stamina.val, 100, 0, 100);
        state.stamina.max = sanitizeNumber(state.stamina.max, 100, 100, 100); // Fixed max for now
    }

    // 3. Sanitize Batteries
    if (state.power && Array.isArray(state.power.batteries)) {
        state.power.batteries.forEach(bat => {
            bat.charge = sanitizeNumber(bat.charge, 0, 0, 100); // Assuming 100 max capacity relative calculation elsewhere
            bat.wear = sanitizeNumber(bat.wear, 0, 0, 100);
        });
    }

    // 4. Sanitize Skills
    if (state.skills) {
        for (const key in state.skills) {
            if (state.skills[key]) {
                state.skills[key].lvl = sanitizeNumber(state.skills[key].lvl, 1, 1);
                state.skills[key].xp = sanitizeNumber(state.skills[key].xp, 0, 0);
                state.skills[key].next = sanitizeNumber(state.skills[key].next, 100, 1);
            }
        }
    }

    // 5. Sanitize Hangar
    if (state.hangar) {
        for (const key in state.hangar) {
            state.hangar[key] = sanitizeNumber(state.hangar[key], 0, 0);
        }
    }

    // 6. Sanitize Components
    if (state.components) {
        for (const key in state.components) {
            state.components[key] = sanitizeNumber(state.components[key], 0, 0);
        }
    }

    // 7. Sanitize Environment
    if (state.environment) {
        state.environment.flux = sanitizeNumber(state.environment.flux, 0.15, 0, 1);
    }
    
    // 8. Sanitize Cooldowns
    if (state.cooldowns) {
        for (const key in state.cooldowns) {
             state.cooldowns[key] = sanitizeNumber(state.cooldowns[key], 0, 0);
        }
    }

    return state;
};

// --- RATE LIMITING ---

// 1. Global Limit
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 2000, 
    standardHeaders: true,
    legacyHeaders: false,
    message: { msg: 'Too many requests from this IP (Global Limit), please try again later' }
});
app.use(globalLimiter);

// 2. Auth Limit
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 20, 
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false },
    keyGenerator: (req) => {
        return req.body.username || req.ip;
    },
    message: { msg: 'Too many login attempts for this account, please try again later' }
});
app.use('/api/auth', authLimiter);

// 3. Market Limit
const marketLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 150, 
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false },
    keyGenerator: (req) => {
        const token = req.header('x-auth-token');
        if (token) {
            try {
                const decoded = jwt.verify(token, JWT_SECRET);
                return decoded.user.id; 
            } catch (e) {
                return req.ip; 
            }
        }
        return req.ip;
    },
    message: { msg: 'Market transaction limit reached for your account. Slow down.' }
});
app.use('/api/market', marketLimiter);

// Middleware
app.use(express.json({ limit: '500kb' }));
app.use(cors());
app.use(express.static('public'));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/exodus_prime', {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000
})
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
    const { username, password, registration_token_public } = req.body;

    // --- HONEYPOT CHECK ---
    if (registration_token_public) {
        logAction('BOT_REGISTRATION_HONEYPOT', null, username, req, { token: registration_token_public });
        return res.status(200).json({ msg: 'Registration queued for review.' });
    }

    try {
        let user = await User.findOne({ username });
        if (user) {
            logAction('REGISTER_FAIL_EXISTS', null, username, req);
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({ username, password });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        
        user.gameState = {
            inventory: { 
                Helium3: 0, 
                Scrap: 0,
                "Ice water": 50,
                "Water": 5,
                "Soil": 100,
                "Seeds: Sprouts": 100,
                "Seeds: Amaranth": 5,
                "Seeds: Guarana": 5,
                "Seeds: Potato": 5,
                "Seeds: Maize": 5,
                "Rocket Fuel": 100,
                "Energy Bar": 10,
                "Pt": 5
            },
            market: { offers: [] },
            power: {
                batteries: [
                    { id: 'INIT_1', charge: 30, wear: 0, loc: 'grid' },
                    { id: 'INIT_2', charge: 30, wear: 0, loc: 'grid' },
                    { id: 'INIT_3', charge: 20, wear: 0, loc: 'grid' },
                    { id: 'INIT_4', charge: 20, wear: 0, loc: 'inventory' },
                    { id: 'INIT_5', charge: 20, wear: 0, loc: 'inventory' }
                ]
            },
            cad: { slots: [{id:0},{id:1}] },
            refinery: { 
                waterSlots: [{id:0},{id:1}], 
                sabatierSlots: [{id:0},{id:1}], 
                smelterSlots: [{id:0},{id:1}],
                fermenterSlot: { id: 0, active: false } 
            },
            greenhouse: { slots: Array(6).fill(null).map((_, i) => ({ id: i, status: 'empty' })) },
            composter: { slots: [{id:0},{id:1},{id:2}] },
            kitchen: { roasterSlots: [{id:0},{id:1}], grinderSlots: [{id:0},{id:1}], brewerSlots: [{id:0},{id:1}] },
            fuelFactory: { slots: [{id:0},{id:1},{id:2},{id:3}] },
            chemlab: { slots: [{id:0},{id:1},{id:2},{id:3}] },
            metalworks: { slots: [{id:0},{id:1},{id:2}] },
            machineParts: { slots: [{id:0},{id:1},{id:2}] },
            printer: { slots: [{id:0},{id:1}] },
            stamina: { val: 100, max: 100 },
            skills: {
                 scavenging: { lvl: 1, xp: 0, next: 100, locked: false },
                 agriculture: { lvl: 1 }, metallurgy: { lvl: 1 }, chemistry: { lvl: 1 }, 
                planetary_exploration: { lvl: 1 }, engineering: { lvl: 1 }
            }
        };
        await user.save();
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
            logAction('LOGIN_FAIL_USER', null, username, req);
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            logAction('LOGIN_FAIL_PASSWORD', user.id, username, req);
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

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
        
        if(!user.gameState.inventory) user.gameState.inventory = new Map();
        if(!user.gameState.inventory.has('Helium3')) user.gameState.inventory.set('Helium3', 0);

        logAction('GAME_LOAD', user.id, user.username, req);

        res.setHeader('x-server-time', Date.now());
        res.json(user.gameState);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// 4. Save Game (Protected) with Anti-Cheat, CRAFTING VALIDATION, HONEYPOT & TYPE PROTECTION
app.post('/api/game/save', auth, async (req, res) => {
    try {
        let { gameState, clientTime } = req.body;

        // --- NEW: NEGATIVE VALUE / NAN PREVENTION ---
        // Secure the incoming state before any logic processes it
        gameState = secureGameState(gameState);

        // --- HONEYPOT CHECK ---
        if (gameState) {
            for (const trapKey of HONEYPOT_KEYS) {
                if (gameState.hasOwnProperty(trapKey) || (gameState.inventory && gameState.inventory[trapKey])) {
                    await logAction('CHEAT_HONEYPOT_TRIGGER', req.user.id, 'UNKNOWN', req, { trap: trapKey });
                    return res.status(403).json({ msg: 'Security integrity violation detected.' });
                }
            }
        }

        const newState = gameState; 
        const serverNow = Date.now();

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        const oldState = user.gameState || {}; 
        
        // --- MOVED UP HELPER FOR USE IN COOLDOWN CHECK ---
        const getOldInv = (key) => (oldState.inventory instanceof Map) ?
            (oldState.inventory.get(key) || 0) : (oldState.inventory[key] || 0);

        let timeSinceLastSave = 0;
        
        let dbHelium3 = 0;
        if (oldState.inventory instanceof Map) {
            dbHelium3 = oldState.inventory.get('Helium3') || 0;
        } else if (oldState.inventory) {
            dbHelium3 = oldState.inventory.Helium3 || 0;
        }
        
        if (!newState.inventory) newState.inventory = {};
        newState.inventory.Helium3 = dbHelium3;

        // --- ANTI-CHEAT CHECKS ---

        // 1. Time Check
        if (clientTime) {
            // Check for valid number on clientTime
            const safeClientTime = sanitizeNumber(clientTime, serverNow);
            const timeDifference = Math.abs(serverNow - safeClientTime);
            const maxAllowedDifference = 5 * 60 * 1000; 

            if (timeDifference > maxAllowedDifference) {
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
                        const oldQty = getOldInv(item);
                        const newQty = newState.inventory[item] || 0;
                        if (newQty < oldQty) {
                            hasConsumedFood = true;
                            break;
                        }
                    }

                    if (!hasConsumedFood && staminaDiff > 0.5) {
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

        // --- 4.5 NEW COOLDOWN PROTECTION (UPSCALE) ---
        if (newState.inventory) {
            const EATING_COOLDOWN_MS = 2.5 * 60 * 60 * 1000; // 2.5 Hours
            const TRACKED_FOODS = ['Snack', 'Meal', 'Feast', 'Energy Bar'];
            for (const foodItem of TRACKED_FOODS) {
                const oldFoodQty = getOldInv(foodItem);
                const newFoodQty = newState.inventory[foodItem] || 0;

                // User consumed food
                if (newFoodQty < oldFoodQty) {
                    let lastEaten = 0;
                    if (oldState.cooldowns) {
                        if (oldState.cooldowns instanceof Map) {
                            lastEaten = oldState.cooldowns.get(foodItem) || 0;
                        } else {
                            lastEaten = oldState.cooldowns[foodItem] || 0;
                        }
                    }

                    // Strict server-side check
                    if ((serverNow - lastEaten) < EATING_COOLDOWN_MS) {
                        logAction('CHEAT_COOLDOWN_BYPASS', user.id, user.username, req, {
                             item: foodItem,
                            lastEaten: lastEaten,
                            serverNow: serverNow,
                            diff: serverNow - lastEaten
                        });
                        return res.status(400).json({ msg: `Game integrity error: ${foodItem} is on cooldown. Wait longer.` });
                    }

                    // Enforce server-side timestamp to prevent client-side clearing
                    if (!newState.cooldowns) newState.cooldowns = {};
                    newState.cooldowns[foodItem] = serverNow;
                }
            }
        }
        // ----------------------------------------------

        // 5. Scavenging & Resources Check
        
        let dScrap = 0;
        let maxActionsPossible = 10;
        if (oldState.inventory && newState.inventory) {
            const dRegolith = (newState.inventory.Regolith || 0) - getOldInv("Regolith");
            const dIce = (newState.inventory["Ice water"] || 0) - getOldInv("Ice water");
            dScrap = (newState.inventory.Scrap || 0) - getOldInv("Scrap");
            const SCAV_DURATION_MS = 5000;
            const MAX_REG_PER_SCAV = 10;
            const MAX_ICE_PER_SCAV = 3;
            const MAX_SCRAP_PER_SCAV = 10;
            maxActionsPossible = Math.ceil(timeSinceLastSave / SCAV_DURATION_MS) + 2;
            const SHIP_BUFFER = 100;
            if (dScrap > (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20) {
                  logAction('CHEAT_RESOURCE_SCRAP', user.id, user.username, req, { 
                    delta: dScrap, 
                    maxAllowed: (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20,
                    timeElapsed: timeSinceLastSave 
                });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Scrap increase detected.' });
            }

            if (dIce > ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)) {
                  logAction('CHEAT_RESOURCE_ICE', user.id, user.username, req, { 
                    delta: dIce,
                    maxAllowed: ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)
                  });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Ice increase detected.' });
            }

            if (dRegolith > ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)) {
                  logAction('CHEAT_RESOURCE_REGOLITH', user.id, user.username, req, { 
                    delta: dRegolith, 
                    maxAllowed: ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)
                  });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Regolith increase detected.' });
            }

            // 6. Food & Harvest Check
            const dSnack = (newState.inventory.Snack || 0) - getOldInv("Snack");
            const dMeal = (newState.inventory.Meal || 0) - getOldInv("Meal");
            const dFeast = (newState.inventory.Feast || 0) - getOldInv("Feast");
            const dIsotonic = (newState.inventory["Energy Isotonic"] || 0) - getOldInv("Energy Isotonic");
            const dFood = (newState.inventory.Food || 0) - getOldInv("Food");
            const dAmaranth = (newState.inventory.Amaranth || 0) - getOldInv("Amaranth");
            const dGuarana = (newState.inventory.Guarana || 0) - getOldInv("Guarana");

            let impliedFoodCost = 0;
            if (dSnack > 0) impliedFoodCost += dSnack * 30; 
            if (dMeal > 0) impliedFoodCost += dMeal * 60;
            if (dFeast > 0) impliedFoodCost += dFeast * 90; 

            const MAX_FOOD_HARVEST_BUFFER = 1200;
            if ((dFood + impliedFoodCost) > MAX_FOOD_HARVEST_BUFFER) {
                logAction('CHEAT_RESOURCE_FOOD_BALANCE', user.id, user.username, req, {
                    dFood, 
                    impliedFoodCost, 
                    netGain: dFood + impliedFoodCost,
                    limit: MAX_FOOD_HARVEST_BUFFER
                });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Food/Ration production balance.' });
            }

            if (dAmaranth > 300) {
                logAction('CHEAT_CROP_AMARANTH', user.id, user.username, req, { delta: dAmaranth });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Amaranth harvest.' });
            }
            if (dGuarana > 400) {
                logAction('CHEAT_CROP_GUARANA', user.id, user.username, req, { delta: dGuarana });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Guarana harvest.' });
            }

            if (dIsotonic > 25) {
                logAction('CHEAT_RESOURCE_ISOTONIC', user.id, user.username, req, { delta: dIsotonic });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Energy Isotonic increase.' });
            }
            
            // 7. Seeds Check
            const seedTypes = ['Seeds: Sprouts', 'Seeds: Potato', 'Seeds: Maize', 'Seeds: Amaranth', 'Seeds: Guarana'];
            const MAX_SEEDS_DROP_BUFFER = 50;

            for (const seedName of seedTypes) {
                const oldSeedQty = getOldInv(seedName);
                const newSeedQty = newState.inventory[seedName] || 0;
                const dSeed = newSeedQty - oldSeedQty;
                if (dSeed > 0) {
                    if (dScrap >= 0 && dSeed > MAX_SEEDS_DROP_BUFFER) {
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
                const oldQty = getOldInv(ore.key);
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
                const oldQty = getOldInv(gas.key);
                const newQty = newState.inventory[gas.key] || 0;
                const dQty = newQty - oldQty;
                if (dQty > 0) {
                    const limit = (gas.maxPerRun * MAX_CAD_SLOTS) + CAD_SAFETY_BUFFER;
                    if (dQty > limit) {
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
            const dWater = (newState.inventory.Water || 0) - getOldInv("Water");
            if (dWater > 0) {
                const FILTER_SLOTS = 2;
                const WATER_PER_SLOT = 25;
                const WATER_BUFFER = 10; 
                const maxWaterGain = (FILTER_SLOTS * WATER_PER_SLOT) + WATER_BUFFER;
                if (dWater > maxWaterGain) {
                      logAction('CHEAT_RESOURCE_WATER_FILTER', user.id, user.username, req, {
                        delta: dWater,
                        limit: maxWaterGain
                    });
                    return res.status(400).json({ msg: 'Game integrity error: Abnormal Water increase (Filter violation).' });
                }
            }

            // 11. Fermentation Check
            const dFermGuarana = (newState.inventory["Fermented Guarana"] || 0) - getOldInv("Fermented Guarana");
            const dFermAmaranth = (newState.inventory["Fermented Amaranth"] || 0) - getOldInv("Fermented Amaranth");

            const totalFermGain = Math.max(0, dFermGuarana) + Math.max(0, dFermAmaranth);
            if (totalFermGain > 0) {
                const FERM_SLOTS = 2;
                const FERM_PER_SLOT = 37; 
                const FERM_BUFFER = 3; 
                const maxFermGain = (FERM_SLOTS * FERM_PER_SLOT) + FERM_BUFFER;
                if (totalFermGain > maxFermGain) {
                    logAction('CHEAT_RESOURCE_FERMENTATION', user.id, user.username, req, {
                        dFermGuarana,
                        dFermAmaranth,
                         totalGain: totalFermGain,
                        limit: maxFermGain
                    });
                    return res.status(400).json({ msg: 'Game integrity error: Abnormal Fermentation output detected.' });
                }
            }

            // 11.5. Kitchen Chain Check
            const kitchenItems = [
                { key: "Roasted Guarana", maxPerSlot: 20, slots: 2, buffer: 5 },
                { key: "Ground Guarana", maxPerSlot: 13, slots: 2, buffer: 5 },
                { key: "Energy Isotonic", maxPerSlot: 5, slots: 2, buffer: 3 }
            ];
            for (const item of kitchenItems) {
                const oldQ = getOldInv(item.key);
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;
                if (delta > 0) {
                    const limit = (item.maxPerSlot * item.slots) + item.buffer;
                    if (delta > limit) {
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
                const oldQ = getOldInv(item.key);
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;
                if (delta > 0) {
                    const limit = (item.maxPerSlot * CHEM_SLOTS) + CHEM_BUFFER;
                    if (delta > limit) {
                        logAction(`CHEAT_CHEMLAB_${item.key.toUpperCase().replace(' ', '_')}`, user.id, user.username, req, {
                            resource: item.key,
                            delta: delta,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal Chemical Lab output for ${item.key}.` });
                    }
                }
            }
            
            // 13. Factory Check
            const factoryItems = [
                { key: "Aluminium Plate", maxPerSlot: 10, slots: 3, buffer: 5 },
                { key: "Titanium Plate", maxPerSlot: 10, slots: 3, buffer: 5 },
                { key: "Machined Parts", maxPerSlot: 5, slots: 3, buffer: 5 },
                { key: "Moving Parts", maxPerSlot: 5, slots: 3, buffer: 5 },
                { key: "Structural Part", maxPerSlot: 2, slots: 2, buffer: 2 },
                { key: "PVC Pipe", maxPerSlot: 5, slots: 2, buffer: 3 },
                { key: "Electronic Parts", maxPerSlot: 3, slots: 2, buffer: 2 }
            ];
            for (const item of factoryItems) {
                const oldQ = getOldInv(item.key);
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;
                if (delta > 0) {
                    const limit = (item.maxPerSlot * item.slots) + item.buffer;
                    if (delta > limit) {
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
                const oldQ = getOldInv(item.key);
                const newQ = newState.inventory[item.key] || 0;
                const delta = newQ - oldQ;
                if (delta > 0) {
                    const limit = (item.maxPerSlot * item.slots) + item.buffer;
                    if (delta > limit) {
                        logAction(`CHEAT_FUEL_${item.key.toUpperCase().replace(/ /g, '_')}`, user.id, user.username, req, {
                            resource: item.key,
                            delta: delta,
                            limit: limit
                        });
                        return res.status(400).json({ msg: `Game integrity error: Abnormal Fuel Factory output for ${item.key}.` });
                    }
                }
            }

            // 15. CRAFTING COST VALIDATION
            const CRAFT_COST_RULES = [
                { out: "Steel", in: "Iron Ore", ratio: 1.0 }, 
                { out: "Aluminium Plate", in: "Aluminium Ore", ratio: 0.8 }, 
                { out: "Titanium Plate", in: "Titanium Ore", ratio: 0.8 }, 
                { out: "Rocket Fuel", in: "Liquid CH4", ratio: 0.4 }, 
                { out: "Rocket Fuel", in: "Liquid O2", ratio: 0.4 },
                { out: "PVC Pipe", in: "PVC", ratio: 0.3 }, 
                { out: "Structural Part", in: "Steel", ratio: 2.0 }, 
                { out: "Machined Parts", in: "Aluminium Plate", ratio: 1.0 }, 
                { out: "Moving Parts", in: "Titanium Plate", ratio: 0.5 } 
            ];
            for (const rule of CRAFT_COST_RULES) {
                const oldOutQty = getOldInv(rule.out);
                const newOutQty = newState.inventory[rule.out] || 0;
                const dOut = newOutQty - oldOutQty;
                if (dOut > 5) {
                    const minInputRequired = dOut * rule.ratio;
                    const miningBuffer = (maxActionsPossible * 15) + 200;
                    const maxTheoreticalInput = getOldInv(rule.in) + miningBuffer - minInputRequired;
                    const actualNewInput = newState.inventory[rule.in] || 0;
                    if (actualNewInput > maxTheoreticalInput) {
                         logAction(`CHEAT_CRAFT_COST_${rule.out.toUpperCase().replace(' ', '_')}`, user.id, user.username, req, {
                            outputGained: dOut,
                            inputResource: rule.in,
                            actualNewInput: actualNewInput,
                            maxTheoreticalInput: maxTheoreticalInput,
                            requiredSpend: minInputRequired,
                            miningBuffer: miningBuffer
                         });
                        return res.status(400).json({ msg: `Game integrity error: Crafted ${rule.out} without spending enough ${rule.in}.` });
                    }
                }
            }
        }

        // --- SUCCESSFUL SAVE ---
        user.gameState = gameState;
        user.lastSaveTime = serverNow;
        user.markModified('gameState');
        await user.save();
        
        logAction('GAME_SAVE', req.user.id, user.username, req, {
            savedAt: serverNow
        });
        res.json({ msg: 'Game Saved', serverTime: serverNow }); 
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// --- MARKET ROUTES ---

// 5. Get All Market Offers
app.get('/api/market', auth, async (req, res) => {
    try {
        const offers = await MarketOffer.find().sort({ postedAt: -1 }).limit(100);
        const mappedOffers = offers.map(o => ({
            id: o._id,
            seller: (o.sellerId.toString() === req.user.id) ? 'ME' : o.sellerName,
            item: o.item,
            qty: o.qty,
            price: o.price,
            currency: o.currency
        }));
        res.json({ offers: mappedOffers });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// 6. Buy Scavenging License (Protected with MongoDB Session)
app.post('/api/market/license', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const user = await User.findById(req.user.id).session(session);
        if(!user) {
            await session.abortTransaction();
            return res.status(404).json({msg: "User not found"});
        }

        const COST = 200;
        const currentScrap = user.gameState.inventory.get('Scrap') || 0;

        if(currentScrap < COST) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Insufficient Scrap"});
        }

        user.gameState.inventory.set('Scrap', currentScrap - COST);
        const currentLic = user.gameState.inventory.get("Scavenging License") || 0;
        user.gameState.inventory.set("Scavenging License", currentLic + 1);
        
        user.markModified('gameState');
        await user.save({ session });
        await session.commitTransaction();

        // Background logging
        logAction('MARKET_BUY_LICENSE', user.id, user.username, req);
        res.json({ msg: "License Acquired", inventory: user.gameState.inventory });

    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

// 7. Post an Offer (Protected with MongoDB Session & Negative/NaN Check)
app.post('/api/market/offer', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        let { item, qty, price } = req.body;
        
        // --- NEW: SANITIZATION FOR MARKET ---
        // Ensure values are numbers, integers, and positive.
        // sanitizeNumber(val, default, min)
        qty = sanitizeNumber(qty, 0, 1);
        price = sanitizeNumber(price, 0, 1);
        const safeItem = String(item);

        // Explicit Check to reject 0 (sanitized bad inputs)
        if (!safeItem || qty < 1 || price < 1 || !Number.isInteger(qty) || !Number.isInteger(price)) {
             await session.abortTransaction();
             return res.status(400).json({msg: "Invalid offer data (Must be positive integer)"});
        }

        if(safeItem === 'Helium3' || safeItem === 'Scavenging License') {
            await session.abortTransaction();
            return res.status(400).json({msg: "Restricted Item"});
        }

        const user = await User.findById(req.user.id).session(session);
        if(!user) {
            await session.abortTransaction();
            return res.status(404).json({msg: "User not found"});
        }

        // Check Inventory
        const currentQty = user.gameState.inventory.get(safeItem) || 0;
        if(currentQty < qty) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Insufficient items in inventory"});
        }

        // Deduct Item
        user.gameState.inventory.set(safeItem, currentQty - qty);
        user.markModified('gameState');
        await user.save({ session });

        // Create Offer in DB
        const newOffer = new MarketOffer({
            sellerId: user.id,
            sellerName: user.username,
            sellerIp: req.ip, 
            item: safeItem,
            qty: qty,
            price: price
        });
        await newOffer.save({ session });

        await session.commitTransaction();
        // Logging and fetching new offers list (outside transaction for performance)
        logAction('MARKET_POST', user.id, user.username, req, { item: safeItem, qty: qty, price: price });
        const offers = await MarketOffer.find().sort({ postedAt: -1 }).limit(100);
        const mappedOffers = offers.map(o => ({
            id: o._id,
            seller: (o.sellerId.toString() === req.user.id) ? 'ME' : o.sellerName,
            item: o.item,
            qty: o.qty,
            price: o.price,
            currency: o.currency
        }));
        
        res.json({ msg: "Offer Posted", offerId: newOffer._id, inventory: user.gameState.inventory, offers: mappedOffers });
    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

// 8. Cancel an Offer (Protected with MongoDB Session)
app.post('/api/market/cancel', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { offerId } = req.body;

        // NoSQL Injection Protection
        if (!mongoose.Types.ObjectId.isValid(offerId)) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Invalid Offer ID"});
        }

        const offer = await MarketOffer.findById(offerId).session(session);

        if(!offer) {
            await session.abortTransaction();
            return res.status(404).json({msg: "Offer not found"});
        }
        
        // Ownership Check
        if(offer.sellerId.toString() !== req.user.id) {
            await session.abortTransaction();
            return res.status(403).json({msg: "Not authorized"});
        }

        const user = await User.findById(req.user.id).session(session);
        
        // Return Items
        const current = user.gameState.inventory.get(offer.item) || 0;
        user.gameState.inventory.set(offer.item, current + offer.qty);
        
        user.markModified('gameState');
        await user.save({ session });
        // Delete Offer
        await MarketOffer.deleteOne({ _id: offerId }, { session });

        await session.commitTransaction();
        // Refresh offers
        const offers = await MarketOffer.find().sort({ postedAt: -1 }).limit(100);
        const mappedOffers = offers.map(o => ({
            id: o._id,
            seller: (o.sellerId.toString() === req.user.id) ? 'ME' : o.sellerName,
            item: o.item,
            qty: o.qty,
            price: o.price,
            currency: o.currency
        }));
        logAction('MARKET_CANCEL', user.id, user.username, req, { item: offer.item, qty: offer.qty });
        res.json({ msg: "Offer Cancelled", inventory: user.gameState.inventory, offers: mappedOffers });
    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

// 9. Buy an Offer (PROTECTED WITH MONGODB SESSION - NO RACE CONDITIONS)
app.post('/api/market/buy', auth, async (req, res) => {
    const { offerId } = req.body;
    const buyerId = req.user.id;

    // NoSQL Injection Protection
    if (!mongoose.Types.ObjectId.isValid(offerId)) {
        return res.status(400).json({msg: "Invalid Offer ID"});
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        // 1. Load Buyer with Session
        const buyer = await User.findById(buyerId).session(session);
        if(!buyer) {
            await session.abortTransaction();
            return res.status(500).json({msg: "User data error"});
        }

        // 2. Fetch Offer with Session
        const securedOffer = await MarketOffer.findById(offerId).session(session);
        if(!securedOffer) {
            await session.abortTransaction();
            return res.status(404).json({msg: "Offer no longer exists or was just sold"});
        }
        
        if(securedOffer.sellerId.toString() === buyerId) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Cannot buy your own offer"});
        }

        if (securedOffer.sellerIp === req.ip) {
            await session.abortTransaction();
            logAction('MARKET_IP_BAN', buyerId, buyer.username, req, { sellerIp: securedOffer.sellerIp, buyerIp: req.ip });
            return res.status(403).json({ msg: "Anti-Cheat: Cannot trade with yourself or same network." });
        }

        // 3. Check Funds
        const buyerH3 = buyer.gameState.inventory.get('Helium3') || 0;
        if(buyerH3 < securedOffer.price) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Insufficient Helium3"});
        }

        // 4. Execute Transfer (Buyer)
        buyer.gameState.inventory.set('Helium3', buyerH3 - securedOffer.price);
        const buyerItemQty = buyer.gameState.inventory.get(securedOffer.item) || 0;
        buyer.gameState.inventory.set(securedOffer.item, buyerItemQty + securedOffer.qty);

        buyer.markModified('gameState');
        await buyer.save({ session });
        // 5. Execute Transfer (Seller)
        const seller = await User.findById(securedOffer.sellerId).session(session);
        if (seller) {
            if(!seller.gameState.inventory) seller.gameState.inventory = new Map();
            const currentSellerH3 = seller.gameState.inventory.get('Helium3') || 0;
            seller.gameState.inventory.set('Helium3', currentSellerH3 + securedOffer.price);
            seller.markModified('gameState');
            await seller.save({ session });
        }

        // 6. Delete the Offer
        await MarketOffer.deleteOne({ _id: offerId }, { session });
        // 7. Commit Transaction
        await session.commitTransaction();
        // Background logging
        logAction('MARKET_BUY', buyer.id, buyer.username, req, { 
            item: securedOffer.item, 
            qty: securedOffer.qty, 
            price: securedOffer.price, 
            sellerId: securedOffer.sellerId 
        });
        res.json({ msg: "Purchase Successful", inventory: buyer.gameState.inventory });

    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
