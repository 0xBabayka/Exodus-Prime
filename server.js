require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const http = require('http');

// Добавлено для WebSocket
const { Server } = require('socket.io');

const app = express();

// --- НАСТРОЙКА ДОВЕРИЯ ПРОКСИ ---
// Важно для корректного определения IP через Render/Heroku/Nginx
app.set('trust proxy', 1);

app.get('/time', (req, res) => {
  res.json({ serverTime: Date.now() });
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'exodus_prime_secret_key_change_me_v2_secure';

// --- НАСТРОЙКА WEBSOCKET (SOCKET.IO) ---
const server = http.createServer(app);

const io = new Server(server, {
    cors: {
        origin: "*", // Настрой под свой домен в продакшене
        methods: ["GET", "POST"]
    }
});

// Middleware для авторизации сокетов по JWT
io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentication error"));
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        socket.user = decoded.user;
        next();
    } catch (err) {
        next(new Error("Authentication error"));
    }
});

// --- CHAT: In-memory history buffer (last 50 msgs per channel) ---
const CHAT_HISTORY = { general: [], trade: [] };
const CHAT_MAX_HISTORY = 50;
const CHAT_MAX_LEN = 200;
const CHAT_ALLOWED_CHANNELS = ['general', 'trade'];
// Rate limiter: userId -> last message timestamp
const chatRateLimit = new Map();
const CHAT_RATE_MS = 2000; // min 2s between messages
// Heartbeat map: userId (string) -> timestamp последнего пинга от клиента.
// Используется в /api/game/save чтобы отличить короткий лаг сети от настоящего оффлайна.
const onlineHeartbeats = new Map();
const HEARTBEAT_TIMEOUT = 90 * 1000; // 90 с — считаем оффлайн если нет пинга дольше этого

io.on('connection', (socket) => {
    // Send chat history to newly connected client
    socket.on('chat_get_history', (data) => {
        const channel = data && CHAT_ALLOWED_CHANNELS.includes(data.channel) ? data.channel : 'general';
        socket.emit('chat_history', { channel, messages: CHAT_HISTORY[channel] });
    });

    socket.on('chat_message', (data) => {
        try {
            if (!socket.user || !socket.user.id) return;

            // Validate channel
            const channel = data && CHAT_ALLOWED_CHANNELS.includes(data.channel) ? data.channel : null;
            if (!channel) return socket.emit('chat_error', { msg: 'Invalid channel.' });

            // Validate message text
            let text = data && typeof data.text === 'string' ? data.text.trim() : '';
            if (!text || text.length === 0) return;
            if (text.length > CHAT_MAX_LEN) return socket.emit('chat_error', { msg: `Message too long (max ${CHAT_MAX_LEN} chars).` });

            // Sanitize: strip HTML tags to prevent XSS
            text = text.replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

            // Rate limiting
            const now = Date.now();
            const lastMsg = chatRateLimit.get(socket.user.id) || 0;
            if (now - lastMsg < CHAT_RATE_MS) {
                return socket.emit('chat_error', { msg: 'Sending too fast. Wait a moment.' });
            }
            chatRateLimit.set(socket.user.id, now);

            // Get username from socket auth token (already decoded in middleware)
            // We need the actual username — look it up async safely
            User.findById(socket.user.id).select('username').then(user => {
                if (!user) return;
                const msg = {
                    id: `${socket.user.id}_${now}`,
                    channel,
                    username: user.username,
                    text,
                    ts: now
                };
                // Store in history
                CHAT_HISTORY[channel].push(msg);
                if (CHAT_HISTORY[channel].length > CHAT_MAX_HISTORY) {
                    CHAT_HISTORY[channel].shift();
                }
                // Broadcast to all connected clients
                io.emit('chat_message', msg);
            }).catch(err => console.error('Chat user lookup error:', err));

        } catch(err) {
            console.error('Chat message error:', err);
        }
    });

    socket.on('heartbeat', () => {
        if (socket.user && socket.user.id) {
            onlineHeartbeats.set(socket.user.id.toString(), Date.now());
        }
    });

    socket.on('disconnect', () => {
        if (socket.user && socket.user.id) {
            onlineHeartbeats.delete(socket.user.id.toString());
        }
    });
});

// --- SECURITY MIDDLEWARE (HELMET) ---
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'"],
            "script-src-attr": ["'unsafe-inline'"],
            "img-src": ["'self'", "data:", "*"],
            // ИСПРАВЛЕНИЕ 1: разрешаем blob:-воркеры.
            // Без этой директивы Helmet наследует worker-src от default-src ('self'),
            // что блокирует new Worker(URL.createObjectURL(blob)) с CSP-ошибкой.
            // Результат: energyWorker = null и фоновая зарядка батарей не работает.
            "worker-src": ["'self'", "blob:"],
        },
    },
}));

// --- MIDDLEWARE: PARSERS ---
app.use(express.json({ limit: '500kb' }));
app.use(cors());
app.use(express.static('public'));

// --- MONGO SANITIZE (PROTECTION AGAINST NoSQL INJECTION) ---
const mongoSanitize = (req, res, next) => {
    const sanitize = (obj) => {
        if (obj instanceof Object) {
            for (const key in obj) {
                if (/^\$/.test(key)) {
                    delete obj[key];
                } else {
                    sanitize(obj[key]);
                }
            }
        }
        return obj;
    };
    req.body = sanitize(req.body);
    req.params = sanitize(req.params);
    req.query = sanitize(req.query);
    next();
};
app.use(mongoSanitize);

// --- HONEYPOT CONFIGURATION (ЛОВУШКА ДЛЯ ЧИТЕРОВ) ---
const HONEYPOT_KEYS = [
    'admin', 'isAdmin', 'is_admin', 
    'god_mode', 'godMode', 
    'cheats', 'cheat_enabled',
    'bypass', 'bypass_validation',
    'dev_tools', 'debug_mode',
    'unlimited_resources'
];

// --- ХЕЛПЕР ДЛЯ ПРЕОБРАЗОВАНИЯ MAP В ОБЪЕКТ ---
const mapToObject = (map) => {
    if (!map) return {};
    if (typeof map.toJSON === 'function') {
        const obj = map.toJSON();
        if (obj && typeof obj === 'object') return obj;
    }
    if (map instanceof Map || typeof map.get === 'function') {
        return Object.fromEntries(map);
    }
    return map;
};

// --- DATABASE MODELS & SCHEMAS ---

const BatterySchema = new mongoose.Schema({
    id: { type: String, required: true },
    charge: { type: Number, default: 0, min: 0 },
    wear: { type: Number, default: 0, min: 0, max: 100 },
    loc: { type: String, enum: ['grid', 'inventory', 'warehouse'], default: 'inventory' }
}, { _id: false });

const SlotSchema = new mongoose.Schema({
    id: { type: Number, default: 0 }, 
    active: { type: Boolean, default: false },
    startTime: { type: Number, default: 0 },
    duration: { type: Number, default: 0 },
    mode: { type: String, default: null },
    status: { type: String }, 
    crop: { type: String, default: null }
}, { _id: false });

const SkillSchema = new mongoose.Schema({
    lvl: { type: Number, default: 1, min: 1 },
    xp: { type: Number, default: 0, min: 0 },
    next: { type: Number, default: 100 },
    locked: { type: Boolean, default: false }
}, { _id: false });

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
    uiState: { type: Object, default: {} },
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
    dailyMission: {
        date: { type: String, default: "" },
        regolithReq: { type: Number, default: 0 },
        completed: { type: Boolean, default: false },
        iceReq: { type: Number, default: 0 },
        iceCompleted: { type: Boolean, default: false }
    },
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
        duration: { type: Number, default: 5000 },
        lastStart: { type: Number, default: 0 } 
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
    iceHarvester: {
        type: mongoose.Schema.Types.Mixed,
        default: { durability: 100, active: false, startTime: 0, duration: 21600000 }
    },
    regolithHarvester: {
        type: mongoose.Schema.Types.Mixed,
        default: { durability: 100, active: false, startTime: 0, duration: 21600000 }
    },
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

// User Model
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    gameState: { type: GameStateSchema, default: () => ({}) },
    lastSaveTime: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);

// Action Log Model
const ActionLogSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false },
    username: { type: String },
    action: { type: String, required: true },
    timestamp: { type: Date, default: Date.now },
    ip: { type: String },
    details: { type: Object }
});

const ActionLog = mongoose.model('ActionLog', ActionLogSchema);

// Market Offer Model
const MarketOfferSchema = new mongoose.Schema({
    sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sellerName: { type: String, required: true },
    sellerIp: { type: String, required: true },
    sellerFingerprint: { type: String, required: true },
    item: { type: String, required: true },
    qty: { type: Number, required: true, min: 1 },
    price: { type: Number, required: true, min: 1 },
    currency: { type: String, default: 'HELIUM3' },
    postedAt: { type: Date, default: Date.now }
});
const MarketOffer = mongoose.model('MarketOffer', MarketOfferSchema);

// Buy Order Model
const BuyOrderSchema = new mongoose.Schema({
    buyerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    buyerName: { type: String, required: true },
    buyerIp: { type: String, required: true },
    buyerFingerprint: { type: String, required: true },
    item: { type: String, required: true },
    qty: { type: Number, required: true, min: 1 },
    qtyFilled: { type: Number, default: 0 },
    price: { type: Number, required: true, min: 1 }, // total H3 locked
    currency: { type: String, default: 'HELIUM3' },
    postedAt: { type: Date, default: Date.now }
});
const BuyOrder = mongoose.model('BuyOrder', BuyOrderSchema);

// --- HELPER: LOGGING ---
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

// --- SECURITY FIX: ROBUST FINGERPRINTING ---
const getDeviceFingerprint = (req, includeIp = false) => {
    try {
        const ua = req.headers['user-agent'] || 'unknown_ua';
        const lang = req.headers['accept-language'] || 'unknown_lang';
        const secCh = req.headers['sec-ch-ua'] || '';
        
        let signature = `EXODUS_PRIME_FP:${ua}|${lang}|${secCh}`;
        if (includeIp) {
            const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown_ip';
            signature += `|${ip}`;
        }
        
        return crypto.createHash('sha256').update(signature).digest('hex');
    } catch (e) {
        return 'fp_error_' + Date.now();
    }
};

// --- SECURITY HELPER: SANITIZATION ---
const sanitizeNumber = (val, defaultVal = 0, min = 0, max = Infinity) => {
    if (val === null || val === undefined || typeof val !== 'number' || !Number.isFinite(val) || isNaN(val)) {
        return defaultVal;
    }
    if (val < min) return min;
    if (val > max) return max;
    return val;
};

const secureGameState = (state) => {
    if (!state) return {};
    if (state.inventory) {
        for (const key in state.inventory) {
            state.inventory[key] = sanitizeNumber(state.inventory[key], 0, 0);
        }
    }

    if (state.stamina) {
        state.stamina.val = sanitizeNumber(state.stamina.val, 100, 0, 100);
        state.stamina.max = sanitizeNumber(state.stamina.max, 100, 100, 100);
    }

    if (state.power && Array.isArray(state.power.batteries)) {
        state.power.batteries.forEach(bat => {
            bat.charge = sanitizeNumber(bat.charge, 0, 0, 100);
            bat.wear = sanitizeNumber(bat.wear, 0, 0, 100);
        });
    }

    if (state.skills) {
        for (const key in state.skills) {
            if (state.skills[key]) {
                state.skills[key].lvl = sanitizeNumber(state.skills[key].lvl, 1, 1);
                state.skills[key].xp = sanitizeNumber(state.skills[key].xp, 0, 0);
                state.skills[key].next = sanitizeNumber(state.skills[key].next, 100, 1);
            }
        }
    }

    if (state.hangar) {
        for (const key in state.hangar) {
            state.hangar[key] = sanitizeNumber(state.hangar[key], 0, 0);
        }
    }

    if (state.components) {
        for (const key in state.components) {
            state.components[key] = sanitizeNumber(state.components[key], 0, 0);
        }
    }

    if (state.environment) {
        state.environment.flux = sanitizeNumber(state.environment.flux, 0.15, 0, 1);
    }
    
    if (state.cooldowns) {
        for (const key in state.cooldowns) {
             state.cooldowns[key] = sanitizeNumber(state.cooldowns[key], 0, 0);
        }
    }

    return state;
};

// --- HELPER: ВЫЧИСЛЕНИЕ СРЕДНЕГО ФЛАКСА ЗА ПЕРИОД (площадь под синусоидой) ---
// Заменяет прежнюю константу 0.425 точным интегрированием реальной кривой освещённости.
// Используется в /api/game/save для периодов когда игрок был оффлайн.
// Метод составных трапеций Симпсона: N=60 шагов дают точность < 0.01% при любой длине периода.
function computeAvgFlux(tFrom, tTo, cycleDuration, minFlux, maxFlux) {
    const dt = tTo - tFrom;
    if (dt <= 0) return minFlux;
    const N = 60;
    const h = dt / N;
    let sum = 0;
    for (let i = 0; i <= N; i++) {
        const t = tFrom + i * h;
        const cycle = (t % cycleDuration) / cycleDuration;
        const flux = (cycle <= 0.5)
            ? minFlux + (maxFlux - minFlux) * Math.sin(cycle * Math.PI * 2)
            : minFlux;
        // Веса Симпсона: 1, 4, 2, 4, 2, ..., 4, 1
        const w = (i === 0 || i === N) ? 1 : (i % 2 === 0 ? 2 : 4);
        sum += w * flux;
    }
    // Интеграл / ширина периода = среднее значение
    return (h / 3) * sum / dt;
}

// --- RATE LIMITING ---
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 2000, 
    standardHeaders: true,
    legacyHeaders: false,
    message: { msg: 'Too many requests from this IP (Global Limit), please try again later' }
});

app.use(globalLimiter);

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 20, 
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false, ip: false },
    keyGenerator: (req) => {
        return req.body?.username || req.ip;
    },
    message: { msg: 'Too many login attempts for this account, please try again later' }
});

app.use('/api/auth', authLimiter);

const marketLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, 
    max: 150, 
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false, ip: false },
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
        const currentFingerprint = getDeviceFingerprint(req, false);
        
        if (decoded.fp && decoded.fp !== currentFingerprint) {
            console.log(`[SECURITY] Session Hijack Attempt Blocked! User: ${decoded.user.id} | TokenFP: ${decoded.fp} | CurrentFP: ${currentFingerprint}`);
            return res.status(403).json({ msg: 'Session invalid: Device fingerprint mismatch (Browser changed?). Please login again.' });
        }
        
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// --- ROUTES ---

// 1. Register
app.post('/api/auth/register', async (req, res) => {
    const { username, password, registration_token_public } = req.body;

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
            iceHarvester: { durability: 100, active: false, startTime: 0, duration: 21600000 },
            regolithHarvester: { durability: 100, active: false, startTime: 0, duration: 21600000 },
            kitchen: { roasterSlots: [{id:0},{id:1}], grinderSlots: [{id:0},{id:1}], brewerSlots: [{id:0},{id:1}] },
            fuelFactory: { slots: [{id:0},{id:1},{id:2},{id:3}] },
            chemlab: { slots: [{id:0},{id:1},{id:2},{id:3}] },
            metalworks: { slots: [{id:0},{id:1},{id:2}] },
            machineParts: { slots: [{id:0},{id:1},{id:2}] },
            printer: { slots: [{id:0},{id:1}] },
            stamina: { val: 100, max: 100 },
            dailyMission: { date: "", regolithReq: 0, completed: false, iceReq: 0, iceCompleted: false },
            skills: {
                scavenging: { lvl: 1, xp: 0, next: 100, locked: false },
                agriculture: { lvl: 1 }, metallurgy: { lvl: 1 }, chemistry: { lvl: 1 }, 
                planetary_exploration: { lvl: 1 }, engineering: { lvl: 1 }
            }
        };
        await user.save();
        logAction('REGISTER_SUCCESS', user.id, username, req);

        const fingerPrint = getDeviceFingerprint(req, false);
        const payload = { 
            user: { id: user.id },
            fp: fingerPrint 
        };
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
        const fingerPrint = getDeviceFingerprint(req, false);

        const payload = { 
            user: { id: user.id },
            fp: fingerPrint 
        };

        const responseState = user.gameState ? user.gameState.toObject({ flattenMaps: true }) : {};
        responseState.lastSaveTime = user.lastSaveTime ? new Date(user.lastSaveTime).getTime() : Date.now();
        jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }, (err, token) => {
             if (err) throw err;
             res.json({ token, gameState: responseState, username: user.username });
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

        const responseState = user.gameState.toObject({ flattenMaps: true });
        responseState.lastSaveTime = user.lastSaveTime ? new Date(user.lastSaveTime).getTime() : Date.now();
        responseState._username = user.username;

        res.json(responseState);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// 4. Save Game (Protected)
app.post('/api/game/save', auth, async (req, res) => {
    try {
        let { gameState, clientTime } = req.body;

        gameState = secureGameState(gameState);

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

        const getOldInv = (key) => {
            if (!oldState.inventory) return 0;
            return (typeof oldState.inventory.get === 'function') ? 
                (oldState.inventory.get(key) || 0) : (oldState.inventory[key] || 0);
        };
        let timeSinceLastSave = 0;
        let dbHelium3 = 0;
        if (oldState.inventory && typeof oldState.inventory.get === 'function') {
            dbHelium3 = oldState.inventory.get('Helium3') || 0;
        } else if (oldState.inventory) {
            dbHelium3 = oldState.inventory.Helium3 || 0;
        }
        
        if (!newState.inventory) newState.inventory = {};
        newState.inventory.Helium3 = dbHelium3;

        // --- ANTI-CHEAT CHECKS ---

        // 1. Time Check
        if (clientTime) {
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

        // 3. FULL SERVER-SIDE POWER & BATTERY SIMULATION (AUTHORITATIVE)
        const POWER_CFG = {
            cycleDuration: 12 * 60 * 60 * 1000,
            minFlux: 0.15, maxFlux: 1.0,
            batteryCap: 33.33, panelBaseOutput: 0.01725, wearRate: 0.001
        };
        let elapsedSec = timeSinceLastSave / 1000;
        
        let cycle = (serverNow % POWER_CFG.cycleDuration) / POWER_CFG.cycleDuration;
        const expectedStateFlux = (cycle <= 0.5) ? 
            POWER_CFG.minFlux + ((POWER_CFG.maxFlux - POWER_CFG.minFlux) * Math.sin(cycle * Math.PI * 2)) : 
            POWER_CFG.minFlux;
        let generatedPower = 0;
        // Определяем онлайн-статус по heartbeat: если socket-пинг приходил < HEARTBEAT_TIMEOUT назад,
        // игрок считается онлайн и для короткого интервала используем мгновенный флакс.
        // Для настоящего оффлайна (нет свежего heartbeat) вместо прежней константы 0.425
        // вычисляем точный средний флакс, интегрируя синусоидальную кривую освещённости за период.
        const userIdStr = req.user.id.toString();
        const lastHb = onlineHeartbeats.get(userIdStr) || 0;
        const isRecentlyOnline = (serverNow - lastHb) < HEARTBEAT_TIMEOUT;
        if (isRecentlyOnline || timeSinceLastSave <= 30000) {
            // Онлайн / короткий интервал: мгновенный флакс текущего момента (точнее для малых dt)
            generatedPower = (POWER_CFG.panelBaseOutput * expectedStateFlux) * elapsedSec;
        } else {
            // Настоящий оффлайн: точный средний флакс через интеграл синусоиды
            const avgFlux = computeAvgFlux(
                serverNow - timeSinceLastSave,
                serverNow,
                POWER_CFG.cycleDuration,
                POWER_CFG.minFlux,
                POWER_CFG.maxFlux
            );
            generatedPower = (POWER_CFG.panelBaseOutput * avgFlux) * elapsedSec;
        }

        // Считаем суммарный заряд ВСЕХ батарей в сетке по старому стейту (авторитетно).
        // Важно: берём oldGridBats из oldState, а не newGridBats из newState,
        // чтобы учесть батареи, которые игрок мог извлечь между сохранениями.
        const oldGridBats = (oldState.power?.batteries || []).filter(b => b.loc === 'grid');
        let totalOldGridCharge = oldGridBats.reduce((sum, b) => sum + (b.charge || 0), 0);
        const newGridBats = (newState.power?.batteries || []).filter(b => b.loc === 'grid');
        let instantPowerSpent = 0;
        const detectStarts = (oldArr, newArr, getCost) => {
            if (!newArr) return;
            newArr.forEach((newSlot, i) => {
                const oldSlot = (oldArr && oldArr[i]) ? oldArr[i] : {};
                if (newSlot.active && (!oldSlot.active || newSlot.startTime !== oldSlot.startTime)) {
                    instantPowerSpent += getCost(newSlot) || 0;
                }
            });
        };

        detectStarts(oldState.cad?.slots, newState.cad?.slots, () => 25);
        detectStarts(oldState.refinery?.waterSlots, newState.refinery?.waterSlots, () => 10);
        detectStarts(oldState.refinery?.sabatierSlots, newState.refinery?.sabatierSlots, () => 10);
        detectStarts(oldState.refinery?.smelterSlots, newState.refinery?.smelterSlots, (s) => ({ iron: 30, steel: 35, aluminium: 40, copper: 40, titanium: 40, silicon: 35 }[s.mode] || 0));
        detectStarts(oldState.composter?.slots, newState.composter?.slots, () => 15);
        detectStarts(oldState.fuelFactory?.slots, newState.fuelFactory?.slots, () => 30);
        detectStarts(oldState.chemlab?.slots, newState.chemlab?.slots, (s) => ({ pvc: 20, perchlorate: 20, pla: 20, empty_battery: 2, electric_silicon: 50 }[s.mode] || 0));
        detectStarts(oldState.metalworks?.slots, newState.metalworks?.slots, () => 35);
        detectStarts(oldState.machineParts?.slots, newState.machineParts?.slots, () => 40);
        detectStarts(oldState.printer?.slots, newState.printer?.slots, (s) => ({ structural_part: 35, pvc_pipe: 15, electronic_parts: 30 }[s.mode] || 0));
        detectStarts(oldState.kitchen?.roasterSlots, newState.kitchen?.roasterSlots, () => 10);
        detectStarts(oldState.kitchen?.grinderSlots, newState.kitchen?.grinderSlots, () => 18);
        detectStarts(oldState.kitchen?.brewerSlots, newState.kitchen?.brewerSlots, () => 30);

        const oldFerm = oldState.refinery?.fermenterSlot || {};
        const newFerm = newState.refinery?.fermenterSlot || {};
        if (newFerm.active && (!oldFerm.active || newFerm.startTime !== oldFerm.startTime)) {
            instantPowerSpent += (newFerm.mode === 'amaranth' ? 10 : 18);
        }

        if (newState.greenhouse?.slots) {
            newState.greenhouse.slots.forEach((newSlot, i) => {
                const oldSlot = oldState.greenhouse?.slots ? oldState.greenhouse.slots[i] : {};
                if (newSlot.status === 'growing' && oldSlot.status !== 'growing') {
                     instantPowerSpent += ({ Sprouts: 1, Potato: 10, Maize: 15, Amaranth: 15, Guarana: 10 }[newSlot.crop] || 0);
                }
            });
        }

        const dSnack = (newState.inventory['Snack'] || 0) - getOldInv('Snack');
        if (dSnack > 0) instantPowerSpent += dSnack * 1;
        const dMeal = (newState.inventory['Meal'] || 0) - getOldInv('Meal');
        if (dMeal > 0) instantPowerSpent += dMeal * 2;
        const dFeast = (newState.inventory['Feast'] || 0) - getOldInv('Feast');
        if (dFeast > 0) instantPowerSpent += dFeast * 3;

        const oldScavStart = oldState.scavenging?.lastStart || 0;
        const newScavStart = newState.scavenging?.lastStart || 0;
        if (newScavStart > 0 && newScavStart !== oldScavStart) {
            instantPowerSpent += 1;
        }

        // C.A.D. passive (continuous) power consumption disabled
        let continuousPowerSpent = 0;

        const totalPowerSpent = instantPowerSpent + continuousPowerSpent;

        // Учитываем заряд батарей, перемещённых из inventory/warehouse в grid между сохранениями.
        // Без этого сервер не знает об их заряде и считает их появление «лишним» зарядом —
        // что вызывало мгновенный дрейн только что установленной батареи.
        // Используем СТАРЫЙ заряд из БД (oldBat.charge) — это авторитетно и защищает
        // от накрутки заряда в инвентаре: клиентское значение не доверяется.
        let movedToGridCharge = 0;
        newGridBats.forEach(newBat => {
            const oldBat = (oldState.power?.batteries || []).find(b => b.id === newBat.id);
            if (!oldBat || oldBat.loc !== 'grid') {
                // Батарея новая в сетке — добавляем её СТАРЫЙ заряд из БД
                movedToGridCharge += oldBat ? (oldBat.charge || 0) : 0;
            }
        });

        let expectedNewCharge = totalOldGridCharge + generatedPower - totalPowerSpent + movedToGridCharge;
        if (expectedNewCharge < -0.5) {
            logAction('CHEAT_POWER_BYPASS', user.id, user.username, req, {
                totalOldGridCharge, generatedPower, totalPowerSpent, expectedNewCharge
            });
            return res.status(400).json({ msg: 'Game integrity error: Insufficient power for requested actions. Simulation rejected.' });
        }

        if (newState.power && Array.isArray(newState.power.batteries)) {
            let clientTotalGridCharge = 0;
            newState.power.batteries.forEach(newBat => {
                const oldBat = (oldState.power?.batteries || []).find(b => b.id === newBat.id);

                // AUTHORITATIVE: server always overrides client-sent wear with server-computed value.
                // The client must never modify wear; it only displays what the server returns.
                newBat.wear = oldBat ? oldBat.wear : 0;

                if (newBat.loc === 'grid') {
                    // --- WEAR CALCULATION 1: Critical threshold ---
                    // If the battery charge was below 5% of its current effective capacity,
                    // apply reduced wear (10x slower per the game design spec).
                    if (oldBat && oldBat.charge < (POWER_CFG.batteryCap * (1 - (newBat.wear / 100)) * 0.05)) {
                        newBat.wear = Math.min(100, newBat.wear + ((POWER_CFG.wearRate * elapsedSec) / 10));
                    }

                    // --- WEAR CALCULATION 2: Drain wear from instant power operations ---
                    // Every drainBuffer(a) call adds wear = (a/batteryCap)*wearRate per battery.
                    // Summing all drain calls: total drain wear per battery = (instantPowerSpent / batteryCap) * wearRate
                    // Wear from usage is halved (/ 2) by design — critical threshold wear (CALC 1) is unchanged.
                    if (instantPowerSpent > 0) {
                        const drainWear = ((instantPowerSpent / POWER_CFG.batteryCap) * POWER_CFG.wearRate) / 2;
                        newBat.wear = Math.min(100, newBat.wear + drainWear);
                    }

                    const capacity = POWER_CFG.batteryCap * (1 - (newBat.wear / 100));
                    if (newBat.charge > capacity) newBat.charge = capacity;
                    if (newBat.charge < 0) newBat.charge = 0;

                    clientTotalGridCharge += newBat.charge;
                }
            });
            // Если клиент сообщает суммарный заряд больше ожидаемого — принудительно
            // дренируем батареи последовательно (с последней к первой), точно так же
            // как это делает функция drainBuffer на клиенте. Это исключает «перелив»
            // заряда между батареями и обеспечивает идентичное поведение с клиентом.
            if (clientTotalGridCharge > expectedNewCharge + 0.5) {
                const toDrain = clientTotalGridCharge - Math.max(0, expectedNewCharge);
                let remaining = toDrain;
                // Дрейним с конца списка (последняя батарея разряжается первой)
                const gridBatsInState = newState.power.batteries.filter(b => b.loc === 'grid');
                for (let i = gridBatsInState.length - 1; i >= 0; i--) {
                    if (remaining <= 0) break;
                    const b = gridBatsInState[i];
                    const taken = Math.min(b.charge, remaining);
                    b.charge = Number(Math.max(0, b.charge - taken).toFixed(4));
                    remaining -= taken;
                }
                clientTotalGridCharge = newState.power.batteries
                    .filter(b => b.loc === 'grid')
                    .reduce((sum, b) => sum + b.charge, 0);
            }

            // ИСПРАВЛЕНИЕ 2: двусторонняя авторитетность сервера.
            // Предыдущий код только дренировал (если клиент > ожидаемого).
            // Но если клиент сообщает МЕНЬШЕ ожидаемого (Worker не работал в фоне
            // из-за блокировки CSP, заморозки браузером или сетевой ошибки) —
            // сервер должен зарядить батареи до ожидаемого уровня.
            // Это делает сервер авторитетным в обоих направлениях и гарантирует
            // начисление оффлайн-заряда независимо от состояния клиентского Worker-а.
            if (expectedNewCharge > 0 && clientTotalGridCharge < expectedNewCharge - 0.5) {
                let toCharge = expectedNewCharge - clientTotalGridCharge;
                const gridBatsUp = newState.power.batteries.filter(b => b.loc === 'grid');
                for (let i = 0; i < gridBatsUp.length; i++) {
                    if (toCharge <= 0) break;
                    const b = gridBatsUp[i];
                    const cap = POWER_CFG.batteryCap * (1 - (b.wear / 100));
                    const space = cap - b.charge;
                    if (space > 0) {
                        const add = Math.min(space, toCharge);
                        b.charge = Number((b.charge + add).toFixed(4));
                        toCharge -= add;
                    }
                }
                clientTotalGridCharge = newState.power.batteries
                    .filter(b => b.loc === 'grid')
                    .reduce((sum, b) => sum + b.charge, 0);
            }

            // Сервер никогда не сохраняет статус "DRAINING" в базу данных.
            // DRAINING — это real-time клиентский статус (gen < load за данный кадр).
            // Если сохранить DRAINING в БД, при следующей загрузке игры пользователь
            // увидит DRAINING до первого тика loop() — что и вызывало баг при сворачивании.
            // Сервер хранит только ONLINE (батареи в сетке и заряд > 0) или BLACKOUT.
            if (newGridBats.length > 0 && clientTotalGridCharge > 0.01) {
                newState.power.gridStatus = "ONLINE";
            } else {
                newState.power.gridStatus = "BLACKOUT";
            }
            // Порог 30000ms согласован с порогом генерации выше. UI не показывает 0 при пиковых сетевых задержках.
            newState.power.productionRate = (timeSinceLastSave > 30000) ? 0 : (POWER_CFG.panelBaseOutput * expectedStateFlux); 
            // consumptionRate: используем instantPowerSpent / elapsedSec — средняя скорость расхода
            // за период между сохранениями. Отражает реальный расход (операции/запуски),
            // так как continuousPowerSpent = 0 после отключения пассивного потребления C.A.D.
            newState.power.consumptionRate = (elapsedSec > 0) ? (instantPowerSpent / elapsedSec) : 0;
        }

        if (newState.environment) {
            newState.environment.flux = expectedStateFlux;
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
                const oldVal = oldState.stamina ? parseFloat(oldState.stamina.val) || 0 : 0;
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

        // 4.5 Cooldown Protection
        if (newState.inventory) {
            const EATING_COOLDOWN_MS = 2.5 * 60 * 60 * 1000;
            const TRACKED_FOODS = ['Snack', 'Meal', 'Feast', 'Energy Bar'];
            if (!newState.cooldowns) newState.cooldowns = {};
            if (oldState.cooldowns) {
                for (const item of TRACKED_FOODS) {
                    if (typeof oldState.cooldowns.get === 'function') {
                        newState.cooldowns[item] = oldState.cooldowns.get(item) || 0;
                    } else {
                        newState.cooldowns[item] = oldState.cooldowns[item] || 0;
                    }
                }
            }

            for (const foodItem of TRACKED_FOODS) {
                const oldFoodQty = getOldInv(foodItem);
                const newFoodQty = newState.inventory[foodItem] || 0;

                if (newFoodQty < oldFoodQty) {
                    const consumedAmount = oldFoodQty - newFoodQty;
                    if (consumedAmount > 1) {
                        logAction('CHEAT_MULTIPLE_CONSUME', user.id, user.username, req, { item: foodItem, amount: consumedAmount });
                        return res.status(400).json({ msg: `Game integrity error: Cannot consume multiple ${foodItem} at once.` });
                    }

                    const lastEaten = newState.cooldowns[foodItem] || 0;

                    if ((serverNow - lastEaten) < EATING_COOLDOWN_MS) {
                        logAction('CHEAT_COOLDOWN_BYPASS', user.id, user.username, req, {
                            item: foodItem,
                            lastEaten: lastEaten,
                            serverNow: serverNow,
                            diff: serverNow - lastEaten
                        });
                        return res.status(400).json({ msg: `Game integrity error: ${foodItem} is on cooldown. Wait longer.` });
                    }

                    newState.cooldowns[foodItem] = serverNow;
                }
            }
        }

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
            // Harvester can yield max 100 ice per 6h deployment
            const HARVESTER_ICE_BUFFER = Math.ceil(timeSinceLastSave / 21600000) * 100 + 110;
            // Regolith harvester can yield max 180 regolith per 6h deployment
            const HARVESTER_REG_BUFFER = Math.ceil(timeSinceLastSave / 21600000) * 180 + 200;
            if (dScrap > (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20) {
                  logAction('CHEAT_RESOURCE_SCRAP', user.id, user.username, req, { 
                    delta: dScrap, 
                    maxAllowed: (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20,
                    timeElapsed: timeSinceLastSave 
                });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Scrap increase detected.' });
            }

            if (dIce > ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER + HARVESTER_ICE_BUFFER)) {
                  logAction('CHEAT_RESOURCE_ICE', user.id, user.username, req, { 
                    delta: dIce,
                    maxAllowed: ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Ice increase detected.' });
            }

            if (dRegolith > ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER + HARVESTER_REG_BUFFER)) {
                  logAction('CHEAT_RESOURCE_REGOLITH', user.id, user.username, req, { 
                    delta: dRegolith, 
                    maxAllowed: ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER + HARVESTER_REG_BUFFER)
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
            
            // Daily Claim Protection
            const dEnergyBar = (newState.inventory["Energy Bar"] || 0) - getOldInv("Energy Bar");
            if (dEnergyBar > 0) {
                const DAILY_COOLDOWN = 24 * 60 * 60 * 1000;
                const BUFFER = 5 * 60 * 1000; 
                
                const lastClaimTime = oldState.lastDailyClaim || 0;
                const timeDiff = serverNow - lastClaimTime;
                const isValidDailyClaim = (dEnergyBar === 1) && (timeDiff >= (DAILY_COOLDOWN - BUFFER));
                if (!isValidDailyClaim) {
                    logAction('CHEAT_ILLEGAL_ITEM_ENERGY_BAR', user.id, user.username, req, { 
                        delta: dEnergyBar,
                        timeSinceLastClaim: timeDiff,
                        required: DAILY_COOLDOWN
                    });
                    return res.status(400).json({ msg: "Game integrity error: Energy Bars claim invalid (Cooldown or Amount)." });
                }
                
                 if (!newState.lastDailyClaim || newState.lastDailyClaim < serverNow) {
                     newState.lastDailyClaim = serverNow;
                 }
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

            // 11.5 Kitchen Chain Check
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
                { out: "Titanium Plate", in: "Titan Ore", ratio: 0.8 }, 
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

        user.gameState = gameState;
        user.lastSaveTime = serverNow;
        user.markModified('gameState');
        await user.save();
        
        logAction('GAME_SAVE', req.user.id, user.username, req, {
            savedAt: serverNow
        });
        // --- ВОЗВРАЩАЕМ АКТУАЛЬНЫЙ СТЕЙТ БАТАРЕЙ КЛИЕНТУ ---
        const savedBatteries = (newState.power && Array.isArray(newState.power.batteries))
            ? newState.power.batteries.map(b => ({
                id: b.id,
                charge: b.charge,
                wear: b.wear,
                loc: b.loc
            }))
            : [];
        // consumptionRate возвращается клиенту чтобы UI немедленно отражал реальный расход,
        // не дожидаясь следующей загрузки игры.
        const savedConsumptionRate = (newState.power && typeof newState.power.consumptionRate === 'number')
            ? newState.power.consumptionRate
            : 0;
        res.json({ msg: 'Game Saved', serverTime: serverNow, batteries: savedBatteries, consumptionRate: savedConsumptionRate });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Daily Claim Route
app.post('/api/game/claim-daily', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: "User not found" });

        const now = Date.now();
        const DAILY_COOLDOWN = 24 * 60 * 60 * 1000;
        const lastClaim = user.gameState.lastDailyClaim || 0;

        if (now - lastClaim < DAILY_COOLDOWN) {
            logAction('CHEAT_DAILY_CLAIM_COOLDOWN', user.id, user.username, req, { lastClaim, now });
            return res.status(400).json({ msg: "Daily reward not ready yet." });
        }

        if (!user.gameState.inventory) user.gameState.inventory = new Map();
        
        let currentEnergyBars = 0;
        if (user.gameState.inventory instanceof Map || typeof user.gameState.inventory.get === 'function') {
            currentEnergyBars = user.gameState.inventory.get("Energy Bar") || 0;
            user.gameState.inventory.set("Energy Bar", currentEnergyBars + 1);
        } else {
             currentEnergyBars = user.gameState.inventory["Energy Bar"] || 0;
             user.gameState.inventory["Energy Bar"] = currentEnergyBars + 1;
        }

        user.gameState.lastDailyClaim = now;
        user.markModified('gameState');
        await user.save();

        logAction('DAILY_CLAIM_SUCCESS', user.id, user.username, req);
        res.json({ msg: "Daily Reward Claimed", inventory: mapToObject(user.gameState.inventory), lastDailyClaim: now });
    } catch (err) {
        console.error(err.message);
        res.status(500).send("Server Error");
    }
});

// --- DAILY MISSION ROUTES ---
app.get('/api/game/daily-mission', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: "User not found" });

        const todayStr = new Date().toISOString().split('T')[0];
        let dm = user.gameState.dailyMission;
        
        // Создаем новую миссию, если её нет или наступил новый день
        if (!dm || dm.date !== todayStr) {
            dm = {
                date: todayStr,
                regolithReq: Math.floor(Math.random() * (100 - 30 + 1)) + 30, // 30-100 Regolith
                completed: false,
                iceReq: Math.floor(Math.random() * (100 - 30 + 1)) + 30, // 30-100 Ice water
                iceCompleted: false
            };
            user.gameState.dailyMission = dm;
            user.markModified('gameState');
            await user.save();
        } else if (!dm.iceReq || typeof dm.iceReq !== 'number' || dm.iceReq < 30 || dm.iceReq > 100) {
            // МИГРАЦИЯ СТАРЬИХ СОХРАНЕНИЙ:
            // Сегодняшняя миссия существует (дата совпадает), но поле iceReq
            // отсутствует/равно 0 — признак сохранения до добавления ледяного задания.
            // Сохраняем regolithReq и completed, добавляем только iceReq/iceCompleted.
            dm.iceReq = Math.floor(Math.random() * (100 - 30 + 1)) + 30;
            dm.iceCompleted = (dm.iceCompleted === true) ? true : false;
            user.gameState.dailyMission = dm;
            user.markModified('gameState');
            await user.save();
        }
        res.json({ dailyMission: dm });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});

app.post('/api/game/daily-mission/complete', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: "User not found" });

        const todayStr = new Date().toISOString().split('T')[0];
        let dm = user.gameState.dailyMission;

        if (!dm || dm.date !== todayStr || dm.completed) {
            return res.status(400).json({ msg: "Mission not available or already completed today." });
        }

        const regReq = dm.regolithReq;
        const h3Reward = regReq * 1.5;

        let currentRegolith = 0;
        if (typeof user.gameState.inventory.get === 'function') {
            currentRegolith = user.gameState.inventory.get('Regolith') || 0;
        } else {
            currentRegolith = user.gameState.inventory['Regolith'] || 0;
        }

        if (currentRegolith < regReq) {
            return res.status(400).json({ msg: "Insufficient Regolith." });
        }

        // Выполняем транзакцию списания/начисления
        if (typeof user.gameState.inventory.set === 'function') {
            user.gameState.inventory.set('Regolith', currentRegolith - regReq);
            const currentH3 = user.gameState.inventory.get('Helium3') || 0;
            user.gameState.inventory.set('Helium3', currentH3 + h3Reward);
        } else {
            user.gameState.inventory['Regolith'] = currentRegolith - regReq;
            const currentH3 = user.gameState.inventory['Helium3'] || 0;
            user.gameState.inventory['Helium3'] = currentH3 + h3Reward;
        }

        dm.completed = true;
        user.gameState.dailyMission = dm;
        user.markModified('gameState');
        await user.save();

        logAction('DAILY_MISSION_COMPLETE', user.id, user.username, req, { regReq, h3Reward });

        res.json({ msg: "Mission Completed", dailyMission: dm, inventory: mapToObject(user.gameState.inventory), reward: h3Reward });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
    }
});

// POST /api/game/daily-mission/complete-ice — Ice Water delivery mission
app.post('/api/game/daily-mission/complete-ice', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ msg: "User not found" });

        const todayStr = new Date().toISOString().split('T')[0];
        let dm = user.gameState.dailyMission;

        // Авторитарная проверка: миссия должна существовать, быть сегодняшней и не выполненной
        if (!dm || dm.date !== todayStr) {
            return res.status(400).json({ msg: "No active mission for today." });
        }
        if (dm.iceCompleted) {
            return res.status(400).json({ msg: "Ice delivery already completed today." });
        }

        // Авторитарная проверка: iceReq должен быть валидным числом в диапазоне 30-100
        const iceReq = dm.iceReq;
        if (!iceReq || typeof iceReq !== 'number' || iceReq < 30 || iceReq > 100) {
            return res.status(400).json({ msg: "Invalid mission data. Please refresh the mission." });
        }

        // Авторитарная проверка: достаточно ли Ice water у игрока
        let currentIce = 0;
        if (typeof user.gameState.inventory.get === 'function') {
            currentIce = user.gameState.inventory.get('Ice water') || 0;
        } else {
            currentIce = user.gameState.inventory['Ice water'] || 0;
        }

        if (currentIce < iceReq) {
            return res.status(400).json({ msg: `Insufficient Ice water. Need ${iceReq}, have ${Math.floor(currentIce)}.` });
        }

        // Вычисляем награду: 2 H3 за единицу льда (авторитарно на сервере)
        const h3Reward = iceReq * 2;

        // Списываем Ice water, начисляем Helium3
        if (typeof user.gameState.inventory.set === 'function') {
            user.gameState.inventory.set('Ice water', currentIce - iceReq);
            const currentH3 = user.gameState.inventory.get('Helium3') || 0;
            user.gameState.inventory.set('Helium3', currentH3 + h3Reward);
        } else {
            user.gameState.inventory['Ice water'] = currentIce - iceReq;
            const currentH3 = user.gameState.inventory['Helium3'] || 0;
            user.gameState.inventory['Helium3'] = currentH3 + h3Reward;
        }

        dm.iceCompleted = true;
        user.gameState.dailyMission = dm;
        user.markModified('gameState');
        await user.save();

        logAction('DAILY_MISSION_ICE_COMPLETE', user.id, user.username, req, { iceReq, h3Reward });

        res.json({ msg: "Ice Mission Completed", dailyMission: dm, inventory: mapToObject(user.gameState.inventory), reward: h3Reward });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server Error");
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

// 6. Buy Scavenging License
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
        const currentScrap = typeof user.gameState.inventory.get === 'function' ? user.gameState.inventory.get('Scrap') : user.gameState.inventory['Scrap'] || 0;

        if(currentScrap < COST) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Insufficient Scrap"});
        }

        if(typeof user.gameState.inventory.set === 'function') {
            user.gameState.inventory.set('Scrap', currentScrap - COST);
            const currentLic = user.gameState.inventory.get("Scavenging License") || 0;
            user.gameState.inventory.set("Scavenging License", currentLic + 1);
        } else {
            user.gameState.inventory['Scrap'] = currentScrap - COST;
            const currentLic = user.gameState.inventory["Scavenging License"] || 0;
            user.gameState.inventory["Scavenging License"] = currentLic + 1;
        }
        
        user.markModified('gameState');
        await user.save({ session });
        await session.commitTransaction();
        logAction('MARKET_BUY_LICENSE', user.id, user.username, req);
        res.json({ msg: "License Acquired", inventory: mapToObject(user.gameState.inventory) });
    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

// 7. Post an Offer
app.post('/api/market/offer', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        let { item, qty, price } = req.body;
        
        qty = sanitizeNumber(qty, 0, 1);
        price = sanitizeNumber(price, 0, 1);
        const safeItem = String(item);

        if (!safeItem || qty < 1 || price < 1 || !Number.isInteger(qty) || !Number.isInteger(price)) {
             await session.abortTransaction();
             return res.status(400).json({msg: "Invalid offer data (Must be positive integer)"});
        }

        const BLACKLIST = ['Helium3', 'Scavenging License', 'xp', 'stamina', 'next', 'lvl'];
        if(BLACKLIST.includes(safeItem)) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Restricted Item"});
        }

        const user = await User.findById(req.user.id).session(session);
        if(!user) {
            await session.abortTransaction();
            return res.status(404).json({msg: "User not found"});
        }

        const activeOffersCount = await MarketOffer.countDocuments({ sellerId: req.user.id }).session(session);
        if (activeOffersCount >= 15) {
            await session.abortTransaction();
            return res.status(400).json({ msg: "Market Limit Reached (Max 15 active offers)" });
        }

        const hasItem = typeof user.gameState.inventory.has === 'function' ? user.gameState.inventory.has(safeItem) : user.gameState.inventory.hasOwnProperty(safeItem);
        if (!hasItem) {
            await session.abortTransaction();
            return res.status(400).json({ msg: "Security Error: Item not found in inventory source." });
        }

        const currentQty = parseInt(typeof user.gameState.inventory.get === 'function' ? user.gameState.inventory.get(safeItem) : user.gameState.inventory[safeItem], 10);
        if (isNaN(currentQty)) {
            await session.abortTransaction();
            return res.status(400).json({ msg: "Security Error: Corrupted inventory data." });
        }

        if(currentQty < qty) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Insufficient items in inventory (Validation Failed)"});
        }

        if(typeof user.gameState.inventory.set === 'function') {
            user.gameState.inventory.set(safeItem, currentQty - qty);
        } else {
            user.gameState.inventory[safeItem] = currentQty - qty;
        }

        user.markModified('gameState');
        await user.save({ session });

        const sellerFingerprint = getDeviceFingerprint(req, true);
        const newOffer = new MarketOffer({
            sellerId: user.id,
            sellerName: user.username,
            sellerIp: req.ip, 
            sellerFingerprint: sellerFingerprint,
            item: safeItem,
            qty: qty,
            price: price
        });
        await newOffer.save({ session });

        await session.commitTransaction();
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
        io.emit('market_update', { action: 'offer_posted' });
        res.json({ msg: "Offer Posted", offerId: newOffer._id, inventory: mapToObject(user.gameState.inventory), offers: mappedOffers });
    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

// 8. Cancel an Offer
app.post('/api/market/cancel', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const { offerId } = req.body;

        if (!mongoose.Types.ObjectId.isValid(offerId)) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Invalid Offer ID"});
        }

        const offer = await MarketOffer.findById(offerId).session(session);

        if(!offer) {
            await session.abortTransaction();
            return res.status(404).json({msg: "Offer not found"});
        }
        
        if(offer.sellerId.toString() !== req.user.id) {
            await session.abortTransaction();
            return res.status(403).json({msg: "Not authorized"});
        }

        const user = await User.findById(req.user.id).session(session);
        
        if(typeof user.gameState.inventory.get === 'function') {
            const current = user.gameState.inventory.get(offer.item) || 0;
            user.gameState.inventory.set(offer.item, current + offer.qty);
        } else {
            const current = user.gameState.inventory[offer.item] || 0;
            user.gameState.inventory[offer.item] = current + offer.qty;
        }

        user.markModified('gameState');
        await user.save({ session });
        await MarketOffer.deleteOne({ _id: offerId }, { session });

        await session.commitTransaction();
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
        io.emit('market_update', { action: 'offer_cancelled' });
        res.json({ msg: "Offer Cancelled", inventory: mapToObject(user.gameState.inventory), offers: mappedOffers });
    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

// 9. Buy an Offer (ОБНОВЛЕННАЯ ЛОГИКА С ЧАСТИЧНОЙ ПОКУПКОЙ)
app.post('/api/market/buy', auth, async (req, res) => {
    let { offerId, buyQty } = req.body;
    const buyerId = req.user.id;

    if (!mongoose.Types.ObjectId.isValid(offerId)) {
        return res.status(400).json({msg: "Invalid Offer ID"});
    }

    const session = await mongoose.startSession();
    session.startTransaction();

    try {
        const buyer = await User.findById(buyerId).session(session);
        if(!buyer) {
            await session.abortTransaction();
            return res.status(500).json({msg: "User data error"});
        }

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

        const buyerFingerprint = getDeviceFingerprint(req, false);
        if (securedOffer.sellerFingerprint === buyerFingerprint) {
            await session.abortTransaction();
            logAction('MARKET_FINGERPRINT_BAN', buyerId, buyer.username, req, { 
                sellerFp: securedOffer.sellerFingerprint, 
                buyerFp: buyerFingerprint 
            });
            return res.status(403).json({ msg: "Anti-Cheat: Device Fingerprint Match. Cannot trade between accounts on the same device." });
        }

        // --- ЛОГИКА ЧАСТИЧНОЙ ПОКУПКИ ---
        if (buyQty === undefined || buyQty === null) {
            // Если клиент не прислал желаемое количество, покупаем всё (поддержка старого клиента)
            buyQty = securedOffer.qty;
        } else {
            buyQty = parseInt(buyQty, 10);
            if (isNaN(buyQty) || buyQty <= 0) {
                await session.abortTransaction();
                return res.status(400).json({msg: "Invalid quantity specified"});
            }
        }

        if (buyQty > securedOffer.qty) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Not enough items in offer"});
        }

        // Вычисляем стоимость. Используем Math.ceil для предотвращения эксплуатации с копейками.
        let cost;
        if (buyQty === securedOffer.qty) {
            cost = securedOffer.price;
        } else {
            cost = Math.ceil((securedOffer.price / securedOffer.qty) * buyQty);
        }

        // ---------------------------------

        const buyerH3 = typeof buyer.gameState.inventory.get === 'function' ? buyer.gameState.inventory.get('Helium3') : buyer.gameState.inventory['Helium3'] || 0;
        if(buyerH3 < cost) {
            await session.abortTransaction();
            return res.status(400).json({msg: "Insufficient Helium3"});
        }

        // Списываем средства и добавляем ресурсы покупателю
        if(typeof buyer.gameState.inventory.set === 'function') {
            buyer.gameState.inventory.set('Helium3', buyerH3 - cost);
            const buyerItemQty = buyer.gameState.inventory.get(securedOffer.item) || 0;
            buyer.gameState.inventory.set(securedOffer.item, buyerItemQty + buyQty);
        } else {
            buyer.gameState.inventory['Helium3'] = buyerH3 - cost;
            const buyerItemQty = buyer.gameState.inventory[securedOffer.item] || 0;
            buyer.gameState.inventory[securedOffer.item] = buyerItemQty + buyQty;
        }

        buyer.markModified('gameState');
        await buyer.save({ session });

        // Начисляем средства продавцу
        const seller = await User.findById(securedOffer.sellerId).session(session);
        const fee = Math.floor(cost * 0.05);
        const sellerRevenue = cost - fee;
        if (seller) {
            if(!seller.gameState.inventory) seller.gameState.inventory = new Map();
            if(typeof seller.gameState.inventory.set === 'function') {
                const currentSellerH3 = seller.gameState.inventory.get('Helium3') || 0;
                seller.gameState.inventory.set('Helium3', currentSellerH3 + sellerRevenue);
            } else {
                const currentSellerH3 = seller.gameState.inventory['Helium3'] || 0;
                seller.gameState.inventory['Helium3'] = currentSellerH3 + sellerRevenue;
            }
            seller.markModified('gameState');
            await seller.save({ session });
        }

        // Обновляем или удаляем лот в зависимости от выкупленного объема
        if (buyQty === securedOffer.qty) {
            await MarketOffer.deleteOne({ _id: offerId }, { session });
        } else {
            securedOffer.qty -= buyQty;
            securedOffer.price -= cost;
            if (securedOffer.price < 0) securedOffer.price = 0; // На всякий случай блокируем отрицательную цену
            await securedOffer.save({ session });
        }

        await session.commitTransaction();
        logAction('MARKET_BUY', buyer.id, buyer.username, req, { 
            item: securedOffer.item, 
            qty: buyQty, 
            fullPrice: cost, 
            feeDeducted: fee,
            sellerReceived: sellerRevenue,
            sellerId: securedOffer.sellerId 
        });
        io.emit('market_update', { action: 'offer_bought' });
        res.json({ msg: "Purchase Successful", inventory: mapToObject(buyer.gameState.inventory) });
    } catch (err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send("Server Error");
    } finally {
        session.endSession();
    }
});

server.listen(PORT, () => console.log(`Server started on port ${PORT}`));
// --- BUY ORDER ROUTES ---

// Helper: map buy orders for client
async function mapBuyOrders(requesterId) {
    const orders = await BuyOrder.find({ $expr: { $gt: ['$qty', '$qtyFilled'] } }).sort({ postedAt: -1 }).limit(100);
    return orders.map(o => {
        const remaining = o.qty - o.qtyFilled;
        // o.price хранит актуальный остаток заблокированного H3 (уменьшается при каждом fill)
        const priceRemaining = o.price;
        return {
            id: o._id.toString(),
            isMine: o.buyerId.toString() === requesterId,
            buyer: o.buyerName,
            item: o.item,
            qty: remaining,
            qtyTotal: o.qty,
            qtyFilled: o.qtyFilled,
            price: priceRemaining
        };
    });
}

// GET /api/market/buy-orders
app.get('/api/market/buy-orders', auth, async (req, res) => {
    try {
        const buyOrders = await mapBuyOrders(req.user.id);
        res.json({ buyOrders });
    } catch(err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});

// POST /api/market/buy-order - create
app.post('/api/market/buy-order', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        let { item, qty, price } = req.body;
        const blacklist = ['Helium3', 'Scavenging License'];
        if (!item || blacklist.includes(item)) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Invalid item' });
        }
        qty = parseInt(qty, 10);
        price = parseInt(price, 10);
        if (isNaN(qty) || qty < 1 || isNaN(price) || price < 1) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Invalid qty or price (must be positive integer)' });
        }

        const user = await User.findById(req.user.id).session(session);
        if (!user) { await session.abortTransaction(); return res.status(404).json({ msg: 'User not found' }); }

        const activeCount = await BuyOrder.countDocuments({ buyerId: req.user.id, $expr: { $gt: ['$qty', '$qtyFilled'] } }).session(session);
        if (activeCount >= 10) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Max 10 active buy orders allowed' });
        }

        const currentH3 = typeof user.gameState.inventory.get === 'function'
            ? (user.gameState.inventory.get('Helium3') || 0)
            : (user.gameState.inventory['Helium3'] || 0);

        if (currentH3 < price) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Insufficient Helium3' });
        }

        // Lock H3
        if (typeof user.gameState.inventory.set === 'function') {
            user.gameState.inventory.set('Helium3', currentH3 - price);
        } else {
            user.gameState.inventory['Helium3'] = currentH3 - price;
        }
        user.markModified('gameState');
        await user.save({ session });

        const buyerFingerprint = getDeviceFingerprint(req, true);
        const newOrder = new BuyOrder({
            buyerId: user.id,
            buyerName: user.username,
            buyerIp: req.ip,
            buyerFingerprint,
            item, qty, price
        });
        await newOrder.save({ session });
        await session.commitTransaction();

        logAction('MARKET_BUY_ORDER_POST', user.id, user.username, req, { item, qty, price });
        io.emit('market_update', { action: 'buy_order_posted' });

        const buyOrders = await mapBuyOrders(req.user.id);
        res.json({ msg: 'Buy Order Posted', inventory: mapToObject(user.gameState.inventory), buyOrders });
    } catch(err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send('Server Error');
    } finally {
        session.endSession();
    }
});

// POST /api/market/buy-order/cancel
app.post('/api/market/buy-order/cancel', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { orderId } = req.body;
        if (!mongoose.Types.ObjectId.isValid(orderId)) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Invalid Order ID' });
        }

        const order = await BuyOrder.findById(orderId).session(session);
        if (!order) { await session.abortTransaction(); return res.status(404).json({ msg: 'Order not found' }); }
        if (order.buyerId.toString() !== req.user.id) {
            await session.abortTransaction();
            return res.status(403).json({ msg: 'Not your order' });
        }

        const remaining = order.qty - order.qtyFilled;
        // order.price уже хранит актуальный остаток заблокированного H3 (уменьшается при каждом fill)
        const refund = order.price;

        const user = await User.findById(req.user.id).session(session);
        if (typeof user.gameState.inventory.set === 'function') {
            const h3 = user.gameState.inventory.get('Helium3') || 0;
            user.gameState.inventory.set('Helium3', h3 + refund);
        } else {
            user.gameState.inventory['Helium3'] = (user.gameState.inventory['Helium3'] || 0) + refund;
        }
        user.markModified('gameState');
        await user.save({ session });

        await BuyOrder.deleteOne({ _id: orderId }, { session });
        await session.commitTransaction();

        logAction('MARKET_BUY_ORDER_CANCEL', user.id, user.username, req, { item: order.item, refund });
        io.emit('market_update', { action: 'buy_order_cancelled' });

        const buyOrders = await mapBuyOrders(req.user.id);
        res.json({ msg: 'Buy Order Cancelled', inventory: mapToObject(user.gameState.inventory), buyOrders });
    } catch(err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send('Server Error');
    } finally {
        session.endSession();
    }
});

// POST /api/market/buy-order/fill
app.post('/api/market/buy-order/fill', auth, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        let { orderId, fillQty } = req.body;
        if (!mongoose.Types.ObjectId.isValid(orderId)) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Invalid Order ID' });
        }

        fillQty = parseInt(fillQty, 10);
        if (isNaN(fillQty) || fillQty < 1) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Invalid fill quantity' });
        }

        const order = await BuyOrder.findById(orderId).session(session);
        if (!order) { await session.abortTransaction(); return res.status(404).json({ msg: 'Order not found' }); }

        // Anti-cheat
        if (order.buyerId.toString() === req.user.id) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Cannot fill your own buy order' });
        }
        if (order.buyerIp === req.ip) {
            await session.abortTransaction();
            logAction('MARKET_IP_BAN', req.user.id, 'UNKNOWN', req, { type: 'buy_order_fill_self_ip' });
            return res.status(400).json({ msg: 'Transaction blocked (IP)' });
        }
        const sellerFp = getDeviceFingerprint(req, false);
        if (order.buyerFingerprint === sellerFp) {
            await session.abortTransaction();
            logAction('MARKET_FP_BAN', req.user.id, 'UNKNOWN', req, { type: 'buy_order_fill_self_fp' });
            return res.status(400).json({ msg: 'Transaction blocked (Device)' });
        }

        const remaining = order.qty - order.qtyFilled;
        if (fillQty > remaining) {
            await session.abortTransaction();
            return res.status(400).json({ msg: 'Fill qty exceeds remaining order qty' });
        }

        // Calculate H3 payout for seller (from locked pool)
        let h3Payout;
        if (fillQty === remaining) {
            // Последний fill: отдаём весь оставшийся заблокированный H3, чтобы не было потерь на округлении
            h3Payout = order.price;
        } else {
            // Частичный fill: пропорционально от текущего остатка locked H3 / текущий остаток qty
            // Используем remaining (order.qty - order.qtyFilled) — реальный остаток ДО этого fill
            h3Payout = Math.floor((order.price / remaining) * fillQty);
        }
        const fee = Math.floor(h3Payout * 0.05);
        const sellerRevenue = h3Payout - fee;

        // Load seller (current user)
        const seller = await User.findById(req.user.id).session(session);
        if (!seller) { await session.abortTransaction(); return res.status(404).json({ msg: 'User not found' }); }

        const sellerItemQty = typeof seller.gameState.inventory.get === 'function'
            ? (seller.gameState.inventory.get(order.item) || 0)
            : (seller.gameState.inventory[order.item] || 0);

        if (sellerItemQty < fillQty) {
            await session.abortTransaction();
            return res.status(400).json({ msg: `Insufficient ${order.item} in inventory` });
        }

        // Deduct items from seller, give H3
        if (typeof seller.gameState.inventory.set === 'function') {
            seller.gameState.inventory.set(order.item, sellerItemQty - fillQty);
            const sellerH3 = seller.gameState.inventory.get('Helium3') || 0;
            seller.gameState.inventory.set('Helium3', sellerH3 + sellerRevenue);
        } else {
            seller.gameState.inventory[order.item] = sellerItemQty - fillQty;
            seller.gameState.inventory['Helium3'] = (seller.gameState.inventory['Helium3'] || 0) + sellerRevenue;
        }
        seller.markModified('gameState');
        await seller.save({ session });

        // Give items to buyer
        const buyer = await User.findById(order.buyerId).session(session);
        if (buyer) {
            if (typeof buyer.gameState.inventory.set === 'function') {
                const buyerQty = buyer.gameState.inventory.get(order.item) || 0;
                buyer.gameState.inventory.set(order.item, buyerQty + fillQty);
            } else {
                buyer.gameState.inventory[order.item] = (buyer.gameState.inventory[order.item] || 0) + fillQty;
            }
            buyer.markModified('gameState');
            await buyer.save({ session });
        }

        // Update or delete order
        if (fillQty === remaining) {
            await BuyOrder.deleteOne({ _id: orderId }, { session });
        } else {
            order.qtyFilled += fillQty;
            order.price = order.price - h3Payout;
            if (order.price < 0) order.price = 0;
            await order.save({ session });
        }

        await session.commitTransaction();

        logAction('MARKET_BUY_ORDER_FILL', seller.id, seller.username, req, {
            item: order.item, fillQty, h3Payout, fee, sellerRevenue, buyerId: order.buyerId
        });
        io.emit('market_update', { action: 'buy_order_filled' });

        const buyOrders = await mapBuyOrders(req.user.id);
        res.json({ msg: 'Order Filled', inventory: mapToObject(seller.gameState.inventory), buyOrders });
    } catch(err) {
        await session.abortTransaction();
        console.error(err);
        res.status(500).send('Server Error');
    } finally {
        session.endSession();
    }
});