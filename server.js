require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet'); 
const rateLimit = require('express-rate-limit'); 
const User = require('./models/User'); // Убедитесь, что этот путь верный в вашей структуре

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'exodus_prime_secret_key_change_me';

// --- SECURITY MIDDLEWARE (HELMET) ---
// Настроили CSP, чтобы разрешить 'onclick' и другие инлайн-скрипты
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            ...helmet.contentSecurityPolicy.getDefaultDirectives(),
            "script-src": ["'self'", "'unsafe-inline'"], // Разрешает <script> внутри HTML
            "script-src-attr": ["'unsafe-inline'"],      // Разрешает onclick="..."
            "img-src": ["'self'", "data:", "*"],          // Разрешает картинки
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

// Вспомогательная функция для записи лога
const logAction = async (action, userId, username, req, details = {}) => {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
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
        console.error('Logging Error:', err);
    }
};

// --- RATE LIMITING ---

// 1. Глобальный лимитер (для всех маршрутов)
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 100, // Лимит 100 запросов с одного IP
    message: { msg: 'Too many requests from this IP, please try again later' }
});
app.use(globalLimiter);

// 2. Лимитер для авторизации (более строгий для защиты от брутфорса)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 минут
    max: 20, // Лимит 20 попыток входа/регистрации
    message: { msg: 'Too many login attempts, please try again later' }
});
app.use('/api/auth', authLimiter); // Применяем только к маршрутам auth

// Middleware
app.use(express.json({ limit: '10mb' }));
app.use(cors());
app.use(express.static('public'));

// MongoDB Connection
// Убедитесь, что переменная окружения MONGO_URI задана
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
            await logAction('REGISTER_FAIL_EXISTS', null, username, req);
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({ username, password });
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        
        // Инициализация пустого состояния игры при регистрации
        user.gameState = {}; 
        
        await user.save();

        await logAction('REGISTER_SUCCESS', user.id, username, req);

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
            await logAction('LOGIN_FAIL_USER', null, username, req);
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            await logAction('LOGIN_FAIL_PASSWORD', user.id, username, req);
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        await logAction('LOGIN_SUCCESS', user.id, username, req);

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

        await logAction('GAME_LOAD', user.id, user.username, req);

        // Добавлен заголовок с серверным временем для синхронизации клиента.
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
        const newState = gameState; // Алиас для удобства
        const serverNow = Date.now();

        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        const oldState = user.gameState || {}; // Предыдущее сохраненное состояние
        let timeSinceLastSave = 0;

        // --- 1. ЗАЩИТА ОТ ПЕРЕМОТКИ ВРЕМЕНИ (ANTI-TIME-CHEAT) ---
        if (clientTime) {
            const timeDifference = Math.abs(serverNow - clientTime);
            const maxAllowedDifference = 5 * 60 * 1000; 

            if (timeDifference > maxAllowedDifference) {
                await logAction('CHEAT_ATTEMPT_TIME', user.id, user.username, req, { clientTime, serverNow });
                return res.status(400).json({ msg: 'Time manipulation detected or device clock out of sync. Please sync your clock.' });
            }
        }

        // --- 2. ПРОВЕРКА ЧАСТОТЫ СОХРАНЕНИЙ ---
        if (user.lastSaveTime) {
            timeSinceLastSave = serverNow - new Date(user.lastSaveTime).getTime();
            if (timeSinceLastSave < 1000) { 
                return res.status(429).json({ msg: 'Saving too frequently. Slow down.' });
            }
        } else {
            // Если это первое сохранение, даем буфер времени (например, 30 сек), чтобы разрешить начальные ресурсы
            timeSinceLastSave = 30000;
        }

        // --- 3. ПРОВЕРКА СТАМИНЫ (CAP CHECK & CONSUMPTION CHECK) ---
        
        // Проверка наличия объектов стамины в новом состоянии
        if (newState.stamina) {
            const MAX_STAMINA_LIMIT = 100;

            // A. Cap Check: Проверка превышения лимита
            if (newState.stamina.val > MAX_STAMINA_LIMIT || newState.stamina.max > MAX_STAMINA_LIMIT) {
                await logAction('CHEAT_STAMINA_CAP', user.id, user.username, req, { 
                    val: newState.stamina.val, 
                    max: newState.stamina.max 
                });
                return res.status(400).json({ msg: 'Game integrity error: Stamina values exceed allowable limits.' });
            }

            // B. Consumption Check: Проверка оправданности роста стамины
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
                        await logAction('CHEAT_STAMINA_NO_CONSUME', user.id, user.username, req, { 
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

        // --- 4. VALIDATION: SCAVENGING & RESOURCES (ICE, REGOLITH, SCRAP) ---
        if (oldState.inventory && newState.inventory) {
            // Рассчитываем изменение ресурсов
            const dRegolith = (newState.inventory.Regolith || 0) - (oldState.inventory.Regolith || 0);
            const dIce = (newState.inventory["Ice water"] || 0) - (oldState.inventory["Ice water"] || 0);
            const dScrap = (newState.inventory.Scrap || 0) - (oldState.inventory.Scrap || 0);

            // Параметры Scavenging из клиента (CODE_LOCAL)
            const SCAV_DURATION_MS = 5000;
            const MAX_REG_PER_SCAV = 10;
            const MAX_ICE_PER_SCAV = 3;
            const MAX_SCRAP_PER_SCAV = 10;

            const maxActionsPossible = Math.ceil(timeSinceLastSave / SCAV_DURATION_MS) + 2;
            const SHIP_BUFFER = 100;

            if (dScrap > (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20) {
                 await logAction('CHEAT_RESOURCE_SCRAP', user.id, user.username, req, { 
                    delta: dScrap, 
                    maxAllowed: (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20,
                    timeElapsed: timeSinceLastSave 
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Scrap increase detected.' });
            }

            if (dIce > ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)) {
                 await logAction('CHEAT_RESOURCE_ICE', user.id, user.username, req, { 
                    delta: dIce,
                    maxAllowed: ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Ice increase detected.' });
            }

            if (dRegolith > ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)) {
                 await logAction('CHEAT_RESOURCE_REGOLITH', user.id, user.username, req, { 
                    delta: dRegolith,
                    maxAllowed: ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Regolith increase detected.' });
            }

            // --- 5. VALIDATION: FOOD PRODUCTION & CONSUMPTION ---
            
            // 5a. Calculate Deltas for Rations and High-Tier Consumables
            const dSnack = (newState.inventory.Snack || 0) - (oldState.inventory.Snack || 0);
            const dMeal = (newState.inventory.Meal || 0) - (oldState.inventory.Meal || 0);
            const dFeast = (newState.inventory.Feast || 0) - (oldState.inventory.Feast || 0);
            const dIsotonic = (newState.inventory["Energy Isotonic"] || 0) - (oldState.inventory["Energy Isotonic"] || 0);
            
            // Deltas for raw crops/food
            const dFood = (newState.inventory.Food || 0) - (oldState.inventory.Food || 0);
            const dAmaranth = (newState.inventory.Amaranth || 0) - (oldState.inventory.Amaranth || 0);
            const dGuarana = (newState.inventory.Guarana || 0) - (oldState.inventory.Guarana || 0);

            // 5b. Validate Ration Cooking (Input/Output consistency)
            // Calculate how much generic "Food" resource SHOULD have been spent based on rations created
            let impliedFoodCost = 0;
            if (dSnack > 0) impliedFoodCost += dSnack * 30; // Cost: 30 Food
            if (dMeal > 0) impliedFoodCost += dMeal * 60;   // Cost: 60 Food
            if (dFeast > 0) impliedFoodCost += dFeast * 90; // Cost: 90 Food

            // 5c. Validate Maximum Harvest (Buffer check)
            // Theoretical max harvest logic:
            // Maize Yield: 70-90. Crit (Skill/5 stacks): 1.5x. Max per slot ~135.
            // Greenhouse Slots: 6. Max total single harvest: ~810 Food.
            // We give a generous buffer (1200) to account for rapid clicks or slight sync delays.
            // Formula: The "Net Change in Food" + "Food Spent on Rations" must be <= "Max Possible New Food from Harvest"
            // Example: If I cooked 1 Meal (Cost 60), my dFood is -60. (-60 + 60) <= 1200. OK.
            // Example: If I hacked +100 Meals, dFood is 0 (didn't spend). (0 + 6000) > 1200. CHEAT.
            const MAX_FOOD_HARVEST_BUFFER = 1200; 
            
            if ((dFood + impliedFoodCost) > MAX_FOOD_HARVEST_BUFFER) {
                await logAction('CHEAT_RESOURCE_FOOD_BALANCE', user.id, user.username, req, {
                    dFood, 
                    impliedFoodCost, 
                    netGain: dFood + impliedFoodCost,
                    limit: MAX_FOOD_HARVEST_BUFFER
                });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Food/Ration production balance.' });
            }

            // 5d. Validate Specific Crops (Amaranth/Guarana)
            // Amaranth/Guarana are items, not "Food" resource.
            // Amaranth Max: ~20 * 1.5 * 6 = 180. Buffer: 300.
            if (dAmaranth > 300) {
                await logAction('CHEAT_CROP_AMARANTH', user.id, user.username, req, { delta: dAmaranth });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Amaranth harvest.' });
            }
            // Guarana Max: ~30 * 1.5 * 6 = 270. Buffer: 400.
            if (dGuarana > 400) {
                await logAction('CHEAT_CROP_GUARANA', user.id, user.username, req, { delta: dGuarana });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Guarana harvest.' });
            }

            // 5e. Validate Time-Gated Production (Isotonic)
            // Isotonic takes 2 hours to brew. Max slots = 2. Max yield per slot = 5. 
            // Max yield per cycle = 10.
            // Even if multiple cycles finished exactly between saves (highly unlikely in 30s window),
            // a value > 25 indicates speed-hacking or inventory injection.
            if (dIsotonic > 25) {
                await logAction('CHEAT_RESOURCE_ISOTONIC', user.id, user.username, req, { delta: dIsotonic });
                return res.status(400).json({ msg: 'Game integrity error: Abnormal Energy Isotonic increase.' });
            }
        }

        // --- СОХРАНЕНИЕ ---
        user.gameState = gameState;
        user.lastSaveTime = serverNow;
        await user.save();

        await logAction('GAME_SAVE', req.user.id, user.username, req, {
            savedAt: serverNow
        });

        res.json({ msg: 'Game Saved', serverTime: serverNow }); 
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
