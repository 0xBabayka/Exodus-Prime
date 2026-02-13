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
            // Max Regolith: 5 (base) + 5 (lucky bonus) = 10
            const MAX_REG_PER_SCAV = 10;
            // Max Ice: 3 (base) = 3
            const MAX_ICE_PER_SCAV = 3;
            // Max Scrap: 5 (base) + 5 (lucky bonus) = 10
            const MAX_SCRAP_PER_SCAV = 10;

            // Рассчитываем, сколько раз игрок мог теоретически нажать Scavenge за время между сохранениями
            // Добавляем +2 к количеству действий как буфер на сетевые задержки и погрешность таймера
            const maxActionsPossible = Math.ceil(timeSinceLastSave / SCAV_DURATION_MS) + 2;

            // Буфер для ресурсов, добытых кораблями (например, Miner привозит 50-75 ед.) или фильтрами
            // Так как корабли прибывают мгновенно, а сейв раз в 30 сек, большой скачок допустим, 
            // но мы ограничиваем аномально огромные значения (накрутку).
            const SHIP_BUFFER = 100;

            // 1. Валидация Scrap (Scrap добывается почти только Scavenging)
            // Здесь буфер меньше, так как корабли обычно не возят Scrap (согласно конфигу SPECS)
            if (dScrap > (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20) {
                 await logAction('CHEAT_RESOURCE_SCRAP', user.id, user.username, req, { 
                    delta: dScrap, 
                    maxAllowed: (maxActionsPossible * MAX_SCRAP_PER_SCAV) + 20,
                    timeElapsed: timeSinceLastSave 
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Scrap increase detected.' });
            }

            // 2. Валидация Ice (Scavenging + Ice World Mining + Trade)
            if (dIce > ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)) {
                 await logAction('CHEAT_RESOURCE_ICE', user.id, user.username, req, { 
                    delta: dIce,
                    maxAllowed: ((maxActionsPossible * MAX_ICE_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Ice increase detected.' });
            }

            // 3. Валидация Regolith (Scavenging + Mining + Water Filter Output)
            if (dRegolith > ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)) {
                 await logAction('CHEAT_RESOURCE_REGOLITH', user.id, user.username, req, { 
                    delta: dRegolith,
                    maxAllowed: ((maxActionsPossible * MAX_REG_PER_SCAV) + SHIP_BUFFER)
                });
                 return res.status(400).json({ msg: 'Game integrity error: Abnormal Regolith increase detected.' });
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
