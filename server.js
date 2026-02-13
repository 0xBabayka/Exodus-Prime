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
            const timeSinceLastSave = serverNow - new Date(user.lastSaveTime).getTime();
            if (timeSinceLastSave < 1000) { 
                return res.status(429).json({ msg: 'Saving too frequently. Slow down.' });
            }
        }

        // --- 3. ПРОВЕРКА СТАМИНЫ (CAP CHECK & CONSUMPTION CHECK) ---
        
        // Проверка наличия объектов стамины в новом состоянии
        if (newState.stamina) {
            const MAX_STAMINA_LIMIT = 100;

            // A. Cap Check: Проверка превышения лимита
            // Если текущее значение или максимальное значение больше 100 -> Чит (Memory hack)
            if (newState.stamina.val > MAX_STAMINA_LIMIT || newState.stamina.max > MAX_STAMINA_LIMIT) {
                await logAction('CHEAT_STAMINA_CAP', user.id, user.username, req, { 
                    val: newState.stamina.val, 
                    max: newState.stamina.max 
                });
                return res.status(400).json({ msg: 'Game integrity error: Stamina values exceed allowable limits.' });
            }

            // B. Consumption Check: Проверка оправданности роста стамины
            // Логика работает только если есть предыдущее состояние для сравнения
            if (oldState.stamina && oldState.inventory && newState.inventory) {
                const oldVal = parseFloat(oldState.stamina.val) || 0;
                const newVal = parseFloat(newState.stamina.val) || 0;
                const staminaDiff = newVal - oldVal;

                // Если стамина увеличилась
                if (staminaDiff > 0) {
                    // Список еды, которая дает стамину (из кода клиента)
                    const foodItems = [
                        'Snack', 
                        'Meal', 
                        'Feast', 
                        'Energy Bar', 
                        'Energy Isotonic'
                    ];

                    let hasConsumedFood = false;

                    // Проверяем, уменьшилось ли количество хоть одного типа еды
                    for (const item of foodItems) {
                        const oldQty = oldState.inventory[item] || 0;
                        const newQty = newState.inventory[item] || 0;
                        if (newQty < oldQty) {
                            hasConsumedFood = true;
                            break; // Нашли потребление, выход из цикла
                        }
                    }

                    // Если стамина выросла, но еда не уменьшилась -> Чит
                    // (Учитываем небольшой порог погрешности float, на всякий случай, но здесь логика жесткая: diff > 0.5)
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
