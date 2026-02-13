require('dotenv').config(); // [cite: 1]
const express = require('express'); // [cite: 2]
const mongoose = require('mongoose'); // [cite: 3]
const cors = require('cors'); // [cite: 4]
const bcrypt = require('bcryptjs'); // [cite: 5]
const jwt = require('jsonwebtoken'); // [cite: 6]
const User = require('./models/User'); // [cite: 7]

const app = express(); // [cite: 8]
const PORT = process.env.PORT || 5000; // [cite: 9]
const JWT_SECRET = process.env.JWT_SECRET || 'exodus_prime_secret_key_change_me'; // [cite: 10]

// --- НОВАЯ МОДЕЛЬ ДЛЯ ЛОГОВ (Лучше вынести в models/ActionLog.js) ---
const ActionLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }, // false, т.к. при ошибке входа ID может не быть
  username: { type: String }, // Для записи попыток входа
  action: { type: String, required: true }, // Например: 'REGISTER', 'LOGIN', 'GAME_SAVE'
  timestamp: { type: Date, default: Date.now },
  ip: { type: String },
  details: { type: Object } // Любые доп. данные
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

// Middleware
app.use(express.json({ limit: '10mb' })); // [cite: 12]
app.use(cors()); // [cite: 13]
app.use(express.static('public')); // [cite: 14]

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI) // [cite: 16]
  .then(() => console.log('MongoDB Atlas Connected')) // [cite: 17]
  .catch(err => console.error('MongoDB Error:', err)); // [cite: 18]

// --- AUTH MIDDLEWARE ---
const auth = (req, res, next) => { // [cite: 20]
  const token = req.header('x-auth-token'); // [cite: 21]
  if (!token) return res.status(401).json({ msg: 'No token, authorization denied' }); // [cite: 22]

  try {
    const decoded = jwt.verify(token, JWT_SECRET); // [cite: 24]
    req.user = decoded.user; // [cite: 25]
    next(); // [cite: 26]
  } catch (err) {
    res.status(401).json({ msg: 'Token is not valid' }); // [cite: 28]
  }
};

// --- ROUTES ---

// 1. Register
app.post('/api/auth/register', async (req, res) => { // 
  const { username, password } = req.body; // [cite: 34]
  try {
    let user = await User.findOne({ username }); // [cite: 36]
    if (user) {
        // Логируем неудачную попытку регистрации
        await logAction('REGISTER_FAIL_EXISTS', null, username, req); 
        return res.status(400).json({ msg: 'User already exists' }); // [cite: 37]
    }

    user = new User({ username, password }); // [cite: 38]
    const salt = await bcrypt.genSalt(10); // [cite: 40]
    user.password = await bcrypt.hash(password, salt); // [cite: 41]
    await user.save(); // [cite: 42]

    // Логируем успешную регистрацию
    await logAction('REGISTER_SUCCESS', user.id, username, req); 

    const payload = { user: { id: user.id } }; // [cite: 44]
    jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }, (err, token) => { // [cite: 45]
      if (err) throw err;
      res.json({ token }); // [cite: 47]
    });
  } catch (err) {
    console.error(err.message); // [cite: 50]
    res.status(500).send('Server error'); // [cite: 51]
  }
});

// 2. Login
app.post('/api/auth/login', async (req, res) => { // 
  const { username, password } = req.body; // [cite: 56]
  try {
    let user = await User.findOne({ username }); // [cite: 58]
    if (!user) {
        // Логируем попытку входа с неверным именем пользователя
        await logAction('LOGIN_FAIL_USER', null, username, req); 
        return res.status(400).json({ msg: 'Invalid Credentials' }); // [cite: 59]
    }

    const isMatch = await bcrypt.compare(password, user.password); // [cite: 60]
    if (!isMatch) {
        // Логируем попытку входа с неверным паролем
        await logAction('LOGIN_FAIL_PASSWORD', user.id, username, req); 
        return res.status(400).json({ msg: 'Invalid Credentials' }); // [cite: 61]
    }

    // Логируем успешный вход
    await logAction('LOGIN_SUCCESS', user.id, username, req); 

    const payload = { user: { id: user.id } }; // [cite: 62]
    jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' }, (err, token) => { // [cite: 63]
      if (err) throw err;
      res.json({ token, gameState: user.gameState }); // [cite: 65]
    });
  } catch (err) {
    console.error(err.message); // [cite: 68]
    res.status(500).send('Server error'); // [cite: 69]
  }
});

// 3. Load Game (Protected)
app.get('/api/game/load', auth, async (req, res) => { // 
  try {
    const user = await User.findById(req.user.id).select('-password'); // [cite: 75]
    
    // Логируем попытку загрузки игры
    await logAction('GAME_LOAD', user.id, user.username, req); 
    
    res.json(user.gameState); // [cite: 76]
  } catch (err) {
    console.error(err.message); // [cite: 78]
    res.status(500).send('Server Error'); // [cite: 79]
  }
});

// 4. Save Game (Protected)
app.post('/api/game/save', auth, async (req, res) => { // 
  try {
    const { gameState } = req.body; // [cite: 85]
    
    await User.findByIdAndUpdate(req.user.id, { // [cite: 87]
      gameState: gameState, // [cite: 88]
      lastSaveTime: Date.now() // [cite: 89]
    });

    // Получаем пользователя, чтобы узнать имя (или сохраняем без него, только по ID)
    const user = await User.findById(req.user.id);

    // Логируем сохранение игры (можно сохранить и сам gameState, если нужно, в details)
    await logAction('GAME_SAVE', req.user.id, user ? user.username : 'Unknown', req, {
        savedAt: Date.now()
        // gameState: gameState // <-- Раскомментировать, если нужно хранить историю сохранений
    });

    res.json({ msg: 'Game Saved' }); // [cite: 91]
  } catch (err) {
    console.error(err.message); // [cite: 93]
    res.status(500).send('Server Error'); // [cite: 94]
  }
});

app.listen(PORT, () => console.log(`Server started on port ${PORT}`)); // [cite: 97]
