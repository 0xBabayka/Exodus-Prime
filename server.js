require('dotenv').config();
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const { Server } = require('socket.io');
const path = require('path');
const GameState = require('./models/GameState');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- Middleware ---
// Простой middleware для логирования действий сокета
const socketLogger = (socket, next) => {
    console.log(`[SOCKET] New connection attempt: ${socket.id} at ${new Date().toISOString()}`);
    next();
};

io.use(socketLogger);

// Подключение к MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Atlas Connected'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// Раздача статики (клиентский код)
app.use(express.static(path.join(__dirname, 'public')));

// --- WebSocket Logic ---
io.on('connection', (socket) => {
    console.log(`User connected: ${socket.id}`);

    // Загрузка состояния при входе
    socket.on('join_game', async (userId) => {
        try {
            let state = await GameState.findOne({ userId });
            if (!state) {
                console.log(`Creating new save for user: ${userId}`);
                // Если сохранения нет, отправляем null, клиент создаст дефолтное состояние
                socket.emit('load_state', null);
            } else {
                console.log(`Loaded save for user: ${userId}`);
                socket.emit('load_state', state);
            }
        } catch (e) {
            console.error('Error loading state:', e);
        }
    });

    // Сохранение состояния (получаем полный STATE от клиента)
    socket.on('save_state', async (data) => {
        const { userId, state } = data;
        if (!userId || !state) return;

        try {
            // Обновляем или создаем запись (upsert)
            await GameState.findOneAndUpdate(
                { userId },
                { 
                    $set: {
                        lastSaveTime: Date.now(),
                        inventory: state.inventory,
                        stamina: state.stamina,
                        skills: state.skills,
                        hangar: state.hangar,
                        components: state.components,
                        power: state.power,
                        cad: state.cad,
                        metalworks: state.metalworks,
                        machineParts: state.machineParts,
                        refinery: state.refinery,
                        fuelFactory: state.fuelFactory,
                        chemlab: state.chemlab,
                        greenhouse: state.greenhouse,
                        composter: state.composter,
                        scavenging: state.scavenging,
                        cooldowns: state.cooldowns,
                        lastDailyClaim: state.lastDailyClaim,
                        buildQueue: state.buildQueue
                    }
                },
                { upsert: true, new: true }
            );
            // console.log(`State saved for ${userId}`); // Можно раскомментировать для отладки
        } catch (e) {
            console.error('Error saving state:', e);
        }
    });

    socket.on('disconnect', () => {
        console.log(`User disconnected: ${socket.id}`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
