const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    gameState: {
        type: Object,
        default: {} // Сюда будет сохраняться весь объект STATE
    },
    lastSaveTime: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('User', UserSchema);
