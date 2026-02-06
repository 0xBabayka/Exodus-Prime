const mongoose = require('mongoose');

const GameStateSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  lastSaveTime: { type: Number, default: Date.now },
  inventory: { type: mongoose.Schema.Types.Mixed, default: {} },
  stamina: { 
      val: { type: Number, default: 100 },
      max: { type: Number, default: 100 }
  },
  skills: { type: mongoose.Schema.Types.Mixed, default: {} },
  hangar: { type: mongoose.Schema.Types.Mixed, default: {} },
  components: { type: mongoose.Schema.Types.Mixed, default: {} },
  // Сохраняем сложные массивы слотов как Mixed объекты
  power: { type: mongoose.Schema.Types.Mixed, default: {} },
  cad: { type: mongoose.Schema.Types.Mixed, default: {} },
  metalworks: { type: mongoose.Schema.Types.Mixed, default: {} },
  machineParts: { type: mongoose.Schema.Types.Mixed, default: {} },
  refinery: { type: mongoose.Schema.Types.Mixed, default: {} },
  fuelFactory: { type: mongoose.Schema.Types.Mixed, default: {} },
  chemlab: { type: mongoose.Schema.Types.Mixed, default: {} },
  greenhouse: { type: mongoose.Schema.Types.Mixed, default: {} },
  composter: { type: mongoose.Schema.Types.Mixed, default: {} },
  scavenging: { type: mongoose.Schema.Types.Mixed, default: {} },
  cooldowns: { type: mongoose.Schema.Types.Mixed, default: {} },
  lastDailyClaim: { type: Number, default: 0 },
  buildQueue: { type: Array, default: [] }
});

module.exports = mongoose.model('GameState', GameStateSchema);
