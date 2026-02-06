// --- CONFIG ---
const socket = io(); // Инициализация сокета
const USER_ID = "pilot_001"; // Для простоты хардкодим ID, в реальной системе это должно быть динамично

const CANVAS = document.getElementById('map');
const CTX = CANVAS.getContext('2d', { alpha: false });
const AU_SCALE = 150;
const BASE_SPEED = 0.001;
const DAILY_COOLDOWN = 24 * 60 * 60 * 1000;

// POWER & WEAR CONFIG
const POWER_CFG = {
    cycleDuration: 12 * 60 * 60 * 1000,
    minFlux: 0.15, maxFlux: 1.0,
    batteryCap: 33.33, panelBaseOutput: 0.015,
    baseLoad: 0, factoryLoad: 0,
    wearRate: 0.001,
    maxGridSlots: 3
};
const CAD_CFG = { powerCost: 25, staminaCost: 5, duration: 12 * 60 * 60 * 1000 };
const FILTER_CFG = { cost: { ice: 25, power: 10, stamina: 2 }, output: { water: 16, regolith: 4 }, duration: 4 * 60 * 60 * 1000 };
const COMPOST_CFG = { cost: { regolith: 20, waste: 5, water: 8, energy: 15, stamina: 8 }, output: { soil: 10 }, duration: 18 * 60 * 60 * 1000 };
const SMELTER_CFG = {
    iron: { cost: { regolith: 500, power: 30, stamina: 3 }, duration: 6 * 60 * 60 * 1000 },
    steel: { cost: { co2: 10, "Iron Ore": 10, power: 35, stamina: 8 }, duration: 6 * 60 * 60 * 1000 },
    aluminium: { cost: { regolith: 800, power: 40, stamina: 10 }, duration: 6 * 60 * 60 * 1000 },
    copper: { cost: { regolith: 1200, power: 40, stamina: 5 }, duration: 6 * 60 * 60 * 1000 },
    titanium: { cost: { regolith: 2000, power: 40, stamina: 5 }, duration: 6 * 60 * 60 * 1000 }
};
const SABATIER_CFG = {
    split: { cost: { water: 2, power: 10, stamina: 2 }, output: { h2: 2, o2: 1 }, duration: 3.5 * 60 * 60 * 1000 },
    methane: { cost: { h2: 5, co2: 2, power: 10, stamina: 4 }, output: { methane: 1, water: 2 }, duration: 4 * 60 * 60 * 1000 }
};
const FUEL_CFG = {
    methane: { cost: { methane: 25, power: 30, stamina: 10 }, output: { liquidMethane: 20 }, duration: 2 * 60 * 60 * 1000 },
    oxygen: { cost: { o2: 25, power: 30, stamina: 10 }, output: { liquidO2: 20 }, duration: 2 * 60 * 60 * 1000 },
    synthesis: { cost: { liquidMethane: 20, liquidO2: 20, power: 30, stamina: 15 }, output: { rocketFuel: 40 }, duration: 4 * 60 * 60 * 1000 }
};
// FERMENTATION CONFIG
const FERMENT_CFG = {
    amaranth: { cost: { amaranth: 20, power: 10, stamina: 2 }, output: { min: 13, max: 18 }, duration: 12 * 60 * 60 * 1000 },
    guarana: { cost: { guarana: 25, power: 18, stamina: 1 }, output: { min: 15, max: 20 }, duration: 12 * 60 * 60 * 1000 }
};
// CHEM LAB CONFIG
const CHEM_CFG = {
    pvc: { cost: { methane: 5, h2: 5, water: 5, power: 20, stamina: 4 }, duration: 8 * 60 * 60 * 1000 },
    perchlorate: { cost: { halite: 5, water: 6, power: 20, stamina: 5 }, duration: 6 * 60 * 60 * 1000 },
    pla: { cost: { "Fermented Guarana": 20, co2: 5, power: 20, stamina: 2 }, duration: 6 * 60 * 60 * 1000 },
    empty_battery: { cost: { perchlorate: 5, water: 5, "Iron Ore": 2, PVC: 2, power: 2, stamina: 2 }, duration: 4 * 60 * 60 * 1000 }
};
// METALWORKS CONFIG
const METALWORKS_CFG = {
    alum_plate: {
        cost: { "Aluminium Ore": 5, power: 35, stamina: 5 },
        output: { min: 2, max: 5 },
        duration: 2 * 60 * 60 * 1000
    },
    titanium_plate: {
        cost: { "Titanium Ore": 5, power: 35, stamina: 5 },
        output: { min: 2, max: 5 },
        duration: 2 * 60 * 60 * 1000
    }
};
// MACHINE PARTS CONFIG (NEW)
const MACHINE_PARTS_CFG = {
    machined_parts: {
        cost: { "Aluminium Plate": 5, Steel: 5, power: 40, stamina: 5 },
        output: { min: 2, max: 3 },
        duration: 6 * 60 * 60 * 1000
    },
    moving_parts: {
        cost: { "Aluminium Plate": 3, "Titanium Plate": 3, power: 40, stamina: 5 },
        output: { min: 2, max: 3 },
        duration: 6 * 60 * 60 * 1000
    }
};

const CROPS = {
    'Sprouts': { time: 4 * 60 * 60 * 1000, cost: { seed: 1, water: 1, soil: 1, energy: 1, stamina: 1 }, yieldMin: 10, yieldMax: 14, xp: 4 },
    'Potato': { time: 8 * 60 * 60 * 1000, cost: { seed: 1, water: 5, soil: 4, energy: 10, stamina: 3 }, yieldMin: 25, yieldMax: 55, xp: 12 },
    'Maize': { time: 12 * 60 * 60 * 1000, cost: { seed: 1, water: 10, soil: 5, energy: 15, stamina: 5 }, yieldMin: 70, yieldMax: 90, xp: 25 },
    'Amaranth': { time: 12 * 60 * 60 * 1000, cost: { seed: 1, water: 10, soil: 3, energy: 15, stamina: 3 }, yieldMin: 10, yieldMax: 20, xp: 20 },
    'Guarana': { time: 24 * 60 * 60 * 1000, cost: { seed: 1, water: 10, soil: 4, energy: 10, stamina: 5 }, yieldMin: 20, yieldMax: 30, xp: 30 }
};
const RATION_RECIPES = {
    'Snack': { food: 30, water: 10, energy: 1, waste: 2, minStam: 16, maxStam: 16 },
    'Meal':  { food: 60, water: 20, energy: 2, waste: 4, minStam: 20, maxStam: 28 },
    'Feast': { food: 90, water: 30, energy: 3, waste: 6, minStam: 28, maxStam: 36 }
};
const EATING_COOLDOWN_MS = 2.5 * 60 * 60 * 1000;

// --- SCAVENGING SKILL CONFIG UPDATED ---
const SCAV_TIERS = [
    { name: "NOVICE", min: 1, max: 10, xpReq: 100, color: "#a8a9ad", cert: "None" },
    { name: "APPRENTICE", min: 11, max: 20, xpReq: 250, color: "#44EE77", cert: "Certificate: Apprentice" },
    { name: "JOURNEYMAN", min: 21, max: 30, xpReq: 500, color: "#0099ff", cert: "Certificate: Journeyman" },
    { name: "EXPERT", min: 31, max: 40, xpReq: 1000, color: "#d400ff", cert: "Certificate: Expert" },
    { name: "MASTER", min: 41, max: 50, xpReq: 2500, color: "#FF8800", cert: "Certificate: Master" },
    { name: "ARTISAN", min: 51, max: 60, xpReq: 5000, color: "#FF3333", cert: "Certificate: Artisan" }
];

// UI CACHE OPTIMIZATION
const UI_CACHE = {};
// --- SAVE SYSTEM MODIFIED FOR WEBSOCKETS ---
const StorageSys = {
    save: function() {
        try {
            // Emit save event to server
            socket.emit('save_state', { userId: USER_ID, state: STATE });
        } catch(e) { console.error("Save failed", e); }
    },
    // Load is now handled via socket listener in init()
    processLoad: function(data) {
        try {
            if(data) {
                // Merge data from server into STATE
                Object.assign(STATE, data);

                // --- OFFLINE CHARGING LOGIC (FLUX SYNC) ---
                if(data.lastSaveTime) {
                    const now = Date.now();
                    const dt = now - data.lastSaveTime;
                    if(dt > 5000) { // Minimum 5 seconds to trigger

                        // CALCULATE AVERAGE FLUX BASED ON TIME CYCLE
                        let avgFlux = 0.425; // Default math average if time is huge (>24h)
                        if (dt < 24 * 60 * 60 * 1000) {
                            // Simulate flux minute by minute for accuracy under 24h
                            let accumulatedFlux = 0;
                            let steps = 0;
                            let simTime = data.lastSaveTime;
                            const stepSize = 60000; // 1 minute steps

                            while(simTime < now) {
                                let cycle = (simTime % POWER_CFG.cycleDuration) / POWER_CFG.cycleDuration;
                                let currentFlux = (cycle <= 0.5) ? 0.15 + (0.85 * Math.sin(cycle*2*Math.PI)) : 0.15;
                                accumulatedFlux += currentFlux;
                                simTime += stepSize;
                                steps++;
                            }
                            if(steps > 0) avgFlux = accumulatedFlux / steps;
                        }

                        // FIX: Convert dt (ms) to seconds for generation calc
                        const offlineGen = (POWER_CFG.panelBaseOutput * avgFlux) * (dt / 1000);
                        // Last recorded consumption (also converted to seconds)
                        const offlineLoad = (STATE.power.consumptionRate || 0) * (dt / 1000);
                        let net = offlineGen - offlineLoad;

                        if(net > 0) {
                            // Ensure batteries exist
                            if (!STATE.power.batteries) STATE.power.batteries = [];
                            const gBats = STATE.power.batteries.filter(b => b.loc === 'grid');
                            for(let b of gBats) {
                                if(net <= 0) break;
                                const max = POWER_CFG.batteryCap * (1 - (b.wear/100));
                                const space = max - b.charge;
                                if(space > 0) {
                                    const fill = Math.min(space, net);
                                    b.charge += fill;
                                    net -= fill;
                                }
                            }
                            setTimeout(() => log(`SYS: Offline ${(dt/3600000).toFixed(2)}h. Flux Avg: ${(avgFlux*100).toFixed(1)}%. Charge: +${(offlineGen-offlineLoad).toFixed(2)}kW`), 1000);
                        }
                    }
                }
                // ------------------------------

                // Force existence of items if missing from old saves
                const items = ['Snack', 'Meal', 'Feast', 'Energy Bar', 'Biological Waste', 'Methane', 'O2', 'Aluminium Ore', 'Copper Ore', 'Titanium Ore', 'Halite', 'Liquid CH4', 'Liquid O2', 'Rocket Fuel', 'PVC', 'Perchlorate', 'PLA', 'Empty Battery', 'Full Battery', 'Amaranth', 'Seeds: Amaranth', 'Guarana', 'Seeds: Guarana', 'Fermented Amaranth', 'Fermented Guarana', 'Scavenging License', 'Worms', 'Potato', 'Seeds: Potato', 'Seeds: Maize', 'Aluminium Plate', 'Titanium Plate', 'Machined Parts', 'Moving Parts'];
                items.forEach(i => { if(STATE.inventory[i] === undefined) STATE.inventory[i] = 0; });
                if(STATE.inventory.Barite === undefined) STATE.inventory.Barite = 0;
                if (!STATE.composter) STATE.composter = { slots: [{id:0, active:false, startTime:0, duration:0}, {id:1, active:false, startTime:0, duration:0}, {id:2, active:false, startTime:0, duration:0}] };
                if (!STATE.refinery.sabatierSlots) STATE.refinery.sabatierSlots = [{ id: 0, active: false, mode: null, startTime: 0, duration: 0 }, { id: 1, active: false, mode: null, startTime: 0, duration: 0 }];
                if (!STATE.refinery.smelterSlots) STATE.refinery.smelterSlots = [{ id: 0, active: false, mode: null, startTime: 0, duration: 0 }, { id: 1, active: false, mode: null, startTime: 0, duration: 0 }];
                if (!STATE.fuelFactory) {
                    STATE.fuelFactory = {
                        slots: [
                            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 2, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 3, active: false, mode: null, startTime: 0, duration: 0 }
                        ]
                    };
                } else {
                    STATE.fuelFactory.slots.forEach(s => { if(s.mode === undefined) s.mode = null; });
                }

                // --- METALWORKS INIT CHECK ---
                if (!STATE.metalworks) {
                    STATE.metalworks = {
                        slots: [
                            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 2, active: false, mode: null, startTime: 0, duration: 0 }
                        ]
                    };
                }

                // --- MACHINE PARTS INIT CHECK (NEW) ---
                if (!STATE.machineParts) {
                    STATE.machineParts = {
                        slots: [
                            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 2, active: false, mode: null, startTime: 0, duration: 0 }
                        ]
                    };
                }

                if (!STATE.cad.slots) {
                    const oldActive = STATE.cad.active || false;
                    const oldStart = STATE.cad.startTime || 0;
                    const oldDur = STATE.cad.duration || 0;
                    STATE.cad = {
                        slots: [
                            { id: 0, active: oldActive, startTime: oldStart, duration: oldDur },
                            { id: 1, active: false, startTime: 0, duration: 0 }
                        ]
                    };
                }

                if (!STATE.chemlab) {
                    STATE.chemlab = {
                        slots: [
                            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 2, active: false, mode: null, startTime: 0, duration: 0 },
                            { id: 3, active: false, mode: null, startTime: 0, duration: 0 }
                        ]
                    };
                }

                if (!STATE.refinery.fermenterSlot) {
                    STATE.refinery.fermenterSlot = { active: false, startTime: 0, duration: 0, mode: null };
                } else if (STATE.refinery.fermenterSlot.mode === undefined) {
                    STATE.refinery.fermenterSlot.mode = null;
                }

                const newSkills = ['metallurgy', 'chemistry', 'piloting', 'planetary_exploration', 'engineering', 'energy'];
                newSkills.forEach(s => {
                    if (!STATE.skills[s]) STATE.skills[s] = { lvl: 1, xp: 0, next: 100 };
                });
                if(STATE.skills.scavenging.locked === undefined) STATE.skills.scavenging.locked = false;
                if(STATE.skills.scavenging.lvl === 0) { STATE.skills.scavenging.lvl = 1; STATE.skills.scavenging.next = 100; }


                if (!STATE.lastDailyClaim) STATE.lastDailyClaim = 0;
                return true;
            }
        } catch(e) { console.error("Load failed", e); }
        return false;
    }
};

const DragManager = {
    item: null, offsetX: 0, offsetY: 0, zIndex: 50,
    init: function() {
        document.querySelectorAll('.draggable').forEach(el => {
            const h = el.querySelector('.header'); if(!h) return;
            h.addEventListener('mousedown', (e) => this.startDrag(e, el));
        });
        window.addEventListener('mousemove', (e) => this.drag(e));
        window.addEventListener('mouseup', () => this.stopDrag());
        document.getElementById('modal-overlay').addEventListener('mousedown', (e) => {
            if(e.target.id === 'modal-overlay') closeModal(null, true);
        });
    },
    startDrag: function(e, el) {
        this.item = el; this.zIndex++; this.item.style.zIndex = this.zIndex;
        const r = this.item.getBoundingClientRect();
        this.offsetX = e.clientX - r.left; this.offsetY = e.clientY - r.top;
        if (this.item.style.bottom && this.item.style.bottom !== 'auto') { this.item.style.top = r.top + 'px'; this.item.style.bottom = 'auto'; }
        if (this.item.style.right && this.item.style.right !== 'auto') { this.item.style.left = r.left + 'px'; this.item.style.right = 'auto'; }
    },
    drag: function(e) {
        if (!this.item) return; e.preventDefault();
        this.item.style.left = (e.clientX - this.offsetX) + 'px';
        this.item.style.top = (e.clientY - this.offsetY) + 'px'; this.item.style.transform = 'none';
    },
    stopDrag: function() { this.item = null; }
};

const COMPONENTS = {
    hull: { name: "Hull Plating", cost: { Steel: 20 } },
    engine: { name: "Ion Engine", cost: { Steel: 10, H2: 50 } },
    electronics: { name: "Electronics", cost: { Si: 15, Steel: 5 } },
    avionics: { name: "Avionics Suite", cost: { Si: 20, Pt: 1 } },
    lifesupport: { name: "Life Support", cost: { Steel: 10, Water: 5 } },
    battery: { name: "Micro-Cell", cost: { Steel: 10, Si: 10, Electronics: 1 } }
};
const SPECS = {
    probe:  { speed: 3.0, fuel: 0.2, cargo: 0,   color: '#00ffaa', buildTime: 2000, cost: {"Iron Ore":10, Si:5}, name: "Probe", desc: "Scanner" },
    miner:  { speed: 1.0, fuel: 1.0, cargo: 50,  color: '#0099ff', buildTime: 5000, cost: { hull:1, engine:1, electronics:1 }, name: "Miner", bonus: ['Iron Ore', 'Si', 'Steel'] },
    hauler: { speed: 0.5, fuel: 2.5, cargo: 400, color: '#d400ff', buildTime: 12000, cost: { hull:3, engine:2, electronics:1, avionics:1 }, name: "Hauler", bonus: [] },
    gas:    { speed: 1.2, fuel: 1.5, cargo: 100, color: '#e74c3c', buildTime: 8000, cost: { hull:1, engine:2, lifesupport:1, electronics:1 }, name: "Gas Harvester", bonus: ['Gas'] }
};

// --- STATE & INITIALIZATION ---
const STATE = {
    camera: { x: 0, y: 0 }, isDragging: false, lastMouse: { x: 0, y: 0 }, dragStart: { x: 0, y: 0 },
    zoom: 0.8, selectedObj: null,
    inventory: {
        H2: 0, "Iron Ore": 0, Si: 0, Steel: 0, "Ice water": 50, Water: 5,
        CO2: 0, Nitrogen: 0, Argon: 0, Neon: 0, Krypton: 0, Xenon: 0, Pt: 5, Gas: 0, Scrap: 0,
        Soil: 100, "Seeds: Sprouts": 100, "Seeds: Amaranth": 5, "Seeds: Guarana": 5, "Seeds: Potato": 5, "Seeds: Maize": 5, Food: 0, Regolith: 0, "Biological Waste": 0, Methane: 0, O2: 0,
        Snack: 0, Meal: 0, Feast: 0, "Energy Bar": 10, Barite: 0,
        "Aluminium Ore": 0, "Copper Ore": 0, "Titanium Ore": 0, Halite: 0, "Liquid CH4": 0, "Liquid O2": 0, "Rocket Fuel": 100, PVC: 0, Perchlorate: 0, PLA: 0, "Empty Battery": 0, "Full Battery": 0, Amaranth: 0, Guarana: 0, Potato: 0, "Fermented Amaranth": 0, "Fermented Guarana": 0,
        "Scavenging License": 0, Worms: 0, "Aluminium Plate": 0, "Titanium Plate": 0, "Machined Parts": 0, "Moving Parts": 0
    },
    stamina: { val: 100, max: 100 },
    cooldowns: { Snack: 0, Meal: 0, Feast: 0, "Energy Bar": 0 },
    skills: {
        scavenging: { lvl: 1, xp: 0, next: 100, locked: false },
        agriculture: { lvl: 1, xp: 0, next: 100 },
        metallurgy: { lvl: 1, xp: 0, next: 100 },
        chemistry: { lvl: 1, xp: 0, next: 100 },
        piloting: { lvl: 1, xp: 0, next: 100 },
        planetary_exploration: { lvl: 1, xp: 0, next: 100 },
        engineering: { lvl: 1, xp: 0, next: 100 },
        energy: { lvl: 1, xp: 0, next: 100 }
    },
    components: { hull: 0, engine: 0, electronics: 0, avionics: 0, lifesupport: 0 },
    hangar: { probe: 1, miner: 0, hauler: 0, gas: 0 },
    ships: [], bodies: [],
    buildQueue: [],
    lastFrameTime: 0,
    environment: { flux: 0.15 },
    power: { batteries: [], productionRate: 0, consumptionRate: 0, gridStatus: "ONLINE" },
    scavenging: { active: false, timer: 0, duration: 5000 },
    cad: {
        slots: [ { id: 0, active: false, startTime: 0, duration: 0 }, { id: 1, active: false, startTime: 0, duration: 0 } ]
    },
    metalworks: {
        slots: [
            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 2, active: false, mode: null, startTime: 0, duration: 0 }
        ]
    },
    machineParts: {
        slots: [
            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 2, active: false, mode: null, startTime: 0, duration: 0 }
        ]
    },
    refinery: {
        waterSlots: [{ id: 0, active: false, startTime: 0, duration: 0 }, { id: 1, active: false, startTime: 0, duration: 0 }],
        sabatierSlots: [{ id: 0, active: false, mode: null, startTime: 0, duration: 0 }, { id: 1, active: false, mode: null, startTime: 0, duration: 0 }],
        smelterSlots: [{ id: 0, active: false, mode: null, startTime: 0, duration: 0 }, { id: 1, active: false, mode: null, startTime: 0, duration: 0 }],
        fermenterSlot: { active: false, startTime: 0, duration: 0, mode: null }
    },
    fuelFactory: {
        slots: [
            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 2, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 3, active: false, mode: null, startTime: 0, duration: 0 }
        ]
    },
    chemlab: {
        slots: [
            { id: 0, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 1, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 2, active: false, mode: null, startTime: 0, duration: 0 },
            { id: 3, active: false, mode: null, startTime: 0, duration: 0 }
        ]
    },
    greenhouse: { slots: Array(6).fill(null).map((_, i) => ({ id: i, status: 'empty', crop: null, startTime: 0, duration: 0 })), selectedSlot: null },
    composter: { slots: [{id:0, active:false, startTime:0, duration:0}, {id:1, active:false, startTime:0, duration:0}, {id:2, active:false, startTime:0, duration:0}] },
    lastDailyClaim: 0
};

function init() {
    // Cache DOM elements
    ['sys-time', 'top-flux-val', 'stamina-val', 'btn-daily', 'grid-output', 'grid-load', 'grid-status-text', 'flux-bar', 'active-systems-panel', 'inventory', 'active-grid-list', 'battery-rack', 'fleet-list', 'obj-list', 'console', 'c-probe', 'c-miner', 'c-hauler', 'c-gas', 'scav-progress', 'btn-scavenge'].forEach(id => {
        const el = document.getElementById(id);
        if(el) UI_CACHE[id] = el;
    });

    // --- SOCKET LOGIC START ---
    log("NET: Connecting to server...");
    socket.emit('join_game', USER_ID);

    socket.on('load_state', (data) => {
        if (!data) {
            log("NET: New user. Creating default system...");
            createSystem();
            createBattery('grid'); createBattery('grid'); createBattery('inventory'); createBattery('inventory'); createBattery('inventory');
            STATE.power.batteries[0].charge = 20; STATE.power.batteries[1].charge = 10;
            STATE.power.batteries[2].charge = 33.33; STATE.power.batteries[3].charge = 33.33;
            STATE.power.batteries[4].charge = 33.33;
        } else {
            log("NET: Save data loaded.");
            if (!STATE.bodies || STATE.bodies.length === 0) createSystem(); // Ensure bodies exist even on load
            StorageSys.processLoad(data);
             // Restore session integrity
            while(STATE.power.batteries.length < 5) {
                createBattery('inventory');
                STATE.power.batteries[STATE.power.batteries.length-1].charge = 33.33;
            }
        }
        
        // Start Loop only after load
        STATE.lastFrameTime = performance.now(); 
        requestAnimationFrame(loop); 
        setInterval(updateUI, 500);
        setInterval(() => StorageSys.save(), 10000); 
    });
    // --- SOCKET LOGIC END ---

    resize();
    window.addEventListener('resize', resize); DragManager.init();
    CANVAS.addEventListener('mousedown', e => { STATE.isDragging = true; STATE.dragStart = {x:e.clientX, y:e.clientY}; STATE.lastMouse = {x:e.clientX, y:e.clientY}; });
    window.addEventListener('mousemove', e => { if (STATE.isDragging && !DragManager.item) { STATE.camera.x += e.clientX - STATE.lastMouse.x; STATE.camera.y += e.clientY - STATE.lastMouse.y; STATE.lastMouse = {x:e.clientX, y:e.clientY}; }});
    window.addEventListener('mouseup', e => { STATE.isDragging = false; if (Math.hypot(e.clientX - STATE.dragStart.x, e.clientY - STATE.dragStart.y) < 5 && !DragManager.item) handleClick(e); });
    CANVAS.addEventListener('wheel', e => { e.preventDefault(); STATE.zoom = Math.max(0.1, Math.min(STATE.zoom - e.deltaY * 0.001, 3)); }, { passive: false });

    window.addEventListener('beforeunload', () => StorageSys.save());
}

// --- LOGIC FUNCTIONS ---
function createBattery(loc) { if(!STATE.power.batteries) STATE.power.batteries=[]; STATE.power.batteries.push({ id: Math.random().toString(36).substr(2, 6).toUpperCase(), charge: 0, wear: 0, loc: loc }); }

function installBattery(id) {
    if(STATE.power.batteries.filter(b => b.loc === 'grid').length >= POWER_CFG.maxGridSlots) { log("ERR: GRID FULL."); return; }
    const b = STATE.power.batteries.find(b => b.id === id);
    if(b) { b.loc = 'grid'; updateUI(); }
}
function ejectBattery(id) {
    const rackCount = STATE.power.batteries.filter(b => b.loc === 'inventory').length;
    if (rackCount >= 5) return log("ERR: RACK FULL.");
    const b = STATE.power.batteries.find(b => b.id === id);
    if(b) { b.loc = 'inventory'; updateUI(); }
}

function storeBattery(id) {
    const b = STATE.power.batteries.find(b => b.id === id);
    if(b) {
        b.loc = 'warehouse'; updateUI();
        if(document.getElementById('modal-warehouse').style.display === 'block') renderWarehouse();
        log(`STORE: BAT-${id} moved to Warehouse.`);
    }
}

function retrieveBattery(id) {
    const rackCount = STATE.power.batteries.filter(b => b.loc === 'inventory').length;
    if (rackCount >= 5) return log("ERR: RACK FULL.");
    const b = STATE.power.batteries.find(b => b.id === id);
    if(b) {
        b.loc = 'inventory'; updateUI();
        if(document.getElementById('modal-warehouse').style.display === 'block') renderWarehouse();
        log(`RETRIEVE: BAT-${id} returned to Rack.`);
    }
}

function createRation(type) {
    const r = RATION_RECIPES[type];
    if(!r) return;
    if(STATE.power.gridStatus === 'BLACKOUT') return log("ERR: NO POWER.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p < r.energy) return log("ERR: LOW ENERGY.");
    if((STATE.inventory.Food||0)<r.food || (STATE.inventory.Water||0)<r.water) return log("ERR: MISSING INGREDIENTS.");
    drainBuffer(r.energy); STATE.inventory.Food-=r.food; STATE.inventory.Water-=r.water;
    STATE.inventory[type]=(STATE.inventory[type]||0)+1;
    log(`KITCHEN: ${type} prepared.`); updateUI();
}

function plantCrop(type) {
    const s = STATE.greenhouse.selectedSlot; if(s===null) return;
    const c = CROPS[type];
    if(STATE.power.gridStatus === 'BLACKOUT') return log("ERR: NO POWER.");
    if(STATE.stamina.val < c.cost.stamina) return log("ERR: TIRED.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p < c.cost.energy) return log("ERR: LOW ENERGY.");
    if((STATE.inventory.Water||0)<c.cost.water || (STATE.inventory.Soil||0)<c.cost.soil || (STATE.inventory["Seeds: "+type]||0)<c.cost.seed) return log("ERR: MISSING RES.");

    useStamina(c.cost.stamina); drainBuffer(c.cost.energy);
    STATE.inventory.Water-=c.cost.water;
    STATE.inventory.Soil-=c.cost.soil; STATE.inventory["Seeds: "+type]-=c.cost.seed;
    const slot = STATE.greenhouse.slots[s];
    slot.status='growing'; slot.crop=type; slot.startTime=Date.now(); slot.duration=c.time;
    log(`AGRI: Planted ${type}.`); closeCropSelect(); renderGreenhouse(); updateUI();
}

function harvestCrop(id) {
    const s = STATE.greenhouse.slots[id];
    if(s.status!=='ready') return;
    const c = CROPS[s.crop];
    let y = Math.floor(Math.random()*(c.yieldMax-c.yieldMin+1))+c.yieldMin;
    if(Math.random() < (STATE.skills.agriculture.lvl*0.05)) { y=Math.floor(y*1.5); log("AGRI: CRITICAL HARVEST!"); }

    if (s.crop === 'Sprouts' || s.crop === 'Potato' || s.crop === 'Maize') {
        STATE.inventory.Food=(STATE.inventory.Food||0)+y;
        log(`AGRI: +${y} Food.`);
    } else {
        STATE.inventory[s.crop]=(STATE.inventory[s.crop]||0)+y;
        log(`AGRI: +${y} ${s.crop}.`);
        if (s.crop === 'Guarana') {
            if (Math.random() < 0.10) {
                STATE.inventory["Seeds: Guarana"] = (STATE.inventory["Seeds: Guarana"] || 0) + 1;
                log("AGRI: Lucky! Recovered 1 Guarana Seed.");
            }
        }
    }
    if (s.crop !== 'Guarana') {
        if (Math.random() < 0.05) {
            STATE.inventory["Seeds: " + s.crop] = (STATE.inventory["Seeds: " + s.crop] || 0) + 1;
            log(`AGRI: Lucky! Recovered 1 ${s.crop} Seed.`);
        }
    }

    STATE.skills.agriculture.xp+=c.xp;
    if(STATE.skills.agriculture.xp >= STATE.skills.agriculture.next) { STATE.skills.agriculture.lvl++; STATE.skills.agriculture.xp=0; STATE.skills.agriculture.next=Math.floor(STATE.skills.agriculture.next*1.5);
        log(`SKILL UP: AGRI LVL ${STATE.skills.agriculture.lvl}`); }
    s.status='empty';
    s.crop=null; renderGreenhouse(); updateUI();
}

function renderGreenhouse() {
    const g = document.getElementById('greenhouse-grid');
    if (!g) return;
    g.innerHTML = STATE.greenhouse.slots.map(s => {
        if(s.status==='empty') {
            return `<div class="gh-slot empty" onclick="openCropSelect(${s.id})"><div style="font-size:30px; color:#444;">+</div></div>`;
        } else {
            const isReady = s.status === 'ready';
            let icon = '🌱';
            if(isReady) {
                if(s.crop === 'Sprouts') icon = '🥦';
                else if(s.crop === 'Amaranth') icon = '🌾';
                else if(s.crop === 'Guarana') icon = '🔴';
                else if(s.crop === 'Potato') icon = '🥔';
                else if(s.crop === 'Maize') icon = '🌽';
            }

            let timerHtml = '';
            if (!isReady) {
                let el = Date.now() - s.startTime;
                let rem = Math.max(0, s.duration - el);
                let tStr = `${Math.floor(rem/3600000)}h ${Math.floor((rem%3600000)/60000)}m`;
                timerHtml = `<div id="gh-time-${s.id}" style="font-size:9px; color:#889; margin-top:2px;">${tStr}</div>`;
            }

            return `<div class="gh-slot ${s.status}" ${isReady ? `onclick="harvestCrop(${s.id})"` : ''}>
<div class="gh-icon">${icon}</div>
<div style="font-size:10px; color:${isReady?'var(--agri)':'#aaa'}">${s.crop}</div>
${timerHtml}
<div class="gh-progress-bg" style="width:100%; height:4px; background:#111; margin-top:5px;">
<div id="gh-prog-${s.id}" style="height:100%; background:var(--agri); width:${isReady ? '100%' : '0%'}"></div>
</div>${isReady?'<div style="font-size:9px; color:var(--agri);">HARVEST</div>':''}</div>`;
        }
    }).join('');
    const skillVal = document.getElementById('gh-skill-val'); if(skillVal) skillVal.innerText = STATE.skills.agriculture.lvl;
    const soilVal = document.getElementById('gh-soil-val'); if(soilVal) soilVal.innerText = STATE.inventory.Soil;
    const seedsVal = document.getElementById('gh-seeds-val');
    if(seedsVal) seedsVal.innerText = STATE.inventory["Seeds: Sprouts"]||0;
}
function openCropSelect(id) { if(STATE.greenhouse.slots[id].status!=='empty')return; STATE.greenhouse.selectedSlot=id; document.getElementById('crop-select-overlay').style.display='flex'; }
function closeCropSelect() { document.getElementById('crop-select-overlay').style.display='none'; STATE.greenhouse.selectedSlot=null; }

function startCompost(id) {
    const s = STATE.composter.slots[id];
    if(s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p < COMPOST_CFG.cost.energy) return log("ERR: LOW POWER.");
    if((STATE.inventory.Regolith||0) < COMPOST_CFG.cost.regolith) return log("ERR: NO REGOLITH.");
    if((STATE.inventory["Biological Waste"]||0) < COMPOST_CFG.cost.waste) return log("ERR: NO WASTE.");
    if((STATE.inventory.Water||0) < COMPOST_CFG.cost.water) return log("ERR: NO WATER.");
    if(!useStamina(COMPOST_CFG.cost.stamina)) return;

    drainBuffer(COMPOST_CFG.cost.energy);
    STATE.inventory.Regolith -= COMPOST_CFG.cost.regolith;
    STATE.inventory["Biological Waste"] -= COMPOST_CFG.cost.waste;
    STATE.inventory.Water -= COMPOST_CFG.cost.water;
    s.active = true; s.startTime = Date.now(); s.duration = COMPOST_CFG.duration;
    log(`BIO: Composter ${id+1} started.`);
    renderComposter(); updateUI();
}
function completeCompost(s) {
    s.active = false;
    STATE.inventory.Soil = (STATE.inventory.Soil||0) + COMPOST_CFG.output.soil;
    let msg = `BIO: Composter ${s.id+1} finished. +${COMPOST_CFG.output.soil} Soil`;
    STATE.skills.agriculture.xp += 15;
    if (Math.random() < 0.05) {
        let worms = Math.floor(Math.random() * 5) + 1;
        STATE.inventory.Worms = (STATE.inventory.Worms || 0) + worms;
        STATE.skills.agriculture.xp += 5;
        msg += ` & found ${worms} Worms!`;
    }
    if(STATE.skills.agriculture.xp >= STATE.skills.agriculture.next) {
        STATE.skills.agriculture.lvl++;
        STATE.skills.agriculture.xp=0;
        STATE.skills.agriculture.next=Math.floor(STATE.skills.agriculture.next*1.5);
        log(`SKILL UP: AGRI LVL ${STATE.skills.agriculture.lvl}`);
    }
    log(msg + "."); renderComposter(); updateUI();
}
function renderComposter() {
    const c = document.getElementById('composter-ui'); if(!c) return;
    c.innerHTML = STATE.composter.slots.map(s => {
        let t = "IDLE", p = 0;
        if(s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let btnClass = s.active ? "ref-btn btn-filtering" : "ref-btn";
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1);">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>UNIT ${s.id+1}</span><span id="cp-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="cp-bar-${s.id}" style="height:100%; background:var(--agri); width:${p}%"></div></div>
<button class="${btnClass}" style="width:100%; margin-top:5px; font-size:9px; border-color:var(--agri); color:var(--agri);" onclick="startCompost(${s.id})" ${s.active?'disabled':''}>${s.active?'ACTIVE':'START CYCLE'}</button></div>`;
    }).join('');
}

// --- SABATIER LOGIC ---
function startSabatier(id, mode) {
    const s = STATE.refinery.sabatierSlots[id];
    const cfg = SABATIER_CFG[mode];
    if(s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if(STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p < cfg.cost.power) return log("ERR: LOW POWER.");
    if(mode === 'split') {
        if((STATE.inventory.Water||0) < cfg.cost.water) return log("ERR: NO WATER.");
    } else if(mode === 'methane') {
        if((STATE.inventory.H2||0) < cfg.cost.h2) return log("ERR: NO H2.");
        if((STATE.inventory.CO2||0) < cfg.cost.co2) return log("ERR: NO CO2.");
    }

    useStamina(cfg.cost.stamina);
    if(mode === 'split') {
        STATE.inventory.Water -= cfg.cost.water;
    } else if(mode === 'methane') {
        STATE.inventory.H2 -= cfg.cost.h2;
        STATE.inventory.CO2 -= cfg.cost.co2;
    }

    drainBuffer(cfg.cost.power);
    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`SABATIER: Reactor ${id+1} started [${mode.toUpperCase()}].`);
    renderSabatier(); updateUI();
}

function completeSabatier(s) {
    const cfg = SABATIER_CFG[s.mode];
    let xp = 0;
    if(s.mode === 'split') {
        STATE.inventory.H2 = (STATE.inventory.H2||0) + cfg.output.h2;
        STATE.inventory.O2 = (STATE.inventory.O2||0) + cfg.output.o2;
        let msg = `SABATIER: Reactor ${s.id+1} finished. +H2, +O2`;
        xp += 8;
        if (Math.random() < 0.2222) {
            let haliteAmt = Math.floor(Math.random() * (6 - 2 + 1)) + 2;
            STATE.inventory.Halite = (STATE.inventory.Halite || 0) + haliteAmt;
            msg += `, +${haliteAmt} Halite`;
            xp += 5;
        }
        log(msg + ".");
    } else if(s.mode === 'methane') {
        STATE.inventory.Methane = (STATE.inventory.Methane||0) + cfg.output.methane;
        STATE.inventory.Water = (STATE.inventory.Water||0) + cfg.output.water;
        log(`SABATIER: Reactor ${s.id+1} finished. +Methane, +Water.`);
        xp += 15;
    }

    if(xp > 0) {
        STATE.skills.chemistry.xp += xp;
        if(STATE.skills.chemistry.xp >= STATE.skills.chemistry.next) {
            STATE.skills.chemistry.lvl++;
            STATE.skills.chemistry.xp = 0;
            STATE.skills.chemistry.next = Math.floor(STATE.skills.chemistry.next * 1.5);
            log(`SKILL UP: CHEMISTRY LVL ${STATE.skills.chemistry.lvl}`);
        }
    }

    s.active = false; s.mode = null; renderSabatier(); updateUI();
}
function renderSabatier() {
    const c = document.getElementById('sabatier-ui');
    if(!c) return;
    c.innerHTML = STATE.refinery.sabatierSlots.map(s => {
        let t = "IDLE", p = 0;
        if(s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let controls = !s.active ?
            `<div style="display:flex; gap:2px; margin-top:5px;"><button class="ref-btn" style="flex:1; font-size:8px; border-color:var(--miner);" onclick="startSabatier(${s.id}, 'split')">SPLIT WATER</button><button class="ref-btn" style="flex:1; font-size:8px; border-color:var(--warning);" onclick="startSabatier(${s.id}, 'methane')">METHANE</button></div>` :
            `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px;" disabled>${s.mode.toUpperCase()}...</button>`;
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1);">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>CORE ${s.id+1}</span><span id="sab-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="sab-bar-${s.id}" style="height:100%; background:var(--warning); width:${p}%"></div></div>${controls}</div>`;
    }).join('');
}

// --- C.A.D. LOGIC ---
function startCad(id) {
    const s = STATE.cad.slots[id];
    if(s.active || STATE.power.gridStatus==='BLACKOUT') return;
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p < CAD_CFG.powerCost) return log("ERR: LOW POWER.");
    if(!useStamina(CAD_CFG.staminaCost)) return;

    drainBuffer(CAD_CFG.powerCost);
    s.active = true; s.startTime = Date.now(); s.duration = CAD_CFG.duration;
    log(`ATMOS: C.A.D. Cell ${id+1} started.`);
    renderCad(); updateUI();
}

function completeCad(s) {
    s.active = false;
    let msg = `CAD ${s.id+1} DONE: `;
    let c = Math.floor(Math.random()*4)+2; STATE.inventory.CO2 = (STATE.inventory.CO2||0)+c; msg+=`${c} CO2`;
    if(Math.random() < 0.1111) { let b=Math.floor(Math.random()*10)+1; STATE.inventory.CO2+=b; msg+=` (+${b} Bonus)`; }
    if(Math.random() < 0.15) { let n=Math.floor(Math.random()*2)+1; STATE.inventory.Nitrogen=(STATE.inventory.Nitrogen||0)+n; msg+=`, ${n} N2`; }
    if(Math.random() < 0.10) { let a=Math.floor(Math.random()*2)+1; STATE.inventory.Argon=(STATE.inventory.Argon||0)+a; msg+=`, ${a} Ar`; }
    if(Math.random() < 0.05) { let ne=Math.floor(Math.random()*2)+1; STATE.inventory.Neon=(STATE.inventory.Neon||0)+ne; msg+=`, ${ne} Ne`; }
    if(Math.random() < 0.03) { let kr=Math.floor(Math.random()*2)+1; STATE.inventory.Krypton=(STATE.inventory.Krypton||0)+kr; msg+=`, ${kr} Kr`; }
    if(Math.random() < 0.02) { let xe=Math.floor(Math.random()*2)+1; STATE.inventory.Xenon=(STATE.inventory.Xenon||0)+xe; msg+=`, ${xe} Xe`; }

    log(msg); renderCad(); updateUI();
}

function renderCad() {
    const c = document.getElementById('cad-container');
    if(!c) return;
    c.innerHTML = STATE.cad.slots.map(s => {
        let t = "IDLE", p = 0;
        if (s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let btnClass = s.active ? "ref-btn btn-filtering" : "ref-btn";
        return `<div style="background:rgba(255,255,255,0.02); padding:10px; border:1px solid rgba(255,255,255,0.1);">
<div style="color:var(--neon); font-weight:bold;">C.A.D. CELL ${s.id+1}</div>
<div style="font-size:10px; color:#889; margin:5px 0;">Cost: 25kW <span style="color:var(--stamina)">[-5 Stam]</span></div>
<div style="font-size:9px; color:#666; margin-bottom:5px;">Cycle: 12h. Output: CO₂, N₂, Ar, Ne...</div>
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa; margin-top:2px;">
<span>STATUS</span><span id="cad-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span>
</div>
<div style="width:100%; height:4px; background:#111; margin-top:2px;">
<div id="cad-bar-${s.id}" style="height:100%; background:var(--neon); width:${p}%; box-shadow: 0 0 5px var(--neon); transition: width 0.5s;"></div>
</div>
<button class="${btnClass}" id="cad-btn-${s.id}" style="width:100%" onclick="startCad(${s.id})" ${s.active?'disabled':''}>${s.active?'EXTRACTION...':'START EXTRACTION (12h)'}</button>
</div>`;
    }).join('');
}

function startWaterFilter(id) {
    const s = STATE.refinery.waterSlots[id];
    if(s.active || STATE.power.gridStatus==='BLACKOUT') return;
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p<FILTER_CFG.cost.power) return log("ERR: LOW POWER.");
    if((STATE.inventory["Ice water"]||0)<FILTER_CFG.cost.ice) return log("ERR: NO ICE.");
    if(!useStamina(FILTER_CFG.cost.stamina)) return;

    drainBuffer(FILTER_CFG.cost.power); STATE.inventory["Ice water"]-=FILTER_CFG.cost.ice;
    s.active=true; s.startTime=Date.now(); s.duration=FILTER_CFG.duration; log(`REF: Cell ${id+1} filtering.`); renderWaterFilter();
    updateUI();
}
function completeWaterFilter(s) {
    s.active=false; STATE.inventory.Water=(STATE.inventory.Water||0)+FILTER_CFG.output.water;
    STATE.inventory.Regolith=(STATE.inventory.Regolith||0)+FILTER_CFG.output.regolith;
    log(`REF: Cell ${s.id+1} done. +Water, +Regolith.`); renderWaterFilter(); updateUI();
}

function startFermentation(mode) {
    const s = STATE.refinery.fermenterSlot;
    const cfg = FERMENT_CFG[mode];
    if(s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if(STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p < cfg.cost.power) return log("ERR: LOW POWER.");

    if(mode === 'amaranth') {
        if((STATE.inventory.Amaranth||0) < cfg.cost.amaranth) return log("ERR: NO AMARANTH.");
        STATE.inventory.Amaranth -= cfg.cost.amaranth;
    } else if(mode === 'guarana') {
        if((STATE.inventory.Guarana||0) < cfg.cost.guarana) return log("ERR: NO GUARANA.");
        STATE.inventory.Guarana -= cfg.cost.guarana;
    }

    useStamina(cfg.cost.stamina); drainBuffer(cfg.cost.power);
    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`REF: Fermentation (${mode}) started.`); renderWaterFilter(); updateUI();
}

function completeFermentation() {
    const s = STATE.refinery.fermenterSlot;
    const cfg = FERMENT_CFG[s.mode];
    s.active = false;
    let yieldAmt = Math.floor(Math.random() * (cfg.output.max - cfg.output.min + 1)) + cfg.output.min;
    if(s.mode === 'amaranth') {
        STATE.inventory["Fermented Amaranth"] = (STATE.inventory["Fermented Amaranth"]||0) + yieldAmt;
        log(`REF: Fermentation complete. +${yieldAmt} Fermented Amaranth.`);
    } else if(s.mode === 'guarana') {
        STATE.inventory["Fermented Guarana"] = (STATE.inventory["Fermented Guarana"]||0) + yieldAmt;
        log(`REF: Fermentation complete. +${yieldAmt} Fermented Guarana.`);
    }
    s.mode = null; renderWaterFilter(); updateUI();
}

function renderWaterFilter() {
    const c=document.getElementById('water-filter-ui');
    if(!c)return;
    let html = STATE.refinery.waterSlots.map(s => {
        let t="IDLE", p=0;
        if(s.active) {
            let el=Date.now()-s.startTime; p=Math.min(100,(el/s.duration)*100); let r=Math.max(0,s.duration-el);
            t=`${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m ${Math.floor((r%60000)/1000)}s`;
        }
        let btnClass = s.active ? "ref-btn btn-filtering" : "ref-btn";
        return `<div class="wf-slot"><div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>CELL ${s.id+1}</span><span id="wf-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div><div class="wf-progress-bg" style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="wf-bar-${s.id}" style="height:100%; background:var(--neon); width:${p}%"></div></div><button id="wf-btn-${s.id}" class="${btnClass}" style="width:100%; margin-top:5px; font-size:9px;"
onclick="startWaterFilter(${s.id})" ${s.active?'disabled':''}>${s.active?'FILTERING...':'START'}</button></div>`;
    }).join('');

    const f = STATE.refinery.fermenterSlot;
    let fTime = "IDLE";
    let fProg = 0;
    if(f.active) {
        let el = Date.now() - f.startTime; fProg = Math.min(100, (el / f.duration) * 100);
        let r = Math.max(0, f.duration - el); fTime = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
    }

    let fControls = "";
    if (f.active) {
        fControls = `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px; border-color:#d400ff; color:#d400ff;" disabled>FERMENTING ${f.mode.toUpperCase()}...</button>`;
    } else {
        fControls = `<div style="display:flex; gap:2px; margin-top:5px;">
<button class="ref-btn" style="flex:1; font-size:9px; border-color:#d400ff; color:#d400ff;" onclick="startFermentation('amaranth')">AMARANTH</button>
<button class="ref-btn" style="flex:1; font-size:9px; border-color:#cc0000; color:#cc0000;" onclick="startFermentation('guarana')">GUARANA</button>
</div>`;
    }

    html += `<div class="wf-slot" style="border-color: #8844cc; margin-top:10px;">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;">
<span style="color:#d400ff">FERMENTER</span>
<span id="ferment-time" style="color:${f.active?'var(--neon)':'#555'}">${fTime}</span>
</div>
<div style="font-size:8px; color:#889; margin:2px 0;">Transforms raw biomass into potent extracts.</div>
<div class="wf-progress-bg" style="width:100%; height:4px; background:#111; margin-top:5px;">
<div id="ferment-bar" style="height:100%; background:#d400ff; width:${fProg}%"></div>
</div>${fControls}</div>`;
    c.innerHTML = html;
}

// --- SMELTER LOGIC ---
function startSmelter(id, mode) {
    const s = STATE.refinery.smelterSlots[id];
    const cfg = SMELTER_CFG[mode];
    if (s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if (STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if (p < cfg.cost.power) return log("ERR: LOW POWER.");

    if (mode === 'iron') { if ((STATE.inventory.Regolith||0) < cfg.cost.regolith) return log("ERR: NO REGOLITH."); }
    else if (mode === 'steel') { if ((STATE.inventory.CO2||0) < cfg.cost.co2) return log("ERR: NO CO2.");
        if ((STATE.inventory["Iron Ore"]||0) < cfg.cost["Iron Ore"]) return log("ERR: NO IRON ORE."); }
    else if (mode === 'aluminium') { if ((STATE.inventory.Regolith||0) < cfg.cost.regolith) return log("ERR: NO REGOLITH."); }
    else if (mode === 'copper') { if ((STATE.inventory.Regolith||0) < cfg.cost.regolith) return log("ERR: NO REGOLITH."); }
    else if (mode === 'titanium') { if ((STATE.inventory.Regolith||0) < cfg.cost.regolith) return log("ERR: NO REGOLITH."); }

    useStamina(cfg.cost.stamina);
    if (mode === 'iron') { STATE.inventory.Regolith -= cfg.cost.regolith; }
    else if (mode === 'steel') { STATE.inventory.CO2 -= cfg.cost.co2; STATE.inventory["Iron Ore"] -= cfg.cost["Iron Ore"]; }
    else if (mode === 'aluminium') { STATE.inventory.Regolith -= cfg.cost.regolith; }
    else if (mode === 'copper') { STATE.inventory.Regolith -= cfg.cost.regolith; }
    else if (mode === 'titanium') { STATE.inventory.Regolith -= cfg.cost.regolith; }

    drainBuffer(cfg.cost.power);
    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`SMELTER: Crucible ${id+1} activated [${mode.toUpperCase()}].`);
    renderSmelter(); updateUI();
}

function completeSmelter(s) {
    s.active = false;
    let msg = "";
    let xp = 0; // Initialize XP

    if (s.mode === 'iron') {
        let yieldAmt = Math.floor(Math.random() * (5 - 2 + 1)) + 2;
        msg = `SMELTER ${s.id+1}: Extracted ${yieldAmt} Iron Ore`;
        if(Math.random() < 0.1111) { let bonus = Math.floor(Math.random() * (8 - 1 + 1)) + 1; yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory["Iron Ore"] = (STATE.inventory["Iron Ore"] || 0) + yieldAmt;
        xp = 12; // Added
    } else if (s.mode === 'steel') {
        let yieldAmt = Math.floor(Math.random() * (5 - 2 + 1)) + 2;
        msg = `FORGE ${s.id+1}: Created ${yieldAmt} Steel`;
        if(Math.random() < 0.1111) { let bonus = Math.floor(Math.random() * (8 - 1 + 1)) + 1; yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory.Steel = (STATE.inventory.Steel || 0) + yieldAmt;
        if(Math.random() < 0.1111) { let bariteAmt = Math.floor(Math.random() * (5 - 1 + 1)) + 1;
            STATE.inventory.Barite = (STATE.inventory.Barite || 0) + bariteAmt; msg += ` Found ${bariteAmt} Barite!`; }
        xp = 18; // Added
    } else if (s.mode === 'aluminium') {
        let yieldAmt = Math.floor(Math.random() * (5 - 2 + 1)) + 2;
        msg = `SMELTER ${s.id+1}: Extracted ${yieldAmt} Alum. Ore`;
        if(Math.random() < 0.1111) { let bonus = Math.floor(Math.random() * (8 - 1 + 1)) + 1; yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory["Aluminium Ore"] = (STATE.inventory["Aluminium Ore"] || 0) + yieldAmt;
        xp = 15; // Added
    } else if (s.mode === 'copper') {
        let yieldAmt = Math.floor(Math.random() * (5 - 2 + 1)) + 2;
        msg = `SMELTER ${s.id+1}: Extracted ${yieldAmt} Copper Ore`;
        if(Math.random() < 0.1111) { let bonus = Math.floor(Math.random() * (8 - 1 + 1)) + 1; yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory["Copper Ore"] = (STATE.inventory["Copper Ore"] || 0) + yieldAmt;
        if(Math.random() < 0.1111) { let bariteAmt = Math.floor(Math.random() * (5 - 1 + 1)) + 1;
            STATE.inventory.Barite = (STATE.inventory.Barite || 0) + bariteAmt; msg += ` Found ${bariteAmt} Barite!`; }
        xp = 14; // Added
    } else if (s.mode === 'titanium') {
        let yieldAmt = Math.floor(Math.random() * (5 - 2 + 1)) + 2;
        msg = `SMELTER ${s.id+1}: Extracted ${yieldAmt} Titanium Ore`;
        if(Math.random() < 0.1111) { let bonus = Math.floor(Math.random() * (8 - 1 + 1)) + 1; yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory["Titanium Ore"] = (STATE.inventory["Titanium Ore"] || 0) + yieldAmt;
        xp = 20; // Added
    }

    // Apply XP Logic
    if(xp > 0) {
        STATE.skills.metallurgy.xp += xp;
        if(STATE.skills.metallurgy.xp >= STATE.skills.metallurgy.next) {
            STATE.skills.metallurgy.lvl++;
            STATE.skills.metallurgy.xp = 0;
            STATE.skills.metallurgy.next = Math.floor(STATE.skills.metallurgy.next * 1.5);
            log(`SKILL UP: METALLURGY LVL ${STATE.skills.metallurgy.lvl}`);
        }
    }

    s.mode = null; log(msg); renderSmelter(); updateUI();
}

function renderSmelter() {
    const c = document.getElementById('smelter-ui'); if(!c) return;
    c.innerHTML = STATE.refinery.smelterSlots.map(s => {
        let t = "IDLE", p = 0;
        if(s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let controls = !s.active ?
            `<div style="display:grid; grid-template-columns: 1fr 1fr; gap:2px; margin-top:5px;">
<button class="ref-btn" style="font-size:8px; border-color:var(--mars);" onclick="startSmelter(${s.id}, 'iron')">SMELT IRON</button>
<button class="ref-btn" style="font-size:8px; border-color:#ccc; color:#ccc;" onclick="startSmelter(${s.id}, 'aluminium')">SMELT AL</button>
<button class="ref-btn" style="font-size:8px; border-color:var(--copper); color:var(--copper);" onclick="startSmelter(${s.id}, 'copper')">SMELT CU</button>
<button class="ref-btn" style="font-size:8px; border-color:var(--titanium); color:var(--titanium);" onclick="startSmelter(${s.id}, 'titanium')">SMELT TI</button>
<button class="ref-btn" style="font-size:8px; grid-column:span 2; border-color:var(--miner);" onclick="startSmelter(${s.id}, 'steel')">FORGE STEEL</button>
</div>` :
            `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px; border-color:var(--mars); color:var(--mars);" disabled>${s.mode === 'steel' ? 'FORGING...' : 'MELTING...'}</button>`;
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1);">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>CRUCIBLE ${s.id+1}</span><span id="sm-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="sm-bar-${s.id}" style="height:100%; background:var(--mars); width:${p}%"></div></div>${controls}</div>`;
    }).join('');
}

// --- METALWORKS LOGIC ---
function startMetalworks(id, mode) {
    const s = STATE.metalworks.slots[id];
    const cfg = METALWORKS_CFG[mode];
    if (s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if (STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if (p < cfg.cost.power) return log("ERR: LOW POWER.");

    if (mode === 'alum_plate') {
        if ((STATE.inventory["Aluminium Ore"]||0) < cfg.cost["Aluminium Ore"]) return log("ERR: MISSING ALUM. ORE.");
        STATE.inventory["Aluminium Ore"] -= cfg.cost["Aluminium Ore"];
    } else if (mode === 'titanium_plate') {
        if ((STATE.inventory["Titanium Ore"]||0) < cfg.cost["Titanium Ore"]) return log("ERR: MISSING TITANIUM ORE.");
        STATE.inventory["Titanium Ore"] -= cfg.cost["Titanium Ore"];
    }

    useStamina(cfg.cost.stamina);
    drainBuffer(cfg.cost.power);
    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`FACTORY: Metalworks ${id+1} started [${mode.toUpperCase()}].`);
    renderMetalworks(); updateUI();
}

function completeMetalworks(s) {
    s.active = false;
    let msg = "";
    const cfg = METALWORKS_CFG[s.mode];

    if (s.mode === 'alum_plate') {
        let yieldAmt = Math.floor(Math.random() * (cfg.output.max - cfg.output.min + 1)) + cfg.output.min;
        msg = `FACTORY: Produced ${yieldAmt} Aluminium Plate`;
        if (Math.random() < 0.1111) {
            let bonus = Math.floor(Math.random() * 5) + 1;
            yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`;
        }
        STATE.inventory["Aluminium Plate"] = (STATE.inventory["Aluminium Plate"] || 0) + yieldAmt;
    } else if (s.mode === 'titanium_plate') {
        let yieldAmt = Math.floor(Math.random() * (cfg.output.max - cfg.output.min + 1)) + cfg.output.min;
        msg = `FACTORY: Produced ${yieldAmt} Titanium Plate`;
        if (Math.random() < 0.1111) {
            let bonus = Math.floor(Math.random() * 5) + 1;
            yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`;
        }
        STATE.inventory["Titanium Plate"] = (STATE.inventory["Titanium Plate"] || 0) + yieldAmt;
    }

    s.mode = null; log(msg + "."); renderMetalworks(); updateUI();
}

function renderMetalworks() {
    const c = document.getElementById('metalworks-ui'); if(!c) return;
    c.innerHTML = STATE.metalworks.slots.map(s => {
        let t = "IDLE", p = 0;
        if (s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let btn = "";
        if (s.active) {
            let lbl = "PROCESSING...";
            btn = `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px;" disabled>${lbl}</button>`;
        } else {
            btn = `<div style="display:grid; grid-template-columns: 1fr 1fr; gap:2px; margin-top:5px;">
<button class="ref-btn" style="font-size:9px; border-color:#e0e0e0; color:#e0e0e0;" onclick="startMetalworks(${s.id}, 'alum_plate')">ALUM PLATE</button>
<button class="ref-btn" style="font-size:9px; border-color:var(--titanium); color:var(--titanium);" onclick="startMetalworks(${s.id}, 'titanium_plate')">TITAN PLATE</button>
</div>`;
        }
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1); margin-bottom:5px;">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>SLOT ${s.id+1}</span><span id="mw-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="mw-bar-${s.id}" style="height:100%; background:var(--white); width:${p}%"></div></div>${btn}</div>`;
    }).join('');
}

// --- MACHINE PARTS LOGIC (NEW) ---
function startMachineParts(id, mode) {
    const s = STATE.machineParts.slots[id];
    const cfg = MACHINE_PARTS_CFG[mode];
    if (s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if (STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if (p < cfg.cost.power) return log("ERR: LOW POWER.");

    // Resource Check
    if (mode === 'machined_parts') {
        if ((STATE.inventory["Aluminium Plate"]||0) < cfg.cost["Aluminium Plate"]) return log("ERR: MISSING AL. PLATE.");
        if ((STATE.inventory.Steel||0) < cfg.cost.Steel) return log("ERR: MISSING STEEL.");

        STATE.inventory["Aluminium Plate"] -= cfg.cost["Aluminium Plate"];
        STATE.inventory.Steel -= cfg.cost.Steel;
    } else if (mode === 'moving_parts') {
        if ((STATE.inventory["Aluminium Plate"]||0) < cfg.cost["Aluminium Plate"]) return log("ERR: MISSING AL. PLATE.");
        if ((STATE.inventory["Titanium Plate"]||0) < cfg.cost["Titanium Plate"]) return log("ERR: MISSING TI. PLATE.");

        STATE.inventory["Aluminium Plate"] -= cfg.cost["Aluminium Plate"];
        STATE.inventory["Titanium Plate"] -= cfg.cost["Titanium Plate"];
    }

    useStamina(cfg.cost.stamina);
    drainBuffer(cfg.cost.power);
    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`FACTORY: Machine Shop ${id+1} started [${mode.toUpperCase()}].`);
    renderMachineParts(); updateUI();
}

function completeMachineParts(s) {
    s.active = false;
    let msg = "";
    const cfg = MACHINE_PARTS_CFG[s.mode];

    if (s.mode === 'machined_parts') {
        let yieldAmt = Math.floor(Math.random() * (cfg.output.max - cfg.output.min + 1)) + cfg.output.min;
        msg = `FACTORY: Produced ${yieldAmt} Machined Parts`;
        if (Math.random() < 0.1111) {
            let bonus = Math.floor(Math.random() * 2) + 1; // 1 to 2
            yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`;
        }
        STATE.inventory["Machined Parts"] = (STATE.inventory["Machined Parts"] || 0) + yieldAmt;
    } else if (s.mode === 'moving_parts') {
        let yieldAmt = Math.floor(Math.random() * (cfg.output.max - cfg.output.min + 1)) + cfg.output.min;
        msg = `FACTORY: Produced ${yieldAmt} Moving Parts`;
        if (Math.random() < 0.1111) {
            let bonus = Math.floor(Math.random() * 2) + 1; // 1 to 2
            yieldAmt += bonus;
            msg += ` (+${bonus} Bonus!)`;
        }
        STATE.inventory["Moving Parts"] = (STATE.inventory["Moving Parts"] || 0) + yieldAmt;
    }

    s.mode = null; log(msg + "."); renderMachineParts(); updateUI();
}

function renderMachineParts() {
    const c = document.getElementById('machineparts-content'); if(!c) return;
    c.innerHTML = STATE.machineParts.slots.map(s => {
        let t = "IDLE", p = 0;
        if (s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let btn = "";
        if (s.active) {
            let lbl = s.mode === 'moving_parts' ? 'MOVING...' : 'MACHINING...';
            btn = `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px;" disabled>${lbl}</button>`;
        } else {
            btn = `<div style="display:grid; grid-template-columns: 1fr 1fr; gap:2px; margin-top:5px;">
<button class="ref-btn" style="font-size:8px; border-color:#e0e0e0; color:#e0e0e0;" onclick="startMachineParts(${s.id}, 'machined_parts')">MACHINED (5Al, 5St)</button>
<button class="ref-btn" style="font-size:8px; border-color:#fff; color:#fff;" onclick="startMachineParts(${s.id}, 'moving_parts')">MOVING (3Al, 3Ti)</button>
</div>`;
        }
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1); margin-bottom:5px;">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>SLOT ${s.id+1}</span><span id="mp-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="mp-bar-${s.id}" style="height:100%; background:var(--white); width:${p}%"></div></div>${btn}</div>`;
    }).join('');
}

// --- FUEL FACTORY LOGIC ---
function startFuelProcess(id, mode) {
    const s = STATE.fuelFactory.slots[id];
    const cfg = FUEL_CFG[mode];
    if (s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if (STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if (p < cfg.cost.power) return log("ERR: LOW POWER.");

    if (mode === 'methane') { if ((STATE.inventory.Methane||0) < cfg.cost.methane) return log("ERR: NO METHANE."); }
    else if (mode === 'oxygen') { if ((STATE.inventory.O2||0) < cfg.cost.o2) return log("ERR: NO OXYGEN."); }
    else if (mode === 'synthesis') { if ((STATE.inventory["Liquid CH4"]||0) < cfg.cost.liquidMethane) return log("ERR: NO LIQ CH4.");
        if ((STATE.inventory["Liquid O2"]||0) < cfg.cost.liquidO2) return log("ERR: NO LIQ O2."); }

    useStamina(cfg.cost.stamina);
    if (mode === 'methane') { STATE.inventory.Methane -= cfg.cost.methane; }
    else if (mode === 'oxygen') { STATE.inventory.O2 -= cfg.cost.o2; }
    else if (mode === 'synthesis') { STATE.inventory["Liquid CH4"] -= cfg.cost.liquidMethane; STATE.inventory["Liquid O2"] -= cfg.cost.liquidO2; }

    drainBuffer(cfg.cost.power);
    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`FUEL: Slot ${id+1} Process (${mode.toUpperCase()}) started.`);
    renderFuelFactory(); updateUI();
}

function completeFuelProcess(s) {
    s.active = false;
    if (s.mode === 'methane') {
        const cfg = FUEL_CFG.methane;
        STATE.inventory["Liquid CH4"] = (STATE.inventory["Liquid CH4"] || 0) + cfg.output.liquidMethane;
        log(`FUEL: Slot ${s.id+1} complete. +${cfg.output.liquidMethane} Liquid CH4.`);
    } else if (s.mode === 'oxygen') {
        const cfg = FUEL_CFG.oxygen;
        STATE.inventory["Liquid O2"] = (STATE.inventory["Liquid O2"] || 0) + cfg.output.liquidO2;
        log(`FUEL: Slot ${s.id+1} complete. +${cfg.output.liquidO2} Liquid O2.`);
    } else if (s.mode === 'synthesis') {
        const cfg = FUEL_CFG.synthesis;
        STATE.inventory["Rocket Fuel"] = (STATE.inventory["Rocket Fuel"] || 0) + cfg.output.rocketFuel;
        log(`FUEL: Slot ${s.id+1} complete. +${cfg.output.rocketFuel} ROCKET FUEL.`);
    }
    s.mode = null; renderFuelFactory(); updateUI();
}

function renderFuelFactory() {
    const c = document.getElementById('fuel-factory-ui'); if(!c) return;
    c.innerHTML = STATE.fuelFactory.slots.map(s => {
        let t = "IDLE", p = 0;
        if(s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let btn = "";
        if (s.active) {
            let lbl = s.mode === 'synthesis' ? 'SYNTHESIS' : 'LIQUEFYING ' + s.mode.toUpperCase();
            btn = `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px; border-color:var(--fuel); color:var(--fuel);" disabled>${lbl}...</button>`;
        } else {
            btn = `
<div style="display:grid; grid-template-columns: 1fr 1fr; gap:2px; margin-top:5px;">
<button class="ref-btn" style="font-size:8px; border-color:var(--fuel); color:var(--fuel);" onclick="startFuelProcess(${s.id}, 'methane')">LIQ CH4</button>
<button class="ref-btn" style="font-size:8px; border-color:var(--neon); color:var(--neon);" onclick="startFuelProcess(${s.id}, 'oxygen')">LIQ O2</button>
<button class="ref-btn" style="grid-column: span 2; font-size:9px; border-color:var(--white); color:var(--white); background: rgba(255,255,255,0.1);" onclick="startFuelProcess(${s.id}, 'synthesis')">SYNTHESIS (FUEL)</button>
</div>`;
        }
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1);">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>SLOT ${s.id+1}</span><span id="fuel-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="fuel-bar-${s.id}" style="height:100%; background:var(--fuel); width:${p}%"></div></div>${btn}</div>`;
    }).join('');
}

// --- CHEM LAB LOGIC ---
function startChem(id, mode) {
    const s = STATE.chemlab.slots[id];
    const cfg = CHEM_CFG[mode];
    if (s.active || STATE.power.gridStatus === 'BLACKOUT') return;
    if (STATE.stamina.val < cfg.cost.stamina) return log("ALERT: HUNGRY.");
    let p = STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if (p < cfg.cost.power) return log("ERR: LOW POWER.");

    if (mode === 'pvc') {
        if ((STATE.inventory.Methane||0) < cfg.cost.methane) return log("ERR: MISSING METHANE.");
        if ((STATE.inventory.H2||0) < cfg.cost.h2) return log("ERR: MISSING H2.");
        if ((STATE.inventory.Water||0) < cfg.cost.water) return log("ERR: MISSING WATER.");
    } else if (mode === 'perchlorate') {
        if ((STATE.inventory.Halite||0) < cfg.cost.halite) return log("ERR: MISSING HALITE.");
        if ((STATE.inventory.Water||0) < cfg.cost.water) return log("ERR: MISSING WATER.");
    } else if (mode === 'pla') {
        if ((STATE.inventory["Fermented Guarana"]||0) < cfg.cost["Fermented Guarana"]) return log("ERR: MISSING FERM. GUARANA.");
        if ((STATE.inventory.CO2||0) < cfg.cost.co2) return log("ERR: MISSING CO2.");
    } else if (mode === 'empty_battery') {
        if ((STATE.inventory.Perchlorate||0) < cfg.cost.perchlorate) return log("ERR: MISSING PERCHLORATE.");
        if ((STATE.inventory.Water||0) < cfg.cost.water) return log("ERR: MISSING WATER.");
        if ((STATE.inventory["Iron Ore"]||0) < cfg.cost["Iron Ore"]) return log("ERR: MISSING IRON ORE.");
        if ((STATE.inventory.PVC||0) < cfg.cost.PVC) return log("ERR: MISSING PVC.");
    }

    useStamina(cfg.cost.stamina); drainBuffer(cfg.cost.power);
    if (mode === 'pvc') { STATE.inventory.Methane -= cfg.cost.methane; STATE.inventory.H2 -= cfg.cost.h2; STATE.inventory.Water -= cfg.cost.water; }
    else if (mode === 'perchlorate') { STATE.inventory.Halite -= cfg.cost.halite; STATE.inventory.Water -= cfg.cost.water; }
    else if (mode === 'pla') { STATE.inventory["Fermented Guarana"] -= cfg.cost["Fermented Guarana"]; STATE.inventory.CO2 -= cfg.cost.co2; }
    else if (mode === 'empty_battery') { STATE.inventory.Perchlorate -= cfg.cost.perchlorate; STATE.inventory.Water -= cfg.cost.water; STATE.inventory["Iron Ore"] -= cfg.cost["Iron Ore"]; STATE.inventory.PVC -= cfg.cost.PVC;
    }

    s.active = true; s.mode = mode; s.startTime = Date.now(); s.duration = cfg.duration;
    log(`CHEM: Reaction ${id+1} started [${mode.toUpperCase()}].`);
    renderChemLab(); updateUI();
}

function completeChem(s) {
    s.active = false;
    let msg = "";
    let xp = 0; // Initialize XP for Chemistry

    if (s.mode === 'pvc') {
        let amt = Math.floor(Math.random() * (4 - 2 + 1)) + 2;
        msg = `CHEM: Synthesized ${amt} PVC`;
        if (Math.random() < 0.10) { let bonus = Math.floor(Math.random() * (8 - 1 + 1)) + 1; amt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory.PVC = (STATE.inventory.PVC || 0) + amt;
        xp = 15; // Set XP
    } else if (s.mode === 'perchlorate') {
        let amt = Math.floor(Math.random() * (3 - 1 + 1)) + 1;
        msg = `CHEM: Synthesized ${amt} Perchlorate`;
        STATE.inventory.Perchlorate = (STATE.inventory.Perchlorate || 0) + amt;
        xp = 18; // Set XP
    } else if (s.mode === 'pla') {
        let amt = Math.floor(Math.random() * (10 - 5 + 1)) + 5;
        msg = `CHEM: Synthesized ${amt} PLA`;
        STATE.inventory.PLA = (STATE.inventory.PLA || 0) + amt;
        xp = 12; // Set XP
    } else if (s.mode === 'empty_battery') {
        let amt = 1;
        msg = `CHEM: Assembled 1 Empty Battery`;
        if (Math.random() < 0.10) { let bonus = Math.floor(Math.random() * 2) + 1; amt += bonus;
            msg += ` (+${bonus} Bonus!)`; }
        STATE.inventory["Empty Battery"] = (STATE.inventory["Empty Battery"] || 0) + amt;
        xp = 10; // Set XP
    }

    // XP Update Logic
    if(xp > 0) {
        STATE.skills.chemistry.xp += xp;
        if(STATE.skills.chemistry.xp >= STATE.skills.chemistry.next) {
            STATE.skills.chemistry.lvl++;
            STATE.skills.chemistry.xp = 0;
            STATE.skills.chemistry.next = Math.floor(STATE.skills.chemistry.next * 1.5);
            log(`SKILL UP: CHEMISTRY LVL ${STATE.skills.chemistry.lvl}`);
        }
    }

    s.mode = null; log(msg + "."); renderChemLab(); updateUI();
}

function renderChemLab() {
    const c = document.getElementById('chemlab-ui'); if(!c) return;
    c.innerHTML = STATE.chemlab.slots.map(s => {
        let t = "IDLE", p = 0;
        if (s.active) {
            let el = Date.now() - s.startTime; p = Math.min(100, (el / s.duration) * 100);
            let r = Math.max(0, s.duration - el); t = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
        }
        let btn = "";
        if (s.active) {
            let lbl = s.mode.toUpperCase();
            btn = `<button class="ref-btn btn-filtering" style="width:100%; margin-top:5px; font-size:9px; border-color:var(--chem); color:var(--chem);" disabled>${lbl}...</button>`;
        } else {
            btn = `<div style="display:grid; grid-template-columns: 1fr 1fr; gap:2px; margin-top:5px;">
<button class="ref-btn" style="font-size:9px; border-color:var(--chem); color:var(--chem);" onclick="startChem(${s.id}, 'pvc')">PVC</button>
<button class="ref-btn" style="font-size:9px; border-color:var(--white); color:var(--white);" onclick="startChem(${s.id}, 'perchlorate')">PERCHLORATE</button>
<button class="ref-btn" style="font-size:9px; border-color:#d400ff; color:#d400ff;" onclick="startChem(${s.id}, 'pla')">PLA PLASTIC</button>
<button class="ref-btn" style="font-size:9px; border-color:var(--warning); color:var(--warning);" onclick="startChem(${s.id}, 'empty_battery')">EMPTY BATTERY</button>
</div>`;
        }
        return `<div style="background:rgba(255,255,255,0.02); padding:5px; border:1px solid rgba(255,255,255,0.1);">
<div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>CELL ${s.id+1}</span><span id="chem-time-${s.id}" style="color:${s.active?'var(--neon)':'#555'}">${t}</span></div>
<div style="width:100%; height:4px; background:#111; margin-top:5px;"><div id="chem-bar-${s.id}" style="height:100%; background:var(--chem); width:${p}%"></div></div>${btn}</div>`;
    }).join('');
}

// --- NEW SCAVENGING LOGIC (STRICT 1-5 BASE) ---
function scavenge() {
    if(STATE.scavenging.active || STATE.power.gridStatus==='BLACKOUT') return;
    let p=STATE.power.batteries.filter(b=>b.loc==='grid').reduce((a,b)=>a+b.charge,0);
    if(p<1) return log("ERR: DRONE POWER LOW.");
    if(!useStamina(1)) return;
    drainBuffer(1); STATE.scavenging.active=true; STATE.scavenging.timer=0; UI_CACHE['btn-scavenge'].disabled=true; log("SCAV: Scanning...");
}

function completeScavenge() {
    STATE.scavenging.active = false;
    UI_CACHE['btn-scavenge'].disabled = false;
    UI_CACHE['scav-progress'].style.width = "0%";
    const sSkill = STATE.skills.scavenging;

    // XP LOGIC with Tiers and Locking
    if (!sSkill.locked && sSkill.lvl < 60) {
        sSkill.xp += 2; // Increased XP gain for better pacing
        if(sSkill.xp >= sSkill.next) {
            if (sSkill.lvl % 10 === 0) {
                sSkill.locked = true;
                sSkill.xp = sSkill.next;
                log(`SKILL: Scavenging Proficiency Locked at LVL ${sSkill.lvl}. License required.`);
            } else {
                levelUpScavenging();
            }
        }
    }

    // BASE LOOT LOGIC: Strictly 1 to 5 Units
    let msg = "FOUND: ";

    // Scrap: 1-5
    let s = Math.floor(Math.random() * 5) + 1;
    STATE.inventory.Scrap = (STATE.inventory.Scrap || 0) + s;
    msg += `${s} Scrap. `;

    // Regolith: 1-5
    let r = Math.floor(Math.random() * 5) + 1;
    STATE.inventory.Regolith = (STATE.inventory.Regolith || 0) + r;
    msg += `${r} Regolith. `;

    // Ice: 1-5 (Chance to find)
    if (Math.random() > 0.7) {
        let i = Math.floor(Math.random() * 5) + 1;
        STATE.inventory["Ice water"] = (STATE.inventory["Ice water"] || 0) + i;
        msg += `${i} Ice.`;
    }

    // LUCKY BONUS MECHANIC
    // Starts working from Level 5. Increases every 5 levels.
    const bonusStacks = Math.floor(sSkill.lvl / 5);

    if (bonusStacks > 0) {
        // Chance increases by 10% per stack
        const chance = bonusStacks * 0.10;

        if (Math.random() < chance) {
            // Bonus triggered
            let bonusAmt = Math.floor(Math.random() * 5) + 1; // Bonus amount is also 1-5
            if (Math.random() > 0.5) {
                STATE.inventory.Scrap += bonusAmt;
                msg += ` +${bonusAmt} Scrap (Lucky!)`;
            } else {
                STATE.inventory.Regolith += bonusAmt;
                msg += ` +${bonusAmt} Regolith (Lucky!)`;
            }
        }
    }

    log(msg);
    updateUI();
}

function levelUpScavenging() {
    const s = STATE.skills.scavenging;
    s.lvl++;
    s.xp = 0;
    const tier = SCAV_TIERS.find(t => s.lvl >= t.min && s.lvl <= t.max);
    if (tier) s.next = tier.xpReq;
    else s.next = 5000;
    log(`SKILL UP: SCAV LVL ${s.lvl} (${tier ? tier.name : 'Unknown'})`);
}

function unlockScavenging() {
    if (!STATE.skills.scavenging.locked) return;
    if ((STATE.inventory["Scavenging License"] || 0) < 1) return log("ERR: Missing License.");

    STATE.inventory["Scavenging License"]--;
    STATE.skills.scavenging.locked = false;
    levelUpScavenging(); // Move from 10 to 11, etc.
    renderProficiency(); updateUI();
}

function buyLicense() {
    if ((STATE.inventory.Scrap || 0) < 200) return log("MARKET: Insufficient Scrap (Need 200).");
    STATE.inventory.Scrap -= 200;
    STATE.inventory["Scavenging License"] = (STATE.inventory["Scavenging License"] || 0) + 1;
    log("MARKET: Scavenging License acquired.");
    renderWarehouse(); updateUI();
}


function useStamina(v) { if(STATE.stamina.val>=v) { STATE.stamina.val-=v; updateUI(); return true; } log("ALERT: HUNGRY."); return false; }

function consume(i) {
    if(!STATE.cooldowns) STATE.cooldowns = {};
    const last = STATE.cooldowns[i] || 0;
    if(Date.now()-last < EATING_COOLDOWN_MS) return log(`BIO: Digesting ${i}...`);
    if(!STATE.inventory[i] || STATE.inventory[i]<1) return;
    if(STATE.stamina.val>=STATE.stamina.max) return log("INFO: Full.");
    let r=RATION_RECIPES[i], g=0, w=0;
    if(i==='Energy Bar') { g = Math.floor(Math.random() * (14 - 8 + 1)) + 8;
        w = Math.floor(Math.random() * (4 - 2 + 1)) + 2; }
    else { g=Math.floor(Math.random()*(r.maxStam-r.minStam+1))+r.minStam; w=r.waste; }
    STATE.inventory[i]--; STATE.stamina.val=Math.min(STATE.stamina.max, STATE.stamina.val+g);
    STATE.inventory["Biological Waste"]+=w;
    STATE.cooldowns[i] = Date.now();
    log(`BIO: Ate ${i}. +${g} STM.`); updateUI();
}

function createSystem() {
    STATE.bodies = [
        { id: 0, name: "Echo-Sphere", dist: 0, speed: 0, color: "#00E5FF", size: 15, type: "Star", angle: 0 },
        { id: 1, name: "B-01 Scorcher", dist: 0.4, speed: 4.7, color: "#a52", size: 4, type: "Planet", res: ["Iron Ore"], angle: 0 },
        { id: 2, name: "V-02 Cloud-Mine", dist: 0.8, speed: 3.5, color: "#da6", size: 6, type: "Planet", res: ["Si", "Gas"], angle: 0 },
        { id: 4, name: "J-03", dist: 1.5, speed: 2.4, color: "#f40", size: 9, type: "BASE", angle: 0 },
        { id: 5, name: "G-04 Heavy-Mass", dist: 4.0, speed: 1.3, color: "#d97", size: 14, type: "Gas Giant", res: ["H2"], angle: 0 },
        { id: 9, name: "R-05 Heavy-Mass", dist: 5.6, speed: 0.8, color: "#567", size: 15, type: "Ice World", res: ["Ice water", "Pt"], angle: 0 }
    ];
    for(let i=0; i<40; i++) STATE.bodies.push({ id: 100+i, name: `A-${100+i}`, dist: 2.0+Math.random()*3, speed: (1.0+Math.random())*0.5, color: "#667", size: 2, type: "Asteroid", scanned: false, res: [], angle: Math.random()*6.28 });

    // Outer Asteroid Belt (Beyond R-05)
    for(let i=0; i<20; i++) {
        STATE.bodies.push({
            id: 200+i,
            name: `X-${200+i}`,
            dist: 6.5 + Math.random() * 3.5, // 6.5 AU to 10.0 AU (Beyond 5.6 AU)
            speed: (0.4 + Math.random()) * 0.3, // Slower orbit for outer bodies
            color: "#445566",
            size: 2,
            type: "Asteroid",
            scanned: false,
            res: [],
            angle: Math.random() * 6.28
        });
    }
}

function loop(ts) {
    const dt = (ts - STATE.lastFrameTime) / 1000;
    STATE.lastFrameTime = ts; const now = Date.now();
    let cycle = (now % POWER_CFG.cycleDuration) / POWER_CFG.cycleDuration;
    STATE.environment.flux = (cycle <= 0.5) ? 0.15 + (0.85 * Math.sin(cycle*2*Math.PI)) : 0.15;
    const gBats = STATE.power.batteries.filter(b => b.loc === 'grid');
    if (gBats.length === 0) { STATE.power.productionRate=0; STATE.power.consumptionRate=0; STATE.power.gridStatus="BLACKOUT"; }
    else {
        const gen = POWER_CFG.panelBaseOutput * STATE.environment.flux;
        let load = POWER_CFG.baseLoad;
        if(STATE.buildQueue.length > 0) load += STATE.buildQueue.length * POWER_CFG.factoryLoad;
        STATE.cad.slots.forEach(s => { if(s.active) load += (CAD_CFG.powerCost / (CAD_CFG.duration/1000)); });
        STATE.power.productionRate=gen; STATE.power.consumptionRate=load;
        let d = (gen - load) * dt;
        if(d > 0) {
            STATE.power.gridStatus="ONLINE";
            for(let b of gBats) { if(d<=0) break; let s = (POWER_CFG.batteryCap*(1-(b.wear/100))) - b.charge; if(s>0){ let a=Math.min(s,d); b.charge+=a; d-=a; }}
        } else {
            let dr = Math.abs(d);
            for(let i=gBats.length-1; i>=0; i--) { if(dr<=0)break; let b=gBats[i]; if(b.charge>0){ let t=Math.min(b.charge, dr); b.charge-=t; dr-=t; }}
            STATE.power.gridStatus = (gBats.reduce((a,b)=>a+b.charge,0) <= 0.001 && dr>0) ? "BLACKOUT" : "DRAINING";
        }
        gBats.forEach(b => { if(b.charge < (POWER_CFG.batteryCap*(1-(b.wear/100))*0.05)) b.wear = Math.min(100, b.wear + (0.0002*dt)); });
    }

    processBuildQueue(dt);
    STATE.cad.slots.forEach(s => {
        if (s.active && (now - s.startTime) >= s.duration) { completeCad(s); }
        else if (s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`cad-bar-${s.id}`); if (b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`cad-time-${s.id}`); if (tEl) { let r = s.duration - (now - s.startTime); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`; }
            }
        }
    });
    STATE.refinery.waterSlots.forEach(s => {
        if(s.active && (now-s.startTime)>=s.duration) { completeWaterFilter(s); } else if(s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b=document.getElementById(`wf-bar-${s.id}`); if(b) b.style.width=Math.min(100,((now-s.startTime)/s.duration)*100)+"%";
                let tEl = document.getElementById(`wf-time-${s.id}`); if(tEl) { let r=Math.max(0, s.duration-(now-s.startTime)); tEl.innerText=`${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m ${Math.floor((r%60000)/1000)}s`; }
            }
        }
    });
    const f = STATE.refinery.fermenterSlot;
    if(f.active && (now - f.startTime) >= f.duration) { completeFermentation(); }
    else if(f.active) {
        const modal = document.getElementById('modal-base');
        if (modal && modal.style.display === 'block') {
            let b = document.getElementById(`ferment-bar`); if (b) b.style.width = Math.min(100, ((now - f.startTime) / f.duration) * 100) + "%";
            let tEl = document.getElementById(`ferment-time`); if (tEl) { let r = Math.max(0, f.duration - (now - f.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
            }
        }
    }
    STATE.refinery.sabatierSlots.forEach(s => {
        if(s.active && (now - s.startTime) >= s.duration) { completeSabatier(s); } else if(s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`sab-bar-${s.id}`); if(b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`sab-time-${s.id}`); if(tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`; }
            }
        }
    });
    STATE.refinery.smelterSlots.forEach(s => {
        if(s.active && (now - s.startTime) >= s.duration) { completeSmelter(s); } else if(s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`sm-bar-${s.id}`); if(b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`sm-time-${s.id}`); if(tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`; }
            }
        }
    });
    STATE.metalworks.slots.forEach(s => {
        if (s.active && (now - s.startTime) >= s.duration) { completeMetalworks(s); } else if (s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`mw-bar-${s.id}`); if (b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`mw-time-${s.id}`); if (tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
                }
            }
        }
    });
    STATE.machineParts.slots.forEach(s => {
        if (s.active && (now - s.startTime) >= s.duration) { completeMachineParts(s); } else if (s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`mp-bar-${s.id}`); if (b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`mp-time-${s.id}`); if (tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`;
                }
            }
        }
    });
    STATE.fuelFactory.slots.forEach(s => {
        if(s.active && (now - s.startTime) >= s.duration) { completeFuelProcess(s); } else if(s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`fuel-bar-${s.id}`); if(b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`fuel-time-${s.id}`); if(tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`; }
            }
        }
    });
    STATE.chemlab.slots.forEach(s => {
        if (s.active && (now - s.startTime) >= s.duration) { completeChem(s); } else if (s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`chem-bar-${s.id}`); if(b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`chem-time-${s.id}`); if(tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`; }
            }
        }
    });
    STATE.composter.slots.forEach(s => {
        if(s.active && (now - s.startTime) >= s.duration) { completeCompost(s); } else if(s.active) {
            const modal = document.getElementById('modal-base');
            if (modal && modal.style.display === 'block') {
                let b = document.getElementById(`cp-bar-${s.id}`); if(b) b.style.width = Math.min(100, ((now - s.startTime) / s.duration) * 100) + "%";
                let tEl = document.getElementById(`cp-time-${s.id}`); if(tEl) { let r = Math.max(0, s.duration - (now - s.startTime)); tEl.innerText = `${Math.floor(r/3600000)}h ${Math.floor((r%3600000)/60000)}m`; }
            }
        }
    });
    STATE.greenhouse.slots.forEach(s => {
        if(s.status==='growing'){
            let el = now - s.startTime;
            let p = (el/s.duration)*100;
            let b = document.getElementById(`gh-prog-${s.id}`);
            if(b) b.style.width=Math.min(100,p)+"%";
            let t = document.getElementById(`gh-time-${s.id}`);
            if(t) {
                let rem = Math.max(0, s.duration - el);
                t.innerText = `${Math.floor(rem/3600000)}h ${Math.floor((rem%3600000)/60000)}m ${Math.floor((rem%60000)/1000)}s`;
            }
            if(p>=100){ s.status='ready'; renderGreenhouse(); }
        }
    });
    if(STATE.scavenging.active) { STATE.scavenging.timer+=dt*1000; UI_CACHE['scav-progress'].style.width=(STATE.scavenging.timer/STATE.scavenging.duration)*100+"%";
        if(STATE.scavenging.timer>=STATE.scavenging.duration) completeScavenge(); }

    // Render Map
    CTX.fillStyle = "#050608"; CTX.fillRect(0, 0, CANVAS.width, CANVAS.height);
    CTX.strokeStyle = "rgba(0, 229, 255, 0.05)"; CTX.lineWidth = 1;
    const gs = 50 * STATE.zoom;
    const ox = STATE.camera.x % gs; const oy = STATE.camera.y % gs;
    CTX.beginPath();
    for (let x=ox; x<CANVAS.width; x+=gs){CTX.moveTo(x,0);CTX.lineTo(x,CANVAS.height);} for (let y=oy; y<CANVAS.height; y+=gs){CTX.moveTo(0,y);CTX.lineTo(CANVAS.width,y);} CTX.stroke();

    const cx = (CANVAS.width/2) + STATE.camera.x;
    const cy = (CANVAS.height/2) + STATE.camera.y;
    const time = (now / POWER_CFG.cycleDuration) * 2000;
    const z = STATE.zoom * AU_SCALE;
    const base = STATE.bodies.find(b => b.type === "BASE");
    STATE.bodies.forEach(b => {
        const p = getOrbitalPos(b, time, z);
        let drawRadius = b.size;
        if(b.type === "Star") { CTX.shadowBlur = 40; CTX.shadowColor = b.color; drawRadius = b.size; }
        else { CTX.shadowBlur = 0; drawRadius = b.size * (STATE.zoom < 0.5 ? 0.5 : 1); }
        if (b.type !== 'Star' && STATE.zoom > 0.1) { CTX.beginPath(); CTX.arc(cx, cy, b.dist*z, 0, Math.PI*2); CTX.strokeStyle=(b.type==="BASE")?"rgba(255,68,0,0.15)":"rgba(255,255,255,0.03)"; CTX.stroke(); }
        CTX.beginPath(); CTX.fillStyle = b.color; CTX.arc(cx+p.x, cy+p.y, drawRadius, 0, Math.PI*2); CTX.fill(); CTX.shadowBlur = 0;
        if (STATE.zoom > 0.5 || b.type==="Planet" || b.type==="BASE") { CTX.fillStyle=(b.type==="BASE")?"var(--mars)":"#aaa"; CTX.font="9px Consolas"; CTX.fillText(b.name, cx+p.x+10, cy+p.y+4); }
    });
    for (let i=STATE.ships.length-1; i>=0; i--) {
        const s = STATE.ships[i];
        const t = STATE.bodies.find(b => b.id === s.targetId);
        if (!t && s.phase !== 'return') { s.phase = 'return'; s.startTime = now; s.startPos = s.lastPos || getOrbitalPos(base, time, z);
        }
        const tp = t ? getOrbitalPos(t, time, z) : {x:0,y:0};

        if (s.phase === 'outbound') {
            s.progress += ((now - s.lastTick)/1000)/s.duration; s.lastTick=now;
            if(s.progress>=1) { if(s.type==='probe'){ scanBody(t); STATE.ships.splice(i,1); continue; } else { s.phase='mining'; s.mineStart=now; } }
            else { const pos = interpolate(s.startPos, tp, s.progress); s.lastPos=pos; drawShip(cx, cy, pos, tp, s); }
        } else if (s.phase === 'mining') {
            const mp = (now - s.mineStart)/5000;
            CTX.strokeStyle = s.spec.color; CTX.beginPath(); CTX.arc(cx+tp.x, cy+tp.y, 8+Math.sin(mp*15)*4, 0, 6.28); CTX.stroke();
            if(mp>=1) { s.phase='return'; s.progress=0; s.lastTick=now; s.startPos={x:tp.x, y:tp.y}; const res=(t.res&&t.res.length)?t.res[0]:"Rock"; s.cargoAmount=(s.spec.bonus&&s.spec.bonus.includes(res))?s.spec.cargo*1.5:s.spec.cargo; s.cargoItem=res; }
        } else if (s.phase === 'return') {
            const mp = getOrbitalPos(base, time, z);
            s.progress += ((now - s.lastTick)/1000)/s.duration; s.lastTick=now;
            if(s.progress>=1) { STATE.inventory[s.cargoItem]=(STATE.inventory[s.cargoItem]||0)+s.cargoAmount; STATE.hangar[s.type]++; log(`LOG: ${s.type} returned with ${Math.floor(s.cargoAmount)} ${s.cargoItem}`); STATE.ships.splice(i,1); updateUI(); }
            else { const pos = interpolate(s.startPos, mp, s.progress); drawShip(cx, cy, pos, mp, s); }
        }
    }
    requestAnimationFrame(loop);
}

function interpolate(p1, p2, t) { return { x: p1.x + (p2.x - p1.x) * t, y: p1.y + (p2.y - p1.y) * t };
}
function getOrbitalPos(b, t, z) { const a = b.angle + (t * b.speed); const r = b.dist * z;
    return { x: Math.cos(a) * r, y: Math.sin(a) * r }; }
function drawShip(cx, cy, p, tp, s) {
    CTX.beginPath(); CTX.setLineDash([2, 4]);
    CTX.moveTo(cx+p.x, cy+p.y); CTX.lineTo(cx+tp.x, cy+tp.y); CTX.strokeStyle=s.spec.color; CTX.globalAlpha=0.3; CTX.stroke(); CTX.setLineDash([]); CTX.globalAlpha=1.0;
    const a = Math.atan2(tp.y-p.y, tp.x-p.x);
    CTX.save(); CTX.translate(cx+p.x, cy+p.y); CTX.rotate(a);
    CTX.fillStyle=s.spec.color; CTX.beginPath();
    CTX.moveTo(5,0); CTX.lineTo(-4,3); CTX.lineTo(-4,-3); CTX.fill(); CTX.restore();
}

function handleClick(e) {
    if(STATE.power.gridStatus === 'BLACKOUT') return;
    const r = CANVAS.getBoundingClientRect();
    const z = STATE.zoom * AU_SCALE;
    const mx = e.clientX - r.left - STATE.camera.x - (CANVAS.width/2);
    const my = e.clientY - r.top - STATE.camera.y - (CANVAS.height/2);
    let c = null;
    const time = (Date.now() / POWER_CFG.cycleDuration) * 2000;

    STATE.bodies.forEach(b => {
        const p = getOrbitalPos(b, time, z);
        if (Math.hypot(p.x-mx, p.y-my) < Math.max(b.size + 10, 20)) c = b;
    });
    if (c) openModal(c);
}

function openModal(obj) {
    STATE.selectedObj = obj;
    document.getElementById('modal-overlay').style.display = 'block';
    ['modal-base','modal-target','modal-warehouse','modal-hangar','modal-proficiency','modal-market'].forEach(id=>document.getElementById(id).style.display='none');

    let m;
    if (obj.type === 'BASE') { m = document.getElementById('modal-base'); renderWaterFilter(); renderSabatier(); renderSmelter(); renderCad(); renderChemLab(); renderMetalworks(); renderMachineParts(); switchTab('refinery'); }
    else {
        m = document.getElementById('modal-target');
        document.getElementById('m-t-name').innerText = obj.name;
        const base = STATE.bodies.find(b => b.type === 'BASE');
        const d = Math.abs(obj.dist - base.dist);
        document.getElementById('m-t-dist').innerText = d.toFixed(2) + " AU";
        document.getElementById('m-t-time').innerText = `~${Math.ceil(d/(BASE_SPEED*60))} MIN`;
        document.getElementById('m-t-res').innerText = obj.scanned ? (obj.res[0]||"None") : "SCAN REQ.";

        const g = document.getElementById('launch-grid'); g.innerHTML="";
        ['probe', 'miner', 'hauler', 'gas'].forEach(t => {
            const s = SPECS[t]; const fc = Math.floor(50 * d * s.fuel); const sc = t==='probe'?5:15;
            let active = (STATE.hangar[t]>0 && (STATE.inventory["Rocket Fuel"]||0)>=fc);
            if(t==='probe' && obj.scanned) active=false;
            if(t!=='probe' && !obj.scanned) active=false;
            const b = document.createElement('button');
            b.disabled=!active; b.innerHTML=`<span>LAUNCH ${t.toUpperCase()}</span> <span style="color:${active?'#fff':'#555'}">${fc} FUEL <span style="color:var(--stamina)">[-${sc}E]</span></span>`;
            b.onclick=()=>launch(t, fc, sc); g.appendChild(b);
        });
    }
    m.style.display = 'block'; m.classList.remove('glitch-anim'); void m.offsetWidth; m.classList.add('glitch-anim'); setTimeout(()=>m.classList.remove('glitch-anim'), 300);
}

function openBaseModalFromUI() { const b = STATE.bodies.find(x => x.type === 'BASE'); if(b) openModal(b); }
function openWarehouse() {
    document.getElementById('modal-overlay').style.display='block'; ['modal-base','modal-target','modal-warehouse','modal-proficiency','modal-hangar','modal-market'].forEach(id=>document.getElementById(id).style.display='none'); document.getElementById('modal-warehouse').style.display='block'; renderWarehouse();
}
function openHangar() {
    document.getElementById('modal-overlay').style.display='block'; ['modal-base','modal-target','modal-warehouse','modal-proficiency','modal-market'].forEach(id=>document.getElementById(id).style.display='none'); document.getElementById('modal-hangar').style.display='block'; renderHangar();
}
function openProficiency() {
    document.getElementById('modal-overlay').style.display='block'; ['modal-base','modal-target','modal-warehouse','modal-hangar','modal-market'].forEach(id=>document.getElementById(id).style.display='none'); document.getElementById('modal-proficiency').style.display='block'; renderProficiency();
}
function openMarket() {
    document.getElementById('modal-overlay').style.display='block'; ['modal-base','modal-target','modal-warehouse','modal-hangar','modal-proficiency'].forEach(id=>document.getElementById(id).style.display='none'); document.getElementById('modal-market').style.display='block'; renderMarket();
}
function renderMarket() { /* Logic later */ }
function createOffer() { log("MARKET: CREATE OFFER system initializing..."); /* Logic later */ }

function closeModal(e, f) { if(f) document.getElementById('modal-overlay').style.display='none'; }

function renderWarehouse() {
    const g = document.getElementById('warehouse-content');
    if (!g) return;
    let htmlBuffer = [];
    const wBats = STATE.power.batteries.filter(b => b.loc === 'warehouse');
    htmlBuffer.push(`<div style="grid-column:1/-1; color:var(--neon); font-size:10px; padding-bottom:5px; margin-bottom:5px;">STORED POWER CELLS</div>`);
    htmlBuffer.push(`<div class="wh-grid" style="margin:0; margin-bottom:10px;">`);

    let slotsToShow = Math.max(4, Math.ceil(wBats.length / 4) * 4);

    for (let i = 0; i < slotsToShow; i++) {
        if (i < wBats.length) {
            let b = wBats[i];
            const cp = (b.charge/POWER_CFG.batteryCap)*100;
            htmlBuffer.push(`<div class="wh-item" onclick="retrieveBattery('${b.id}')" style="border-color:var(--neon);">
<div class="wh-cat">PWR</div><div class="wh-name" style="color:var(--neon)">BAT-${b.id}</div>
<div class="wh-qty" style="font-size:11px">${Math.floor(cp)}%</div><div style="font-size:9px; color:#666; margin-top:2px;">(CLICK TO RETRIEVE)</div></div>`);
        } else {
            htmlBuffer.push(`<div class="wh-item" style="border:1px dashed #334; justify-content:center; color:#445;"><div style="font-size:9px;">[ EMPTY SLOT ]</div></div>`);
        }
    }
    htmlBuffer.push(`</div>`);
    htmlBuffer.push(`<div style="grid-column:1/-1; border-bottom:1px solid #334; margin:5px 0;"></div>`);

    let itemsBuffer = [];
    const add = (c,n,q,col="#9ab") => { if(isNaN(q) || q === undefined || q <= 0) return;
        itemsBuffer.push(`<div class="wh-item"><div class="wh-cat">${c}</div><div class="wh-name" style="color:${col}">${n}</div><div class="wh-qty">${Math.floor(q)}</div></div>`); };

    add("KEY", "Scavenging License", STATE.inventory["Scavenging License"], "var(--xp)");
    add("RES", "H₂", STATE.inventory.H2, "var(--warning)");
    add("RES", "Raw Gas", STATE.inventory.Gas, "#ffaa00");
    add("RES", "Methane", STATE.inventory.Methane, "#90ee90");
    add("RES", "Liquid CH4", STATE.inventory["Liquid CH4"], "var(--fuel)");
    add("RES", "Liquid O2", STATE.inventory["Liquid O2"], "var(--neon)");
    add("FUEL", "Rocket Fuel", STATE.inventory["Rocket Fuel"], "var(--white)");
    add("MAT", "PVC", STATE.inventory.PVC, "var(--white)");
    add("MAT", "Perchlorate", STATE.inventory.Perchlorate, "var(--white)");
    add("MAT", "PLA", STATE.inventory.PLA, "var(--white)");
    add("CMP", "Empty Battery", STATE.inventory["Empty Battery"], "#888");
    add("CMP", "Full Battery", STATE.inventory["Full Battery"], "var(--neon)");
    add("MAT", "Amaranth", STATE.inventory.Amaranth, "#d400ff");
    add("MAT", "Ferm. Amaranth", STATE.inventory["Fermented Amaranth"], "#d400ff");
    add("MAT", "Guarana", STATE.inventory.Guarana, "#cc0000");
    add("MAT", "Ferm. Guarana", STATE.inventory["Fermented Guarana"], "#cc0000");
    add("RES", "Iron Ore", STATE.inventory["Iron Ore"]);
    add("RES", "Alum. Ore", STATE.inventory["Aluminium Ore"], "#e0e0e0");
    add("RES", "Copper Ore", STATE.inventory["Copper Ore"], "var(--copper)");
    add("RES", "Titanium Ore", STATE.inventory["Titanium Ore"], "var(--titanium)");
    add("MAT", "Alum. Plate", STATE.inventory["Aluminium Plate"], "#e0e0e0");
    add("MAT", "Titanium Plate", STATE.inventory["Titanium Plate"], "var(--titanium)");
    add("MAT", "Machined Parts", STATE.inventory["Machined Parts"], "#fff");
    add("MAT", "Moving Parts", STATE.inventory["Moving Parts"], "#fff");
    add("RES", "Si (Silicon)", STATE.inventory.Si);
    add("RES", "Ice", STATE.inventory["Ice water"], "#0ff"); add("RES", "Regolith", STATE.inventory.Regolith);
    add("RES", "Barite", STATE.inventory.Barite, "#eee");
    add("RES", "Halite", STATE.inventory.Halite, "#eee");
    add("RES", "Scrap", STATE.inventory.Scrap);
    add("RES", "Bio-Waste", STATE.inventory["Biological Waste"], "#564");
    add("REF", "Water", STATE.inventory.Water, "#00aaff");
    add("REF", "Steel", STATE.inventory.Steel);
    add("REF", "CO₂", STATE.inventory.CO2);
    add("REF", "Pt (Platinum)", STATE.inventory.Pt, "#e5e4e2");
    add("REF", "Oxygen (O₂)", STATE.inventory.O2, "#00ffaa");
    add("REF", "Nitrogen", STATE.inventory.Nitrogen);
    add("REF", "Argon", STATE.inventory.Argon);
    add("REF", "Neon", STATE.inventory.Neon);
    add("REF", "Krypton", STATE.inventory.Krypton); add("REF", "Xenon", STATE.inventory.Xenon);
    add("BIO", "Soil", STATE.inventory.Soil, "#8d6e63");
    add("BIO", "Worms", STATE.inventory.Worms, "var(--worm)");
    add("BIO", "Seeds: Sprouts", STATE.inventory["Seeds: Sprouts"], "var(--agri)");
    add("BIO", "Seeds: Potato", STATE.inventory["Seeds: Potato"], "#C49C48");
    add("BIO", "Seeds: Maize", STATE.inventory["Seeds: Maize"], "var(--maize)");
    add("BIO", "Potato", STATE.inventory.Potato, "#C49C48");
    add("BIO", "Seeds: Amaranth", STATE.inventory["Seeds: Amaranth"], "var(--agri)");
    add("BIO", "Seeds: Guarana", STATE.inventory["Seeds: Guarana"], "var(--agri)");
    add("BIO", "Food", STATE.inventory.Food, "#88aa00");
    add("RAT", "Snack", STATE.inventory.Snack, "var(--kitchen)");
    add("RAT", "Meal", STATE.inventory.Meal, "var(--kitchen)");
    add("RAT", "Feast", STATE.inventory.Feast, "var(--kitchen)");
    add("RAT", "Energy Bar", STATE.inventory["Energy Bar"], "#d35400");
    for(let k in STATE.components) add("CMP", k.toUpperCase(), STATE.components[k], "#aaa");
    for(let k in STATE.hangar) add("SHIP", k.toUpperCase(), STATE.hangar[k], SPECS[k].color);

    htmlBuffer.push(`<div class="wh-scroll-container"><div class="wh-grid" style="margin:0;">`);
    htmlBuffer.push(itemsBuffer.join(''));
    htmlBuffer.push(`</div></div>`);
    g.innerHTML = htmlBuffer.join('');
}

function renderHangar() {
    const fGrid = document.getElementById('hangar-fleet-grid');
    if(fGrid) {
        fGrid.innerHTML = ['probe','miner','hauler','gas'].map(k => {
            const count = STATE.hangar[k];
            return `<div style="min-width:80px; text-align:center; background:rgba(255,255,255,0.02); border:1px solid rgba(255,255,255,0.1); padding:10px;"><div style="font-weight:bold; color:${SPECS[k].color}">${k.toUpperCase()}</div><div style="font-size:20px; margin:5px 0;">${count}</div><div style="font-size:9px; color:#666">DOCKED</div></div>`;
        }).join('');
    }
    const sGrid = document.getElementById('shipyard-grid');
    if(sGrid) {
        const createBuildBtn = (type, costTxt, costStam) => {
            return `<button class="build-btn" onclick="startBuild('${type}', ${costStam})" style="width:100%; text-align:left; margin-bottom:2px; display:flex; justify-content:space-between; padding:10px;">
<span style="font-weight:bold; color:${SPECS[type].color}">${type.toUpperCase()}</span>
<span style="color:#889; font-size:10px;">${costTxt} <span style="color:var(--stamina)">[-${costStam}E]</span></span>
</button>`;
        };
        let sHtml = createBuildBtn('probe', '10 Iron Ore 5Si', 10);
        sHtml += createBuildBtn('miner', 'MODULAR PARTS', 20);
        sHtml += createBuildBtn('hauler', 'MODULAR PARTS', 20);
        sHtml += createBuildBtn('gas', 'MODULAR PARTS', 20);
        sGrid.innerHTML = sHtml;
    }
    const qGrid = document.getElementById('hangar-build-queue');
    if(qGrid) {
        if(STATE.buildQueue.length === 0) { qGrid.innerHTML = "<div style='color:#445; text-align:center; padding:10px;'>FABRICATION IDLE</div>"; }
        else {
            qGrid.innerHTML = STATE.buildQueue.map((job, i) => {
                const p = Math.min(100, (job.progress / job.totalDuration) * 100);
                return `<div style="margin-bottom:5px;"><div style="display:flex; justify-content:space-between; font-size:9px; color:#aaa;"><span>${job.type.toUpperCase()}</span><span>${Math.floor(p)}%</span></div><div style="background:#111; height:4px; width:100%"><div style="height:100%; width:${p}%; background:var(--success)"></div></div></div>`;
            }).join('');
        }
    }
}

function renderProficiency() {
    const c = document.getElementById('proficiency-content'); if(!c) return;
    let html = `
<div style="background:rgba(255,255,255,0.02); padding:10px; border:1px solid rgba(255,255,255,0.1); margin-bottom:10px;">
<div style="color:var(--stamina); font-weight:bold; margin-bottom:5px;">PHYSICAL CONDITION</div>
<div style="display:flex; justify-content:space-between; font-size:10px; color:#aaa; margin-bottom:5px;">
<span>STAMINA</span><span>${Math.floor(STATE.stamina.val)} / ${STATE.stamina.max}</span>
</div>
<div style="width:100%; height:6px; background:#111; border:1px solid #333;">
<div style="height:100%; width:${(STATE.stamina.val/STATE.stamina.max)*100}%; background:var(--stamina);"></div>
</div></div>`;
    html += `<div style="background:rgba(255,255,255,0.02); padding:10px; border:1px solid rgba(255,255,255,0.1);">
<div style="color:var(--xp); font-weight:bold; margin-bottom:10px;">OPERATOR SKILLS</div>`;

    for(let key in STATE.skills) {
        const s = STATE.skills[key];
        const p = Math.min(100, (s.xp / s.next) * 100);
        let name = key.replace(/_/g, ' ').toUpperCase();
        let extraInfo = "";
        let barColor = "var(--xp)";
        let tierName = "NOVICE";

        const tier = SCAV_TIERS.find(t => s.lvl >= t.min && s.lvl <= t.max);
        if (tier) {
            tierName = tier.name;
            barColor = tier.color;
        } else if (s.lvl > 60) {
            tierName = "ARTISAN+";
            barColor = "#FF3333";
        }

        name += ` <span style="color:${barColor}; font-size:9px;">[${tierName}]</span>`;

        if (s.locked) {
            const nextTier = SCAV_TIERS.find(t => t.min === s.lvl + 1);
            const reqText = nextTier ? nextTier.cert : "UNKNOWN CERTIFICATE";
            barColor = "var(--danger)";
            extraInfo = `<div style="margin-top:2px; display:flex; justify-content:space-between; align-items:center;">
<span style="color:var(--danger); font-size:9px;">🔒 REQ: ${reqText}</span>
<button class="nav-btn" style="padding:2px 6px; font-size:9px; border-color:var(--xp); color:var(--xp);" onclick="unlockScavenging()">UNLOCK (1 LICENSE)</button>
</div>`;
        }

        html += `<div style="margin-bottom:15px;">
<div style="display:flex; justify-content:space-between; font-size:10px; color:#fff; margin-bottom:3px;">
<span>${name} <span style="color:${barColor}">LVL ${s.lvl}</span></span>
<span style="color:#667">${Math.floor(s.xp)} / ${Math.floor(s.next)} XP</span>
</div>
<div style="width:100%; height:4px; background:#111; position:relative;">
<div style="height:100%; width:${p}%; background:${barColor}; box-shadow:0 0 5px ${barColor};"></div>
</div>
${extraInfo}
</div>`;
    }
    html += `</div>`; c.innerHTML = html;
}

function craftComponent(k, s) {
    if(STATE.power.gridStatus==='BLACKOUT') return log("ERR: NO POWER.");
    if(!useStamina(s)) return;
    const c = COMPONENTS[k];
    for(let r in c.cost) { if (STATE.inventory[r]!==undefined) STATE.inventory[r]-=c.cost[r]; else STATE.components[r]-=c.cost[r]; }
    if (k === 'battery') { createBattery('inventory'); log(`FACTORY: Battery created.`); }
    else { STATE.components[k]++; log(`FACTORY: ${c.name} created.`); }
    renderFactory(); updateUI();
}

function launch(t, c, s) {
    if(STATE.power.gridStatus==='BLACKOUT') return; if(!useStamina(s)) return;
    STATE.inventory["Rocket Fuel"]-=c; STATE.hangar[t]--;
    const b = STATE.bodies.find(x=>x.type==="BASE");
    const d = Math.abs(STATE.selectedObj.dist-b.dist)+0.2;
    STATE.ships.push({ type:t, spec:SPECS[t], targetId:STATE.selectedObj.id, phase:'outbound', duration:d/(BASE_SPEED*SPECS[t].speed), progress:0, lastTick:Date.now(), startPos:getOrbitalPos(b,Date.now()*0.00005,AU_SCALE), cargoItem:null, cargoAmount:0 });
    log(`CMD: ${t} launched.`); closeModal(null, true); updateUI();
}

function startBuild(t, s) {
    if(STATE.power.gridStatus==='BLACKOUT') return log("ERR: NO POWER.");
    if(!useStamina(s)) return;
    const sp = SPECS[t]; let ok=true;
    if (t==='probe') { if((STATE.inventory["Iron Ore"]||0)<sp.cost["Iron Ore"] || STATE.inventory.Si<sp.cost.Si) ok=false; }
    else { for(let p in sp.cost) if(STATE.components[p]<sp.cost[p]) ok=false; }
    if(!ok) return log("ERR: MISSING PARTS.");
    if (t==='probe') { STATE.inventory["Iron Ore"]-=sp.cost["Iron Ore"]; STATE.inventory.Si-=sp.cost.Si; }
    else { for(let p in sp.cost) STATE.components[p]-=sp.cost[p]; }
    STATE.buildQueue.push({ type:t, progress:0, totalDuration:sp.buildTime });
    renderHangar(); updateUI();
}

function processBuildQueue(dt) {
    if (STATE.power.gridStatus === 'BLACKOUT') return;
    for (let i = STATE.buildQueue.length - 1; i >= 0; i--) {
        const j = STATE.buildQueue[i]; j.progress += dt * 1000;
        if (j.progress >= j.totalDuration) { STATE.hangar[j.type]++; log(`SHIPYARD: ${j.type} ready.`); STATE.buildQueue.splice(i, 1); }
    }
    if(document.getElementById('modal-hangar').style.display === 'block') renderHangar();
}

function scanBody(b) {
    b.scanned = true;
    const r = Math.random();
    if (b.type === "Asteroid") {
        if (r>0.7) b.res=["Iron Ore"]; else if(r>0.5) b.res=["Si"]; else if(r>0.3) b.res=["Ice water"]; else if(r>0.1) b.res=["Pt"]; else b.res=[];
    }
    log(`DATA: ${b.name} scanned.`); updateUI();
}

function drainBuffer(a) {
    let td=a; const tick=(a/POWER_CFG.batteryCap)*POWER_CFG.wearRate;
    for(let b of STATE.power.batteries.filter(x=>x.loc==='grid')){ if(td<=0)break;
        if(b.charge>0){ let t=Math.min(b.charge,td); b.charge-=t; b.wear=Math.min(100,b.wear+tick); td-=t; }}
}

function switchTab(t) {
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    document.getElementById(`tab-btn-${t}`).classList.add('active');
    ['factory', 'refinery','greenhouse','kitchen', 'chemlab', 'fuel', 'dsn'].forEach(x=>document.getElementById(`tab-${x}`).style.display=(x===t)?'block':'none');
    if(t==='greenhouse'){ renderGreenhouse(); renderComposter(); }
    if(t==='refinery') { renderWaterFilter(); renderSabatier(); renderSmelter(); renderCad(); }
    if(t==='factory') { renderMetalworks(); renderMachineParts(); }
    if(t==='fuel') { renderFuelFactory(); }
    if(t==='chemlab') { renderChemLab(); }
}

function claimDailyReward() {
    const now = Date.now();
    if (now - STATE.lastDailyClaim < DAILY_COOLDOWN) return log("ERR: Daily reward not ready.");
    STATE.lastDailyClaim = now;
    STATE.inventory["Energy Bar"] = (STATE.inventory["Energy Bar"] || 0) + 1;
    log("REWARD: +1 Energy Bar acquired."); updateUI(); StorageSys.save();
}

function resize() { CANVAS.width = window.innerWidth; CANVAS.height = window.innerHeight; }
function log(m) { const c=UI_CACHE['console']; if(c) c.innerHTML = `<div><span style="color:#556">[${new Date().toLocaleTimeString().split(' ')[0]}]</span> ${m}</div>` + c.innerHTML; }

function updateUI() {
    try {
        if(UI_CACHE['sys-time']) UI_CACHE['sys-time'].innerText = new Date().toISOString().split('T')[1].split('.')[0];
        const fl = Math.floor(STATE.environment.flux * 100);
        if(UI_CACHE['top-flux-val']) UI_CACHE['top-flux-val'].innerText = `${fl}%`;

        const st = UI_CACHE['stamina-val'];
        if(st) {
            st.innerText = `${Math.floor(STATE.stamina.val)}/${STATE.stamina.max}`;
            st.style.color = (STATE.stamina.val<20)?"var(--danger)":"var(--stamina)";
        }

        const btnDaily = UI_CACHE['btn-daily'];
        if(btnDaily) {
            const diff = Date.now() - STATE.lastDailyClaim;
            if (diff >= DAILY_COOLDOWN) {
                btnDaily.disabled = false; btnDaily.innerText = "🎁 CLAIM"; btnDaily.style.opacity = "1"; btnDaily.style.borderColor = "var(--warning)"; btnDaily.style.color = "var(--warning)"; btnDaily.style.boxShadow = "none";
            } else {
                btnDaily.disabled = true; const rem = DAILY_COOLDOWN - diff; const h = Math.floor(rem / 3600000);
                const m = Math.floor((rem % 3600000) / 60000);
                btnDaily.innerText = `${h}h ${m}m`; btnDaily.style.opacity = "0.8"; btnDaily.style.borderColor = "var(--danger)"; btnDaily.style.color = "var(--danger)"; btnDaily.style.boxShadow = "0 0 5px var(--danger)";
            }
        }

        if(UI_CACHE['grid-output']) UI_CACHE['grid-output'].innerText = STATE.power.productionRate.toFixed(4);

        if(UI_CACHE['grid-load']) {
            const gBats = STATE.power.batteries.filter(b => b.loc === 'grid');
            let eff = 100;
            if (gBats.length > 0) {
                const totalWear = gBats.reduce((a,b) => a + b.wear, 0);
                eff = 100 - (totalWear / gBats.length);
            }
            UI_CACHE['grid-load'].innerText = eff.toFixed(1) + "%";
        }

        const gs = UI_CACHE['grid-status-text']; const fb = UI_CACHE['flux-bar'];
        if(gs && fb) {
            gs.innerText=STATE.power.gridStatus; fb.style.width=`${fl}%`;
            if(STATE.power.gridStatus==='ONLINE') { gs.style.color="var(--success)"; fb.style.background="var(--neon)"; }
            else if(STATE.power.gridStatus==='DRAINING') { gs.style.color="var(--warning)"; fb.style.background="var(--warning)"; }
            else { gs.style.color="var(--danger)"; fb.style.background="#333"; }
        }

        const aps = UI_CACHE['active-systems-panel'];
        if(aps) {
            let h = '<div class="header" style="background:transparent; border-color:rgba(255,255,255,0.1); font-size:9px; color:#889;">ACTIVE SYSTEMS</div>';
            let hasActive = false;
            const tag = '<span style="color:#4f4; float:right; text-shadow:0 0 5px #4f4;">LAUNCHED</span>';
            if(STATE.cad.slots.some(s=>s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">ATMOS. DISTILLER ${tag}</div>`; hasActive = true; }
            if(STATE.refinery.waterSlots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">ICE PURIFICATION ${tag}</div>`; hasActive = true; }
            if(STATE.refinery.fermenterSlot.active) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#d400ff; font-size:9px;">BIO-FERMENTATION ${tag}</div>`; hasActive = true; }
            if(STATE.refinery.sabatierSlots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">SABATIER REACTOR COMPLEX ${tag}</div>`; hasActive = true; }
            if(STATE.refinery.smelterSlots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">ORE SMELTER ${tag}</div>`; hasActive = true; }
            if(STATE.fuelFactory && STATE.fuelFactory.slots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:var(--fuel); font-size:9px;">FUEL REFINERY ${tag}</div>`; hasActive = true;
            }
            if(STATE.chemlab && STATE.chemlab.slots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:var(--chem); font-size:9px;">CHEMICAL SYNTHESIS ${tag}</div>`; hasActive = true;
            }
            if(STATE.metalworks && STATE.metalworks.slots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#e0e0e0; font-size:9px;">METALWORKS FABRICATION ${tag}</div>`; hasActive = true;
            }
            if(STATE.machineParts && STATE.machineParts.slots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#e0e0e0; font-size:9px;">MACHINE SHOP ${tag}</div>`; hasActive = true;
            }
            if(STATE.greenhouse.slots.some(s => s.status === 'growing')) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">GREENHOUSE HYDROPONICS ${tag}</div>`; hasActive = true;
            }
            if(STATE.composter.slots.some(s => s.active)) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">BIO-COMPOSTER UNIT ${tag}</div>`; hasActive = true; }
            if(STATE.buildQueue.length > 0) { h += `<div style="padding:2px; border-bottom:1px solid rgba(255,255,255,0.05); color:#ccc; font-size:9px;">SHIPYARD FABRICATION ${tag}</div>`; hasActive = true; }
            if(!hasActive) h += '<div style="padding:2px; color:#555; font-size:9px; font-style:italic;">SYSTEMS IDLE</div>';
            aps.innerHTML = h;
        }

        const consumables = ['Snack', 'Meal', 'Feast', 'Energy Bar'];
        consumables.forEach(k => { if (STATE.inventory[k] === undefined) STATE.inventory[k] = 0; });
        const invEl = UI_CACHE['inventory'];
        if(invEl) {
            invEl.innerHTML = Object.entries(STATE.inventory).filter(([k, v]) => consumables.includes(k)).map(([k,v]) => {
                let act="", col="var(--kitchen)";
                if (v > 0) {
                    const last = STATE.cooldowns[k] || 0; const diff = Date.now() - last;
                    if(diff < EATING_COOLDOWN_MS) {
                        let rem = EATING_COOLDOWN_MS - diff;
                        let m = Math.floor(rem/60000);
                        let s = Math.floor((rem%60000)/1000);
                        act=`<span style="font-size:9px; color:#FF3333; font-weight:bold;">[WAIT ${m}m ${s}s]</span>`;
                    }
                    else { act=`<button class="consume-btn" onclick="consume('${k}')">EAT</button>`; }
                } else { act=`<span style="font-size:8px; color:#555">EMPTY</span>`; }
                return `<div style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.01); padding:2px 4px; border-left:2px solid ${col}; margin-bottom:1px;"><div><span style="color:${col}">${k}</span></div><div style="display:flex; align-items:center;"> <span style="color:#eee; margin-right:5px;">${Math.floor(v)}</span>${act}</div></div>`;
            }).join('') || '<div style="color:#444">EMPTY</div>';
        }

        const gBats = STATE.power.batteries.filter(b => b.loc === 'grid');
        let gh = "";
        if (gBats.length === 0) gh = "<div style='color:var(--danger); font-size:9px; font-weight:bold; animation:blink 1s infinite;'>[!] NO POWER</div>";
        else {
            gh = gBats.map(b => {
                const cp=(b.charge/POWER_CFG.batteryCap)*100, dp=b.wear, ep=100-cp-dp;
                return `<div class="battery-item active-slot"><span class="bat-id">BAT-${b.id}</span><div class="bat-gauge-container"><div class="bg-charge" style="width:${cp}%"></div><div class="bg-empty" style="width:${ep}%"></div><div class="bg-wear" style="width:${dp}%"></div></div><span class="bat-text">${b.wear.toFixed(1)}% WR</span><button class="bat-action-btn eject" onclick="ejectBattery('${b.id}')">EJECT</button></div>`;
            }).join('');
        }
        for(let i=0; i < (POWER_CFG.maxGridSlots - gBats.length); i++) gh += `<div style="border:1px dashed #334; padding:4px; font-size:9px; color:#445; text-align:center; margin-bottom:4px;">[ EMPTY SLOT ]</div>`;
        if(UI_CACHE['active-grid-list']) UI_CACHE['active-grid-list'].innerHTML = gh;

        const lBats = STATE.power.batteries.filter(b => b.loc === 'inventory');
        let bh = "";
        for (let i = 0; i < 5; i++) {
            if (i < lBats.length) {
                const b = lBats[i]; const cp = (b.charge / POWER_CFG.batteryCap) * 100; const dp = b.wear;
                const ep = 100 - cp - dp;
                bh += `<div class="battery-item"><span class="bat-id">BAT-${b.id}</span><div class="bat-gauge-container"><div class="bg-charge" style="width:${cp}%"></div><div class="bg-empty" style="width:${ep}%"></div><div class="bg-wear" style="width:${dp}%"></div></div><div style="display:flex; gap:2px;"><button class="bat-action-btn" style="border-color:var(--agri); color:var(--agri);"
onclick="installBattery('${b.id}')">INSTALL</button><button class="bat-action-btn" style="border-color:var(--danger); color:var(--danger);" onclick="storeBattery('${b.id}')">STORE</button></div></div>`;
            } else {
                bh += `<div style="border:1px dashed #334; padding:4px; font-size:9px; color:#445; text-align:center; margin-bottom:4px;">[ EMPTY RACK SLOT ]</div>`;
            }
        }
        if(UI_CACHE['battery-rack']) UI_CACHE['battery-rack'].innerHTML = bh;

        ['probe','miner','hauler','gas'].forEach(k => { if(UI_CACHE['c-'+k]) UI_CACHE['c-'+k].innerText = STATE.hangar[k]; });
        let fh = "";
        if(STATE.ships.length===0) fh="<div style='padding:5px; color:#445'>NO ACTIVE FLIGHTS</div>";
        else {
            fh = STATE.ships.map(s => {
                let sc="st-active", st="EN ROUTE"; if(s.phase==='mining'){sc="st-mining";st="MINING";} if(s.phase==='return'){sc="st-active";st="RETURN";}
                return `<div class="fleet-item"><div style="display:flex; align-items:center;"><span class="fleet-status ${sc}\"></span><span style="color:${s.spec.color}">${s.type.toUpperCase()}</span></div><div style="color:#8daab9">${st}</div></div>`;
            }).join('');
        }
        if(UI_CACHE['fleet-list']) UI_CACHE['fleet-list'].innerHTML = fh;

        if(UI_CACHE['obj-list']) {
            UI_CACHE['obj-list'].innerHTML = STATE.bodies.filter(b => b.scanned || b.id < 10).slice(0, 15).map(b => `
<tr onclick="STATE.bodies.find(x=>x.id===${b.id}) && openModal(STATE.bodies.find(x=>x.id===${b.id}))">
<td style="color:${b.type==='BASE'?'var(--mars)':'#ccc'}">${b.name}</td><td>${b.type}</td><td>${b.dist.toFixed(1)}</td><td style="color:${(b.res&&b.res[0])?'var(--success)':'#555'}">${b.scanned?(b.res[0]||'-'):'???'}</td>
</tr>`).join('');
        }
    } catch(e) { console.error("UI Error:", e); }
}

init();
