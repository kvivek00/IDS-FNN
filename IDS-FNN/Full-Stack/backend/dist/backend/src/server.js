"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const http_1 = require("http");
const socket_io_1 = require("socket.io");
const cors_1 = __importDefault(require("cors"));
const idsClient_1 = require("./idsClient");
const attackDetector_1 = require("./attackDetector");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const app = (0, express_1.default)();
app.use((0, cors_1.default)());
const httpServer = (0, http_1.createServer)(app);
const io = new socket_io_1.Server(httpServer, {
    cors: {
        origin: '*', // Allow all for this project
        methods: ['GET', 'POST']
    }
});
let totalFlowsProcessed = 0;
let totalAttacksDetected = 0;
// To batch flows to frontend
let batchedFlows = [];
// Send batch every 1 second
const FLUSH_INTERVAL = 1000;
io.on('connection', (socket) => {
    console.log(`🔌 Client connected: ${socket.id}`);
    // Send initial stats
    socket.emit('stats_update', {
        totalFlowsProcessed,
        totalAttacksDetected,
        currentThreatLevel: totalAttacksDetected > 0 ? 'WARNING' : 'SAFE'
    });
    socket.on('disconnect', () => {
        console.log(`❌ Client disconnected: ${socket.id}`);
    });
});
setInterval(() => {
    if (batchedFlows.length > 0) {
        io.emit('flows_batch', batchedFlows);
        batchedFlows = [];
    }
    // Update stats periodically
    let currentThreatLevel = 'SAFE';
    // simple heuristic: if we had an attack recently, warning/danger. Here we just fake it based on recent activity.
    // We can just rely on detector state but detector is isolated. We will set it globally during alerts.
    io.emit('stats_update', {
        totalFlowsProcessed,
        totalAttacksDetected,
        currentThreatLevel: attackDetector_1.detector.isAttacking ? 'DANGER' : (totalAttacksDetected > 0 ? 'WARNING' : 'SAFE')
    });
}, FLUSH_INTERVAL);
idsClient_1.idsClient.on('flow', (flow) => {
    totalFlowsProcessed++;
    attackDetector_1.detector.processFlow(flow, (event, lastFlows) => {
        totalAttacksDetected++;
        console.error(`🚨 ATTACK DETECTED! Type: ${event.attack_type}, IP: ${event.source_ip}`);
        // Broadcast alert to frontend
        io.emit('attack_alert', {
            message: `Potential Network Attack Detected`,
            attackClass: event.attack_type,
            flows: lastFlows.map(f => ({
                id: Math.random().toString(36).substr(2, 9),
                timestamp: f.timestamp,
                src_ip: f.src_ip,
                dst_ip: f.dst_ip,
                src_port: f.src_port,
                dst_port: f.dst_port,
                prediction: f.prediction || 0,
                isSuspicious: f.prediction !== undefined && String(f.prediction) !== "0" && f.prediction !== ""
            }))
        });
    });
    batchedFlows.unshift({
        id: Math.random().toString(36).substr(2, 9),
        timestamp: flow.timestamp,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        prediction: flow.prediction,
        isSuspicious: flow.prediction !== undefined && String(flow.prediction) !== "0" && flow.prediction !== ""
    });
    // Limit batch size so we don't bombard the frontend
    if (batchedFlows.length > 50) {
        batchedFlows.length = 50;
    }
});
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
    console.log(`🚀 IDS Backend Server running on port ${PORT}`);
    // Start the mock IDS flow generation
    idsClient_1.idsClient.start();
});
