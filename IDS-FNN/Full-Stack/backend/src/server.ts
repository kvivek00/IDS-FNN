import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { idsClient } from './idsClient';
import { detector } from './attackDetector';
import { IDSFlow, FlowDisplay, DashboardStats, ThreatLevel } from '../../shared/types';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(cors());

const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: '*', // Allow all for this project
    methods: ['GET', 'POST']
  }
});

let totalFlowsProcessed = 0;
let totalAttacksDetected = 0;

// To batch flows to frontend
let batchedFlows: FlowDisplay[] = [];
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
  let currentThreatLevel: ThreatLevel = 'SAFE';
  // simple heuristic: if we had an attack recently, warning/danger. Here we just fake it based on recent activity.
  // We can just rely on detector state but detector is isolated. We will set it globally during alerts.
  
  io.emit('stats_update', {
    totalFlowsProcessed,
    totalAttacksDetected,
    currentThreatLevel: detector.isAttacking ? 'DANGER' : (totalAttacksDetected > 0 ? 'WARNING' : 'SAFE')
  });

}, FLUSH_INTERVAL);

idsClient.on('flow', (flow: IDSFlow) => {
  totalFlowsProcessed++;
  
  detector.processFlow(flow, (event, lastFlows) => {
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
  idsClient.start();
});
