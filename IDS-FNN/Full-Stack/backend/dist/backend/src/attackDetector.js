"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.detector = void 0;
const db_1 = require("./db");
const crypto_1 = require("crypto");
class AttackDetector {
    recentFlows = [];
    isAttacking = false;
    currentAttackStart = null;
    currentAttackFlowCount = 0;
    lastAlertTime = 0;
    lastPrediction = 0;
    async processFlow(flow, onAttackDetected) {
        this.recentFlows.push(flow);
        // Keep a sliding window of the last 200 flows
        if (this.recentFlows.length > 200) {
            this.recentFlows.shift();
        }
        if (flow.prediction !== undefined && String(flow.prediction) !== "0" && flow.prediction !== "") {
            if (!this.isAttacking) {
                this.isAttacking = true;
                this.currentAttackStart = flow;
                this.currentAttackFlowCount = 10; // Account for the 9 preceding flows that triggered this
            }
            else {
                this.currentAttackFlowCount++;
            }
            this.lastPrediction = flow.prediction;
            const now = Date.now();
            // Throttle alerts so frontend popup isn't spammed
            if (now - this.lastAlertTime > 10000) {
                this.lastAlertTime = now;
                const matchingFlows = this.recentFlows.filter(f => f.src_ip === flow.src_ip && f.dst_ip === flow.dst_ip);
                const eventPayload = {
                    attack_id: (0, crypto_1.randomUUID)(),
                    attack_start_time: this.currentAttackStart.timestamp,
                    attack_end_time: flow.timestamp,
                    duration_seconds: 0,
                    source_ip: flow.src_ip,
                    destination_ip: flow.dst_ip,
                    source_port: flow.src_port,
                    destination_port: flow.dst_port,
                    attack_type: flow.prediction,
                    flow_count: this.currentAttackFlowCount
                };
                onAttackDetected(eventPayload, matchingFlows.slice(-10));
            }
        }
        else {
            if (this.isAttacking) {
                // Attack stopped.
                await this.saveAttackToDb(Object.assign({}, this.currentAttackStart), flow);
                this.isAttacking = false;
                this.currentAttackStart = null;
                this.currentAttackFlowCount = 0;
            }
        }
    }
    async saveAttackToDb(startFlow, endFlow) {
        const event = {
            attack_id: (0, crypto_1.randomUUID)(),
            attack_start_time: startFlow.timestamp,
            attack_end_time: endFlow.timestamp,
            duration_seconds: Math.max(0, (new Date(endFlow.timestamp).getTime() - new Date(startFlow.timestamp).getTime()) / 1000),
            source_ip: startFlow.src_ip,
            destination_ip: startFlow.dst_ip,
            source_port: startFlow.src_port,
            destination_port: startFlow.dst_port,
            attack_type: this.lastPrediction,
            flow_count: this.currentAttackFlowCount
        };
        try {
            await db_1.pool.query(`INSERT INTO attack_events 
         (attack_id, attack_start_time, attack_end_time, duration_seconds, source_ip, destination_ip, source_port, destination_port, attack_type, flow_count)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, [
                event.attack_id, event.attack_start_time, event.attack_end_time,
                event.duration_seconds, event.source_ip, event.destination_ip,
                event.source_port, event.destination_port,
                typeof event.attack_type === 'number' ? event.attack_type : (isNaN(Number(event.attack_type)) ? -1 : Number(event.attack_type)),
                event.flow_count
            ]);
        }
        catch (err) {
            console.error('Error saving attack to DB:', err);
        }
    }
}
exports.detector = new AttackDetector();
