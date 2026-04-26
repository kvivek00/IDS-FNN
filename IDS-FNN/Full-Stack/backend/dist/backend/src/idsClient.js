"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.idsClient = void 0;
const events_1 = require("events");
const axios_1 = __importDefault(require("axios"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
class IDSClient extends events_1.EventEmitter {
    url = process.env.IDS_API_URL || 'http://localhost:8000/predict';
    shouldReconnect = true;
    async start() {
        this.shouldReconnect = true;
        this.connect();
    }
    async connect() {
        try {
            console.log(`📡 Connecting to IDS API at ${this.url}`);
            const response = await (0, axios_1.default)({
                method: 'get',
                url: this.url,
                responseType: 'stream'
            });
            console.log('✅ Connected to IDS API stream!');
            let buffer = '';
            response.data.on('data', (chunk) => {
                buffer += chunk.toString();
                const lines = buffer.split('\n');
                // The last part might be an incomplete JSON string
                buffer = lines.pop() || '';
                for (const line of lines) {
                    if (line.trim()) {
                        try {
                            const flow = JSON.parse(line);
                            this.emit('flow', flow);
                        }
                        catch (err) {
                            console.error('Failed to parse IDS stream JSON:', err);
                        }
                    }
                }
            });
            response.data.on('end', () => {
                console.log('🔴 IDS API stream ended.');
                this.reconnect();
            });
            response.data.on('error', (err) => {
                console.error('IDS stream error:', err.message);
                this.reconnect();
            });
        }
        catch (err) {
            console.error(`❌ Failed to connect to IDS API: ${err.message}`);
            this.reconnect();
        }
    }
    reconnect() {
        if (this.shouldReconnect) {
            console.log('🔄 Reconnecting in 5 seconds...');
            setTimeout(() => this.connect(), 5000);
        }
    }
    stop() {
        this.shouldReconnect = false;
    }
}
exports.idsClient = new IDSClient();
