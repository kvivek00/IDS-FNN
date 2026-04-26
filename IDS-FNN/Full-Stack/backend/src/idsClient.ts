import { EventEmitter } from 'events';
import { IDSFlow } from '../../shared/types';
import axios from 'axios';
import dotenv from 'dotenv';

dotenv.config();

class IDSClient extends EventEmitter {
  private url = process.env.IDS_API_URL || 'http://localhost:8000/predict';
  private shouldReconnect = true;

  public async start() {
    this.shouldReconnect = true;
    this.connect();
  }

  private async connect() {
    try {
      console.log(`📡 Connecting to IDS API at ${this.url}`);
      const response = await axios({
        method: 'get',
        url: this.url,
        responseType: 'stream'
      });
      
      console.log('✅ Connected to IDS API stream!');
      
      let buffer = '';

      response.data.on('data', (chunk: Buffer) => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        // The last part might be an incomplete JSON string
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.trim()) {
            try {
              const flow: IDSFlow = JSON.parse(line);
              this.emit('flow', flow);
            } catch (err) {
              console.error('Failed to parse IDS stream JSON:', err);
            }
          }
        }
      });

      response.data.on('end', () => {
        console.log('🔴 IDS API stream ended.');
        this.reconnect();
      });

      response.data.on('error', (err: any) => {
        console.error('IDS stream error:', err.message);
        this.reconnect();
      });

    } catch (err: any) {
      console.error(`❌ Failed to connect to IDS API: ${err.message}`);
      this.reconnect();
    }
  }

  private reconnect() {
    if (this.shouldReconnect) {
      console.log('🔄 Reconnecting in 5 seconds...');
      setTimeout(() => this.connect(), 5000);
    }
  }

  public stop() {
    this.shouldReconnect = false;
  }
}

export const idsClient = new IDSClient();
