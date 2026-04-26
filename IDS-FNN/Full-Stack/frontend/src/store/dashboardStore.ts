import { create } from 'zustand';
import type { FlowDisplay, DashboardStats, ThreatLevel, AttackAlertEvent } from '../../../shared/types';
import { io, Socket } from 'socket.io-client';

interface DashboardState {
  socket: Socket | null;
  isConnected: boolean;
  flows: FlowDisplay[];
  stats: DashboardStats;
  historicStats: { time: string; totalFlows: number; totalAttacks: number }[];
  activeAlert: AttackAlertEvent | null;
  
  // Actions
  connect: (url: string) => void;
  disconnect: () => void;
  clearAlert: () => void;
}

const MAX_FLOWS = 200;
const MAX_HISTORY = 60;

export const useDashboardStore = create<DashboardState>((set, get) => ({
  socket: null,
  isConnected: false,
  flows: [],
  stats: {
    totalFlowsProcessed: 0,
    totalAttacksDetected: 0,
    currentThreatLevel: 'SAFE',
  },
  historicStats: [],
  activeAlert: null,

  connect: (url: string) => {
    const currentSocket = get().socket;
    if (currentSocket) return;

    const socket = io(url);

    socket.on('connect', () => {
      set({ isConnected: true });
    });

    socket.on('disconnect', () => {
      set({ isConnected: false });
    });

    socket.on('flows_batch', (newFlows: FlowDisplay[]) => {
      set((state) => {
        const updatedFlows = [...newFlows, ...state.flows].slice(0, MAX_FLOWS);
        return { flows: updatedFlows };
      });
    });

    socket.on('stats_update', (stats: DashboardStats) => {
      set((state) => {
        const now = new Date();
        const timeLabel = `${now.getHours()}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
        
        const newHistory = [
          ...state.historicStats,
          { time: timeLabel, totalFlows: stats.totalFlowsProcessed, totalAttacks: stats.totalAttacksDetected }
        ].slice(-MAX_HISTORY);

        return { 
          stats,
          historicStats: newHistory
        };
      });
    });

    socket.on('attack_alert', (alert: AttackAlertEvent) => {
      set({ activeAlert: alert });
    });

    set({ socket });
  },

  disconnect: () => {
    const socket = get().socket;
    if (socket) {
      socket.disconnect();
      set({ socket: null, isConnected: false });
    }
  },

  clearAlert: () => {
    set({ activeAlert: null });
  }
}));
