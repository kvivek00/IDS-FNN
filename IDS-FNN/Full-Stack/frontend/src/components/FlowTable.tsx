import React from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { motion, AnimatePresence } from 'framer-motion';
import { Activity } from 'lucide-react';

export const FlowTable: React.FC = () => {
  const { flows } = useDashboardStore();

  const getAttackName = (prediction: number | string | undefined) => {
    if (prediction === undefined || prediction === 0 || prediction === "0" || prediction === "") return "OK";
    
    const mapping: Record<string, string> = {
      '1': 'DoS',
      '2': 'Probe',
      '3': 'R2L',
      '4': 'U2R'
    };

    const classStr = String(prediction);
    return mapping[classStr] || classStr;
  };

  return (
    <div className="bg-[var(--color-cyber-light)]/60 border border-[var(--color-cyber-border)] rounded-xl backdrop-blur-md overflow-hidden flex flex-col h-[500px]">
      <div className="p-4 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-dark)]/40 flex justify-between items-center">
        <h2 className="text-lg font-semibold tracking-wider flex items-center gap-2">
          <Activity className="w-5 h-5 text-[var(--color-neon-blue)]" />
          LIVE TRAFFIC FEED
        </h2>
        <span className="text-xs text-[var(--color-text-muted)] font-mono bg-black/40 px-3 py-1 rounded-full border border-[var(--color-cyber-border)]">
          {flows.length} / 200 EVENTS
        </span>
      </div>
      
      <div className="flex-1 overflow-auto overflow-x-auto relative">
        <table className="w-full text-left font-mono text-sm whitespace-nowrap">
          <thead className="text-[var(--color-text-muted)] sticky top-0 bg-[var(--color-cyber-dark)]/90 backdrop-blur z-10 text-xs">
            <tr>
              <th className="px-6 py-3 font-medium uppercase tracking-wider">Timestamp</th>
              <th className="px-6 py-3 font-medium uppercase tracking-wider">Source</th>
              <th className="px-6 py-3 font-medium uppercase tracking-wider">Destination</th>
              <th className="px-6 py-3 font-medium uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {flows.map((flow) => (
                <motion.tr
                  key={flow.id}
                  initial={{ opacity: 0, y: -20, backgroundColor: 'rgba(0, 240, 255, 0.2)' }}
                  animate={{ opacity: 1, y: 0, backgroundColor: flow.isSuspicious ? 'rgba(255, 51, 51, 0.1)' : 'transparent' }}
                  transition={{ duration: 0.5 }}
                  className={`border-b border-[var(--color-cyber-border)]/50 hover:bg-[var(--color-cyber-border)]/30 transition-colors ${flow.isSuspicious ? 'text-[var(--color-danger-red)]' : 'text-gray-300'}`}
                >
                  <td className="px-6 py-3">
                    {new Date(flow.timestamp).toLocaleTimeString(undefined, {
                      hour12: false,
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                      fractionalSecondDigits: 3
                    } as any)}
                  </td>
                  <td className="px-6 py-3">
                    <span className="opacity-70 text-[var(--color-neon-blue)]">{flow.src_ip}</span>
                    <span className="opacity-50 mx-1">:</span>
                    <span className="text-xs opacity-90">{flow.src_port}</span>
                  </td>
                  <td className="px-6 py-3">
                    <span className="opacity-70 text-[var(--color-neon-pink)]">{flow.dst_ip}</span>
                    <span className="opacity-50 mx-1">:</span>
                    <span className="text-xs opacity-90">{flow.dst_port}</span>
                  </td>
                  <td className="px-6 py-3">
                    {flow.isSuspicious ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-[var(--color-danger-red)]/10 border border-[var(--color-danger-red)]/30 uppercase">
                        <span className="w-2 h-2 rounded-full bg-[var(--color-danger-red)] animate-pulse"></span>
                        {getAttackName(flow.prediction)}
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold text-[var(--color-text-muted)]">
                        <span className="w-2 h-2 rounded-full bg-[var(--color-terminal-green)]/30"></span>
                        OK
                      </span>
                    )}
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
            
            {flows.length === 0 && (
              <tr>
                <td colSpan={4} className="px-6 py-12 text-center text-[var(--color-text-muted)] italic">
                  Awaiting traffic feed...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
