import React, { useEffect } from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, X } from 'lucide-react';

export const AttackAlert: React.FC = () => {
  const { activeAlert, clearAlert } = useDashboardStore();

  useEffect(() => {
    if (activeAlert) {
      // Play alert sound if user has interacted with the document
      const audio = new Audio('https://assets.mixkit.co/active_storage/sfx/933/933-preview.mp3');
      audio.volume = 0.5;
      audio.play().catch(e => console.log("Audio play prevented by browser policy", e));
      
      // Auto clear after 10 seconds
      const timer = setTimeout(() => {
        clearAlert();
      }, 10000);
      return () => clearTimeout(timer);
    }
  }, [activeAlert, clearAlert]);

  const getAttackDisplayName = (attackClass: number | string | undefined) => {
    if (attackClass === undefined) return 'Unknown';
    
    const mapping: Record<string, string> = {
      '1': 'DoS (Denial of Service)',
      '2': 'Probe (Scanning)',
      '3': 'R2L (Remote to Local)',
      '4': 'U2R (User to Root)'
    };

    const classStr = String(attackClass);
    return mapping[classStr] || classStr;
  };

  return (
    <AnimatePresence>
      {activeAlert && (
        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 50 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 50 }}
          className="fixed bottom-8 right-8 z-50 max-w-lg w-full"
        >
          <div className="bg-[var(--color-danger-red)]/10 border border-[var(--color-danger-red)] rounded-xl shadow-[0_0_30px_rgba(255,51,51,0.4)] backdrop-blur-xl overflow-hidden animate-[pulse_2s_infinite]">
            <div className="bg-[var(--color-danger-red)] text-white p-4 flex justify-between items-center relative overflow-hidden">
              <div className="absolute inset-0 bg-white/20 animate-[pulse_1s_infinite]"></div>
              <div className="flex items-center gap-3 relative z-10">
                <AlertTriangle className="w-8 h-8 " />
                <h2 className="text-xl font-black tracking-widest uppercase">CRITICAL ALERT</h2>
              </div>
              <button 
                onClick={clearAlert}
                 className="relative z-10 hover:bg-black/20 p-1 rounded-full text-white/80 hover:text-white transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            <div className="p-5 font-mono">
              <p className="text-[var(--color-danger-red)] font-bold mb-2 text-lg">{activeAlert.message}</p>
              {activeAlert.attackClass !== undefined && (
                <p className="bg-[var(--color-danger-red)]/20 text-[var(--color-danger-red)] px-3 py-1 rounded inline-block mb-4 border border-[var(--color-danger-red)]/50 font-bold">
                  Attack Type: {getAttackDisplayName(activeAlert.attackClass)}
                </p>
              )}
              
              <div className="bg-black/50 rounded-lg p-3 text-sm h-32 overflow-y-auto mb-2 border border-[var(--color-danger-red)]/30 custom-scrollbar">
                {activeAlert.flows.map((flow, idx) => (
                  <div key={idx} className="flex justify-between items-center border-b border-white/5 last:border-0 py-1 font-mono text-xs">
                    <span className="text-[var(--color-neon-blue)] opacity-80">{flow.src_ip}:{flow.src_port}</span>
                    <span className="text-[var(--color-text-muted)] opacity-50">→</span>
                    <span className="text-[var(--color-neon-pink)] opacity-80">{flow.dst_ip}:{flow.dst_port}</span>
                  </div>
                ))}
              </div>
              
              <div className="text-right text-xs text-[var(--color-text-muted)] mt-2">
                System triggered automated response constraints.
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
