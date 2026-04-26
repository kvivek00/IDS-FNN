import React from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { Activity, Radio } from 'lucide-react';

export const Header: React.FC = () => {
  const { isConnected } = useDashboardStore();

  return (
    <header className="flex justify-between items-center py-4 px-6 border-b border-[var(--color-cyber-border)] bg-[var(--color-cyber-dark)]/80 backdrop-blur-md sticky top-0 z-50">
      <div className="flex items-center gap-3">
        <Activity className="text-[var(--color-neon-blue)] w-8 h-8" />
        <h1 className="text-2xl font-bold tracking-wider text-white shadow-neon">
          IDS
        </h1>
      </div>
      
      <div className="flex items-center gap-2 bg-[var(--color-cyber-light)] px-4 py-2 rounded-full border border-[var(--color-cyber-border)]">
        <div className="relative flex h-3 w-3">
          {isConnected ? (
            <>
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--color-terminal-green)] opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-[var(--color-terminal-green)]"></span>
            </>
          ) : (
            <span className="relative inline-flex rounded-full h-3 w-3 bg-[var(--color-danger-red)]"></span>
          )}
        </div>
        <span className="text-sm text-[var(--color-text-muted)] font-mono uppercase tracking-widest">
          {isConnected ? 'System Online' : 'System Offline'}
        </span>
        <Radio className={`w-4 h-4 ml-2 ${isConnected ? 'text-[var(--color-terminal-green)]' : 'text-[var(--color-text-muted)]'}`} />
      </div>
    </header>
  );
};
