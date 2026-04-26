import React from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { ShieldAlert, ShieldCheck, Shield, Activity, Database } from 'lucide-react';

export const StatsPanel: React.FC = () => {
  const { stats } = useDashboardStore();

  const getThreatColors = () => {
    switch (stats.currentThreatLevel) {
      case 'SAFE':
        return 'text-[var(--color-terminal-green)] border-[var(--color-terminal-green)]/30 bg-[var(--color-terminal-green)]/5 shadow-[0_0_15px_rgba(0,255,65,0.15)]';
      case 'WARNING':
        return 'text-[var(--color-warning-yellow)] border-[var(--color-warning-yellow)]/30 bg-[var(--color-warning-yellow)]/5 shadow-[0_0_15px_rgba(255,215,0,0.15)] animate-pulse';
      case 'DANGER':
        return 'text-[var(--color-danger-red)] border-[var(--color-danger-red)]/50 bg-[var(--color-danger-red)]/10 shadow-[0_0_20px_rgba(255,51,51,0.3)] animate-pulse';
      default:
        return 'text-[var(--color-text-muted)] border-[var(--color-cyber-border)]';
    }
  };

  const getThreatIcon = () => {
    switch (stats.currentThreatLevel) {
      case 'SAFE': return <ShieldCheck className="w-10 h-10 mb-2 opacity-80" />;
      case 'WARNING': return <ShieldAlert className="w-10 h-10 mb-2 opacity-80" />;
      case 'DANGER': return <ShieldAlert className="w-10 h-10 mb-2 animate-bounce" />;
      default: return <Shield className="w-10 h-10 mb-2 opacity-50" />;
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      {/* Threat Level Panel */}
      <div className={`flex flex-col items-center justify-center p-6 rounded-xl border backdrop-blur-sm transition-all duration-500 ${getThreatColors()}`}>
        {getThreatIcon()}
        <h3 className="text-sm uppercase tracking-widest opacity-80 mb-1">Threat Level</h3>
        <div className="text-3xl font-black tracking-widest">{stats.currentThreatLevel}</div>
      </div>

      {/* Total Flows Panel */}
      <div className="flex flex-col items-start justify-center p-6 rounded-xl border border-[var(--color-cyber-border)] bg-[var(--color-cyber-light)]/40 backdrop-blur-sm shadow-[0_0_10px_rgba(0,240,255,0.05)] relative overflow-hidden group">
        <div className="absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity duration-500">
          <Activity className="w-32 h-32 text-[var(--color-neon-blue)]" />
        </div>
        <h3 className="text-sm uppercase tracking-widest text-[var(--color-text-muted)] mb-2 flex items-center gap-2">
          <Activity className="w-4 h-4 text-[var(--color-neon-blue)]" /> Analyzed Flows
        </h3>
        <div className="text-4xl font-light text-white font-mono">
          {stats.totalFlowsProcessed.toLocaleString()}
        </div>
      </div>

      {/* Total Attacks Panel */}
      <div className="flex flex-col items-start justify-center p-6 rounded-xl border border-[var(--color-cyber-border)] bg-[var(--color-cyber-light)]/40 backdrop-blur-sm shadow-[0_0_10px_rgba(255,0,229,0.05)] relative overflow-hidden group">
        <div className="absolute -right-4 -top-4 opacity-5 group-hover:opacity-10 transition-opacity duration-500">
          <Database className="w-32 h-32 text-[var(--color-neon-pink)]" />
        </div>
        <h3 className="text-sm uppercase tracking-widest text-[var(--color-text-muted)] mb-2 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-[var(--color-neon-pink)]" /> Detected Attacks
        </h3>
        <div className="text-4xl font-light text-white font-mono">
          {stats.totalAttacksDetected.toLocaleString()}
        </div>
      </div>
    </div>
  );
};
