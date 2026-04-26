import React from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { TrendingUp } from 'lucide-react';

export const Charts: React.FC = () => {
  const { historicStats } = useDashboardStore();

  return (
    <div className="bg-[var(--color-cyber-light)]/60 border border-[var(--color-cyber-border)] rounded-xl p-4 backdrop-blur-md h-[500px] flex flex-col">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-lg font-semibold tracking-wider flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-[var(--color-neon-pink)]" />
          SYSTEM ACTIVITY TIMELINE
        </h2>
      </div>
      
      <div className="flex-1 w-full relative">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart
            data={historicStats}
            margin={{ top: 10, right: 10, left: 0, bottom: 0 }}
          >
            <defs>
              <linearGradient id="colorFlows" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--color-neon-blue)" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="var(--color-neon-blue)" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--color-neon-pink)" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="var(--color-neon-pink)" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--color-cyber-border)" vertical={false} />
            <XAxis dataKey="time" stroke="var(--color-text-muted)" fontSize={12} tickMargin={10} minTickGap={30} />
            <YAxis stroke="var(--color-text-muted)" fontSize={12} tickFormatter={(value) => `${value >= 1000 ? (value / 1000).toFixed(1) + 'k' : value}`} />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'rgba(7, 11, 25, 0.9)', 
                borderColor: 'var(--color-cyber-border)',
                borderRadius: '8px',
                backdropFilter: 'blur(8px)',
                color: 'white'
              }}
              itemStyle={{ fontFamily: 'monospace' }}
            />
            <Area 
              type="monotone" 
              dataKey="totalFlows" 
              name="Processed Flows"
              stroke="var(--color-neon-blue)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorFlows)" 
              isAnimationActive={false}
            />
            <Area 
              type="monotone" 
              dataKey="totalAttacks" 
              name="Detected Attacks"
              stroke="var(--color-neon-pink)" 
              strokeWidth={2}
              fillOpacity={1} 
              fill="url(#colorAttacks)" 
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
