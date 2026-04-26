import { useEffect } from 'react';
import { useDashboardStore } from './store/dashboardStore';
import { Header } from './components/Header';
import { StatsPanel } from './components/StatsPanel';
import { FlowTable } from './components/FlowTable';
import { Charts } from './components/Charts';
import { AttackAlert } from './components/AttackAlert';
import { Footer } from './components/Footer';

function App() {
  const { connect, disconnect } = useDashboardStore();

  useEffect(() => {
    // Connect to Backend WebSocket
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';
    connect(API_URL);

    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  // A grid background overlay for the cyber feel
  return (
    <div className="min-h-screen text-white relative">
      <div className="fixed inset-0 pointer-events-none opacity-[0.03] z-0" 
        style={{
          backgroundImage: `linear-gradient(var(--color-neon-blue) 1px, transparent 1px),
          linear-gradient(90deg, var(--color-neon-blue) 1px, transparent 1px)`,
          backgroundSize: '40px 40px'
        }}
      />
      
      <div className="relative z-10 flex flex-col min-h-screen">
        <Header />
        
        <main className="flex-1 p-6 max-w-[1600px] w-full mx-auto">
          <StatsPanel />
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <FlowTable />
            <Charts />
          </div>
        </main>

        <Footer />
      </div>

      <AttackAlert />
    </div>
  );
}

export default App;
