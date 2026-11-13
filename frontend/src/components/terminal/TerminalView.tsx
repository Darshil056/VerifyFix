import React, { useEffect, useRef } from 'react';
import { ScanLog } from '@/hooks/useScanStream';
import { Terminal as TerminalIcon } from 'lucide-react';

interface TerminalViewProps {
  logs: ScanLog[];
}

export default function TerminalView({ logs }: TerminalViewProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const colorizeLog = (msg: string) => {
    if (msg.includes('[INFO]')) return <span className="text-blue-400">{msg}</span>;
    if (msg.includes('[WARN]') || msg.includes('[Critic]')) return <span className="text-amber-400">{msg}</span>;
    if (msg.includes('[ERROR]')) return <span className="text-rose-500">{msg}</span>;
    if (msg.includes('[Sandbox]') || msg.includes('VULNERABILITY_CONFIRMED')) return <span className="text-rose-400">{msg}</span>;
    if (msg.includes('[Discovery]')) return <span className="text-emerald-400">{msg}</span>;
    if (msg.includes('[Senior Analyst]')) return <span className="text-cyan-400">{msg}</span>;
    return <span className="text-slate-300">{msg}</span>;
  };

  return (
    <div className="w-full h-full flex flex-col bg-[#05070A] border-t border-slate-800">
      <div className="flex items-center gap-2 px-4 py-2 bg-[#0A0C10] border-b border-slate-800">
        <TerminalIcon size={16} className="text-slate-400" />
        <span className="text-xs font-semibold text-slate-300 tracking-wider">LIVE EXECUTION LOGS</span>
      </div>
      
      <div 
        ref={scrollRef}
        className="flex-1 p-4 overflow-y-auto font-mono text-sm leading-relaxed"
      >
        {logs.length === 0 ? (
          <div className="text-slate-600 italic">Waiting for scan to start...</div>
        ) : (
          logs.map((log, i) => (
            <div key={i} className="mb-1">
              <span className="text-slate-600 mr-3">
                {new Date(log.timestamp).toLocaleTimeString()}
              </span>
              {colorizeLog(log.message)}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
