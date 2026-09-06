'use client';

import React, { useState } from 'react';
import DagVisualizer from '@/components/dag/DagVisualizer';
import TerminalView from '@/components/terminal/TerminalView';
import FindingsDrawer from '@/components/findings/FindingsDrawer';
import { useScanStream } from '@/hooks/useScanStream';
import { ShieldCheck, Play, TerminalSquare, AlertCircle } from 'lucide-react';

export default function DashboardPage() {
  const { isScanning, nodeStates, logs, metrics, findings, error, startScan, scanId } = useScanStream();
  
  const [activeTab, setActiveTab] = useState<'terminal' | 'findings'>('terminal');
  const [repoUrl, setRepoUrl] = useState('');
  const [githubPat, setGithubPat] = useState('');
  const [isDemo, setIsDemo] = useState(false);

  const handleStartScan = () => {
    // If not a demo and no repo url provided, default to demo mode for safety
    if (!isDemo && !repoUrl.trim()) {
      startScan('', '', true);
    } else {
      startScan(repoUrl, githubPat, isDemo);
    }
  };

  const isComplete = nodeStates['node_complete'] === 'completed';

  return (
    <div className="w-screen h-screen flex flex-col bg-[#05070A] text-slate-200 overflow-hidden font-sans">
      
      {/* Top Navbar */}
      <header className="h-16 border-b border-slate-800 bg-[#0A0C10] flex items-center justify-between px-6 shrink-0">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-blue-500" />
          <h1 className="text-xl font-bold tracking-tight">VerifyFix <span className="text-blue-500 font-light">SOC</span></h1>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 bg-slate-900 rounded-md border border-slate-700 px-3 py-1">
            <input 
              type="checkbox" 
              id="demoMode" 
              checked={isDemo}
              onChange={(e) => setIsDemo(e.target.checked)}
              className="accent-blue-500"
            />
            <label htmlFor="demoMode" className="text-sm text-slate-300 select-none">Demo Repos</label>
          </div>

          <input 
            type="text" 
            placeholder={isDemo ? "Demo Repository Selected" : "GitHub Repository URL (owner/repo)"}
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            disabled={isDemo || isScanning}
            className="bg-slate-900 border border-slate-700 rounded-md px-3 py-1.5 text-sm w-64 focus:outline-none focus:border-blue-500 focus:shadow-[0_0_10px_rgba(59,130,246,0.3)] disabled:opacity-50"
          />

          <input 
            type="password" 
            placeholder="GitHub PAT (Optional)"
            value={githubPat}
            onChange={(e) => setGithubPat(e.target.value)}
            disabled={isDemo || isScanning}
            className="bg-slate-900 border border-slate-700 rounded-md px-3 py-1.5 text-sm w-48 focus:outline-none focus:border-blue-500 focus:shadow-[0_0_10px_rgba(59,130,246,0.3)] disabled:opacity-50"
          />

          <button
            onClick={handleStartScan}
            disabled={isScanning}
            className={`flex items-center gap-2 px-4 py-1.5 rounded-md font-semibold text-sm transition-all
              ${isScanning 
                ? 'bg-slate-800 text-slate-500 cursor-not-allowed' 
                : 'bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_10px_rgba(37,99,235,0.4)]'
              }`}
          >
            <Play size={16} fill={isScanning ? 'none' : 'currentColor'} />
            {isScanning ? 'Scanning...' : 'Start Verification'}
          </button>
        </div>
      </header>

      {error && (
        <div className="bg-rose-500/20 border-b border-rose-500/30 text-rose-400 px-6 py-2 text-sm flex items-center gap-2">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-h-0">
        
        {/* Top Split: DAG Canvas */}
        <div className="h-[60%] w-full p-4 shrink-0 border-b border-slate-800 bg-[#05070A]">
          <DagVisualizer nodeStates={nodeStates} retryCount={metrics.retries} />
        </div>

        {/* Bottom Split: Drawer */}
        <div className="h-[40%] w-full flex flex-col bg-[#0A0C10]">
          
          {/* Tabs */}
          <div className="flex border-b border-slate-800 shrink-0">
            <button
              onClick={() => setActiveTab('terminal')}
              className={`flex items-center gap-2 px-6 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === 'terminal' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              <TerminalSquare size={16} />
              Live Terminal
            </button>
            <button
              onClick={() => setActiveTab('findings')}
              className={`flex items-center gap-2 px-6 py-3 text-sm font-medium border-b-2 transition-colors ${activeTab === 'findings' ? 'border-blue-500 text-blue-400' : 'border-transparent text-slate-500 hover:text-slate-300'}`}
            >
              <ShieldCheck size={16} />
              Findings & Report
            </button>
          </div>

          {/* Tab Content */}
          <div className="flex-1 min-h-0 relative">
            <div className={`absolute inset-0 ${activeTab === 'terminal' ? 'block' : 'hidden'}`}>
              <TerminalView logs={logs} />
            </div>
            <div className={`absolute inset-0 ${activeTab === 'findings' ? 'block' : 'hidden'}`}>
              <FindingsDrawer findings={findings} metrics={metrics} scanId={scanId} isComplete={isComplete} />
            </div>
          </div>

        </div>

      </div>

    </div>
  );
}
