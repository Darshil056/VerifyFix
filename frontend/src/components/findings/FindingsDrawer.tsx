import React from 'react';
import { Vulnerability } from '@/hooks/useScanStream';
import { Download, Shield, ShieldAlert, Target, FileCode } from 'lucide-react';

interface FindingsDrawerProps {
  findings: Vulnerability[];
  metrics: {
    candidates: number;
    pruned: number;
    confirmed: number;
  };
  scanId: string | null;
  isComplete: boolean;
  onViewInCode?: (finding: Vulnerability) => void;
}

export default function FindingsDrawer({ findings, metrics, scanId, isComplete, onViewInCode }: FindingsDrawerProps) {
  const handleDownload = () => {
    if (scanId) {
      window.location.href = `http://localhost:5000/api/report/download?scan_id=${scanId}`;
    }
  };

  return (
    <div className="w-full h-full flex flex-col bg-[#0A0C10] border-t border-slate-800">
      
      {/* Metrics Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-800 bg-[#111827]">
        <div className="flex gap-6">
          <div className="flex items-center gap-2">
            <Target className="w-5 h-5 text-slate-400" />
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 uppercase">Candidates</span>
              <span className="font-mono text-lg text-slate-200">{metrics.candidates}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-emerald-500" />
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 uppercase">Pruned (Safe)</span>
              <span className="font-mono text-lg text-emerald-400">{metrics.pruned}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-500" />
            <div className="flex flex-col">
              <span className="text-xs text-slate-500 uppercase">Confirmed</span>
              <span className="font-mono text-lg text-rose-400">{metrics.confirmed}</span>
            </div>
          </div>
        </div>

        <button
          onClick={handleDownload}
          disabled={!isComplete || !scanId}
          className={`flex items-center gap-2 px-4 py-2 rounded-md font-semibold text-sm transition-all
            ${isComplete 
              ? 'bg-blue-600 hover:bg-blue-500 text-white shadow-[0_0_10px_rgba(37,99,235,0.4)]' 
              : 'bg-slate-800 text-slate-500 cursor-not-allowed'
            }`}
        >
          <Download size={16} />
          Download Word Report
        </button>
      </div>

      {/* Findings List */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {findings.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500">
            No confirmed vulnerabilities to display yet.
          </div>
        ) : (
          findings.map((finding, idx) => (
            <div key={idx} className="bg-[#111827] rounded-lg border border-slate-800 p-4">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <span className="px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs font-mono">
                    {finding.cwe_id}
                  </span>
                  <h3 className="text-slate-200 font-semibold">{finding.vulnerability_name}</h3>
                </div>
                <div className="flex items-center gap-2">
                  {onViewInCode && finding.file_path && (
                    <button
                      onClick={() => onViewInCode(finding)}
                      className="flex items-center gap-1.5 px-2 py-1 rounded text-xs text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 border border-cyan-500/20 transition-all"
                    >
                      <FileCode size={12} />
                      View in Code
                    </button>
                  )}
                  <span className="text-xs text-slate-400 font-mono">
                    {finding.file_path} : {finding.line_range}
                  </span>
                </div>
              </div>
              
              <div className="text-sm text-slate-400 mb-4">
                <span className="font-semibold text-slate-300">Root Cause:</span> {finding.root_cause}
              </div>

              {finding.patch_diff && (
                <div className="bg-[#05070A] rounded border border-slate-800 p-3 overflow-x-auto">
                  <pre className="text-xs font-mono text-slate-300">
                    <code>{finding.patch_diff}</code>
                  </pre>
                </div>
              )}
            </div>
          ))
        )}
      </div>

    </div>
  );
}
