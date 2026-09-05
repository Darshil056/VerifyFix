"use client";

import { useState, useEffect, useRef } from "react";

type Vulnerability = {
  vulnerability_name: string;
  cwe_id: string;
  severity?: string;
  file_path: string;
  line_range?: string;
};

type Remediation = {
  vulnerability_name: string;
  cwe_id: string;
  severity: string;
  root_cause: string;
  defense_in_depth: string;
  patch_diff: string;
};

export default function Dashboard() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [status, setStatus] = useState<"idle" | "scanning" | "completed" | "error">("idle");
  const [executionStep, setExecutionStep] = useState<string>("WAITING");
  const [logs, setLogs] = useState<{ time: string; msg: string }[]>([]);
  const [candidates, setCandidates] = useState<Vulnerability[]>([]);
  const [remediations, setRemediations] = useState<Remediation[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Connect to SSE when a scan is started
  useEffect(() => {
    if (!scanId || status === "completed" || status === "error") return;

    console.log(`Connecting to SSE stream for scan: ${scanId}`);
    const eventSource = new EventSource(`http://localhost:5000/api/scan/stream?scan_id=${scanId}`);

    eventSource.addEventListener("pipeline_start", (e) => {
      setStatus("scanning");
    });

    eventSource.addEventListener("node_update", (e) => {
      const data = JSON.parse(e.data);
      if (data.step) setExecutionStep(data.step);
    });

    eventSource.addEventListener("log", (e) => {
      const data = JSON.parse(e.data);
      setLogs((prev) => [...prev, { time: new Date().toLocaleTimeString(), msg: data.message }]);
    });

    eventSource.addEventListener("state_delta", (e) => {
      const data = JSON.parse(e.data);
      if (data.candidate_vulns) setCandidates(data.candidate_vulns);
      if (data.final_remediations) setRemediations(data.final_remediations);
    });

    eventSource.addEventListener("pipeline_end", (e) => {
      setStatus("completed");
      setExecutionStep("COMPLETED");
      eventSource.close();
    });

    eventSource.addEventListener("error", (e: any) => {
      // SSE error or custom error event
      if (e.data) {
        try {
          const data = JSON.parse(e.data);
          setErrorMsg(data.message || "Unknown stream error");
        } catch {
          setErrorMsg("Stream connection lost.");
        }
      }
      setStatus("error");
      setExecutionStep("ERROR");
      eventSource.close();
    });

    return () => {
      eventSource.close();
    };
  }, [scanId, status]);

  const startScan = async () => {
    try {
      setScanId(null);
      setLogs([]);
      setCandidates([]);
      setRemediations([]);
      setErrorMsg(null);
      setStatus("scanning");
      setExecutionStep("INITIALIZING");

      // We use the demo repository endpoint as built in the backend
      const res = await fetch("http://localhost:5000/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_owner: "verifyfix-demo",
          repo_name: "vulnerable-flask-auth",
          branch_name: "main",
        }),
      });

      if (!res.ok) {
        throw new Error("Failed to start scan");
      }

      const data = await res.json();
      setScanId(data.scan_id);
      setLogs([{ time: new Date().toLocaleTimeString(), msg: `Scan started with ID: ${data.scan_id}` }]);
    } catch (err: any) {
      setStatus("error");
      setErrorMsg(err.message);
      setExecutionStep("ERROR");
    }
  };

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-zinc-100 font-sans p-8 selection:bg-indigo-500/30">
      <div className="max-w-6xl mx-auto space-y-8">
        
        {/* Header */}
        <header className="flex items-center justify-between border-b border-white/10 pb-6">
          <div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-400 to-cyan-400 bg-clip-text text-transparent">
              VerifyFix Dashboard
            </h1>
            <p className="text-zinc-400 mt-2 text-sm">
              Phase 2 Manual Testing Interface (SSE + DAG Executor)
            </p>
          </div>
          <button
            onClick={startScan}
            disabled={status === "scanning"}
            className="px-6 py-3 rounded-full font-medium bg-white text-black hover:bg-zinc-200 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-[0_0_20px_rgba(255,255,255,0.15)] hover:shadow-[0_0_25px_rgba(255,255,255,0.25)]"
          >
            {status === "scanning" ? "Scanning in Progress..." : "Run Demo Scan"}
          </button>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column: Status & Findings */}
          <div className="lg:col-span-1 space-y-6">
            
            {/* Status Card */}
            <div className="bg-[#121212] border border-white/5 rounded-2xl p-6 shadow-2xl">
              <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Execution State</h2>
              
              <div className="space-y-4">
                <div>
                  <div className="text-xs text-zinc-500 mb-1">Status</div>
                  <div className="flex items-center gap-2">
                    <div className={`w-2.5 h-2.5 rounded-full ${
                      status === "idle" ? "bg-zinc-500" :
                      status === "scanning" ? "bg-amber-400 animate-pulse" :
                      status === "completed" ? "bg-emerald-400" : "bg-red-400"
                    }`} />
                    <span className="capitalize font-medium">{status}</span>
                  </div>
                </div>
                
                <div>
                  <div className="text-xs text-zinc-500 mb-1">Current Node</div>
                  <div className="font-mono text-sm px-3 py-1.5 bg-black/50 border border-white/5 rounded-lg inline-block">
                    {executionStep}
                  </div>
                </div>

                {scanId && (
                  <div>
                    <div className="text-xs text-zinc-500 mb-1">Scan ID</div>
                    <div className="font-mono text-xs text-zinc-400 truncate" title={scanId}>
                      {scanId}
                    </div>
                  </div>
                )}
                
                {errorMsg && (
                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400 text-sm">
                    {errorMsg}
                  </div>
                )}
              </div>
            </div>

            {/* Candidate Vulns */}
            <div className="bg-[#121212] border border-white/5 rounded-2xl p-6 shadow-2xl">
              <h2 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">
                Candidates Found ({candidates.length})
              </h2>
              {candidates.length === 0 ? (
                <div className="text-sm text-zinc-600 italic">Waiting for discovery...</div>
              ) : (
                <ul className="space-y-3">
                  {candidates.map((c, i) => (
                    <li key={i} className="bg-black/40 border border-white/5 p-3 rounded-xl">
                      <div className="font-medium text-amber-300 text-sm">{c.cwe_id}: {c.vulnerability_name}</div>
                      <div className="font-mono text-xs text-zinc-500 mt-1">{c.file_path}</div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

          </div>

          {/* Right Column: Terminal & Remediations */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Terminal Window */}
            <div className="bg-[#0c0c0e] border border-white/10 rounded-2xl overflow-hidden shadow-2xl flex flex-col h-[400px]">
              <div className="bg-white/5 px-4 py-3 flex items-center gap-2 border-b border-white/5">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-amber-500/80"></div>
                  <div className="w-3 h-3 rounded-full bg-emerald-500/80"></div>
                </div>
                <div className="ml-2 text-xs font-mono text-zinc-500">Live SSE Stream</div>
              </div>
              
              <div className="flex-1 p-4 overflow-y-auto font-mono text-sm">
                {logs.length === 0 ? (
                  <div className="text-zinc-600">No logs yet. Start a scan to connect.</div>
                ) : (
                  <div className="space-y-1.5">
                    {logs.map((log, i) => (
                      <div key={i} className="flex gap-3">
                        <span className="text-zinc-500 shrink-0">[{log.time}]</span>
                        <span className="text-zinc-300 whitespace-pre-wrap">
                          {log.msg.includes("[") ? (
                            <>
                              <span className="text-indigo-400">{log.msg.split("]")[0]}]</span>
                              {log.msg.split("]").slice(1).join("]")}
                            </>
                          ) : log.msg}
                        </span>
                      </div>
                    ))}
                    <div ref={logsEndRef} />
                  </div>
                )}
              </div>
            </div>

            {/* Remediations */}
            {remediations.length > 0 && (
              <div className="bg-emerald-950/20 border border-emerald-500/20 rounded-2xl p-6 shadow-2xl animate-in fade-in slide-in-from-bottom-4 duration-500">
                <h2 className="text-sm font-semibold text-emerald-400 uppercase tracking-wider mb-4">
                  Verified Remediations ({remediations.length})
                </h2>
                <div className="space-y-4">
                  {remediations.map((r, i) => (
                    <div key={i} className="bg-black/50 border border-emerald-500/10 p-5 rounded-xl">
                      <div className="flex items-start justify-between">
                        <div>
                          <div className="text-emerald-300 font-semibold">{r.cwe_id} — {r.vulnerability_name}</div>
                          <div className="text-xs text-zinc-400 mt-1 uppercase">Severity: {r.severity}</div>
                        </div>
                      </div>
                      
                      <div className="mt-4">
                        <div className="text-xs text-zinc-500 mb-1">Root Cause</div>
                        <div className="text-sm text-zinc-300">{r.root_cause}</div>
                      </div>

                      <div className="mt-4">
                        <div className="text-xs text-zinc-500 mb-2">Generated Patch</div>
                        <pre className="text-xs font-mono bg-[#0c0c0e] p-4 rounded-lg overflow-x-auto text-emerald-100 border border-white/5">
                          {r.patch_diff}
                        </pre>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>

        </div>
      </div>
    </div>
  );
}
