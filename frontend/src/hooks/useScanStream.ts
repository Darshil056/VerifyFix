import { useState, useEffect, useCallback } from 'react';
import { NodeState } from '@/components/dag/CustomNode';

export interface ScanLog {
  timestamp: string;
  message: string;
}

export interface Vulnerability {
  cwe_id: string;
  vulnerability_name: string;
  severity: string;
  file_path: string;
  line_range: string;
  root_cause: string;
  patch_diff: string;
}

export interface ScanStreamState {
  isScanning: boolean;
  scanId: string | null;
  nodeStates: Record<string, NodeState>;
  logs: ScanLog[];
  metrics: {
    candidates: number;
    pruned: number;
    confirmed: number;
    retries: number;
  };
  findings: Vulnerability[];
  error: string | null;
  // Full context fields
  fullFiles: Record<string, string>;
  dependencyFiles: Record<string, string>;
  fileTree: string;
  contextSummary: string;
}

export function useScanStream() {
  const [state, setState] = useState<ScanStreamState>({
    isScanning: false,
    scanId: null,
    nodeStates: {},
    logs: [],
    metrics: { candidates: 0, pruned: 0, confirmed: 0, retries: 0 },
    findings: [],
    error: null,
    fullFiles: {},
    dependencyFiles: {},
    fileTree: '',
    contextSummary: '',
  });

  const startScan = useCallback(async (repoUrl: string, branchName: string, token: string, isDemo: boolean = false) => {
    setState(prev => ({
      ...prev,
      isScanning: true,
      scanId: null,
      nodeStates: {},
      logs: [],
      metrics: { candidates: 0, pruned: 0, confirmed: 0, retries: 0 },
      findings: [],
      error: null,
      fullFiles: {},
      dependencyFiles: {},
      fileTree: '',
      contextSummary: '',
    }));

    try {
      const response = await fetch('http://localhost:5000/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl, branch_name: branchName, token, demo: isDemo, github_token: token })
      });

      const data = await response.json();
      if (!data.success) {
        throw new Error(data.error || 'Failed to start scan');
      }

      setState(prev => ({ ...prev, scanId: data.scan_id }));
    } catch (err: any) {
      setState(prev => ({ ...prev, isScanning: false, error: err.message }));
    }
  }, []);

  useEffect(() => {
    if (!state.scanId || !state.isScanning) return;

    const eventSource = new EventSource(`http://localhost:5000/api/scan/stream?scan_id=${state.scanId}`);

    eventSource.addEventListener('pipeline_start', () => {
      setState(prev => ({ ...prev, isScanning: true }));
    });

    eventSource.addEventListener('node_update', (event) => {
      try {
        const data = JSON.parse(event.data);
        const nodeName = `node_${data.step.toLowerCase()}`;
        let frontendState: NodeState = 'idle';
        if (data.status === 'running') frontendState = 'running';
        if (data.status === 'completed') frontendState = 'completed';
        if (data.status === 'error') frontendState = 'error';

        setState(prev => ({
          ...prev,
          nodeStates: {
            ...prev.nodeStates,
            [nodeName]: frontendState
          }
        }));
      } catch (err) {
        console.error("Error parsing node_update", err);
      }
    });

    eventSource.addEventListener('log', (event) => {
      try {
        const data = JSON.parse(event.data);
        setState(prev => ({
          ...prev,
          logs: [...prev.logs, { timestamp: new Date().toISOString(), message: data.message }]
        }));
      } catch (err) {
        console.error("Error parsing log", err);
      }
    });

    eventSource.addEventListener('state_delta', (event) => {
      try {
        const data = JSON.parse(event.data);
        setState(prev => {
          const updates = { ...prev };
          
          if (data.candidate_vulns) updates.metrics.candidates = data.candidate_vulns.length;
          if (data.pruned_vulns) updates.metrics.pruned = data.pruned_vulns.length;
          if (data.retry_count !== undefined) updates.metrics.retries = data.retry_count;
          
          if (data.final_remediations) {
            updates.findings = data.final_remediations;
            updates.metrics.confirmed = data.final_remediations.length;
          }

          // Full context fields from GitHub Ingest
          if (data.full_files !== undefined) updates.fullFiles = data.full_files;
          if (data.dependency_files !== undefined) updates.dependencyFiles = data.dependency_files;
          if (data.file_tree !== undefined) updates.fileTree = data.file_tree;
          if (data.analyzed_context_summary !== undefined) updates.contextSummary = data.analyzed_context_summary;

          return updates;
        });
      } catch (err) {
        console.error("Error parsing state_delta", err);
      }
    });

    eventSource.addEventListener('pipeline_end', () => {
      setState(prev => ({ ...prev, isScanning: false, nodeStates: { ...prev.nodeStates, node_complete: 'completed' } }));
      eventSource.close();
    });

    eventSource.addEventListener('error', (e: any) => {
      if (e.data) {
        try {
          const data = JSON.parse(e.data);
          setState(prev => ({ ...prev, error: data.message, isScanning: false }));
        } catch {
          setState(prev => ({ ...prev, error: "Stream connection lost.", isScanning: false }));
        }
      } else {
        setState(prev => ({ ...prev, error: "Connection lost to scan stream.", isScanning: false }));
      }
      eventSource.close();
    });

    return () => {
      eventSource.close();
    };
  }, [state.scanId, state.isScanning]);

  return {
    ...state,
    startScan
  };
}
