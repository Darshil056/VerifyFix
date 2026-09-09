import React, { useEffect } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Edge,
  Node,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import CustomNode, { NodeState } from './CustomNode';
import { GitBranch, Search, Database, Scale, Box, RefreshCw, ShieldAlert, CheckCircle2 } from 'lucide-react';

const nodeTypes = {
  customNode: CustomNode,
};

// Initial nodes layout
const initialNodes: Node[] = [
  { id: 'node_github_ingest', type: 'customNode', position: { x: 250, y: 50 }, data: { label: 'GitHub Ingest', state: 'idle', icon: <GitBranch size={18} /> } },
  { id: 'node_discovery', type: 'customNode', position: { x: 250, y: 150 }, data: { label: 'Discovery Agent', state: 'idle', icon: <Search size={18} /> } },
  { id: 'node_rag', type: 'customNode', position: { x: 250, y: 250 }, data: { label: 'Vector RAG', state: 'idle', icon: <Database size={18} /> } },
  { id: 'node_critic', type: 'customNode', position: { x: 250, y: 350 }, data: { label: 'Critic Agent', state: 'idle', icon: <Scale size={18} /> } },
  { id: 'node_sandbox', type: 'customNode', position: { x: 250, y: 450 }, data: { label: 'Docker Sandbox', state: 'idle', icon: <Box size={18} /> } },
  { id: 'node_retry', type: 'customNode', position: { x: 50, y: 400 }, data: { label: 'Self-Healing', state: 'idle', icon: <RefreshCw size={18} /> } },
  { id: 'node_remediation', type: 'customNode', position: { x: 250, y: 550 }, data: { label: 'Remediation', state: 'idle', icon: <ShieldAlert size={18} /> } },
  { id: 'node_complete', type: 'customNode', position: { x: 250, y: 650 }, data: { label: 'Complete', state: 'idle', icon: <CheckCircle2 size={18} /> } },
];

const initialEdges: Edge[] = [
  { id: 'e1-2', source: 'node_github_ingest', target: 'node_discovery', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e2-3', source: 'node_discovery', target: 'node_rag', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e3-4', source: 'node_rag', target: 'node_critic', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e4-5', source: 'node_critic', target: 'node_sandbox', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e5-7', source: 'node_sandbox', target: 'node_remediation', markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e7-8', source: 'node_remediation', target: 'node_complete', markerEnd: { type: MarkerType.ArrowClosed } },
  // Retry loop
  { id: 'e5-6', source: 'node_sandbox', target: 'node_retry', type: 'smoothstep', animated: true, markerEnd: { type: MarkerType.ArrowClosed } },
  { id: 'e6-4', source: 'node_retry', target: 'node_critic', type: 'smoothstep', animated: true, markerEnd: { type: MarkerType.ArrowClosed } },
];

interface DagVisualizerProps {
  nodeStates: Record<string, NodeState>;
  retryCount?: number;
}

export default function DagVisualizer({ nodeStates, retryCount = 0 }: DagVisualizerProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync external states to nodes
  useEffect(() => {
    setNodes((nds) =>
      nds.map((n) => ({
        ...n,
        data: {
          ...n.data,
          state: nodeStates[n.id] || 'idle',
          retryCount: n.id === 'node_retry' ? retryCount : undefined
        }
      }))
    );
  }, [nodeStates, retryCount, setNodes]);

  // Update edges dynamically based on running state to animate active paths
  useEffect(() => {
    setEdges((eds) => 
      eds.map((e) => {
        // Find if target node is running
        const isTargetRunning = nodeStates[e.target] === 'running';
        return {
          ...e,
          animated: e.id.includes('retry') || isTargetRunning,
          style: { stroke: isTargetRunning ? '#3b82f6' : '#475569', strokeWidth: isTargetRunning ? 2 : 1 }
        };
      })
    );
  }, [nodeStates, setEdges]);

  return (
    <div className="w-full h-full bg-[#0A0C10] relative rounded-xl border border-slate-800 overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        className="dark"
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1e293b" gap={16} size={1} />
        <Controls className="bg-slate-900 border-slate-700 fill-slate-300 text-slate-300" />
      </ReactFlow>
    </div>
  );
}
