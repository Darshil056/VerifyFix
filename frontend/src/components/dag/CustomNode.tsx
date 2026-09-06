import React from 'react';
import { Handle, Position } from '@xyflow/react';
import { cn } from '@/lib/utils';
import { Loader2, CheckCircle, AlertTriangle, Bug } from 'lucide-react';

export type NodeState = 'idle' | 'running' | 'completed' | 'error' | 'confirmed' | 'secure';

interface CustomNodeProps {
  data: {
    label: string;
    state: NodeState;
    retryCount?: number;
    icon?: React.ReactNode;
  };
}

export default function CustomNode({ data }: CustomNodeProps) {
  const { label, state, retryCount, icon } = data;

  // Determine border and glow colors based on state
  let stateClasses = "border-slate-700 bg-slate-900 shadow-sm";
  let iconElement = icon;
  let StatusIcon = null;

  switch (state) {
    case 'running':
      stateClasses = "border-blue-500 bg-slate-800 shadow-[0_0_15px_rgba(59,130,246,0.5)] animate-pulse";
      StatusIcon = <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />;
      break;
    case 'completed':
      stateClasses = "border-slate-500 bg-slate-800";
      StatusIcon = <CheckCircle className="w-4 h-4 text-slate-400" />;
      break;
    case 'secure':
      stateClasses = "border-emerald-500 bg-slate-800 shadow-[0_0_15px_rgba(16,185,129,0.3)]";
      StatusIcon = <CheckCircle className="w-4 h-4 text-emerald-500" />;
      break;
    case 'confirmed':
      stateClasses = "border-rose-500 bg-slate-800 shadow-[0_0_15px_rgba(244,63,94,0.4)]";
      StatusIcon = <Bug className="w-4 h-4 text-rose-500" />;
      break;
    case 'error':
      stateClasses = "border-amber-500 bg-slate-800 shadow-[0_0_15px_rgba(245,158,11,0.4)]";
      StatusIcon = <AlertTriangle className="w-4 h-4 text-amber-500" />;
      break;
    case 'idle':
    default:
      break;
  }

  return (
    <div className={cn(
      "relative px-4 py-3 rounded-lg border-2 min-w-[180px] transition-all duration-300 flex items-center justify-between gap-3",
      stateClasses
    )}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 bg-slate-500 border-none" />
      
      <div className="flex items-center gap-2">
        <div className="text-slate-400">
          {iconElement}
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold text-slate-200">{label}</span>
          {retryCount !== undefined && retryCount > 0 && (
            <span className="text-xs text-amber-400">Retry {retryCount}</span>
          )}
        </div>
      </div>

      <div className="flex-shrink-0">
        {StatusIcon}
      </div>

      <Handle type="source" position={Position.Bottom} className="w-2 h-2 bg-slate-500 border-none" />
    </div>
  );
}
