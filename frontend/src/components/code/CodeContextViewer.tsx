'use client';

import React, { useState, useMemo, useRef, useEffect } from 'react';
import { FileCode, FolderTree, GitBranch, ChevronRight, ChevronDown, Info, AlertTriangle, Eye } from 'lucide-react';
import { Vulnerability } from '@/hooks/useScanStream';

interface CodeContextViewerProps {
  fullFiles: Record<string, string>;
  dependencyFiles: Record<string, string>;
  fileTree: string;
  contextSummary: string;
  findings: Vulnerability[];
  isScanning: boolean;
}

type FileType = 'changed' | 'dependency';

interface FileEntry {
  path: string;
  type: FileType;
  content: string;
}

export default function CodeContextViewer({
  fullFiles,
  dependencyFiles,
  fileTree,
  contextSummary,
  findings,
  isScanning,
}: CodeContextViewerProps) {
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [showTree, setShowTree] = useState(true);
  const codeRef = useRef<HTMLPreElement>(null);

  // Build unified file list
  const allFiles = useMemo<FileEntry[]>(() => {
    const files: FileEntry[] = [];
    for (const [path, content] of Object.entries(fullFiles || {})) {
      files.push({ path, type: 'changed', content });
    }
    for (const [path, content] of Object.entries(dependencyFiles || {})) {
      files.push({ path, type: 'dependency', content });
    }
    return files.sort((a, b) => a.path.localeCompare(b.path));
  }, [fullFiles, dependencyFiles]);

  // Auto-select first file
  useEffect(() => {
    if (!selectedFile && allFiles.length > 0) {
      setSelectedFile(allFiles[0].path);
    }
  }, [allFiles, selectedFile]);

  // Get selected file entry
  const activeFile = useMemo(
    () => allFiles.find(f => f.path === selectedFile),
    [allFiles, selectedFile]
  );

  // Get findings for the active file
  const activeFindings = useMemo(
    () => findings.filter(f => f.file_path && activeFile?.path.endsWith(f.file_path)),
    [findings, activeFile]
  );

  // Get line-level vulnerability markers
  const vulnLines = useMemo(() => {
    const lines = new Set<number>();
    for (const f of activeFindings) {
      if (f.line_range) {
        const parts = f.line_range.split('-');
        const start = parseInt(parts[0]);
        const end = parseInt(parts[1] || parts[0]);
        if (!isNaN(start) && !isNaN(end)) {
          for (let i = start; i <= end; i++) {
            lines.add(i);
          }
        }
      }
    }
    return lines;
  }, [activeFindings]);

  // No context available
  const hasNoContext = allFiles.length === 0;

  if (hasNoContext) {
    return (
      <div className="w-full h-full flex flex-col items-center justify-center bg-[#0A0C10] text-slate-500 gap-4 p-8">
        <FileCode className="w-16 h-16 opacity-30" />
        <div className="text-center space-y-2">
          <p className="text-lg font-medium text-slate-400">No Code Context Available</p>
          {isScanning ? (
            <p className="text-sm">Context will appear here once GitHub Ingest completes...</p>
          ) : (
            <div className="space-y-1">
              <p className="text-sm">Provide a GitHub token when starting a scan to enable full code context.</p>
              <p className="text-xs text-slate-600">Without a token, the analysis runs in diff-only mode.</p>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="w-full h-full flex bg-[#0A0C10] overflow-hidden">

      {/* Left Sidebar: File List */}
      <div className="w-64 flex-shrink-0 border-r border-slate-800 flex flex-col bg-[#080A0E]">

        {/* Context Summary */}
        {contextSummary && (
          <div className="px-3 py-2 border-b border-slate-800 bg-blue-500/5">
            <div className="flex items-center gap-1.5 text-xs text-blue-400 mb-1">
              <Info size={12} />
              <span className="font-medium">Context Summary</span>
            </div>
            <p className="text-[10px] text-slate-400 leading-relaxed whitespace-pre-line">
              {contextSummary.split('\n')[0]}
            </p>
          </div>
        )}

        {/* File Tree Toggle */}
        <button
          onClick={() => setShowTree(!showTree)}
          className="flex items-center gap-2 px-3 py-2 text-xs text-slate-400 hover:text-slate-200 border-b border-slate-800 transition-colors"
        >
          {showTree ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          <FolderTree size={12} />
          <span>Analyzed Files ({allFiles.length})</span>
        </button>

        {/* File List */}
        {showTree && (
          <div className="flex-1 overflow-y-auto">
            {/* Changed Files Section */}
            {allFiles.filter(f => f.type === 'changed').length > 0 && (
              <div>
                <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-amber-500/70 font-semibold bg-amber-500/5">
                  <GitBranch size={10} className="inline mr-1.5" />
                  Changed Files
                </div>
                {allFiles.filter(f => f.type === 'changed').map(file => (
                  <FileListItem
                    key={file.path}
                    file={file}
                    isActive={selectedFile === file.path}
                    hasVuln={findings.some(f => file.path.endsWith(f.file_path))}
                    onClick={() => setSelectedFile(file.path)}
                  />
                ))}
              </div>
            )}

            {/* Dependency Files Section */}
            {allFiles.filter(f => f.type === 'dependency').length > 0 && (
              <div>
                <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-cyan-500/70 font-semibold bg-cyan-500/5">
                  <Eye size={10} className="inline mr-1.5" />
                  Dependency Files
                </div>
                {allFiles.filter(f => f.type === 'dependency').map(file => (
                  <FileListItem
                    key={file.path}
                    file={file}
                    isActive={selectedFile === file.path}
                    hasVuln={false}
                    onClick={() => setSelectedFile(file.path)}
                  />
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right Panel: Code View */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* File Header */}
        {activeFile && (
          <div className="flex items-center justify-between px-4 py-2 border-b border-slate-800 bg-[#0D0F14]">
            <div className="flex items-center gap-3">
              <FileCode size={14} className="text-slate-400" />
              <span className="text-sm font-mono text-slate-200">{activeFile.path}</span>
              <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide ${
                activeFile.type === 'changed'
                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                  : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
              }`}>
                {activeFile.type}
              </span>
            </div>

            {activeFindings.length > 0 && (
              <div className="flex items-center gap-1.5 text-rose-400 text-xs">
                <AlertTriangle size={12} />
                <span>{activeFindings.length} vulnerability{activeFindings.length > 1 ? 'ies' : 'y'} found</span>
              </div>
            )}
          </div>
        )}

        {/* Vulnerability Badges (above code) */}
        {activeFindings.length > 0 && (
          <div className="px-4 py-2 border-b border-slate-800 bg-rose-500/5 flex gap-2 flex-wrap">
            {activeFindings.map((finding, idx) => (
              <div key={idx} className="flex items-center gap-2 px-2 py-1 rounded bg-rose-500/10 border border-rose-500/20">
                <span className="text-[10px] font-mono text-rose-400">{finding.cwe_id}</span>
                <span className="text-[10px] text-rose-300">{finding.vulnerability_name}</span>
                {finding.line_range && (
                  <span className="text-[10px] text-rose-500/70">L{finding.line_range}</span>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Code Content */}
        <div className="flex-1 overflow-auto">
          {activeFile ? (
            <pre ref={codeRef} className="text-xs font-mono leading-relaxed p-0 m-0">
              {activeFile.content.split('\n').map((line, idx) => {
                const lineNum = idx + 1;
                const isVuln = vulnLines.has(lineNum);
                return (
                  <div
                    key={lineNum}
                    className={`flex ${
                      isVuln
                        ? 'bg-rose-500/10 border-l-2 border-rose-500'
                        : 'border-l-2 border-transparent hover:bg-slate-800/30'
                    }`}
                  >
                    <span className={`inline-block w-12 text-right pr-4 select-none flex-shrink-0 ${
                      isVuln ? 'text-rose-400' : 'text-slate-600'
                    }`}>
                      {lineNum}
                    </span>
                    <span className={`flex-1 px-2 whitespace-pre ${
                      isVuln ? 'text-rose-200' : 'text-slate-300'
                    }`}>
                      {line || ' '}
                    </span>
                    {isVuln && (
                      <span className="text-rose-500/50 pr-4 flex-shrink-0">⚠</span>
                    )}
                  </div>
                );
              })}
            </pre>
          ) : (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              Select a file from the sidebar to view its source code
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


/* ------------------------------------------------------------------ */
/* File List Item sub-component                                        */
/* ------------------------------------------------------------------ */

function FileListItem({
  file,
  isActive,
  hasVuln,
  onClick,
}: {
  file: FileEntry;
  isActive: boolean;
  hasVuln: boolean;
  onClick: () => void;
}) {
  const basename = file.path.split('/').pop() || file.path;
  const dirname = file.path.split('/').slice(0, -1).join('/');

  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-1.5 flex items-center gap-2 text-xs transition-colors border-l-2 ${
        isActive
          ? 'bg-blue-500/10 border-blue-500 text-slate-200'
          : 'border-transparent text-slate-400 hover:bg-slate-800/50 hover:text-slate-300'
      }`}
    >
      <FileCode size={12} className="flex-shrink-0 opacity-50" />
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="font-medium truncate">{basename}</span>
          {hasVuln && <AlertTriangle size={10} className="text-rose-400 flex-shrink-0" />}
        </div>
        {dirname && (
          <div className="text-[10px] text-slate-600 truncate">{dirname}/</div>
        )}
      </div>
    </button>
  );
}
