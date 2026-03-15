'use client';

import { useState } from 'react';
import { CopyButton } from './CopyButton';

interface RawJsonViewerProps {
  data: unknown;
  title?: string;
}

export function RawJsonViewer({ data, title = 'Raw JSON' }: RawJsonViewerProps) {
  const [expanded, setExpanded] = useState(false);
  const json = JSON.stringify(data, null, 2);

  return (
    <div className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-surface-200/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          <svg
            width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
            className={`text-slate-500 transition-transform ${expanded ? 'rotate-90' : ''}`}
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
          <span className="text-sm font-medium text-slate-400">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[10px] text-slate-600 font-mono">{json.length.toLocaleString()} chars</span>
          <CopyButton text={json} />
        </div>
      </button>
      {expanded && (
        <div className="border-t border-surface-300/30 overflow-x-auto">
          <pre className="p-5 text-xs font-mono text-slate-400 leading-relaxed whitespace-pre-wrap break-all max-h-[600px] overflow-y-auto">
            {json}
          </pre>
        </div>
      )}
    </div>
  );
}
