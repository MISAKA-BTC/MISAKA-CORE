'use client';

import { cn } from '@/lib/utils/cn';
import { relativeTime, formatTimestamp } from '@/lib/format';

// --- Pagination ---
interface PaginationProps {
  page: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}

export function PaginationBar({ page, totalPages, onPageChange }: PaginationProps) {
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-center gap-2 mt-6">
      <button
        disabled={page <= 1}
        onClick={() => onPageChange(page - 1)}
        className="px-3 py-1.5 rounded-lg text-sm font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all"
      >
        ← Prev
      </button>
      <span className="px-3 py-1.5 text-sm text-slate-500">
        {page} / {totalPages}
      </span>
      <button
        disabled={page >= totalPages}
        onClick={() => onPageChange(page + 1)}
        className="px-3 py-1.5 rounded-lg text-sm font-medium bg-surface-200 text-slate-400 hover:bg-surface-300 hover:text-white disabled:opacity-30 disabled:cursor-not-allowed transition-all"
      >
        Next →
      </button>
    </div>
  );
}

// --- Skeleton ---
export function Skeleton({ className = '', lines = 1 }: { className?: string; lines?: number }) {
  return (
    <div className={cn('space-y-2', className)}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="skeleton h-4 rounded-md" style={{ width: `${70 + Math.random() * 30}%` }} />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, r) => (
        <div key={r} className="flex gap-4">
          {Array.from({ length: cols }).map((_, c) => (
            <div key={c} className="skeleton h-5 rounded flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}

// --- Empty State ---
export function EmptyState({ title = 'No data', description = '' }: { title?: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-full bg-surface-200 flex items-center justify-center mb-4">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-slate-500">
          <circle cx="12" cy="12" r="10" />
          <path d="M8 15h8M9 9h.01M15 9h.01" strokeLinecap="round" />
        </svg>
      </div>
      <h3 className="text-lg font-medium text-slate-300 mb-1">{title}</h3>
      {description && <p className="text-sm text-slate-500 max-w-sm">{description}</p>}
    </div>
  );
}

// --- Timestamp ---
export function TimestampDisplay({ iso, className = '' }: { iso: string; className?: string }) {
  return (
    <span className={cn('text-slate-400', className)} title={formatTimestamp(iso)}>
      {relativeTime(iso)}
    </span>
  );
}
