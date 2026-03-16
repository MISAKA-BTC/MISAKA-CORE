'use client';
import { relativeTime, formatTimestamp } from '@/lib/format';

export function TimestampDisplay({ iso, className = '' }: { iso: string; className?: string }) {
  return (
    <span className={`text-muted text-[12px] ${className}`} title={formatTimestamp(iso)}>
      {relativeTime(iso)}
    </span>
  );
}

export function EmptyState({ title = 'No data', description = '' }: { title?: string; description?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <span className="text-[24px] text-dim mb-4">∅</span>
      <h3 className="text-[14px] font-medium text-subtle mb-1">{title}</h3>
      {description && <p className="text-[12px] text-dim max-w-sm">{description}</p>}
    </div>
  );
}
