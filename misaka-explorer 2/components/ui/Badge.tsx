import { cn } from '@/lib/utils/cn';

interface BadgeProps {
  children: React.ReactNode;
  variant?: 'success' | 'warning' | 'danger' | 'info' | 'neutral';
  className?: string;
}

const variants = {
  success: 'bg-accent-green/10 text-accent-green border-accent-green/20',
  warning: 'bg-accent-yellow/10 text-accent-yellow border-accent-yellow/20',
  danger:  'bg-accent-red/10 text-accent-red border-accent-red/20',
  info:    'bg-misaka-500/10 text-misaka-400 border-misaka-500/20',
  neutral: 'bg-surface-300/50 text-slate-400 border-surface-400/50',
};

export function Badge({ children, variant = 'neutral', className }: BadgeProps) {
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-semibold uppercase tracking-wider border',
      variants[variant],
      className,
    )}>
      {children}
    </span>
  );
}

export function FinalityBadge({ status }: { status: 'finalized' | 'pending' | 'orphaned' | 'degraded' }) {
  const map = {
    finalized: { label: 'Finalized', variant: 'success' as const },
    pending:   { label: 'Pending', variant: 'warning' as const },
    orphaned:  { label: 'Orphaned', variant: 'danger' as const },
    degraded:  { label: 'Degraded', variant: 'warning' as const },
  };
  const { label, variant } = map[status] || map.pending;
  return <Badge variant={variant}>{label}</Badge>;
}

export function StatusBadge({ status }: { status: 'confirmed' | 'pending' | 'orphaned' | 'failed' | 'active' | 'inactive' | 'jailed' | 'clean' | 'slashed' | 'under_review' }) {
  const map: Record<string, { label: string; variant: BadgeProps['variant'] }> = {
    confirmed:    { label: 'Confirmed', variant: 'success' },
    pending:      { label: 'Pending', variant: 'warning' },
    orphaned:     { label: 'Orphaned', variant: 'danger' },
    failed:       { label: 'Failed', variant: 'danger' },
    active:       { label: 'Active', variant: 'success' },
    inactive:     { label: 'Inactive', variant: 'neutral' },
    jailed:       { label: 'Jailed', variant: 'danger' },
    clean:        { label: 'Clean', variant: 'success' },
    slashed:      { label: 'Slashed', variant: 'danger' },
    under_review: { label: 'Review', variant: 'warning' },
  };
  const entry = map[status] || { label: status, variant: 'neutral' as const };
  return <Badge variant={entry.variant}>{entry.label}</Badge>;
}
