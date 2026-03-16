interface BadgeProps {
  children: React.ReactNode;
  variant?: 'success' | 'warning' | 'danger' | 'info' | 'neutral';
}

const variants = {
  success: 'border-fg/20 text-fg',
  warning: 'border-muted/30 text-muted',
  danger:  'border-dim text-dim',
  info:    'border-subtle/30 text-subtle',
  neutral: 'border-dim text-dim',
};

export function Badge({ children, variant = 'neutral' }: BadgeProps) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.15em] border ${variants[variant]}`}>
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

export function StatusBadge({ status }: { status: string }) {
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
