import { cn } from '@/lib/utils/cn';

interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
  icon?: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
  className?: string;
}

export function StatCard({ label, value, subValue, icon, trend, className }: StatCardProps) {
  return (
    <div className={cn(
      'relative overflow-hidden rounded-xl border border-surface-300/50 bg-surface-100 p-5 card-glow',
      className,
    )}>
      <div className="relative z-10">
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-medium uppercase tracking-widest text-slate-500">{label}</span>
          {icon && <span className="text-slate-500">{icon}</span>}
        </div>
        <div className="text-2xl font-semibold font-display text-white tracking-tight">
          {value}
        </div>
        {subValue && (
          <div className={cn(
            'mt-1.5 text-xs font-medium',
            trend === 'up' && 'text-accent-green',
            trend === 'down' && 'text-accent-red',
            !trend && 'text-slate-500',
          )}>
            {trend === 'up' && '↑ '}
            {trend === 'down' && '↓ '}
            {subValue}
          </div>
        )}
      </div>
    </div>
  );
}
