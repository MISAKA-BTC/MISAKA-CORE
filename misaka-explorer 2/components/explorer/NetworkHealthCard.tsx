'use client';

import { cn } from '@/lib/utils/cn';

interface NetworkHealthCardProps {
  health: 'healthy' | 'degraded' | 'down';
  networkName: string;
  version: string;
  genesisTimestamp: string;
}

const healthConfig = {
  healthy:  { color: 'bg-accent-green', ring: 'ring-accent-green/20', label: 'All Systems Operational',  glow: 'shadow-accent-green/20' },
  degraded: { color: 'bg-accent-yellow', ring: 'ring-accent-yellow/20', label: 'Performance Degraded', glow: 'shadow-accent-yellow/20' },
  down:     { color: 'bg-accent-red',    ring: 'ring-accent-red/20',    label: 'Network Issues Detected', glow: 'shadow-accent-red/20' },
};

export function NetworkHealthCard({ health, networkName, version, genesisTimestamp }: NetworkHealthCardProps) {
  const cfg = healthConfig[health];
  const genesisDate = new Date(genesisTimestamp).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });

  return (
    <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 card-glow">
      <div className="flex items-center gap-3 mb-4">
        <div className={cn('w-3 h-3 rounded-full ring-4', cfg.color, cfg.ring, cfg.glow, 'shadow-lg animate-pulse-glow')} />
        <span className="text-sm font-medium text-white">{cfg.label}</span>
      </div>
      <div className="space-y-2">
        <div className="flex justify-between">
          <span className="text-xs text-slate-500">Network</span>
          <span className="text-xs text-slate-300 font-medium">{networkName}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-xs text-slate-500">Version</span>
          <span className="text-xs text-slate-400 font-mono">{version}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-xs text-slate-500">Genesis</span>
          <span className="text-xs text-slate-400">{genesisDate}</span>
        </div>
      </div>
    </div>
  );
}
