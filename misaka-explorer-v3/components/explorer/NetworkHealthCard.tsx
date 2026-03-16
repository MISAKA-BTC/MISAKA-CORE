'use client';
interface Props { health: string; networkName: string; version: string; genesisTimestamp: string; }
export function NetworkHealthCard({ health, networkName, version, genesisTimestamp }: Props) {
  return (
    <div className="border border-line p-6">
      <div className="flex items-center gap-3 mb-5">
        <span className={`w-2 h-2 rounded-full ${health === 'healthy' ? 'bg-fg' : 'bg-dim'}`} />
        <span className="text-[12px] font-medium text-fg">{health === 'healthy' ? 'All Systems Operational' : 'Degraded'}</span>
      </div>
      <div className="space-y-3">
        <div className="flex justify-between">
          <span className="text-[11px] text-dim uppercase tracking-wider">Network</span>
          <span className="text-[12px] text-fg">{networkName}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[11px] text-dim uppercase tracking-wider">Version</span>
          <span className="text-[12px] text-muted font-mono">{version}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-[11px] text-dim uppercase tracking-wider">Genesis</span>
          <span className="text-[12px] text-muted">{new Date(genesisTimestamp).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</span>
        </div>
      </div>
    </div>
  );
}
