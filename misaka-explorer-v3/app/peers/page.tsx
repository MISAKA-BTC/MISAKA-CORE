import { api } from '@/lib/api/client';
import { StatCard } from '@/components/ui/StatCard';

export const revalidate = 10;

const MODE_LABEL: Record<string, string> = {
  seed: 'SEED', public: 'PUBLIC', hidden: 'HIDDEN', validator: 'VALIDATOR',
};

function timeAgo(iso: string): string {
  const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

export default async function PeersPage() {
  const data = await api.getPeers();

  return (
    <div className="page-enter">
      {/* Header */}
      <section className="mb-12">
        <h1 className="text-[36px] font-extralight text-fg tracking-tight mb-2">
          Network Peers
        </h1>
        <p className="text-[13px] text-muted tracking-wide">
          Connected nodes in the MISAKA Network topology
        </p>
      </section>

      {/* Stats */}
      <section className="mb-12">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-px bg-line">
          <StatCard label="Total Peers" value={data.total} />
          <StatCard label="Inbound" value={data.inbound} subValue="connections" />
          <StatCard label="Outbound" value={data.outbound} subValue="connections" />
          <StatCard label="Seed Nodes" value={data.peers.filter(p => p.mode === 'seed').length} subValue="bootstrap" />
        </div>
      </section>

      {/* Peer Table */}
      <section className="mb-16">
        <div className="border-b border-line pb-4 mb-0">
          <span className="text-[10px] font-medium uppercase tracking-[0.25em] text-dim">Connected Peers</span>
        </div>

        {data.peers.length === 0 ? (
          <div className="py-20 text-center">
            <span className="text-[24px] text-dim block mb-3">∅</span>
            <span className="text-[13px] text-muted">No peers connected</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="border-b border-line">
                  <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Node</th>
                  <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Mode</th>
                  <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Direction</th>
                  <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Advertise</th>
                  <th className="text-left py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Remote</th>
                  <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Height</th>
                  <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Connected</th>
                  <th className="text-right py-3 px-5 text-[10px] font-medium uppercase tracking-[0.2em] text-dim">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {data.peers.map((peer, i) => (
                  <tr key={`${peer.remote_addr}-${i}`} className="border-b border-line/50 table-row-hover">
                    <td className="py-3.5 px-5">
                      <div className="flex items-center gap-2.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-fg" />
                        <span className="font-medium text-fg text-[13px]">{peer.node_name}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-5">
                      <span className="inline-flex px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.15em] border border-line text-muted">
                        {MODE_LABEL[peer.mode] || peer.mode.toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3.5 px-5">
                      <span className="text-[12px] text-muted font-mono">
                        {peer.direction === 'inbound' ? '↓ in' : '↑ out'}
                      </span>
                    </td>
                    <td className="py-3.5 px-5">
                      {peer.advertise_addr ? (
                        <span className="font-mono text-[12px] text-subtle">{peer.advertise_addr}</span>
                      ) : (
                        <span className="text-[11px] text-dim italic">—</span>
                      )}
                    </td>
                    <td className="py-3.5 px-5">
                      <span className="font-mono text-[12px] text-dim">{peer.remote_addr}</span>
                    </td>
                    <td className="py-3.5 px-5 text-right">
                      <span className="font-mono text-[12px] text-subtle">{peer.height.toLocaleString()}</span>
                    </td>
                    <td className="py-3.5 px-5 text-right">
                      <span className="text-[12px] text-muted">{timeAgo(peer.connected_at)}</span>
                    </td>
                    <td className="py-3.5 px-5 text-right">
                      <span className="text-[12px] text-muted">{timeAgo(peer.last_seen)}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Legend */}
      <section className="border-t border-line pt-10">
        <span className="text-[10px] font-medium uppercase tracking-[0.25em] text-dim block mb-6">Node Modes</span>
        <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-8">
          <div>
            <span className="inline-flex px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.15em] border border-line text-muted mb-2">SEED</span>
            <p className="text-[12px] text-dim leading-relaxed">Bootstrap node. Serves peer discovery, does not produce blocks.</p>
          </div>
          <div>
            <span className="inline-flex px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.15em] border border-line text-muted mb-2">PUBLIC</span>
            <p className="text-[12px] text-dim leading-relaxed">Full node. Accepts inbound connections, relays transactions and blocks.</p>
          </div>
          <div>
            <span className="inline-flex px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.15em] border border-line text-muted mb-2">VALIDATOR</span>
            <p className="text-[12px] text-dim leading-relaxed">Block producer. Participates in consensus and proposes new blocks.</p>
          </div>
          <div>
            <span className="inline-flex px-2 py-0.5 text-[10px] font-medium uppercase tracking-[0.15em] border border-line text-muted mb-2">HIDDEN</span>
            <p className="text-[12px] text-dim leading-relaxed">Privacy-focused. Outbound only, IP never advertised to the network.</p>
          </div>
        </div>
      </section>
    </div>
  );
}
