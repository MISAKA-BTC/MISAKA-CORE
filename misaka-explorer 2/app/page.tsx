import { api } from '@/lib/api/client';
import { StatCard } from '@/components/ui/StatCard';
import { FinalityBadge } from '@/components/ui/Badge';
import { BlocksTable } from '@/components/explorer/BlocksTable';
import { TransactionsTable } from '@/components/explorer/TransactionsTable';
import { BlockMiniChart } from '@/components/explorer/BlockMiniChart';
import { NetworkHealthCard } from '@/components/explorer/NetworkHealthCard';
import { SearchBar } from '@/components/explorer/SearchBar';
import { AutoRefresh } from '@/components/ui/AutoRefresh';
import { formatNumber, formatBlockTime } from '@/lib/format';
import Link from 'next/link';

export const revalidate = 15;

export default async function HomePage() {
  const [stats, blocksRes, txsRes, chartData] = await Promise.all([
    api.getNetworkStats(),
    api.getLatestBlocks(1, 8),
    api.getLatestTransactions(1, 8),
    api.getBlockProduction(30),
  ]);

  return (
    <div className="page-enter space-y-10">
      {/* Hero */}
      <section className="text-center pt-6 pb-4">
        <div className="inline-flex items-center gap-2 mb-4">
          <div className="w-3 h-3 rounded-full bg-accent-green animate-pulse-glow" />
          <span className="text-xs font-medium text-accent-green uppercase tracking-widest">
            {stats.chainHealth === 'healthy' ? 'Network Healthy' : 'Network Degraded'}
          </span>
        </div>
        <h1 className="font-display text-4xl sm:text-5xl font-bold text-white tracking-tight mb-2">
          MISAKA Explorer
        </h1>
        <p className="text-slate-500 text-sm mb-8 max-w-lg mx-auto">
          Post-quantum, privacy-by-default Layer 1 blockchain explorer
        </p>
        <SearchBar />
      </section>

      {/* Network Stats Grid */}
      <section>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">Network Overview</h2>
          <AutoRefresh />
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard
          label="Block Height"
          value={formatNumber(stats.latestBlockHeight)}
          icon={<BlockIcon />}
        />
        <StatCard
          label="Transactions"
          value={formatNumber(stats.totalTransactions)}
          icon={<TxIcon />}
        />
        <StatCard
          label="Validators"
          value={stats.activeValidators}
          subValue="active"
          icon={<ValidatorIcon />}
        />
        <StatCard
          label="Avg Block Time"
          value={formatBlockTime(stats.avgBlockTime)}
          icon={<ClockIcon />}
        />
        <StatCard
          label="TPS"
          value={stats.tpsEstimate.toFixed(1)}
          subValue="tx/sec"
          icon={<SpeedIcon />}
        />
        <StatCard
          label="Finality"
          value=""
          className="flex flex-col justify-between"
          icon={<FinalityBadge status={stats.finalityStatus} />}
        />
        </div>
      </section>

      {/* Chart + Network Health */}
      <div className="grid lg:grid-cols-3 gap-6">
        <section className="lg:col-span-2 rounded-xl border border-surface-300/50 bg-surface-100 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-display font-semibold text-white text-sm">Block Production</h2>
              <p className="text-xs text-slate-500 mt-0.5">Transaction count per block (last 30 blocks)</p>
            </div>
          </div>
          <BlockMiniChart data={chartData} height={180} />
        </section>

        <NetworkHealthCard
          health={stats.chainHealth}
          networkName={stats.networkName}
          version={stats.networkVersion}
          genesisTimestamp={stats.genesisTimestamp}
        />
      </div>

      {/* Recent Blocks + Recent Transactions */}
      <div className="grid lg:grid-cols-2 gap-6">
        <section className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
          <div className="flex items-center justify-between px-5 pt-5 pb-3">
            <h2 className="font-display font-semibold text-white text-sm">Recent Blocks</h2>
            <Link href="/blocks" className="text-xs text-misaka-400 hover:text-misaka-300 transition-colors">
              View all →
            </Link>
          </div>
          <BlocksTable blocks={blocksRes.data} compact />
        </section>

        <section className="rounded-xl border border-surface-300/50 bg-surface-100 overflow-hidden">
          <div className="flex items-center justify-between px-5 pt-5 pb-3">
            <h2 className="font-display font-semibold text-white text-sm">Recent Transactions</h2>
            <Link href="/txs" className="text-xs text-misaka-400 hover:text-misaka-300 transition-colors">
              View all →
            </Link>
          </div>
          <TransactionsTable transactions={txsRes.data} compact />
        </section>
      </div>
    </div>
  );
}

// Inline icons
function BlockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <path d="M3 9h18M9 21V9" />
    </svg>
  );
}
function TxIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="17 1 21 5 17 9" /><path d="M3 11V9a4 4 0 0 1 4-4h14" />
      <polyline points="7 23 3 19 7 15" /><path d="M21 13v2a4 4 0 0 1-4 4H3" />
    </svg>
  );
}
function ValidatorIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}
function ClockIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
    </svg>
  );
}
function SpeedIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
    </svg>
  );
}
