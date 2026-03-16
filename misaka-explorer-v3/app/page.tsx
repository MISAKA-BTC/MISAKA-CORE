import { api } from '@/lib/api/client';
import { StatCard } from '@/components/ui/StatCard';
import { BlocksTable } from '@/components/explorer/BlocksTable';
import { TransactionsTable } from '@/components/explorer/TransactionsTable';
import { BlockMiniChart } from '@/components/explorer/BlockMiniChart';
import { SearchBar } from '@/components/explorer/SearchBar';
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
    <div className="page-enter">
      {/* Hero */}
      <section className="pt-20 pb-24 text-center">
        <div className="mb-6">
          <span className="inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.3em] text-muted">
            <span className={`w-1.5 h-1.5 rounded-full ${stats.chainHealth === 'healthy' ? 'bg-fg' : 'bg-muted'}`} />
            {stats.chainHealth === 'healthy' ? 'Network Operational' : 'Network Degraded'}
          </span>
        </div>
        <h1 className="text-[56px] sm:text-[72px] font-extralight text-fg tracking-tight leading-[1.05] mb-6">
          MISAKA Explorer
        </h1>
        <p className="text-[14px] text-muted font-light tracking-wide max-w-md mx-auto mb-12">
          Observe the network. Precision, privacy, structure.
        </p>
        <div className="max-w-xl mx-auto">
          <SearchBar />
        </div>
      </section>

      {/* Stats Grid */}
      <section className="mb-20">
        <div className="flex items-center justify-between mb-6">
          <span className="text-[10px] font-medium uppercase tracking-[0.25em] text-muted">Network Overview</span>
          <span className="text-[10px] text-dim tracking-wider">{stats.networkVersion}</span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-px bg-line">
          <StatCard label="Block Height" value={formatNumber(stats.latestBlockHeight)} />
          <StatCard label="Transactions" value={formatNumber(stats.totalTransactions)} />
          <StatCard label="Validators" value={stats.activeValidators} subValue="active" />
          <StatCard label="Block Time" value={formatBlockTime(stats.avgBlockTime)} />
          <StatCard label="TPS" value={stats.tpsEstimate.toFixed(1)} subValue="tx/sec" />
          <StatCard label="Finality" value={stats.finalityStatus === 'finalized' ? '●' : '○'} subValue={stats.finalityStatus} />
        </div>
      </section>

      {/* Chart */}
      <section className="mb-20">
        <div className="border border-line p-8">
          <div className="flex items-center justify-between mb-6">
            <div>
              <span className="text-[10px] font-medium uppercase tracking-[0.25em] text-muted block mb-1">Block Production</span>
              <span className="text-[11px] text-dim">Transactions per block — last 30 blocks</span>
            </div>
          </div>
          <BlockMiniChart data={chartData} height={200} />
        </div>
      </section>

      {/* Recent Blocks + Transactions */}
      <div className="grid lg:grid-cols-2 gap-px bg-line mb-20">
        <section className="bg-bg">
          <div className="flex items-center justify-between px-6 py-5 border-b border-line">
            <span className="text-[11px] font-medium uppercase tracking-[0.2em] text-muted">Recent Blocks</span>
            <Link href="/blocks" className="text-[11px] text-dim hover:text-fg transition-colors tracking-wider uppercase">
              View all →
            </Link>
          </div>
          <BlocksTable blocks={blocksRes.data} compact />
        </section>

        <section className="bg-bg">
          <div className="flex items-center justify-between px-6 py-5 border-b border-line">
            <span className="text-[11px] font-medium uppercase tracking-[0.2em] text-muted">Recent Transactions</span>
            <Link href="/txs" className="text-[11px] text-dim hover:text-fg transition-colors tracking-wider uppercase">
              View all →
            </Link>
          </div>
          <TransactionsTable transactions={txsRes.data} compact />
        </section>
      </div>

      {/* Network Info */}
      <section className="border-t border-line pt-12 pb-8">
        <div className="grid sm:grid-cols-3 gap-8">
          <div>
            <span className="text-[10px] uppercase tracking-[0.2em] text-dim block mb-2">Network</span>
            <span className="text-[13px] text-fg">{stats.networkName}</span>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-[0.2em] text-dim block mb-2">Genesis</span>
            <span className="text-[13px] text-subtle">{new Date(stats.genesisTimestamp).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</span>
          </div>
          <div>
            <span className="text-[10px] uppercase tracking-[0.2em] text-dim block mb-2">Status</span>
            <span className="text-[13px] text-fg">{stats.chainHealth === 'healthy' ? 'All Systems Operational' : 'Degraded'}</span>
          </div>
        </div>
      </section>
    </div>
  );
}
