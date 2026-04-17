import { formatAmount } from "../lib/format";

export default function BalanceHero({ balance }: { balance: number | string | undefined | null }) {
  const display = formatAmount(balance || 0);
  const base = Number(balance || 0).toLocaleString();

  return (
    <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-8 sm:p-12 shadow-sm text-center mb-6">
      <div className="text-sm font-semibold uppercase tracking-widest text-misaka-text3 mb-3">
        Total Balance
      </div>
      <div className="text-4xl sm:text-5xl font-bold tracking-tight text-white mb-2">
        {display}
      </div>
      <div className="text-sm text-misaka-text3 font-mono">
        {base} base units
      </div>
    </div>
  );
}
