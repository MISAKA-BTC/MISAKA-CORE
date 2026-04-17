import { formatNumber } from "../lib/format";

export default function StatsGrid({ stats }: { stats: any }) {
  const height = stats?.blockHeight;
  const validators = stats?.validatorCount;
  const peers = stats?.peerCount;
  const observers = stats?.observerCount;
  
  let health = "—";
  let healthColor = "text-white";
  if (stats?.mode) {
    health = stats.mode === "joined" ? "Healthy" : stats.mode;
    healthColor = stats.mode === "joined" ? "text-green-500" : "text-yellow-500";
  }

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-5 shadow-sm">
        <div className="text-xs text-misaka-text3 uppercase tracking-widest font-semibold mb-2">Block Height</div>
        <div className="text-2xl font-bold text-white tracking-tight">{formatNumber(height)}</div>
      </div>
      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-5 shadow-sm">
        <div className="text-xs text-misaka-text3 uppercase tracking-widest font-semibold mb-2">Validators</div>
        <div className="text-2xl font-bold text-green-500 tracking-tight">{formatNumber(validators)}</div>
      </div>
      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-5 shadow-sm">
        <div className="text-xs text-misaka-text3 uppercase tracking-widest font-semibold mb-2">Observers</div>
        <div className="text-2xl font-bold text-blue-500 tracking-tight">{formatNumber(observers)}</div>
      </div>
      <div className="bg-misaka-bg2 border border-misaka-border rounded-xl p-5 shadow-sm">
        <div className="text-xs text-misaka-text3 uppercase tracking-widest font-semibold mb-2">Chain Health</div>
        <div className={`text-2xl font-bold tracking-tight ${healthColor}`}>{health}</div>
      </div>
    </div>
  );
}
