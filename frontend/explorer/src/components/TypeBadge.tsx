export default function TypeBadge({ type }: { type?: string }) {
  if (!type) return null;
  
  const map: Record<string, { label: string; cls: string }> = {
    TransparentTransfer: { label: "Transfer", cls: "bg-blue-500/10 text-blue-500" },
    Faucet: { label: "Faucet", cls: "bg-purple-500/10 text-purple-500" },
    SystemEmission: { label: "Block Reward", cls: "bg-green-500/10 text-green-500" },
    StakeDeposit: { label: "Stake", cls: "bg-yellow-500/10 text-yellow-500" },
    StakeWithdraw: { label: "Unstake", cls: "bg-yellow-500/10 text-yellow-500" },
    SlashEvidence: { label: "Slash", cls: "bg-white/10 text-misaka-text3" },
  };

  const m = map[type] || { label: type, cls: "bg-white/10 text-misaka-text3" };

  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-[11px] font-semibold uppercase tracking-wider ${m.cls}`}>
      {m.label}
    </span>
  );
}
