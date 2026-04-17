export default function StatusBadge({ status }: { status?: string }) {
  const s = (status || "unknown").toLowerCase();
  let color = "bg-white/5 text-misaka-text3";
  let label = "Unknown";
  let dot = "bg-misaka-text3";

  if (s === "confirmed" || s === "success" || s === "finalized") {
    color = "bg-green-500/10 text-green-500";
    label = "Confirmed";
    dot = "bg-green-500";
  } else if (s === "pending") {
    color = "bg-yellow-500/10 text-yellow-500";
    label = "Pending";
    dot = "bg-yellow-500";
  } else if (s === "dropped" || s === "failed") {
    color = "bg-red-500/10 text-red-500";
    label = "Failed";
    dot = "bg-red-500";
  }

  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />
      {label}
    </span>
  );
}
