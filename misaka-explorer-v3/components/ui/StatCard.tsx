interface StatCardProps {
  label: string;
  value: string | number;
  subValue?: string;
}

export function StatCard({ label, value, subValue }: StatCardProps) {
  return (
    <div className="border border-line p-6 hover:border-dim transition-colors duration-150">
      <span className="text-[10px] font-medium uppercase tracking-[0.2em] text-muted block mb-3">{label}</span>
      <div className="text-[28px] font-light text-fg tracking-tight leading-none font-mono">
        {value}
      </div>
      {subValue && (
        <span className="text-[11px] text-dim mt-2 block tracking-wider uppercase">{subValue}</span>
      )}
    </div>
  );
}
