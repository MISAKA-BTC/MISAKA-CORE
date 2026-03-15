export default function BlockDetailLoading() {
  return (
    <div className="page-enter space-y-8">
      <div className="flex items-center gap-2">
        <div className="skeleton h-4 w-16 rounded" />
        <span className="text-slate-600">/</span>
        <div className="skeleton h-4 w-24 rounded" />
      </div>
      <div className="skeleton h-9 w-48 rounded-lg" />
      <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 space-y-5">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="flex gap-4">
            <div className="skeleton h-4 w-36 rounded shrink-0" />
            <div className="skeleton h-4 flex-1 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}
