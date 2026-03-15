export default function TxsLoading() {
  return (
    <div className="page-enter space-y-6">
      <div>
        <div className="skeleton h-8 w-40 rounded-lg mb-2" />
        <div className="skeleton h-4 w-72 rounded-md" />
      </div>
      <div className="skeleton h-12 w-full rounded-lg" />
      <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 space-y-4">
        {Array.from({ length: 10 }).map((_, i) => (
          <div key={i} className="flex gap-4 items-center">
            <div className="skeleton h-5 flex-1 rounded" />
            <div className="skeleton h-5 w-20 rounded" />
            <div className="skeleton h-5 w-16 rounded" />
            <div className="skeleton h-5 w-20 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}
