export default function ValidatorDetailLoading() {
  return (
    <div className="page-enter space-y-8">
      <div className="flex items-center gap-2">
        <div className="skeleton h-4 w-20 rounded" />
        <span className="text-slate-600">/</span>
        <div className="skeleton h-4 w-28 rounded" />
      </div>
      <div className="flex items-center gap-4">
        <div className="skeleton w-12 h-12 rounded-xl" />
        <div>
          <div className="skeleton h-7 w-48 rounded mb-2" />
          <div className="flex gap-2">
            <div className="skeleton h-5 w-16 rounded" />
            <div className="skeleton h-5 w-14 rounded" />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-surface-300/50 bg-surface-100 p-5">
            <div className="skeleton h-3 w-20 rounded mb-3" />
            <div className="skeleton h-7 w-28 rounded" />
          </div>
        ))}
      </div>
      <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 space-y-5">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex gap-4">
            <div className="skeleton h-4 w-36 rounded shrink-0" />
            <div className="skeleton h-4 flex-1 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}
