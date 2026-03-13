export default function AddressLoading() {
  return (
    <div className="page-enter space-y-8">
      <div>
        <div className="skeleton h-8 w-28 rounded-lg mb-2" />
        <div className="skeleton h-10 w-full rounded-lg" />
      </div>
      <div className="skeleton h-12 w-full rounded-lg" />
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-surface-300/50 bg-surface-100 p-4">
            <div className="skeleton h-3 w-20 rounded mb-2" />
            <div className="skeleton h-6 w-24 rounded" />
          </div>
        ))}
      </div>
      <div>
        <div className="skeleton h-6 w-28 rounded mb-4" />
        <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex gap-4">
              <div className="skeleton h-4 flex-1 rounded" />
              <div className="skeleton h-4 w-12 rounded" />
              <div className="skeleton h-4 w-20 rounded" />
              <div className="skeleton h-4 w-16 rounded" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
