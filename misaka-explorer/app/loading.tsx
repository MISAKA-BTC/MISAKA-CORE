export default function HomeLoading() {
  return (
    <div className="page-enter space-y-10">
      {/* Hero skeleton */}
      <section className="text-center pt-6 pb-4">
        <div className="skeleton h-4 w-32 rounded mx-auto mb-4" />
        <div className="skeleton h-12 w-72 rounded-lg mx-auto mb-2" />
        <div className="skeleton h-4 w-80 rounded mx-auto mb-8" />
        <div className="skeleton h-12 w-full max-w-2xl rounded-xl mx-auto" />
      </section>

      {/* Stats grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="rounded-xl border border-surface-300/50 bg-surface-100 p-5">
            <div className="skeleton h-3 w-20 rounded mb-3" />
            <div className="skeleton h-7 w-24 rounded" />
          </div>
        ))}
      </div>

      {/* Chart skeleton */}
      <div className="rounded-xl border border-surface-300/50 bg-surface-100 p-5">
        <div className="skeleton h-4 w-36 rounded mb-2" />
        <div className="skeleton h-3 w-64 rounded mb-4" />
        <div className="skeleton h-44 w-full rounded-lg" />
      </div>

      {/* Tables */}
      <div className="grid lg:grid-cols-2 gap-6">
        {[0, 1].map((i) => (
          <div key={i} className="rounded-xl border border-surface-300/50 bg-surface-100 p-5 space-y-3">
            <div className="skeleton h-5 w-32 rounded mb-4" />
            {Array.from({ length: 6 }).map((_, j) => (
              <div key={j} className="flex gap-3">
                <div className="skeleton h-4 w-16 rounded" />
                <div className="skeleton h-4 flex-1 rounded" />
                <div className="skeleton h-4 w-12 rounded" />
                <div className="skeleton h-4 w-16 rounded" />
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
