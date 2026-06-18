// Default route-segment loading state — a calm skeleton shown while a Server Component
// page fetches. Mirrors the common page shape (header + a few cards/rows).
export default function Loading() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <div className="skeleton h-5 w-48 rounded-md" />
        <div className="skeleton h-3 w-72 rounded" />
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="skeleton h-24 rounded-xl" />
        ))}
      </div>
      <div className="card divide-y divide-border p-0">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3 px-5 py-3.5">
            <div className="skeleton h-4 w-16 rounded-md" />
            <div className="skeleton h-4 flex-1 rounded" />
            <div className="skeleton h-4 w-20 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}
