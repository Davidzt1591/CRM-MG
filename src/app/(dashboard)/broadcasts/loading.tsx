import { TableSkeleton, MetricCardSkeleton } from "@/components/ui/skeleton-composites";

export default function BroadcastsLoading() {
  return (
    <div className="flex flex-col gap-6 p-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="h-7 w-40 animate-pulse rounded-md bg-primary/10" />
        <div className="h-9 w-36 animate-pulse rounded-md bg-primary/10" />
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <MetricCardSkeleton key={i} />
        ))}
      </div>

      {/* Table */}
      <TableSkeleton rows={6} />
    </div>
  );
}
