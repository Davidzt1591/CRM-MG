import { Skeleton } from "./skeleton";

/**
 * Reusable skeleton composites for common page-loading patterns.
 *
 * These mirror the layout of the real components they stand in for,
 * so the transition from loading → content is seamless — no layout
 * shift, no content jump.
 */

// ---------------------------------------------------------------------------
// Metric cards (dashboard stats row)
// ---------------------------------------------------------------------------

export function MetricCardSkeleton() {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <Skeleton className="mb-2 h-4 w-24" />
      <Skeleton className="h-8 w-16" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Data table (contacts, templates, broadcasts, API keys…)
// ---------------------------------------------------------------------------

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      <Skeleton className="h-9 w-full" />
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="flex items-center gap-4 rounded-lg border border-border bg-card p-3"
        >
          <Skeleton className="size-8 shrink-0 rounded-full" />
          <div className="flex flex-1 flex-col gap-1.5">
            <Skeleton className="h-4 w-1/3" />
            <Skeleton className="h-3 w-1/2" />
          </div>
          <Skeleton className="h-4 w-16" />
          <Skeleton className="h-6 w-20 rounded-full" />
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Settings form (profile, security, WhatsApp config, AI config…)
// ---------------------------------------------------------------------------

export function FormSkeleton({ fields = 4 }: { fields?: number }) {
  return (
    <div className="space-y-6">
      {Array.from({ length: fields }).map((_, i) => (
        <div key={i} className="space-y-2">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-10 w-full" />
          {i === 0 && <Skeleton className="h-3 w-3/4 text-muted-foreground" />}
        </div>
      ))}
      <Skeleton className="h-10 w-28" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Side panel (contact sidebar, deal form, settings rail content)
// ---------------------------------------------------------------------------

export function SidePanelSkeleton() {
  return (
    <div className="space-y-4 p-4">
      <Skeleton className="size-16 rounded-full" />
      <div className="space-y-2">
        <Skeleton className="h-5 w-3/4" />
        <Skeleton className="h-3 w-1/2" />
      </div>
      <div className="space-y-3 border-t border-border pt-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="space-y-1">
            <Skeleton className="h-3 w-20" />
            <Skeleton className="h-5 w-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Chart widget (dashboard charts, pipeline analytics)
// ---------------------------------------------------------------------------

export function ChartSkeleton() {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <Skeleton className="mb-4 h-5 w-40" />
      <Skeleton className="h-48 w-full rounded-md" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Activity feed (dashboard activity-feed block)
// ---------------------------------------------------------------------------

export function ActivitySkeleton({ items = 5 }: { items?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: items }).map((_, i) => (
        <div key={i} className="flex items-center gap-3">
          <Skeleton className="size-8 shrink-0 rounded-full" />
          <div className="flex flex-1 flex-col gap-1.5">
            <Skeleton className="h-3.5 w-3/4" />
            <Skeleton className="h-3 w-1/3" />
          </div>
        </div>
      ))}
    </div>
  );
}
