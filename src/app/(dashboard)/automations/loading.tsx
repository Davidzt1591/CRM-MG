import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";

// Automations page skeleton — mirrors the AutomationsPage layout
// (header + action button + list of automation rows) so the
// loading → content swap is jank-free. Modeled on inbox/loading.tsx:
// Skeleton + cn + Array.from.
export default function AutomationsLoading() {
  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Header (title + new-automation button) */}
      <div className="flex items-center justify-between">
        <Skeleton className="h-7 w-28" />
        <Skeleton className="h-9 w-36" />
      </div>

      {/* Automation row list */}
      <div className="space-y-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className={cn(
              "flex items-center justify-between rounded-lg border border-border bg-card p-4",
              // Alternate row density to mirror the real list's rhythm
              "gap-4",
            )}
          >
            <div className="flex items-center gap-3">
              <Skeleton className="size-9 shrink-0 rounded-lg" />
              <div className="flex flex-col gap-1.5">
                <Skeleton className={cn("h-4", i % 2 === 0 ? "w-40" : "w-48")} />
                <Skeleton className={cn("h-3", i % 2 === 0 ? "w-28" : "w-36")} />
              </div>
            </div>
            <Skeleton className="h-6 w-20 shrink-0 rounded-full" />
          </div>
        ))}
      </div>
    </div>
  );
}
