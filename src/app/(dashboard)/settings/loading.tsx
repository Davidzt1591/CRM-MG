import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";

// Settings page skeleton — mirrors the SettingsPage grid layout
// (header + rail + content panel) so the loading → content swap is
// jank-free. Modeled on inbox/loading.tsx: Skeleton + cn + Array.from.
export default function SettingsLoading() {
  return (
    <div className="flex flex-col gap-6">
      {/* Page header (h1 + description) */}
      <div>
        <Skeleton className="h-8 w-36" />
        <Skeleton className="mt-1 h-4 w-64" />
      </div>

      {/* Rail + content grid — matches SettingsPage two-column layout */}
      <div className="grid gap-6 lg:grid-cols-[236px_minmax(0,1fr)] lg:items-start">
        {/* Settings rail */}
        <nav className="space-y-1">
          {Array.from({ length: 9 }).map((_, i) => (
            <Skeleton
              key={i}
              className={cn(
                "h-9 rounded-lg",
                // First rail item is the active/selected one — slightly wider
                i === 0 ? "w-44" : "w-full",
              )}
            />
          ))}
        </nav>

        {/* Content panel — form fields */}
        <div className="space-y-6">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className={cn(
                "space-y-3",
                // Alternate between a taller "form" block and a shorter one
                // to avoid the mechanical uniform look and better mirror
                // the real content's rhythm.
                i % 2 === 0 ? "pb-1" : "",
              )}
            >
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-4 w-3/4" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
