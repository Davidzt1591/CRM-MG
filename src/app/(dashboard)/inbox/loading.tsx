import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";

export default function InboxLoading() {
  return (
    <div className="flex h-full gap-4">
      {/* Conversation list skeleton */}
      <div className="w-80 shrink-0 space-y-3">
        <Skeleton className="h-10 w-full" />
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3 rounded-lg p-3">
            <Skeleton className="size-10 shrink-0 rounded-full" />
            <div className="flex flex-1 flex-col gap-2">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-3 w-1/2" />
            </div>
          </div>
        ))}
      </div>
      {/* Conversation panel skeleton */}
      <div className="flex flex-1 flex-col gap-4">
        <Skeleton className="h-12 w-full" />
        <div className="flex flex-1 flex-col gap-3 p-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className={cn(
                "flex max-w-[70%] gap-2",
                i % 2 === 0 ? "self-start" : "self-end",
              )}
            >
              <Skeleton
                className={cn(
                  "h-16 w-48 rounded-lg",
                  i % 2 === 0 ? "rounded-bl-sm" : "rounded-br-sm",
                )}
              />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
