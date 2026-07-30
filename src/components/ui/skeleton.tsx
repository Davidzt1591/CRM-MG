import { cn } from "@/lib/utils";

/**
 * Skeleton component for loading states.
 * Renders a pulsing placeholder that matches shadcn/ui conventions.
 *
 * Usage:
 * ```tsx
 * <Skeleton className="h-4 w-[250px]" />
 * ```
 */
export function Skeleton({
  className,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("animate-pulse rounded-md bg-primary/10", className)}
      {...props}
    />
  );
}
