import { TableSkeleton } from "@/components/ui/skeleton-composites";

export default function ContactsLoading() {
  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="flex items-center justify-between">
        <div className="h-7 w-32 animate-pulse rounded-md bg-primary/10" />
        <div className="h-9 w-28 animate-pulse rounded-md bg-primary/10" />
      </div>
      <TableSkeleton rows={8} />
    </div>
  );
}
