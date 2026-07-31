export default function PipelinesLoading() {
  return (
    <div className="flex flex-col gap-4 p-4">
      <div className="h-7 w-32 animate-pulse rounded-md bg-primary/10" />
      <div className="flex gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div
            key={i}
            className="flex min-h-64 flex-1 flex-col gap-3 rounded-lg border border-border bg-card p-4"
          >
            <div className="h-5 w-24 animate-pulse rounded-md bg-primary/10" />
            <div className="h-3 w-16 animate-pulse rounded-md bg-primary/10" />
            {Array.from({ length: 4 }).map((_, j) => (
              <div
                key={j}
                className="h-16 w-full animate-pulse rounded-md bg-primary/10"
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}
