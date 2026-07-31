import { NextResponse } from "next/server";

// SEC-09: CSP violation reporting endpoint.
//
// Browsers POST violation reports to this URL (configured via the
// `report-uri /api/csp-report` and `report-to csp-endpoint` directives
// in src/middleware.ts). The endpoint is deliberately UNAUTHENTICATED —
// browsers do not send credentials with reports — and is rate-limited
// like every other public surface so a flood of junk reports can't be
// used as a DoS vector.
//
// Reports are logged with console.warn so they surface in the platform's
// existing log pipeline; the caller always gets 204 so the browser
// never retries. Anything that isn't a well-formed report gets 400 and
// non-POST methods get 405.

export async function POST(request: Request): Promise<NextResponse> {
  const body = await request.text().catch(() => null);
  if (!body) {
    return NextResponse.json(
      { error: "Missing request body" },
      { status: 400 },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return NextResponse.json(
      { error: "Request body is not valid JSON" },
      { status: 400 },
    );
  }

  // Two shapes are accepted:
  //  - legacy report-uri:  { "csp-report": { ... } }
  //  - reporting-api:      [ { type: "csp-violation", body: { ... } } ]
  // Extract a human-readable description from whichever shape arrived.
  let detail: string | null = null;

  if (isRecord(parsed) && isRecord(parsed["csp-report"])) {
    detail = describeLegacyReport(parsed["csp-report"]);
  } else if (Array.isArray(parsed)) {
    const descriptions = parsed
      .map(describeEntry)
      .filter((d): d is string => d !== null);
    if (descriptions.length > 0) {
      detail = descriptions.join("; ");
    }
  }

  if (!detail) {
    return NextResponse.json(
      { error: "Body is not a CSP violation report" },
      { status: 400 },
    );
  }

  // Reports are fire-and-forget from the browser's perspective; log
  // without blocking or risking the request itself failing.
  console.warn(`[csp-report] ${detail}`);

  return new NextResponse(null, { status: 204 });
}

export async function GET(): Promise<NextResponse> {
  return NextResponse.json(
    { error: "Method not allowed" },
    { status: 405, headers: { Allow: "POST" } },
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Returns a description for a reporting-api entry, or null if it isn't a csp-violation. */
function describeEntry(entry: unknown): string | null {
  if (!isRecord(entry) || entry.type !== "csp-violation") return null;
  if (!isRecord(entry.body)) return null;
  return describeLegacyReport(entry.body);
}

function describeLegacyReport(report: Record<string, unknown>): string {
  const directive = String(report["violated-directive"] ?? "unknown");
  const blocked = String(report["blocked-uri"] ?? "unknown");
  const source = String(report["source-file"] ?? "unknown");
  const line = report["line-number"] != null ? String(report["line-number"]) : "?";
  return `violated-directive=${directive} blocked-uri=${blocked} source=${source}:${line}`;
}
