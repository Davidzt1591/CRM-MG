import { NextResponse } from "next/server";

import {
  checkRateLimit,
  rateLimitResponse,
  RATE_LIMITS,
} from "@/lib/rate-limit";

// SEC-09: CSP violation reporting endpoint.
//
// Browsers POST violation reports to this URL (configured via the
// `report-uri /api/csp-report` and `report-to csp-endpoint` directives
// in src/middleware.ts). The endpoint is deliberately UNAUTHENTICATED —
// browsers do not send credentials with reports — so it is protected
// like any other public surface:
//   - per-IP rate limit (see RATE_LIMITS.cspReport) so a flood of junk
//     reports can't be used as a DoS vector;
//   - a 100 KB body cap (checked via Content-Length when present and
//     again after reading, so a missing/lying header doesn't help);
//   - the reporting-api array is processed at most 20 entries deep;
//   - logged fields are stripped of control characters and truncated,
//     so a crafted report can't inject fake log lines.
//
// Reports are logged with console.warn so they surface in the platform's
// existing log pipeline; the caller always gets 204 so the browser
// never retries. Anything that isn't a well-formed report gets 400,
// oversized bodies get 413, floods get 429, and non-POST methods get 405.

const MAX_BODY_BYTES = 100 * 1024; // 100 KB
const MAX_REPORT_ENTRIES = 20;
const MAX_FIELD_LENGTH = 200;

export async function POST(request: Request): Promise<NextResponse> {
  // Per-IP budget, derived from the left-most X-Forwarded-For entry
  // (the value appended by the platform's own proxy).
  const ip =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
  const limit = checkRateLimit(`csp-report:${ip}`, RATE_LIMITS.cspReport);
  if (!limit.success) return rateLimitResponse(limit);

  // Cheap pre-check: trust a truthful Content-Length and reject before
  // buffering anything.
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (contentLength > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: "Request body too large" },
      { status: 413 },
    );
  }

  const body = await request.text().catch(() => null);
  if (!body) {
    return NextResponse.json(
      { error: "Missing request body" },
      { status: 400 },
    );
  }

  // Belt-and-braces: a missing or lying Content-Length can't smuggle a
  // giant body past the cap.
  if (body.length > MAX_BODY_BYTES) {
    return NextResponse.json(
      { error: "Request body too large" },
      { status: 413 },
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
      .slice(0, MAX_REPORT_ENTRIES)
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
  // without blocking or risking the request itself failing. `detail`
  // is already sanitized by describeLegacyReport.
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

/**
 * Sanitize an attacker-controlled report field: strip control
 * characters (C0/C1 + DEL) so no escape sequence or fake newline can
 * inject log lines, then truncate to a fixed cap so one absurd field
 * can't bloat the log. Empty-after-clean fields read "(empty)".
 */
function sanitizeField(value: string): string {
  const cleaned = value.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
  const capped = cleaned.slice(0, MAX_FIELD_LENGTH);
  return capped.length > 0 ? capped : "(empty)";
}

function describeLegacyReport(report: Record<string, unknown>): string {
  const directive = sanitizeField(String(report["violated-directive"] ?? "unknown"));
  const blocked = sanitizeField(String(report["blocked-uri"] ?? "unknown"));
  const source = sanitizeField(String(report["source-file"] ?? "unknown"));
  const line = sanitizeField(
    report["line-number"] != null ? String(report["line-number"]) : "?",
  );
  return `violated-directive=${directive} blocked-uri=${blocked} source=${source}:${line}`;
}
