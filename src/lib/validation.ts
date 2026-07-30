import { z } from "zod";
import { type NextRequest, NextResponse } from "next/server";

/**
 * Shared validation result for API route handlers.
 */
export interface ValidationResult<T> {
  success: true;
  data: T;
}

export interface ValidationError {
  success: false;
  errors: z.ZodIssue[];
}

/**
 * Validate request body against a Zod schema.
 * Returns `{ success: true, data }` on success or
 * `{ success: false, errors }` on failure.
 */
export function validateBody<T>(schema: z.ZodSchema<T>, body: unknown): ValidationResult<T> | ValidationError {
  const result = schema.safeParse(body);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: result.error.issues };
}

/**
 * Validate a single query param against a Zod schema.
 */
export function validateQueryParam<T>(
  schema: z.ZodSchema<T>,
  value: unknown,
  paramName: string,
): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new ValidationErrorResponse(paramName, result.error.issues);
  }
  return result.data;
}

/**
 * Error class thrown by validateQueryParam when validation fails.
 * Catch it in the route handler and return a 400 response.
 */
export class ValidationErrorResponse extends Error {
  public paramName: string;
  public issues: z.ZodIssue[];

  constructor(paramName: string, issues: z.ZodIssue[]) {
    super(`Query param "${paramName}" validation failed`);
    this.name = "ValidationErrorResponse";
    this.paramName = paramName;
    this.issues = issues;
  }
}

/**
 * Return a 400 JSON response for validation failures.
 */
export function validationErrorResponse(errors: z.ZodIssue[]): NextResponse {
  return NextResponse.json(
    {
      error: "Validation failed",
      details: errors.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
        code: issue.code,
      })),
    },
    { status: 400 },
  );
}

/**
 * Helper to parse and validate a JSON request body in an API route.
 *
 * Usage:
 * ```ts
 * const body = await validatedBody(req, mySchema);
 * if (body instanceof NextResponse) return body; // 400
 * // body is now typed as MySchema
 * ```
 */
export async function parseValidatedBody<T>(
  req: NextRequest,
  schema: z.ZodSchema<T>,
): Promise<T | NextResponse> {
  try {
    const body = await req.json();
    const result = validateBody(schema, body);
    if (!result.success) {
      return validationErrorResponse(result.errors);
    }
    return result.data;
  } catch {
    return NextResponse.json(
      { error: "Invalid JSON body" },
      { status: 400 },
    );
  }
}

// ──────────────────────────────────────────────
// Reusable schema fragments
// ──────────────────────────────────────────────

/** UUID format validator */
export const uuidSchema = z.string().uuid("Invalid UUID format");

/** Generic pagination params */
export const paginationSchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/** Generic ID param for route params */
export const idParamSchema = z.object({
  id: z.string().min(1, "ID is required"),
});
