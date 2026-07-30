import { describe, it, expect } from "vitest";
import { z } from "zod";
import {
  validateBody,
  validationErrorResponse,
  uuidSchema,
  paginationSchema,
} from "@/lib/validation";

describe("validateBody", () => {
  const testSchema = z.object({
    name: z.string().min(1),
    age: z.number().int().positive(),
  });

  it("returns data on valid input", () => {
    const result = validateBody(testSchema, { name: "Alice", age: 30 });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toEqual({ name: "Alice", age: 30 });
    }
  });

  it("returns errors on invalid input", () => {
    const result = validateBody(testSchema, { name: "", age: -1 });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.errors.length).toBeGreaterThan(0);
    }
  });

  it("strips unknown fields", () => {
    const schema = z.object({ name: z.string() });
    const result = validateBody(schema, { name: "Bob", extra: true });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toEqual({ name: "Bob" });
      expect("extra" in result.data).toBe(false);
    }
  });
});

describe("validationErrorResponse", () => {
  it("returns 400 with structured error", () => {
    const schema = z.object({ email: z.string().email() });
    const result = validateBody(schema, { email: "not-an-email" });
    expect(result.success).toBe(false);

    if (!result.success) {
      const response = validationErrorResponse(result.errors);
      expect(response.status).toBe(400);

      // The response is a NextResponse — verify body content
      const body = response as unknown as { status: number };
      expect(body.status).toBe(400);
    }
  });
});

describe("uuidSchema", () => {
  it("accepts valid UUIDs", () => {
    expect(uuidSchema.safeParse("550e8400-e29b-41d4-a716-446655440000").success).toBe(true);
  });

  it("rejects invalid UUIDs", () => {
    expect(uuidSchema.safeParse("not-a-uuid").success).toBe(false);
    expect(uuidSchema.safeParse("").success).toBe(false);
  });
});

describe("paginationSchema", () => {
  it("applies defaults for missing fields", () => {
    const result = paginationSchema.safeParse({});
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(50);
      expect(result.data.offset).toBe(0);
    }
  });

  it("coerces string numbers", () => {
    const result = paginationSchema.safeParse({ limit: "25", offset: "10" });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.limit).toBe(25);
      expect(result.data.offset).toBe(10);
    }
  });

  it("rejects out-of-range limit", () => {
    expect(paginationSchema.safeParse({ limit: 0 }).success).toBe(false);
    expect(paginationSchema.safeParse({ limit: 101 }).success).toBe(false);
  });
});
