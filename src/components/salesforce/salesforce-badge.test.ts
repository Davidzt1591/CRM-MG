import { describe, expect, it } from 'vitest';
import { getBadgeLabel, getBadgeVariant } from './salesforce-badge';

describe('getBadgeLabel', () => {
  it('returns "Escalado a Salesforce" for escalated status', () => {
    expect(getBadgeLabel('escalated')).toBe('Escalado a Salesforce');
  });

  it('returns "Waiting on Customer" for waiting status', () => {
    expect(getBadgeLabel('waiting')).toBe('Waiting on Customer');
  });

  it('returns "Resolved" for resolved status', () => {
    expect(getBadgeLabel('resolved')).toBe('Resolved');
  });

  it('returns the status as-is for unknown values', () => {
    expect(getBadgeLabel('active')).toBe('active');
    expect(getBadgeLabel('')).toBe('');
  });
});

describe('getBadgeVariant', () => {
  it('returns "default" for escalated', () => {
    expect(getBadgeVariant('escalated')).toBe('default');
  });

  it('returns "secondary" for waiting', () => {
    expect(getBadgeVariant('waiting')).toBe('secondary');
  });

  it('returns "outline" for resolved', () => {
    expect(getBadgeVariant('resolved')).toBe('outline');
  });

  it('returns "outline" for unknown statuses', () => {
    expect(getBadgeVariant('active')).toBe('outline');
    expect(getBadgeVariant('')).toBe('outline');
  });
});
