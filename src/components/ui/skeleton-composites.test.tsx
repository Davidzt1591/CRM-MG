import { describe, expect, it } from 'vitest';
import { renderToString } from 'react-dom/server';
import {
  ActivitySkeleton,
  ChartSkeleton,
  FormSkeleton,
  MetricCardSkeleton,
  SidePanelSkeleton,
  TableSkeleton,
} from './skeleton-composites';

// ---------------------------------------------------------------------------
// Smoke tests — verify every composite renders without throwing.
// We use renderToString (no jsdom required; node env only).
// ---------------------------------------------------------------------------

describe('MetricCardSkeleton', () => {
  it('renders without crashing', () => {
    const html = renderToString(<MetricCardSkeleton />);
    expect(html).toContain('animate-pulse');
  });
});

describe('TableSkeleton', () => {
  it('renders the requested number of rows', () => {
    const html = renderToString(<TableSkeleton rows={3} />);
    // Each row has a size-8 avatar skeleton.
    const matches = html.match(/size-8/g);
    expect(matches).toHaveLength(3);
  });

  it('defaults to 5 rows', () => {
    const html = renderToString(<TableSkeleton />);
    const matches = html.match(/size-8/g);
    expect(matches).toHaveLength(5);
  });
});

describe('FormSkeleton', () => {
  it('renders the requested number of fields', () => {
    const html = renderToString(<FormSkeleton fields={2} />);
    // Each field has an h-10 input skeleton.
    const matches = html.match(/h-10 w-full/g);
    expect(matches).toHaveLength(2);
  });

  it('defaults to 4 fields', () => {
    const html = renderToString(<FormSkeleton />);
    const matches = html.match(/h-10 w-full/g);
    expect(matches).toHaveLength(4);
  });
});

describe('SidePanelSkeleton', () => {
  it('renders without crashing', () => {
    const html = renderToString(<SidePanelSkeleton />);
    expect(html).toContain('rounded-full');
    expect(html).toContain('border-t');
  });
});

describe('ChartSkeleton', () => {
  it('renders without crashing', () => {
    const html = renderToString(<ChartSkeleton />);
    expect(html).toContain('h-48');
  });
});

describe('ActivitySkeleton', () => {
  it('renders the requested number of items', () => {
    const html = renderToString(<ActivitySkeleton items={2} />);
    const matches = html.match(/rounded-full/g);
    expect(matches).toHaveLength(2);
  });

  it('defaults to 5 items', () => {
    const html = renderToString(<ActivitySkeleton />);
    const matches = html.match(/rounded-full/g);
    expect(matches).toHaveLength(5);
  });
});
