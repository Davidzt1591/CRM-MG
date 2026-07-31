'use client';

import { Badge } from '@/components/ui/badge';

/**
 * Map an escalation_status to a human-readable label.
 */
export function getBadgeLabel(
  escalationStatus: string | null | undefined,
): string {
  switch (escalationStatus) {
    case 'escalated':
      return 'Escalado a Salesforce';
    case 'waiting':
      return 'Waiting on Customer';
    case 'resolved':
      return 'Resolved';
    default:
      return escalationStatus ?? '';
  }
}

/**
 * Map an escalation_status to a badge variant.
 */
export function getBadgeVariant(
  escalationStatus: string | null | undefined,
): 'default' | 'secondary' | 'outline' {
  switch (escalationStatus) {
    case 'escalated':
      return 'default';
    case 'waiting':
      return 'secondary';
    case 'resolved':
      return 'outline';
    default:
      return 'outline';
  }
}

interface SalesforceBadgeProps {
  escalationStatus: string | null | undefined;
  className?: string;
}

/**
 * A small badge that shows the escalation status of a conversation
 * in the inbox list and conversation header.
 *
 * - `escalated` → "Escalado a Salesforce" (primary/default badge)
 * - `waiting`   → "Waiting on Customer" (secondary badge)
 * - `resolved`  → "Resolved" (outline/neutral)
 * - other/null  → nothing rendered
 */
export function SalesforceBadge({
  escalationStatus,
  className,
}: SalesforceBadgeProps) {
  if (!escalationStatus || escalationStatus === 'active') return null;

  const label = getBadgeLabel(escalationStatus);
  const variant = getBadgeVariant(escalationStatus);

  return (
    <Badge variant={variant} className={className}>
      {label}
    </Badge>
  );
}
