'use client';

import { ProviderConfigPanel } from '@/components/admin/provider-config-panel';

export default function AdminWhatsAppPage() {
  return (
    <div className="mx-auto max-w-2xl space-y-6 py-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-foreground">
          WhatsApp Provider
        </h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Configure which backend powers WhatsApp messaging for this account.
        </p>
      </div>
      <ProviderConfigPanel />
    </div>
  );
}
