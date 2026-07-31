import { getTranslations } from 'next-intl/server';
import { SalesforceConfigPanel } from '@/components/admin/salesforce-config-panel';

export default async function SalesforcePage() {
  const t = await getTranslations('Admin');

  return (
    <div className="flex flex-col gap-4 p-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">
          {t('salesforce')}
        </h1>
        <p className="text-sm text-muted-foreground">
          {t('pageDesc') ?? 'Configure Salesforce integration'}
        </p>
      </div>
      <SalesforceConfigPanel />
    </div>
  );
}
