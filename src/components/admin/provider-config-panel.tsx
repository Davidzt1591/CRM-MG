'use client';

import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Loader2, CheckCircle2, XCircle, Save } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';

const MASKED = '••••••••••••••••';

interface ProviderFormData {
  provider: 'meta' | 'openwa';
  // Meta fields
  phone_number_id: string;
  waba_id: string;
  access_token: string;
  // OpenWA fields
  api_url: string;
  api_key: string;
  webhook_secret: string;
}

const EMPTY_FORM: ProviderFormData = {
  provider: 'meta',
  phone_number_id: '',
  waba_id: '',
  access_token: '',
  api_url: '',
  api_key: '',
  webhook_secret: '',
};

export function ProviderConfigPanel() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState<ProviderFormData>(EMPTY_FORM);
  // Track which fields the user edited so we can detect masked vs. new value.
  const [edited, setEdited] = useState<Set<string>>(new Set());

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/api/admin/whatsapp/provider');
        const data = await res.json();
        if (cancelled) return;

        setForm({
          provider: data.provider ?? 'meta',
          phone_number_id: data.phone_number_id ?? '',
          waba_id: data.waba_id ?? '',
          access_token: data.access_token ?? '',
          api_url: data.api_url ?? '',
          api_key: data.api_key ?? '',
          webhook_secret: data.webhook_secret ?? '',
        });
        setEdited(new Set());
      } catch (err) {
        console.error('Failed to load provider config:', err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  function set<K extends keyof ProviderFormData>(field: K, value: ProviderFormData[K]) {
    setForm((prev) => ({ ...prev, [field]: value }));
    setEdited((prev) => new Set(prev).add(field));
  }

  async function handleSave() {
    try {
      setSaving(true);

      const body: Record<string, unknown> = { provider: form.provider };

      if (form.provider === 'meta') {
        body.phone_number_id = form.phone_number_id;
        body.waba_id = form.waba_id;
        // Only send access_token if the user edited the field AND the
        // value differs from the masked placeholder.
        if (edited.has('access_token') && form.access_token !== MASKED) {
          body.access_token = form.access_token;
        }
      } else {
        body.api_url = form.api_url;
        if (edited.has('api_key') && form.api_key !== MASKED) {
          body.api_key = form.api_key;
        }
        if (edited.has('webhook_secret') && form.webhook_secret !== MASKED) {
          body.webhook_secret = form.webhook_secret;
        }
      }

      const res = await fetch('/api/admin/whatsapp/provider', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Failed to save provider configuration');
        return;
      }

      toast.success('Provider configuration saved');
      setEdited(new Set());
    } catch (err) {
      console.error('Save error:', err);
      toast.error('Failed to save provider configuration');
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="size-6 animate-spin text-primary" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Provider selector */}
      <Card>
        <CardHeader>
          <CardTitle>Provider</CardTitle>
          <CardDescription>
            Choose which WhatsApp backend this account uses. Meta Cloud API
            is the default. OpenWA requires a running wa-automate-nodejs
            instance.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>WhatsApp Provider</Label>
            <Select
              value={form.provider}
              onValueChange={(v: 'meta' | 'openwa') => set('provider', v)}
            >
              <SelectTrigger className="w-64 bg-muted border-border text-foreground">
                <SelectValue placeholder="Select provider" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="meta">Meta Cloud API</SelectItem>
                <SelectItem value="openwa">OpenWA (baileys)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Meta fields */}
      {form.provider === 'meta' && (
        <Card>
          <CardHeader>
            <CardTitle>Meta Cloud API Configuration</CardTitle>
            <CardDescription>
              Enter your WhatsApp Business API credentials from the Meta
              Developer Console.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>Phone Number ID</Label>
              <Input
                placeholder="e.g. 100234567890123"
                value={form.phone_number_id}
                onChange={(e) => set('phone_number_id', e.target.value)}
                className="bg-muted border-border text-foreground"
              />
            </div>
            <div className="space-y-2">
              <Label>WABA ID</Label>
              <Input
                placeholder="e.g. 100234567890456"
                value={form.waba_id}
                onChange={(e) => set('waba_id', e.target.value)}
                className="bg-muted border-border text-foreground"
              />
            </div>
            <div className="space-y-2">
              <Label>Access Token</Label>
              <Input
                type="password"
                placeholder="Enter your permanent access token"
                value={form.access_token}
                onChange={(e) => set('access_token', e.target.value)}
                onFocus={() => {
                  if (form.access_token === MASKED) {
                    set('access_token', '');
                  }
                }}
                className="bg-muted border-border text-foreground"
              />
              {!edited.has('access_token') && form.access_token === MASKED && (
                <p className="text-xs text-muted-foreground">
                  Token is stored encrypted. Re-enter to change.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* OpenWA fields */}
      {form.provider === 'openwa' && (
        <Card>
          <CardHeader>
            <CardTitle>OpenWA Configuration</CardTitle>
            <CardDescription>
              Connect to your self-hosted wa-automate-nodejs (baileys)
              instance.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label>API URL</Label>
              <Input
                placeholder="e.g. http://localhost:2785"
                value={form.api_url}
                onChange={(e) => set('api_url', e.target.value)}
                className="bg-muted border-border text-foreground"
              />
            </div>
            <div className="space-y-2">
              <Label>API Key</Label>
              <Input
                type="password"
                placeholder="Your OpenWA API secret key"
                value={form.api_key}
                onChange={(e) => set('api_key', e.target.value)}
                onFocus={() => {
                  if (form.api_key === MASKED) {
                    set('api_key', '');
                  }
                }}
                className="bg-muted border-border text-foreground"
              />
              {!edited.has('api_key') && form.api_key === MASKED && (
                <p className="text-xs text-muted-foreground">
                  Key is stored encrypted. Re-enter to change.
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label>Webhook Secret</Label>
              <Input
                type="password"
                placeholder="HMAC secret for webhook signature verification"
                value={form.webhook_secret}
                onChange={(e) => set('webhook_secret', e.target.value)}
                onFocus={() => {
                  if (form.webhook_secret === MASKED) {
                    set('webhook_secret', '');
                  }
                }}
                className="bg-muted border-border text-foreground"
              />
              {!edited.has('webhook_secret') && form.webhook_secret === MASKED && (
                <p className="text-xs text-muted-foreground">
                  Secret is stored encrypted. Re-enter to change.
                </p>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Save button */}
      <div className="flex items-center gap-3">
        <Button
          onClick={handleSave}
          disabled={saving}
          className="bg-primary hover:bg-primary/90 text-primary-foreground"
        >
          {saving ? (
            <>
              <Loader2 className="size-4 animate-spin" />
              Saving…
            </>
          ) : (
            <>
              <Save className="size-4" />
              Save Configuration
            </>
          )}
        </Button>
      </div>

      {/* Webhook URL hint — varies by provider */}
      <div className="rounded border border-border bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
        {form.provider === 'meta' ? (
          <p>
            Meta webhook URL:{' '}
            <code className="text-foreground font-mono text-xs">
              {typeof window !== 'undefined'
                ? `${window.location.origin}/api/whatsapp/webhook`
                : ''}
            </code>
          </p>
        ) : (
          <p>
            OpenWA webhook URL:{' '}
            <code className="text-foreground font-mono text-xs">
              {typeof window !== 'undefined'
                ? `${window.location.origin}/api/whatsapp/webhook?account_id=YOUR_ACCOUNT_ID`
                : ''}
            </code>
            <br />
            Append <code className="text-foreground font-mono text-xs">account_id</code> so the
            route knows which account owns this OpenWA instance.
          </p>
        )}
      </div>
    </div>
  );
}
