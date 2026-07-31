'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { toast } from 'sonner';
import {
  Eye,
  EyeOff,
  CheckCircle2,
  XCircle,
  Loader2,
  Zap,
  ExternalLink,
} from 'lucide-react';
import { createClient } from '@/lib/supabase/client';
import { useAuth } from '@/hooks/use-auth';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from '@/components/ui/accordion';

const MASKED_TOKEN = '••••••••••••••••';

type ConnectionStatus = 'connected' | 'disconnected' | 'unknown';

interface SalesforceConfigData {
  id?: string;
  account_id?: string;
  instance_url?: string;
  is_sandbox?: boolean;
  client_id?: string;
  client_secret?: string;
  username?: string;
  password?: string;
  security_token?: string;
  webhook_secret?: string;
  connected_at?: string;
  last_test_at?: string;
}

export function SalesforceConfigPanel() {
  const supabase = createClient();
  const { user, accountId, loading: authLoading, profileLoading } = useAuth();

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [config, setConfig] = useState<SalesforceConfigData | null>(null);
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>('unknown');
  const [statusMessage, setStatusMessage] = useState('');

  // Form fields
  const [instanceUrl, setInstanceUrl] = useState('');
  const [isSandbox, setIsSandbox] = useState(true);
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [securityToken, setSecurityToken] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');

  // Show/hide secret fields
  const [showClientSecret, setShowClientSecret] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showSecurityToken, setShowSecurityToken] = useState(false);

  // Track which fields have been edited
  const [edited, setEdited] = useState<Record<string, boolean>>({});
  const loadedAccountIdRef = useRef<string | null>(null);

  const markEdited = (field: string) =>
    setEdited((prev) => ({ ...prev, [field]: true }));

  const fetchConfig = useCallback(
    async (acctId: string) => {
      setLoading(true);
      try {
        const res = await fetch('/api/admin/salesforce');
        const data = await res.json();

        if (data.config) {
          const c = data.config as SalesforceConfigData;
          setConfig(c);
          setInstanceUrl(c.instance_url ?? '');
          setIsSandbox(c.is_sandbox ?? true);
          setClientId(c.client_id ?? MASKED_TOKEN);
          setClientSecret(c.client_secret ?? MASKED_TOKEN);
          setUsername(c.username ?? MASKED_TOKEN);
          setPassword(c.password ?? MASKED_TOKEN);
          setSecurityToken(c.security_token ?? '');
          setWebhookSecret(c.webhook_secret ?? '');
          setConnectionStatus('unknown');
          setEdited({});
        } else {
          setConfig(null);
          setInstanceUrl('');
          setIsSandbox(true);
          setClientId('');
          setClientSecret('');
          setUsername('');
          setPassword('');
          setSecurityToken('');
          setWebhookSecret('');
          setConnectionStatus('unknown');
          setEdited({});
        }
      } catch (err) {
        console.error('Failed to load Salesforce config:', err);
        toast.error('Failed to load Salesforce configuration');
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  useEffect(() => {
    if (authLoading || profileLoading) return;
    if (!user || !accountId) {
      loadedAccountIdRef.current = null;
      setLoading(false);
      return;
    }
    if (loadedAccountIdRef.current === accountId) return;
    loadedAccountIdRef.current = accountId;
    fetchConfig(accountId);
  }, [authLoading, profileLoading, user?.id, accountId, fetchConfig]);

  function isFieldMasked(value: string): boolean {
    return value === MASKED_TOKEN;
  }

  function getFieldValue(field: string, currentValue: string): string {
    if (edited[field] && !isFieldMasked(currentValue)) return currentValue;
    if (isFieldMasked(currentValue)) return '';
    return currentValue;
  }

  async function handleSave() {
    if (!instanceUrl.trim()) {
      toast.error('Instance URL is required');
      return;
    }

    try {
      setSaving(true);

      const payload: Record<string, unknown> = {
        instance_url: instanceUrl.trim(),
        is_sandbox: isSandbox,
      };

      // Only send fields that have been edited, or if no config exists
      if (!config || edited.client_id) payload.client_id = clientId;
      else payload.client_id = MASKED_TOKEN;

      if (!config || edited.client_secret)
        payload.client_secret = clientSecret;
      else payload.client_secret = MASKED_TOKEN;

      if (!config || edited.username) payload.username = username;
      else payload.username = MASKED_TOKEN;

      if (!config || edited.password) payload.password = password;
      else payload.password = MASKED_TOKEN;

      if (!config || edited.security_token)
        payload.security_token = securityToken || MASKED_TOKEN;
      else payload.security_token = MASKED_TOKEN;

      if (!config || edited.webhook_secret)
        payload.webhook_secret = webhookSecret || MASKED_TOKEN;
      else payload.webhook_secret = MASKED_TOKEN;

      const res = await fetch('/api/admin/salesforce', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();

      if (!res.ok) {
        toast.error(data.error || 'Failed to save configuration');
        return;
      }

      toast.success('Salesforce configuration saved');
      if (accountId) await fetchConfig(accountId);
    } catch (err) {
      console.error('Save error:', err);
      toast.error('Failed to save configuration');
    } finally {
      setSaving(false);
    }
  }

  async function handleTestConnection() {
    try {
      setTesting(true);
      const res = await fetch('/api/admin/salesforce/test', {
        method: 'POST',
      });
      const data = await res.json();

      if (data.success) {
        setConnectionStatus('connected');
        setStatusMessage(data.message || '');
        toast.success(
          data.userInfo
            ? `Connected as ${data.userInfo.username ?? 'unknown'}`
            : 'Connection successful',
        );
      } else {
        setConnectionStatus('disconnected');
        setStatusMessage(data.message || 'Connection failed');
        toast.error(data.message || 'Connection test failed');
      }
    } catch (err) {
      console.error('Test connection error:', err);
      setConnectionStatus('disconnected');
      setStatusMessage('Connection test failed. Check network and try again.');
      toast.error('Connection test failed');
    } finally {
      setTesting(false);
    }
  }

  // Helper to render a masked secret input
  function renderSecretField({
    id,
    label,
    value,
    onChange,
    show,
    onToggleShow,
    placeholder,
    hint,
  }: {
    id: string;
    label: string;
    value: string;
    onChange: (v: string) => void;
    show: boolean;
    onToggleShow: () => void;
    placeholder: string;
    hint?: string;
  }) {
    const isMasked = isFieldMasked(value) && !edited[id];
    return (
      <div className="space-y-2">
        <Label htmlFor={id} className="text-muted-foreground">
          {label}
        </Label>
        <div className="relative">
          <Input
            id={id}
            type={show ? 'text' : 'password'}
            placeholder={placeholder}
            value={isMasked ? MASKED_TOKEN : value}
            onChange={(e) => {
              onChange(e.target.value);
              markEdited(id);
            }}
            onFocus={() => {
              if (isFieldMasked(value)) {
                onChange('');
                markEdited(id);
              }
            }}
            className="bg-muted border-border text-foreground placeholder:text-muted-foreground pr-10"
          />
          <button
            type="button"
            onClick={onToggleShow}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
          >
            {show ? (
              <EyeOff className="size-4" />
            ) : (
              <Eye className="size-4" />
            )}
          </button>
        </div>
        {isMasked && !edited[id] && (
          <p className="text-xs text-muted-foreground">
            Stored value is hidden. Focus the field to change it.
          </p>
        )}
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
    );
  }

  if (loading) {
    return (
      <section className="animate-in fade-in-50 duration-200">
        <div className="flex items-center justify-center py-12">
          <Loader2 className="size-6 animate-spin text-primary" />
        </div>
      </section>
    );
  }

  return (
    <section className="animate-in fade-in-50 duration-200">
      <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
        {/* Main config form */}
        <div className="space-y-6">
          {/* Connection Status */}
          <Alert className="bg-card border-border">
            <div className="flex items-center gap-2">
              {connectionStatus === 'connected' ? (
                <CheckCircle2 className="size-4 text-primary" />
              ) : (
                <XCircle className="size-4 text-red-500" />
              )}
              <AlertTitle className="text-foreground mb-0">
                {connectionStatus === 'connected'
                  ? 'Connected to Salesforce'
                  : connectionStatus === 'unknown'
                    ? 'Not tested'
                    : 'Disconnected'}
              </AlertTitle>
            </div>
            <AlertDescription className="text-muted-foreground">
              {connectionStatus === 'connected'
                ? 'Salesforce API connection verified'
                : statusMessage || 'Configure your credentials and test the connection'}
            </AlertDescription>
          </Alert>

          {/* Instance Settings */}
          <Card>
            <CardHeader>
              <CardTitle className="text-foreground">
                Salesforce Instance
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                Configure your Salesforce org connection
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label
                  htmlFor="instance-url"
                  className="text-muted-foreground"
                >
                  Instance URL <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="instance-url"
                  placeholder="https://your-domain.my.salesforce.com"
                  value={instanceUrl}
                  onChange={(e) => setInstanceUrl(e.target.value)}
                  className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
                />
              </div>

              <div className="flex items-center gap-3">
                <Switch
                  id="sandbox-toggle"
                  checked={isSandbox}
                  onCheckedChange={setIsSandbox}
                />
                <Label
                  htmlFor="sandbox-toggle"
                  className="text-muted-foreground cursor-pointer"
                >
                  Sandbox environment
                </Label>
              </div>
            </CardContent>
          </Card>

          {/* API Credentials */}
          <Card>
            <CardHeader>
              <CardTitle className="text-foreground">
                API Credentials
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                Connected App OAuth2 credentials. All secrets are encrypted at
                rest.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="client-id" className="text-muted-foreground">
                  Client ID
                </Label>
                <Input
                  id="client-id"
                  placeholder="e.g. 3MVG9..."
                  value={
                    isFieldMasked(clientId) && !edited.client_id
                      ? MASKED_TOKEN
                      : clientId
                  }
                  onChange={(e) => {
                    setClientId(e.target.value);
                    markEdited('client_id');
                  }}
                  onFocus={() => {
                    if (isFieldMasked(clientId)) {
                      setClientId('');
                      markEdited('client_id');
                    }
                  }}
                  className="bg-muted border-border text-foreground placeholder:text-muted-foreground"
                />
              </div>

              {renderSecretField({
                id: 'client-secret',
                label: 'Client Secret',
                value: clientSecret,
                onChange: setClientSecret,
                show: showClientSecret,
                onToggleShow: () => setShowClientSecret(!showClientSecret),
                placeholder: 'e.g. **********************************',
              })}

              {renderSecretField({
                id: 'username',
                label: 'Username',
                value: username,
                onChange: setUsername,
                show: true,
                onToggleShow: () => {},
                placeholder: 'admin@example.com',
              })}

              {renderSecretField({
                id: 'password',
                label: 'Password',
                value: password,
                onChange: setPassword,
                show: showPassword,
                onToggleShow: () => setShowPassword(!showPassword),
                placeholder: 'Your Salesforce password',
              })}

              {renderSecretField({
                id: 'security-token',
                label: 'Security Token',
                value: securityToken,
                onChange: setSecurityToken,
                show: showSecurityToken,
                onToggleShow: () =>
                  setShowSecurityToken(!showSecurityToken),
                placeholder: 'Optional — e.g. ************',
                hint: 'Only required if your IP is not on Salesforce Trusted IP Ranges',
              })}

              {renderSecretField({
                id: 'webhook-secret',
                label: 'Webhook Secret',
                value: webhookSecret,
                onChange: setWebhookSecret,
                show: true,
                onToggleShow: () => {},
                placeholder: 'Shared secret for HMAC verification',
                hint: 'Used to verify Salesforce CDC webhook signatures',
              })}
            </CardContent>
          </Card>

          {/* Webhook URL */}
          <Card>
            <CardHeader>
              <CardTitle className="text-foreground">
                Webhook Configuration
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                Register this URL in Salesforce Change Data Capture for Case
                events
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              <Label className="text-muted-foreground">
                Salesforce Webhook URL
              </Label>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={
                    accountId
                      ? `${typeof window !== 'undefined' ? window.location.origin : ''}/api/webhooks/salesforce?account_id=${accountId}`
                      : 'Loading...'
                  }
                  className="bg-muted border-border text-muted-foreground font-mono text-sm"
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => {
                    const url = accountId
                      ? `${window.location.origin}/api/webhooks/salesforce?account_id=${accountId}`
                      : '';
                    navigator.clipboard.writeText(url);
                    toast.success('Webhook URL copied to clipboard');
                  }}
                  className="shrink-0 border-border text-muted-foreground hover:text-foreground hover:bg-muted"
                >
                  <ExternalLink className="size-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Include the <code>account_id</code> query parameter so the
                webhook knows which organization the event belongs to.
              </p>
            </CardContent>
          </Card>

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3">
            <Button
              onClick={handleSave}
              disabled={saving}
              className="bg-primary hover:bg-primary/90 text-primary-foreground"
            >
              {saving ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Saving...
                </>
              ) : (
                'Save Configuration'
              )}
            </Button>
            <Button
              variant="outline"
              onClick={handleTestConnection}
              disabled={testing || !config}
              className="border-border text-muted-foreground hover:text-foreground hover:bg-muted"
            >
              {testing ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Testing...
                </>
              ) : (
                <>
                  <Zap className="size-4" />
                  Test Connection
                </>
              )}
            </Button>
          </div>
        </div>

        {/* Setup Instructions Sidebar */}
        <div>
          <Card>
            <CardHeader>
              <CardTitle className="text-foreground text-base">
                Setup Instructions
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                How to connect MagnetoCRM to Salesforce
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Accordion>
                <AccordionItem className="border-border">
                  <AccordionTrigger className="text-muted-foreground hover:text-foreground hover:no-underline">
                    <span className="flex items-center gap-2">
                      <span className="flex size-5 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
                        1
                      </span>
                      Create a Connected App
                    </span>
                  </AccordionTrigger>
                  <AccordionContent className="text-muted-foreground">
                    <ol className="list-decimal list-inside space-y-1 text-sm">
                      <li>
                        In Salesforce Setup, search for &quot;App
                        Manager&quot;
                      </li>
                      <li>
                        Create a new Connected App with OAuth2 settings
                      </li>
                      <li>
                        Enable OAuth2 Password flow (Resource Owner
                        Password Credentials)
                      </li>
                      <li>
                        Copy the Consumer Key (Client ID) and Consumer
                        Secret (Client Secret)
                      </li>
                    </ol>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem className="border-border">
                  <AccordionTrigger className="text-muted-foreground hover:text-foreground hover:no-underline">
                    <span className="flex items-center gap-2">
                      <span className="flex size-5 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
                        2
                      </span>
                      Get your credentials
                    </span>
                  </AccordionTrigger>
                  <AccordionContent className="text-muted-foreground">
                    <ol className="list-decimal list-inside space-y-1 text-sm">
                      <li>Use your Salesforce username (email)</li>
                      <li>
                        Use your Salesforce password (not SSO)
                      </li>
                      <li>
                        Get your Security Token from Setup → My
                        Personal Information → Reset My Security Token
                      </li>
                    </ol>
                  </AccordionContent>
                </AccordionItem>

                <AccordionItem className="border-border">
                  <AccordionTrigger className="text-muted-foreground hover:text-foreground hover:no-underline">
                    <span className="flex items-center gap-2">
                      <span className="flex size-5 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
                        3
                      </span>
                      Configure CDC
                    </span>
                  </AccordionTrigger>
                  <AccordionContent className="text-muted-foreground">
                    <ol className="list-decimal list-inside space-y-1 text-sm">
                      <li>
                        In Salesforce Setup, search for &quot;Change Data
                        Capture&quot;
                      </li>
                      <li>Enable CDC for the Case object</li>
                      <li>
                        Register the webhook URL shown above as a
                        notification endpoint
                      </li>
                      <li>
                        Set the webhook secret and include it in the
                        <code> x-salesforce-signature</code> header
                      </li>
                    </ol>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>

              <div className="mt-4 pt-4 border-t border-border">
                <a
                  href="https://developer.salesforce.com/docs/atlas.en-us.change_data_capture.meta/change_data_capture/cdc_setup.htm"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-sm text-primary hover:text-primary/80 transition-colors"
                >
                  <ExternalLink className="size-3.5" />
                  Salesforce CDC Docs
                </a>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}
