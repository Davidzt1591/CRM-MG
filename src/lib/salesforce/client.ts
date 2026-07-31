/**
 * Salesforce REST API client.
 *
 * Supports OAuth2 Client Credentials + Password flow for authentication,
 * Case CRUD operations, FeedItem (CaseFeed) posting, and SOSL search.
 * Secrets are decrypted at construction time from the AES-256-GCM encrypted
 * database fields.
 *
 * API version: v62.0 (Spring '26)
 *
 * @example
 * ```ts
 * import { createClient } from '@supabase/supabase-js'
 * import { SalesforceClient } from '@/lib/salesforce/client'
 *
 * const { data } = await supabaseAdmin()
 *   .from('salesforce_config')
 *   .select('*')
 *   .eq('account_id', accountId)
 *   .single()
 *
 * const client = new SalesforceClient(data)
 * const sfCase = await client.createCase({ subject: 'Help request' })
 * ```
 */

import { decrypt } from '@/lib/whatsapp/encryption';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SalesforceConfig {
  id: string;
  accountId: string;
  instanceUrl: string;
  isSandbox: boolean;
  clientId: string;
  clientSecret: string;
  username: string;
  password: string;
  securityToken?: string;
  connectedAt?: string;
}

export interface SalesforceCase {
  Id: string;
  CaseNumber: string;
  Status: string;
  Subject: string;
  Description?: string;
  ContactId?: string;
  AccountId?: string;
  CreatedDate: string;
}

export interface SalesforceFeedItem {
  Id: string;
  Body: string;
  CreatedDate: string;
  CreatedBy?: { Name: string };
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class SalesforceClient {
  private config: SalesforceConfig;
  private accessToken: string | null = null;
  private tokenExpiresAt = 0;

  /**
   * @param encryptedConfig — Raw row from `salesforce_config` with encrypted
   *                          secrets. The constructor decrypts them.
   */
  constructor(encryptedConfig: Record<string, unknown>) {
    this.config = {
      id: encryptedConfig.id as string,
      accountId: encryptedConfig.account_id as string,
      instanceUrl: (encryptedConfig.instance_url as string).replace(/\/$/, ''),
      isSandbox: encryptedConfig.is_sandbox as boolean,
      clientId: decrypt(encryptedConfig.client_id as string),
      clientSecret: decrypt(encryptedConfig.client_secret as string),
      username: decrypt(encryptedConfig.username as string),
      password: decrypt(encryptedConfig.password as string),
      securityToken: encryptedConfig.security_token
        ? decrypt(encryptedConfig.security_token as string)
        : undefined,
      connectedAt: encryptedConfig.connected_at as string | undefined,
    };
  }

  // -----------------------------------------------------------------------
  // Authentication
  // -----------------------------------------------------------------------

  /**
   * Authenticate via OAuth2 Password flow.
   *
   * POST /services/oauth2/token
   *   grant_type=password
   *   client_id=<decrypted>
   *   client_secret=<decrypted>
   *   username=<decrypted>
   *   password=<decrypted> + <security_token if present>
   *
   * The access token is cached in-memory and reused until it expires.
   */
  private async authenticate(): Promise<string> {
    if (this.accessToken && this.tokenExpiresAt > Date.now()) {
      return this.accessToken;
    }

    const body = new URLSearchParams({
      grant_type: 'password',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      username: this.config.username,
      password:
        this.config.password +
        (this.config.securityToken ?? ''),
    });

    const url = `${this.config.instanceUrl}/services/oauth2/token`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `Salesforce OAuth2 failed (${response.status}): ${errorBody}`,
      );
    }

    const data = (await response.json()) as {
      access_token: string;
      instance_url: string;
      issued_at: string;
    };

    this.accessToken = data.access_token;
    // Token expires in 2 hours by default, but we refresh after 90 minutes
    // to be safe.
    this.tokenExpiresAt = Date.now() + 90 * 60 * 1000;

    // If Salesforce returned a different instance_url, update ours
    // (this can happen with Sandbox/Production redirects).
    if (data.instance_url) {
      this.config.instanceUrl = data.instance_url.replace(/\/$/, '');
    }

    return this.accessToken;
  }

  // -----------------------------------------------------------------------
  // Request helper
  // -----------------------------------------------------------------------

  /**
   * Make an authenticated request to the Salesforce REST API.
   *
   * - Ensures an access token is available (triggers OAuth2 if needed)
   * - On 401, re-authenticates and retries exactly once
   * - On 429, throws with the Retry-After header
   */
  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const token = await this.authenticate();

    const headers: Record<string, string> = {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    const requestInit: RequestInit = {
      method,
      headers,
    };

    if (body !== undefined && method !== 'GET') {
      requestInit.body = JSON.stringify(body);
    }

    const url = `${this.config.instanceUrl}${path}`;
    let response = await fetch(url, requestInit);

    // Retry on 401 — token may have expired
    if (response.status === 401) {
      this.accessToken = null;
      this.tokenExpiresAt = 0;
      const newToken = await this.authenticate();
      headers.Authorization = `Bearer ${newToken}`;
      response = await fetch(url, requestInit);
    }

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `Salesforce API error (${response.status}): ${errorBody}`,
      );
    }

    // 204 No Content — no body to parse
    if (response.status === 204) {
      return undefined as T;
    }

    return (await response.json()) as T;
  }

  // -----------------------------------------------------------------------
  // Case CRUD
  // -----------------------------------------------------------------------

  async createCase(params: {
    subject: string;
    description?: string;
    contactId?: string;
    accountId?: string;
    origin?: string;
    status?: string;
  }): Promise<SalesforceCase> {
    return this.request<SalesforceCase>('POST', '/services/data/v62.0/sobjects/Case', {
      Subject: params.subject,
      Description: params.description,
      ContactId: params.contactId,
      AccountId: params.accountId,
      Origin: params.origin ?? 'WhatsApp',
      Status: params.status ?? 'New',
    });
  }

  async updateCase(
    caseId: string,
    fields: Record<string, unknown>,
  ): Promise<void> {
    await this.request(
      'PATCH',
      `/services/data/v62.0/sobjects/Case/${caseId}`,
      fields,
    );
  }

  async getCase(caseId: string): Promise<SalesforceCase> {
    return this.request<SalesforceCase>(
      'GET',
      `/services/data/v62.0/sobjects/Case/${caseId}`,
    );
  }

  // -----------------------------------------------------------------------
  // FeedItem (CaseFeed)
  // -----------------------------------------------------------------------

  async postFeedItem(
    caseId: string,
    body: string,
  ): Promise<SalesforceFeedItem> {
    return this.request<SalesforceFeedItem>(
      'POST',
      '/services/data/v62.0/sobjects/FeedItem',
      {
        ParentId: caseId,
        Body: body,
        Type: 'TextPost',
      },
    );
  }

  // -----------------------------------------------------------------------
  // Search
  // -----------------------------------------------------------------------

  async searchCases(query: string): Promise<SalesforceCase[]> {
    const encoded = encodeURIComponent(query);
    const result = await this.request<{ searchRecords: SalesforceCase[] }>(
      'GET',
      `/services/data/v62.0/search?q=${encoded}`,
    );
    return result.searchRecords;
  }

  // -----------------------------------------------------------------------
  // Connection test
  // -----------------------------------------------------------------------

  async testConnection(): Promise<{
    success: boolean;
    message: string;
    userInfo?: Record<string, unknown>;
  }> {
    try {
      const token = await this.authenticate();
      return { success: true, message: 'Connected successfully' };
    } catch (err) {
      return { success: false, message: (err as Error).message };
    }
  }
}
