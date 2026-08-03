# Key Rotation Database Contract

This document describes the database boundary implemented by migration 046. It
is not the operator runbook; deployment and incident procedures remain task 4.8.

## State machine

```text
planned -> awaiting_approval -> approved -> running -> completed -> retired
                 |                 |          |
                 +--------------> blocked <---+
```

- `prepare_key_rotation_run` creates a stable row inventory while operations
  may remain disabled.
- An authenticated account owner or administrator imports row/path ownership
  evidence. A different owner or administrator must approve the latest digest.
- A service-role caller enables operations and starts the approved run.
- Row rotation is atomic and payload-bound. Matching retries return
  `already_applied`; a different replacement payload returns `conflict`.
- Finalization requires expected, visited, and terminal item counts to match and
  every item to be applied.
- Previous-key retirement requires completed current-only aggregate evidence
  while writes are disabled. It starts the 90-day retention clock.
- Purge is rejected before day 90. Eligible purge deletes row/path evidence and
  retains only secret-safe aggregate run and audit data.

## Lock order

Every state-changing RPC follows this transaction-scoped order:

**control → run → item → encrypted row**

The control row is the global barrier. A successful emergency disable therefore
means no rotation can write afterward: in-flight writers finish before disable
returns, and queued writers re-read the disabled state. Run locks serialize
manifest import, approval, start, rotation, finalization, retirement, and purge.
Item locks serialize retries. The final `UPDATE` takes the encrypted-row lock.
No code may acquire these locks in reverse order.

## Security boundary

- Mutation and monitoring RPCs are executable only by `service_role`.
- Manifest import and approval are executable by `authenticated`, then enforce
  account membership and owner/admin role in PostgreSQL.
- `SECURITY DEFINER` functions use a fixed trusted search path. Pgcrypto calls
  resolve explicitly through `extensions.digest`.
- API roles have no direct access to rotation tables. Monitoring uses
  `get_key_rotation_status`, which returns aggregate fields only.
- Errors and audit rows contain reason codes, identifiers, versions, and opaque
  fingerprints only—never plaintext, ciphertext, request bodies, or raw errors.

## Fresh-schema compatibility

Migration 045 historically includes its DOWN section in the same file and drops
`salesforce_config.webhook_secret` after adding it. Because migration 046 has not
been deployed, it explicitly and additively restores that nullable column before
creating any trigger or function that references it. Existing migration history
is not rewritten.

## Verification boundary

CI starts an isolated local Supabase stack, resets it from all migrations, runs
pgTAP contracts, and executes deterministic `dblink` two-session tests. No test
links to or mutates a remote database.
