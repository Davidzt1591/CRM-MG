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
- A service-role caller enables operations and starts an approved `apply` run.
  Read-only `dry_run` can start without a manifest; `final_audit` requires
  approved current-only evidence unless the account has zero inventory.
- Row rotation is atomic and payload-bound. Matching retries return
  `already_applied`; a different replacement payload returns `conflict`.
- Finalization reacquires the account write barrier and reconciles the snapshot
  against actual encrypted rows. Apply requires every item to be applied;
  read-only modes validate metadata without issuing encrypted-table updates.
- Previous-key retirement requires completed current-only aggregate evidence
  while writes are disabled. It starts the 90-day retention clock.
- Purge is rejected before day 90. Eligible purge deletes row/path evidence and
  retains only secret-safe aggregate run and audit data.

## Lock order

Every state-changing RPC follows this transaction-scoped order:

**control → account barrier → run → item → encrypted row**

The control row serializes emergency state changes. An account-scoped advisory
lock is the secret-write barrier. Insert, update, and delete triggers acquire it
only for allow-listed encrypted values; unrelated JSONB properties do not
acquire it. Deleting an encrypted row acquires the barrier for the row's
account, and moving an encrypted row to another account acquires both account
locks in sorted, deterministic order so transfers can never deadlock or race a
rotation of either account. Preparation, rotation, finalization, and retirement
acquire it before run/item locks. Run locks serialize lifecycle changes, item
locks serialize retries, and the final `UPDATE` takes the encrypted-row lock.
Every state-changing RPC bounds the whole mutating transaction with an
eight-second lock timeout and a thirty-second statement timeout, so emergency
disable and its peers always fail fast and recoverably instead of parking on a
blocked peer. CI concurrency sessions additionally use bounded statement
timeouts. No code may acquire these locks in reverse order.

## Mode contract

- `rotate_encrypted_row` accepts only a locked `apply` run in `running` state.
- `dry_run` and `final_audit` are encrypted-table read-only. Their lifecycle
  updates only secret-free rotation evidence and aggregate counters.
- The legacy CLI's `--apply` path is deliberately disabled in this child. Child
  2 may re-enable apply only through lifecycle RPC orchestration; direct
  PostgREST table updates must not return.
- Replacement ciphertext has a named maximum of 16 KiB. Larger values are
  rejected without entering audit data.

## Security boundary

- Mutation and monitoring RPCs are executable only by `service_role`.
- Manifest import and approval are executable by `authenticated`, then enforce
  account membership and owner/admin role in PostgreSQL.
- `SECURITY DEFINER` functions use a fixed trusted search path. Pgcrypto calls
  resolve explicitly through `extensions.digest`.
- API roles have no direct access to rotation tables. Monitoring uses
  `get_key_rotation_status`, `list_active_key_rotation_runs`, and
  `get_key_rotation_audit_summary`, which return aggregate fields only. The
  contract exposes lifecycle age, stuck-run classification, error counts/rates,
  last event time, and waiting advisory-lock count.
- Errors and audit rows contain reason codes, identifiers, versions, and opaque
  fingerprints only—never plaintext, ciphertext, request bodies, or raw errors.

## Fresh-schema compatibility

Migration 045 historically includes its DOWN section in the same file and drops
`salesforce_config.webhook_secret` after adding it. Because migration 046 has not
been deployed, it explicitly and additively restores that nullable column before
creating any trigger or function that references it. Existing migration history
is not rewritten.

Migration 046 is still unshipped, so corrective commits update that migration to
preserve a valid fresh-checkout sequence. Once deployed, this file becomes
immutable and every later correction must use a new additive migration.

## Recovery contract

- An early finalization failure returns a secret-safe reason and leaves the run
  `running`; operators can remediate missing/conflicting evidence and retry.
- Identical canonical manifest imports return the existing revision and preserve
  its approval. Only changed canonical evidence creates a revision and requires
  new approval.
- Applied replay runs before any terminal-state rejection and revalidates
  current row metadata. A changed row is a conflict, never `already_applied`;
  a matching replay returns `already_applied` even after the run has left the
  `running`/`apply` state.
- Empty accounts can prepare, start, and finalize read-only runs entirely through
  public RPCs without inserting internal evidence rows.
- Monitoring discovers active/stuck runs and aggregate failures; detailed
  backup, deployment, alert thresholds, and incident procedures remain task 4.8.

## Verification boundary

CI starts an isolated local Supabase stack, resets it from all migrations, runs
pgTAP contracts, and executes deterministic `dblink` two-session tests. No test
links to or mutates a remote database.
