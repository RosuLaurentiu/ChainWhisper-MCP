# Changelog

## 0.1.0-beta.0 - 2026-08-08

Initial public beta release candidate.

### Agent Wallet and Agent Control

- Added safe `wallet-setup-required` startup with
  `chainwhisper_open_control_panel`.
- Added local existing-wallet import and cryptographically secure wallet
  generation with one-time raw-key backup.
- Kept one public signer tool catalog from startup and activated the first
  configured wallet in-process without reconnecting MCP or Agent Control.
- Added selected `.env` support, safe atomic files, state path validation,
  process-over-file precedence, and one-beta legacy JSON migration.
- Removed normal setup requirements for user-supplied privacy and storage
  material; pairing and storage keys are generated internally.
- Namespaced signer state, policies, recovery, and secrets by Agent Wallet.
- Prevented wallet replacement from inheriting legacy AES material or an old
  expected-wallet pin; unbound root-vault privacy keys now require explicit
  privacy re-onboarding.
- Added a persistent ChainWhisper-branded loopback Agent Control page with
  one rotated session, bounded one-use CSRF tokens across concurrent reloads,
  replay/origin protections, strict CSP, no remote assets, no telemetry,
  redacted diagnostics, responsive accessible forms, authenticated
  same-origin event-stream presence, active-tab reuse, one replacement after a
  closed-tab grace period, and authenticated-page arrival checks.
- Rebuilt configured-wallet Agent Control as a compact operational dashboard:
  wallet and signer status, verified-asset balances, agent mode, five recent
  activity entries, and collapsed wallet settings and diagnostics.
- Added cached local balance reads for native COTI, public ERC-20 assets, and
  locally decrypted prepared private tokens, with concurrent refresh
  deduplication, partial-failure stale values, exact-amount disclosure, and
  contextual private-token preparation.
- Kept decrypted balances local to the authenticated dashboard and out of MCP
  status, prompts, logs, diagnostics, and page refresh keys.
- Made successful privacy onboarding invalidate and refresh all verified
  private-token balance rows immediately. Standard EOAs treat a zero
  encryption-address mapping as wallet-ready; only foreign mappings or
  unsupported wallet configurations need token-specific recovery.
- Added merged Agent Control activity from the encrypted local journal and the
  wallet-wide attested ChainWhisper history reader, with five recent entries,
  twenty-entry pagination, order/transaction links, deduplication, and local
  exact-term snapshots.
- Kept the dashboard mounted while desktop confirmations open in a focused
  side panel and mobile confirmations use a full-width review sheet. Setup,
  signing, broadcasting, confirming, completion, and failure update in place
  without full-page reloads.
- Added structured allowlisted Agent Control diagnostic codes to signer status
  so agents can distinguish setup progress and safe failures without receiving
  local error text or secrets.
- Fixed real-browser Agent Control submissions by preserving the selected
  action before disabling buttons and using an authenticated-page referrer
  policy that lets Chrome provide the exact same-origin value required by the
  signer.
- Serialized signer-state reads and atomic replacements, with bounded retries
  for transient Windows file locks, so concurrent autonomy and status polling
  cannot misclassify a valid operation as a transaction failure.

### Signing and autonomy

- Changed multi-step writes to one complete logical-action confirmation.
- Added structured compact order reviews with pair, action, recurring/private/
  access badges, sell inventory, buy budget, prices and market offsets, readable
  reference time, protocol fee, maximum network cost, and closed technical
  details.
- Added complete technical step digests, per-step fee ceilings, and fresh
  full-action materialization before autonomous retry or restart signing.
- Added `AutonomyPolicyV1`, bounded policies up to 30 days, and full audited
  economic autonomy up to 24 hours.
- Added local activation, two explicit full-autonomy acknowledgements, atomic
  budgets, structured policy denials, pause, local resume, and local revoke.
- Added optional `policyId` to planned execution and private-message writes.
- Added `signer-input` and policy-gated `agent-provided` private amount modes.
- Added one policy-or-local-confirmation-gated private-state tool for verified
  private balances, owned hidden inventory, recurring progress, and
  wallet-scoped fill receipts.
- Defined `agentVisiblePrivateAmounts` as one explicit policy-wide consent for
  both choosing private amounts and viewing policy-scoped private balances,
  hidden order inventory/progress, and participant receipts, with the combined
  authority shown throughout Agent Control.
- Hardened operation discard with exact hash and mandatory local confirmation.
- Changed action execution to a durable asynchronous queue with safe semantic
  operation polling and signer-restart restoration, including exact-hash
  private-message receipt recovery.
- Bound fill policy scope to the verified source maker rather than the fill
  recipient.
- Added verified create-event decoding so completed Standard, Direct,
  private-liquidity, and recurring operations return their canonical order
  handle, status, and ChainWhisper app link.
- Reduced the public signer surface to ChainWhisper execution, status,
  gated wallet-scoped private reads, autonomy request/pause, and structured
  `cw.otc/1` negotiation. Privacy setup, token setup, resume, revoke, discard,
  and manual recovery remain local to Agent Control.

### Protocol surface

- Added the canonical ten ChainWhisper one-off and recurring order types.
- Made create tools derive the canonical type from economic intent and kept
  direct-recipient recurring creation internal until it exists in the app.
- Added best-single-visible-order Swap preparation and exact or
  market-offset recurring prices.
- Added create, fill, counter, edit, lifecycle, recurring inventory, Privacy
  Portal, private-token, and structured private-messaging support for the
  audited deployed runtime.
- Embedded the official COTI private-messaging SDK; no separate messaging MCP
  or ChainWhisper skill is needed.
- Stopped republishing the SDK's seven generic COTI messaging tools.
- Added bytecode attestations for ChainWhisper contracts, COTI onboarding,
  verified private tokens, Privacy Portal contracts, and private messaging.

### Release hardening

- Added Node.js 22/24/26 CI on Windows, macOS, and Linux.
- Added CodeQL, dependency review, and Dependabot configuration.
- Replaced activity formatting and explorer URL regular expressions with
  linear parsing after CodeQL identified denial-of-service risk, and made
  concurrent wallet-history coalescing deterministic across slower filesystems.
- Split unprivileged evidence building from protected publish-only execution.
- Bound release identity to the exact protected tag, package version, and
  centralized source version.
- Added exact-source Solidity reproduction for the deployed recurring
  contract, including compiler input, creation-bytecode, runtime, ABI, and
  selector evidence.
- Overrode the Solidity compiler's legacy temporary-file helper with the
  patched compatible release used by the evidence build.
- Publish the previously built tarball and attach checksum, production SBOM,
  runtime audit, contract provenance, and release notes to a GitHub
  prerelease.

### Known beta constraints

- The local host is trusted; use a dedicated, minimally funded Agent Wallet.
- There is no unlisted recurring product.
- Privacy Portal conversion amounts are public calldata under the deployed
  bridge interface.
- Wallet replacement requires a signer restart.
- Desktop-local writes and policies are the supported beta deployment model.
