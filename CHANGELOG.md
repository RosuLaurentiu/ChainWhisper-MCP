# Changelog

All notable changes to `@chainwhisper/agent-tools` are documented here.

## 0.1.0-beta.0 - 2026-07-29

Initial public beta release candidate.

### Added

- Two paired local stdio MCP servers: the keyless `chainwhisper-mcp` planner and
  the credential-holding `chainwhisper-coti-signer`.
- A canonical catalog of ten executable ChainWhisper order types: six one-off
  types and four recurring types.
- Planning and signer-verified execution for creation, fill, counter, edit,
  lifecycle, and recurring inventory workflows supported by the deployed
  allowlisted contracts.
- COTI Privacy Portal planning and execution for the allowlisted COTI, WETH,
  WBTC, USDT, USDC.e, wADA, gCOTI, and WISP public/private token pairs.
- Private-token onboarding and per-token readiness checks through the local
  signer.
- Integrated `cw.otc/1` negotiation through the official COTI private-messaging
  SDK. No separate messaging MCP or ChainWhisper skill is required.
- MCP and local-web confirmation channels, encrypted local signer state,
  transaction journaling, and recovery tools.
- Durable privacy-onboarding recovery that preserves the RSA material and exact
  signed transaction before broadcast.

### Security

- Wallet private keys, COTI AES keys, vault passphrases, pairing secrets, and
  order access secrets stay outside planner tool arguments.
- Plans are paired, expiring, allowlisted, simulated, independently verified by
  the signer, and explicitly confirmed before each write.
- Confidential order values are collected directly by the signer and are not
  returned to the planner or agent.
- Received private messages are treated as untrusted, draft-only input and
  cannot execute a transaction.
- The signer defaults to its loopback local-web confirmation channel. MCP forms
  never collect confidential amounts or access secrets.
- Confirmations label exact send/receive/private values and show a maximum
  network fee. A signer-wide gas and fee ceiling also covers SDK-managed
  onboarding and private-message writes.
- Ordinary and private-token preparation failures before a signed hash is
  persisted are safely retryable. Hash-bound uncertain writes stay
  `processing` and reconcile only that exact transaction.
- Definitively reverted onboarding and private-token setup writes may be tried
  again only after a fresh confirmation; uncertain onboarding keeps reconciling
  the same signed bytes.
- An uncertain official-SDK message send is never automatically resent or
  identified from a nonce alone, even if the SDK returned no transaction hash.
  A state-directory lock prevents concurrent signer processes from racing
  wallet nonces or encrypted-vault updates.
- Received access secrets are persisted only after the official COTI message
  metadata, live maker, and exact on-chain access commitment all agree.
- Private-artifact recipes must contain the exact outputs required by their
  signed call. Planner input and message traversal have explicit resource
  limits.

### Verification

- The package build and 209-test MCP suite pass on the release-candidate
  working tree; three POSIX-specific checks are skipped on Windows.
- Stdio smoke coverage verifies the planner surface and the unconfigured
  signer's read-only status.
- The npm tarball gate checks allowlisted contents, installs the exact release
  archive into an external clean consumer, and starts both npm-created command
  shims before that same archive can be published.
- CI covers Node.js 20, 22, and 24 on Ubuntu and Node.js 22 on Windows.

### Known beta constraints

- The product has no unlisted recurring order type. Recurring orders use public
  or fixed-recipient access, with visible or private-token inventory.
- Administrative calls, arbitrary calldata, arbitrary token or contract
  addresses, standalone wallet transfers, and legacy p.WISP recovery are
  outside the MCP execution surface.
- Every write requires a separate local user confirmation in this beta, even
  when an agent is authorized to choose or draft order terms autonomously.
- The beta uses a static 100 gwei per-gas safety ceiling. A legitimate fee quote
  above that limit fails closed until a reviewed release changes the policy.
