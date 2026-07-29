# Changelog

## 0.1.0-beta.0 - 2026-07-29

Initial public beta release candidate.

### Agent Wallet and Agent Control

- Added safe `wallet-setup-required` startup with
  `chainwhisper_open_control_panel`.
- Added local existing-wallet import and cryptographically secure wallet
  generation with one-time raw-key backup.
- Added selected `.env` support, safe atomic files, state path validation,
  process-over-file precedence, and one-beta legacy JSON migration.
- Removed normal setup requirements for user-supplied privacy and storage
  material; pairing and storage keys are generated internally.
- Namespaced signer state, policies, recovery, and secrets by Agent Wallet.
- Prevented wallet replacement from inheriting legacy AES material or an old
  expected-wallet pin; unbound root-vault privacy keys now require explicit
  privacy re-onboarding.
- Added a persistent ChainWhisper-branded loopback Agent Control page with
  one rotated session, CSRF/replay/origin protections, strict CSP, no remote
  assets, no telemetry, redacted diagnostics, and responsive accessible forms.

### Signing and autonomy

- Changed multi-step writes to one complete logical-action confirmation.
- Added complete technical step digests and post-authorization re-simulation
  with exact fee ceilings.
- Added `AutonomyPolicyV1`, bounded policies up to 30 days, and full audited
  economic autonomy up to 24 hours.
- Added local activation, two explicit full-autonomy acknowledgements, atomic
  budgets, structured policy denials, pause, local resume, and local revoke.
- Added optional `policyId` to planned execution and private-message writes.
- Added `signer-input` and policy-gated `agent-provided` private amount modes.
- Hardened operation discard with exact hash and mandatory local confirmation.

### Protocol surface

- Added the canonical ten ChainWhisper one-off and recurring order types.
- Added create, fill, counter, edit, lifecycle, recurring inventory, Privacy
  Portal, private-token, and structured private-messaging support for the
  audited deployed runtime.
- Embedded the official COTI private-messaging SDK; no separate messaging MCP
  or ChainWhisper skill is needed.
- Added bytecode attestations for ChainWhisper contracts, COTI onboarding,
  verified private tokens, Privacy Portal contracts, and private messaging.

### Release hardening

- Added Node.js 22/24/26 CI on Windows, macOS, and Linux.
- Added CodeQL, dependency review, and Dependabot configuration.
- Split unprivileged evidence building from protected publish-only execution.
- Bound release identity to the exact protected tag, package version, and
  centralized source version.
- Publish the previously built tarball and attach checksum, production SBOM,
  runtime audit, and release notes to a GitHub prerelease.

### Known beta constraints

- The local host is trusted; use a dedicated, minimally funded Agent Wallet.
- There is no unlisted recurring product.
- Privacy Portal conversion amounts are public calldata under the deployed
  bridge interface.
- Wallet replacement requires a signer restart.
- Desktop-local writes and policies are the supported beta deployment model.
