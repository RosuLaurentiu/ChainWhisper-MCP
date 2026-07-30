# ChainWhisper MCP public beta release

This checklist releases the paired planner and signer as
`@chainwhisper/agent-tools@0.1.0-beta.0`.

Publishing the npm package does not deploy the ChainWhisper app and does not
authorize a funded Mainnet transaction.

## Beta boundary

- One keyless planner MCP.
- One local signer MCP with a persistent signer-owned Agent Control page.
- One active Agent Wallet and signer process.
- Manual signing, bounded autonomy up to 30 days, or full audited economic
  autonomy up to 24 hours.
- Desktop-local writes for the first beta. Headless environments are read-only
  unless the signer-owned confirmation/policy surface is available.
- No arbitrary calldata, transfers, contracts, selectors, administration, or
  wallet credentials in MCP schemas.
- Official COTI private messaging is embedded. Do not register its standalone
  MCP.
- A compatible COTI MCP remains an independent companion for generic,
  read-only COTI functions. It never receives the ChainWhisper Agent Wallet
  private key, wallet privacy/AES material, or access secrets.
- ChainWhisper exposes app-economic actions. Trade amounts, prices, and budgets
  may be visible to or chosen by the user's agent. Each confirmation states
  which values are encrypted and which are public under the deployed contract.
  Credentials, pairing and session tokens, and raw access secrets remain
  signer-only.
- The local-host beta boundary is explicit: use a dedicated, minimally funded
  Agent Wallet.

## Repository settings required before tagging

- [ ] Confirm the repository is the standalone ChainWhisper MCP repository.
- [ ] Enable private vulnerability reporting.
- [ ] Enable Dependabot security updates.
- [ ] Enable CodeQL default or the committed CodeQL workflow.
- [ ] Require dependency review on pull requests.
- [ ] Protect `main` and require the complete CI matrix.
- [ ] Protect `v*` tags against deletion and unauthorized creation.
- [ ] Require signed or otherwise reviewed release tags according to the
      organization policy.
- [ ] Create the protected `npm-beta` environment.
- [ ] Require an environment reviewer.
- [ ] Limit deployment branches/tags to protected release tags.

The committed workflows do not replace repository branch, tag, environment, or
vulnerability-reporting settings.

## npm ownership and authentication

- [ ] Verify the maintainer can publish the exact
      `@chainwhisper/agent-tools` package.
- [ ] Do not use an alternate package name or scope.
- [ ] For the first publish only, create a short-lived granular npm token
      restricted to this package and store it as the protected environment
      secret `NPM_TOKEN`.
- [ ] Never place an npm token in source, workflow inputs, issues, logs, or a
      conversation.
- [ ] After the first publish, configure npm trusted publishing for this exact
      repository and workflow environment.
- [ ] Remove `NPM_TOKEN` and revoke the bootstrap token.

The publish job has `id-token: write` for npm provenance and trusted
publishing.

## Source identity

- [ ] `package.json` is `0.1.0-beta.0`.
- [ ] `src/shared/version.ts` is the same version.
- [ ] `CHANGELOG.md` contains the exact version and date.
- [ ] The release commit is reviewed and contained in protected `main`.
- [ ] The exact protected tag is `v0.1.0-beta.0`.
- [ ] No conflicting package with that immutable version exists on npm.

The release workflow rejects a tag/package/source mismatch, a non-beta
version, a tag outside `main`, and a conflicting already-published artifact. If
the exact tarball is already published byte-for-byte, the workflow verifies it
and safely skips republishing.

## Deployed recurring source identity

- [ ] Synchronize the active recurring Solidity source and exported ABI with
      the deployed `WithSecret` fill selectors used by the app, runtime
      manifest, and attested Mainnet bytecode.
- [ ] Reproduce the attested recurring bytecode from the synchronized release
      source or attach equivalent reviewed deployment provenance.

The signer already fails closed against the live bytecode hash and selector
set. This repository drift does not authorize a wrong call, but it must be
resolved before describing the beta contract artifacts as reproducible.

## Local release checks

Run from a clean checkout with Node.js 24:

```sh
npm ci
npm audit signatures
npm run lint
npm run build
npm test
npm run smoke
npm run audit:dependencies
npm run verify:tarball
```

Run the read-only COTI Mainnet checks:

```sh
npm run smoke:live
npm run smoke:live:readonly
npm run audit:runtime
```

Confirm:

- [ ] No test, smoke, or audit signed or broadcast a transaction.
- [ ] The unconfigured signer started in `wallet-setup-required`.
- [ ] `chainwhisper_open_control_panel` returned no URL or token.
- [ ] The exact tarball installed and both npm-created shims started in a clean
      consumer.
- [ ] The production dependency audit reports no advisory.
- [ ] Every ChainWhisper, onboarding, private-token, Privacy Portal, and
      messaging bytecode attestation passed.
- [ ] Planner, configured-signer, and wallet-setup `tools/list` names and input
      schemas exactly match the README allowlists and the locked domain,
      signer-tool, and package-smoke expectations; no extra SDK, setup,
      recovery, credential, or arbitrary-transaction tool is public.

## CI matrix

All nine jobs must pass:

| OS | Node 22 | Node 24 | Node 26 |
| --- | --- | --- | --- |
| Ubuntu | required | required | required |
| Windows | required | required | required |
| macOS | required | required | required |

CI must run lint, strict TypeScript, tests, package smoke, and the appropriate
artifact checks. No skipped platform job may be treated as release evidence.

## Agent Control acceptance

- [ ] Existing-wallet import writes only the selected signer `.env`.
- [ ] Generated wallet uses a cryptographic random source and displays the raw
      key once for backup.
- [ ] First wallet setup activates inside the existing signer process without
      changing its MCP catalog, PID, or Agent Control port.
- [ ] Address, COTI balance, copy actions, and funding instructions are clear.
- [ ] Process environment overrides `.env`; `.env` overrides legacy JSON.
- [ ] Default and custom `.env` paths reload correctly.
- [ ] Unsafe paths, symlinks, junctions, file types, and POSIX permissions fail
      closed.
- [ ] Replacing a wallet requires local action, no pending operation, and no
      active or paused policy.
- [ ] Replacement makes the current signer read-only until restart.
- [ ] Pairing and internal storage keys are generated automatically.
- [ ] No user-facing setup asks for privacy key material or a storage
      passphrase.
- [ ] Privacy onboarding starts from Agent Control and stores recovered
      material internally.
- [ ] Private state, policies, recovery, and access secrets are wallet
      namespaced.
- [ ] One active browser session is enforced and opening another invalidates
      the first.
- [ ] A browser launch counts as opened only after Agent Control receives a
      real local navigation; launch-without-arrival remains retryable and
      preserves the pending card.
- [ ] Bootstrap, cookie, CSRF, Host/Origin, replay, CSP, frame, no-store, body
      limit, and rate-limit tests pass.
- [ ] There are no remote assets, analytics, telemetry, or app configuration.
- [ ] Keyboard, screen-reader labels, focus states, reduced motion, and mobile
      width are checked.

## Signing acceptance

- [ ] A multi-step approval/reset/protocol operation produces exactly one
      confirmation.
- [ ] The order/action type is the primary heading.
- [ ] Send/receive amounts, privacy, price, recurring inventory, recipient,
      expiry, protocol fee, and maximum network cost are understandable.
- [ ] Technical details contain every exact contract, selector, calldata
      digest, gas ceiling, step digest, and operation hash.
- [ ] The button names the complete action and the only alternative is
      **Decline**.
- [ ] Every step is re-attested, revalidated, and re-simulated after approval.
- [ ] Changed calldata or an exceeded fee ceiling requires new authorization.
- [ ] Private trade values can be entered locally or supplied by the agent and
      are shown in the complete action review. Wallet/AES credentials,
      pairing/session tokens, and raw access secrets never enter MCP schemas,
      prompts, results, URLs, logs, or diagnostics.
- [ ] Discard and manual recovery are available only in Agent Control, require
      local authorization, and are absent from the public MCP surface.

## Autonomy acceptance

- [ ] Bounded policy validation covers actions, assets, pairs, order types,
      counterparties, bridge routes, messaging, private-amount disclosure,
      price bands, amounts, fee limits, counts, and duration.
- [ ] Full autonomy requires the dedicated-wallet warning and two explicit
      acknowledgements.
- [ ] Full policies expire in at most 24 hours; bounded policies in at most 30
      days.
- [ ] Policy activation is wallet/chain/manifest bound.
- [ ] A local edit can narrow and never broaden a proposal.
- [ ] Policy editing uses human token/COTI amounts, quote-per-base prices, and
      local date/time; exact atomic values remain in technical details.
- [ ] `policyId` is optional for action and message writes.
- [ ] A mismatch returns a structured denial without a fallback prompt.
- [ ] Bounded activation, resume, and revocation reviews visibly list the
      allowed pairs, full counterparty addresses, Privacy Portal directions,
      and private-messaging recipients.
- [ ] Every Agent Control editor, activation/resume/revocation confirmation,
      and active-policy summary states that enabling
      `agentVisiblePrivateAmounts=true` lets the agent both choose private
      amounts and view policy-scoped private balances, hidden order
      inventory/progress, and participant receipts.
- [ ] Budgets reserve atomically before signing.
- [ ] Concurrent reservations cannot overspend.
- [ ] A pre-sign failure releases; signed, pending, or uncertain writes remain
      consumed.
- [ ] Exact step digests, operation hash, fee ceilings, and policy terms are
      bound to the reservation.
- [ ] Pause is immediate.
- [ ] Resume and revocation require local action.
- [ ] Discard, onboarding, token setup, wallet replacement, policy changes, and
      secret deletion cannot execute autonomously.

## Protocol acceptance

Use deterministic tests for:

- [ ] all eight app-exposed public/private/recurring create routes;
- [ ] all ten canonical classifications, including proof that the two internal
      direct-recipient recurring types are not advertised or creatable;
- [ ] fill, counter, edit, lifecycle, cancel, and recurring inventory routes;
- [ ] public and private amount modes;
- [ ] both Privacy Portal directions for every allowlisted pair;
- [ ] private-token readiness and exact encrypted approval;
- [x] policy-or-local-confirmation-gated private balances, owned hidden
      inventory, recurring progress, and wallet-scoped participant receipts;
- [ ] structured private messaging and untrusted received messages;
- [ ] restart recovery, uncertain broadcast recovery, pause, and revoke.

There is no unlisted recurring product. Do not add one in the MCP catalog.
Privacy Portal amounts are public calldata under the deployed bridge ABI.
For recurring private-liquidity orders, each private-token inventory or budget
side is encrypted on-chain; a public-token side remains visible. Buy and sell
prices remain public order terms. Autonomy policy budgets and price bands stay
only in wallet-scoped local signer state.

## Disposable Mainnet canary

This is a separately authorized release gate. It is never part of ordinary CI.

- [ ] Use a new disposable Agent Wallet with the smallest useful amounts.
- [ ] Record the exact release tarball checksum.
- [ ] Fund only the required COTI and test assets.
- [ ] Import or generate the wallet through Agent Control.
- [ ] Complete privacy onboarding.
- [ ] Enable the required private-token accounts.
- [ ] Complete smallest-value public, private, and recurring order lifecycles.
- [ ] Complete one smallest-value Privacy Portal action in each direction.
- [ ] Send and read one structured encrypted message.
- [ ] Restart and recover exact pending state.
- [ ] Exercise pause and revoke.
- [ ] Remove remaining funds after the canary.
- [ ] Record only public transaction links and secret-safe diagnostics.

## Immutable evidence and publish

Push the exact protected tag. The workflow:

1. checks out that tag with no publish credential;
2. verifies tag, package, and source version identity;
3. installs with `npm ci`;
4. verifies dependency signatures;
5. runs lint, build, tests, smoke, and production audit;
6. builds and clean-installs one exact tarball;
7. writes `runtime-audit.json`, `SHA256SUMS`, production-only
   `sbom.cdx.json`, and `RELEASE_NOTES.md`;
8. uploads the immutable evidence artifact;
9. waits at protected `npm-beta`;
10. downloads and re-verifies the same evidence;
11. publishes the already-built tarball with the `beta` tag and provenance;
12. verifies the registry version; and
13. creates a GitHub prerelease with the tarball, checksum, SBOM, runtime
    audit, and release notes.

Do not rebuild inside the publish job.

## Post-publish

- [ ] Install the exact published version into a clean machine.
- [ ] Register both stdio commands.
- [ ] Restart the MCP connections.
- [ ] Run only `chainwhisper_status` and `chainwhisper_signer_status`.
- [ ] Compare the installed tarball checksum with the GitHub prerelease.
- [ ] Confirm npm provenance and the `beta` dist-tag.
- [ ] Configure trusted publishing and revoke the first-publish token.
- [ ] Publish the release notes and beta security boundary.
