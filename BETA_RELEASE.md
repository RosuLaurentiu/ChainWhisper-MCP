# ChainWhisper MCP Public Beta

## Release scope

This repository publishes the external ChainWhisper agent tools:

- `chainwhisper-mcp`, the keyless planner.
- `chainwhisper-coti-signer`, the local credential-holding signer.

They are distributed together as
`@chainwhisper/agent-tools@0.1.0-beta.0`. The separate
[ChainWhisper application](https://github.com/RosuLaurentiu/ChainWhisper)
contains the in-app Agent area and setup interface. External MCP transactions
do not pay the app Trade Agent request fee; they pay normal COTI gas and the
current ChainWhisper contract fee.

## App and external-agent signing flows

The app and external MCP use the same allowlisted ChainWhisper contracts, but
the interaction model is different:

- In the app, a user chooses terms in the ChainWhisper interface and approves
  the resulting action through the app's wallet or ChainWhisper account flow.
- With the MCP, the user may choose terms in conversation or authorize an agent
  to research, draft, and decide them. Public parameters go to the keyless
  planner; confidential values go directly to the local signer.
- The signer independently validates the paired plan, current contracts, fees,
  calldata intent, approvals, and simulation. It then displays the exact order
  type, assets, amounts, transactions, and maximum network cost for local
  confirmation.
- The local-web form is the default signing and confidential-input boundary,
  not a second trading app. It does not browse markets or silently change the
  planned terms. An explicitly selected MCP form can confirm non-confidential
  writes, but MCP form responses never carry private amounts or access secrets.

Every on-chain write requires its own local confirmation in this beta. An agent
may make decisions within the authority a user gives it, but cannot bypass that
confirmation.

## MCP security boundary

- `chainwhisper-mcp` owns protocol reads, order discovery, price references,
  validation, simulation, and authenticated `ActionEnvelopeV1` plans. It never
  receives wallet credentials, COTI AES keys, private order values, or access
  secrets.
- `chainwhisper-coti-signer` owns locally configured credentials, private
  inputs, exact approvals, confirmation, signing, broadcast, transaction
  journaling, recovery, and the encrypted secret vault.
- Both processes share a locally generated pairing secret. The secret is not a
  tool argument and is never returned to an agent.
- The unconfigured signer exposes only `chainwhisper_signer_status`, reports
  `configuration-required`, and performs no network, pairing, signing,
  messaging, or persistence work.
- Preparation reports `ready`, `needs_input`, or `unsupported`. Unsupported
  routes have no executable envelope.
- The deployed COTI Mainnet bytecode and committed runtime manifest are
  authoritative. A live audit can disable a write capability without disabling
  safe reads.
- Received `cw.otc/1` messages are untrusted and draft-only. They cannot execute
  an action.
- Access secrets from messages are persisted only after verifying the official
  message id, recipient, sender, allowlisted order, live on-chain maker, and
  exact on-chain access commitment.
- Ordinary and private-token failures before a signed transaction hash is
  persisted are safely retryable. Once a locally prepared hash may have been
  broadcast, the write remains recoverable or `processing` and the signer
  reconciles only that exact hash.
- A definitive onboarding or private-token setup revert may be retried only
  through a fresh confirmation. An SDK message send with an uncertain outcome
  is never automatically resent, even when the SDK returned no transaction
  hash. A state-directory instance lock prevents concurrent signer processes.
- The signer freezes the network fee before confirmation and applies a 100 gwei
  per-gas and 12,000,000 gas-unit ceiling to all wallet and SDK writes.
- Clients without a working local confirmation channel remain read-only.
  Private-value workflows specifically require the signer-owned local-web
  channel because MCP form responses are visible to the MCP host.

## Canonical order types

`chainwhisper_order_types` exposes exactly ten types. The classification is
selected before creation, included in summaries and plans, independently
recomputed by the signer, and shown in confirmation.

| Order type | Access | Terms and liquidity |
| --- | --- | --- |
| `one-off.standard-public` | Public listing | Public terms and visible amounts |
| `one-off.unlisted` | Unlisted link | Encrypted exact terms |
| `one-off.direct` | Fixed recipient | Participant-bound encrypted exact terms |
| `one-off.private-liquidity.public` | Public listing | Public price terms with hidden private-token liquidity |
| `one-off.private-liquidity.unlisted` | Unlisted link | Encrypted terms with hidden private-token liquidity |
| `one-off.private-liquidity.direct` | Fixed recipient | Participant-bound terms with hidden private-token liquidity |
| `recurring.public` | Public | Reusable buy and sell sides with visible inventory |
| `recurring.direct` | Fixed recipient | Reusable buy and sell sides with visible inventory |
| `recurring.private-liquidity.public` | Public | Private-token inventory hidden; public-token inventory visible |
| `recurring.private-liquidity.direct` | Fixed recipient | Private-token inventory hidden; public-token inventory visible |

ChainWhisper has no unlisted recurring product. The MCP therefore does not
expose `recurring.unlisted` or
`recurring.private-liquidity.unlisted`. Recurring orders use public or
fixed-recipient access.

## Executable beta capabilities

The execution surface is contract-, selector-, and recipe-allowlisted. It
supports:

- creation and fill for public, unlisted, and fixed-recipient one-off orders;
- creation and fill for public, unlisted, and fixed-recipient
  private-liquidity one-off orders;
- public and fixed-recipient recurring creation, fill, edit, and inventory
  settlement, including private-token inventory when the live runtime audit
  enables the route;
- Direct counterorders against supported Standard, Private, and Direct parents,
  with live cross-escrow trust checks;
- supported Standard, private-liquidity, Direct, and recurring edit recipes,
  including exact approvals and signer-local confidential replacement terms;
- allowlisted pause, resume, refresh, extend, cancel, decline, close,
  reclaim-expired, and recurring inventory updates as applicable to the order;
- exact Privacy Portal shielding and unshielding for the COTI, WETH, WBTC,
  USDT, USDC.e, wADA, gCOTI, and WISP public/private pairs;
- official COTI privacy onboarding and verified private-token account setup,
  each with its own exact confirmation;
- structured private order negotiation plus an allowlisted read/list/send
  subset of the official COTI private-messaging SDK.

The signer collects confidential amounts and access values locally. Private
token assets are supported for both visible-amount and private-liquidity
workflows when the wallet, token, escrow, balance, and encrypted approval checks
all pass.

Privacy Portal preparation pins the exact pair, direction, bridge, deployed
bytecode, live state, limits, fee quote, and allowlisted selector. The bridge
ABI necessarily exposes the conversion amount in public calldata, including
when the input token is private.

Administrative calls, arbitrary calldata, arbitrary contract or token
addresses, standalone wallet transfers, and legacy p.WISP recovery remain
outside the MCP execution surface.

## Integrated private messaging

Private negotiation is already part of `chainwhisper-coti-signer` through the
official COTI private-messaging SDK. Do not register the SDK's standalone
messaging MCP, and do not install a separate ChainWhisper skill.

Structured `cw.otc/1` proposal, counter, acceptance, decline, status, and access
messages may create or update a draft, but cannot call
`chainwhisper_execute_action`. Access secrets stay in the encrypted signer
vault and are shared only by local reference through encrypted messaging.

## Readiness and verification gates

- Disconnected in-app Agent guidance opens the existing account connection
  flow.
- Composer availability is derived from shared readiness state.
- Focused Agent tests cover `prompt-needed`, `account-needed`, `ready`,
  `loading`, `retryable`, and `error`.
- Browser coverage includes Agent, wallet, create-order, recurring-order,
  terminal, Privacy Portal, and mobile flows.
- Agent Setup remains free and has no wallet, payment, signature, or WISP side
  effects.
- Package CI runs on Ubuntu with Node.js 20, 22, and 24, and on Windows with
  Node.js 22.
- The package gate builds and tests the MCP, checks the stdio surfaces, creates
  the npm tarball, installs it into an external clean consumer, and starts both
  npm-created command shims.
- Automated release verification does not perform live signing, transaction
  broadcast, privacy onboarding, private-token setup, or private-message writes.
  Those checks require explicit authorization and an intentionally funded
  wallet.

## Verification commands

```sh
npm run lint
npm run build
npm run test
npm run smoke
npm run verify:tarball
npm run smoke:live
npm run audit:runtime
```

The live status and runtime-audit commands are read-only. Do not run funded
signing or messaging diagnostics as part of an ordinary release check.

## Verification record

Standalone extraction verified locally on July 29, 2026:

- Lint and the strict TypeScript build passed.
- The 24-file suite passed: 209 tests passed and three POSIX permission checks
  remained intentionally skipped on Windows.
- The previously timing-sensitive private-messaging suite passed three
  additional focused runs without resource contention.
- The standalone production dependency audit reported zero vulnerabilities.
- The built stdio smoke passed without credentials, writes, signing, or private
  messages.
- The exact npm tarball was inspected, production-audited, installed outside
  the repository, and started through both npm-created command shims.
- The read-only COTI Mainnet audit passed at block `0x8224e2`: every committed
  contract bytecode hash and selector set matched, and recurring writes remained
  enabled.
- The completed security review covered all 83 files in the MCP package
  snapshot. Its release-blocking transaction recovery, fee binding, signer
  concurrency, private-value boundary, artifact verification, and message
  provenance findings were remediated in this hardening change.

The final standalone GitHub CI matrix must attest the release commit before
publication.

## Publishing prerequisites

The manual `Publish ChainWhisper Agent Tools` GitHub Actions workflow is the
documented release path.

Before dispatch:

1. Confirm package ownership and publish access for the `@chainwhisper` npm
   scope.
2. Create a protected GitHub Actions environment named `npm-beta`.
3. Configure an npm automation or granular access token as the environment
   secret `NPM_TOKEN`. Never put the token in the repository, a workflow input,
   an issue, or a conversation.
4. Require an environment reviewer if the repository plan supports it.
5. Confirm CI is green for the exact release commit.
6. Dispatch the workflow with the exact beta version in the package manifest,
   currently `0.1.0-beta.0`.

The workflow rejects a mismatched, non-beta, or previously published immutable
version. It runs release verification, builds one tarball, installs and
shim-tests that exact archive, records its SHA-256 checksum and CycloneDX SBOM,
uploads them as retained evidence, and publishes the same tarball with the
`beta` dist-tag and npm provenance.

## Remaining public-beta gates

- Require every package matrix job to pass on GitHub.
- Review the uploaded tarball, checksum, and SBOM evidence before approving the
  protected `npm-beta` environment.
- Publish the pinned version only after the COTI Mainnet read-only runtime audit
  passes for the release commit.
- Install the published exact version in a clean environment and rerun
  `chainwhisper_status` and `chainwhisper_signer_status` before authorizing any
  funded beta test.

No ChainWhisper app deployment, transaction broadcast, or private-message write
is implied by preparing the npm beta.
