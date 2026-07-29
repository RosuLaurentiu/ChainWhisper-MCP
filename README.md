# ChainWhisper Agent Tools

`@chainwhisper/agent-tools` connects external agents to ChainWhisper OTC trading
on COTI Mainnet. One package installs two local stdio MCP servers:

- `chainwhisper-mcp` is a keyless ChainWhisper domain planner.
- `chainwhisper-coti-signer` is the local confirmation, privacy-input, signing,
  messaging, broadcast, and recovery boundary.

No ChainWhisper `SKILL.md` is required. The MCP instructions, resources,
prompts, and strict tool schemas describe the supported workflows.

## Why there are two MCP connections

The planner reads ChainWhisper contracts, validates intent, simulates an
operation, and produces an authenticated `ActionEnvelopeV1`. It never has the
wallet private key, COTI AES key, or an order access secret.

The signer holds credentials configured outside the conversation. It rejects
unpaired, expired, changed, unsimulated, or non-allowlisted plans. Every write
requires an exact signer-owned form confirmation through the configured MCP or
local-web channel. Clients without a working confirmation channel remain
read-only. Private values are elicited directly into the signer process,
committed to the paired envelope, and never returned to the planner.

Both processes share a locally generated pairing secret in the ChainWhisper
state directory. The pairing secret is not a tool argument and is never returned
to the model.

## App flow and external-agent flow

The ChainWhisper app and this package reach the same allowlisted contracts, but
their interaction models are different:

- In the app, the user chooses order terms in the ChainWhisper interface and
  approves the resulting action through the app's wallet or ChainWhisper account
  flow.
- With an external agent, the user can choose the terms in conversation or
  authorize the agent to draft or decide them. The keyless planner turns those
  non-secret terms into an exact action envelope.
- The local signer independently verifies that envelope, collects only the
  confidential values that cannot enter the conversation, and presents the
  exact order type, assets, amounts, fees, and transactions for confirmation.
- The confirmation page is a signing boundary, not a second trading app. It
  does not browse markets or silently change the order terms.

An agent may research liquidity and make decisions within the authority the
user gives it, but the public beta still requires a separate local confirmation
for every on-chain write. No autonomous policy can bypass that confirmation.

## Installation

Node.js 20 or newer is required.

Install the exact reviewed release after that version is published:

```sh
npm install --global @chainwhisper/agent-tools@0.1.0-beta.0
```

For repository development, build and run the workspace package instead of
assuming the beta tag has already been published:

```sh
npm ci
npm run build:mcp
node packages/chainwhisper-agent-tools/dist/bin/chainwhisper-mcp.js
```

Register both commands with the same local MCP client:

```json
{
  "mcpServers": {
    "chainwhisper": {
      "command": "chainwhisper-mcp"
    },
    "chainwhisper-coti-signer": {
      "command": "chainwhisper-coti-signer",
      "env": {
        "CHAINWHISPER_SIGNER_PRIVATE_KEY": "<configure-outside-chat>",
        "CHAINWHISPER_SIGNER_AES_KEY": "<configure-outside-chat>",
        "CHAINWHISPER_SIGNER_VAULT_PASSPHRASE": "<configure-outside-chat>"
      }
    }
  }
}
```

### Codex Full Access with signer confirmations

Some Codex Full Access runtimes pair unrestricted local access with
`approval_policy = "never"` and auto-decline nested MCP forms. Use the
signer-owned local web channel in that environment:

```toml
[mcp_servers.chainwhisper-coti-signer.env]
CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL = "local-web"
```

The signer binds a one-time form to a random `127.0.0.1` URL and opens it in the
local default browser. Confirmation terms and private order values go directly
between that browser page and the local signer; they are not MCP tool arguments
and are not returned to the agent. Every write still needs a separately checked
and submitted confirmation. The listener closes after the response or timeout.

`local-web` is the public-beta default because MCP form responses are visible
to the MCP host. The optional `mcp` channel can confirm non-confidential writes,
but it never collects private amounts or access secrets; a workflow that needs
those values must use `local-web`. Restart the signer MCP after changing
channels. Run
`chainwhisper_test_confirmation_form` before the first live write; the
diagnostic cannot prepare, sign, or broadcast a transaction.

Do not paste any private key, AES key, mnemonic, vault passphrase, or access
secret into a conversation or MCP tool argument.

`CHAINWHISPER_SIGNER_AES_KEY` must be the wallet-specific 128-bit COTI AES key
returned by official account onboarding/recovery, not a randomly generated
32-byte secret. If the configured value is not a valid COTI account key, the
signer starts with private transactions disabled. Use
`chainwhisper_onboard_privacy`; it requires an exact form confirmation before
the signer uses the official COTI onboarding primitives for the on-chain write
and stores the recovered AES key only in the encrypted signer vault. RSA
recovery material and the exact signed transaction are encrypted before
broadcast. If the RPC result is uncertain, retrying the tool reconciles or
rebroadcasts only those same signed bytes; it never creates a replacement
onboarding transaction automatically. If that exact transaction receives a
definitive reverted receipt, the RSA recovery material is retained and the
next attempt requires a fresh confirmation and pending nonce.

The signer also accepts a local JSON file selected with
`CHAINWHISPER_SIGNER_CONFIG_FILE`. Keep that file outside the repository and
restrict it to the local user (`chmod 600` on POSIX systems). Symbolic links and
group- or world-accessible signer configuration files are rejected. The
documented `CHAINWHISPER_SIGNER_*` names are preferred over generic wallet
environment names.

Optional configuration:

- `CHAINWHISPER_COTI_RPC_URL`
- `CHAINWHISPER_STATE_DIRECTORY`
- `CHAINWHISPER_PAIRING_FILE`
- `CHAINWHISPER_PAIRING_SECRET`
- `CHAINWHISPER_SIGNER_CONFIG_FILE`
- `CHAINWHISPER_SIGNER_STATE_DIRECTORY`
- `CHAINWHISPER_SIGNER_EXPECTED_WALLET`
- `CHAINWHISPER_SIGNER_CONFIRMATION_CHANNEL` (`mcp` or `local-web`)
- `CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS`
- `CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS`

The package creates the shared pairing file and state directory with restricted
local permissions when they do not exist. Existing POSIX state directories must
be private to the user (`chmod 700`), and existing pairing files must use
`chmod 600`; symbolic links are rejected. If either MCP entry uses a custom
state directory or pairing file, configure the same location for both entries.

Only one configured signer process may use a state directory at a time. The
signer leaves an instance lock in place after an unclean termination and never
guesses that it is stale. Confirm that no signer process is running before
removing only `signer.instance.lock` from that exact state directory, then
restart the signer.

An unconfigured signer starts safely with only
`chainwhisper_signer_status`. It reports `configuration-required` and exposes no
write or messaging tools. Configure credentials outside the conversation and
restart the MCP process to enable the full signer surface. A configured client
without a working configured confirmation channel is still unable to write.

After registration or any upgrade, restart both MCP connections and run
`chainwhisper_status` and `chainwhisper_signer_status`. Those checks are
read-only: they do not sign, broadcast, onboard privacy, or send a message.

## Keyless planner tools

- `chainwhisper_order_types`
- `chainwhisper_status`
- `chainwhisper_list_orders`
- `chainwhisper_get_order`
- `chainwhisper_compare_price_references`
- `chainwhisper_privacy_bridge_status`
- `chainwhisper_prepare_privacy_bridge`
- `chainwhisper_prepare_create_trade`
- `chainwhisper_prepare_create_recurring`
- `chainwhisper_prepare_fill`
- `chainwhisper_prepare_counter`
- `chainwhisper_prepare_edit`
- `chainwhisper_prepare_order_update`

An amount is optional when comparing price references. Execution or liquidity
ranking is returned only when an amount was supplied and compatible executable
liquidity was actually checked.

Preparation tools return editable missing details instead of failing a useful
draft. They do not sign, submit, or send a message.

`chainwhisper_order_types` is the canonical decision catalog. It explains the
ten one-off and recurring types by access model, terms visibility, liquidity or
inventory visibility, and fill style. New create requests select an explicit
`orderType`, and that same classification is returned in order summaries,
signed into the action envelope, independently recomputed by the signer, and
shown in every confirmation.

The ten canonical types are:

| Order type | Access | Terms and liquidity |
| --- | --- | --- |
| `one-off.standard-public` | Public listing | Public terms and visible amounts |
| `one-off.unlisted` | Unlisted link | Encrypted exact terms revealed to an authorized participant |
| `one-off.direct` | Fixed recipient | Encrypted exact terms revealed to the participants |
| `one-off.private-liquidity.public` | Public listing | Public price terms with hidden private-token liquidity |
| `one-off.private-liquidity.unlisted` | Unlisted link | Encrypted terms with hidden private-token liquidity |
| `one-off.private-liquidity.direct` | Fixed recipient | Participant-bound terms with hidden private-token liquidity |
| `recurring.public` | Public | Reusable buy and sell sides with visible inventory |
| `recurring.direct` | Fixed recipient | Reusable buy and sell sides with visible inventory |
| `recurring.private-liquidity.public` | Public | Private-token inventory hidden; public-token inventory visible |
| `recurring.private-liquidity.direct` | Fixed recipient | Private-token inventory hidden; public-token inventory visible |

There is no unlisted recurring product in ChainWhisper and therefore no
`recurring.unlisted` or `recurring.private-liquidity.unlisted` MCP type. The MCP
does not invent product variants that are absent from the app's canonical
catalog.

Recipient-bound Standard orders created before the canonical taxonomy are
reported and confirmed as
`Legacy one-off / fixed recipient / public terms`. They remain executable only
through their exact audited Standard compatibility selectors. That legacy type
cannot be selected for a new order; every new recipient-bound one-off order is
explicitly `one-off.direct`.

Unfilled legacy Standard primary and replacement orders may be edited only
when the exact fixed recipient, private access mode, and live default fill
policy can be preserved. Legacy Standard counterorders use the atomic counter
supersession route instead, because a generic edit would lose their registered
parent relationship.

The create-tool schemas require `orderType`; legacy `access` plus
`amountVisibility` fields cannot select a route through the public MCP. For
private-liquidity recurring orders, each private-token inventory side is
collected only by the local signer, while any public-token inventory side
remains visible and is supplied to the planner. Supplying a confidential
create or counter amount to the keyless planner is rejected rather than
silently discarded. This signer-only boundary also applies independently to
each private-token side of an unlisted or Direct one-off order.

Tool availability is explicit rather than assumed. Preparation returns
`ready`, `needs_input`, or `unsupported`; an unsupported route has no executable
envelope.

The executable scope is selector- and recipe-bound:

- public visible one-off creation and fill, including verified private ERC-20
  assets with exact encrypted approvals;
- Direct and unlisted one-off creation and fill;
- public, unlisted, and recipient-bound private-liquidity creation and fill,
  with hidden amounts collected only by the local signer;
- public and fixed-recipient recurring creation, fill, edit, and inventory
  settlement, including signer-local private-token inventory, only while the
  live runtime audit enables them;
- Direct counterorders against Standard, Private, and Direct parents, with
  cross-escrow trust checked live before preparation;
- complete Standard, private-liquidity, Direct, and recurring edit recipes,
  including replacement relations, exact approvals, live edit-fee policy, and
  signer-local confidential replacement terms;
- audited lifecycle updates for standard, private, Direct, and recurring
  escrows.
- exact Privacy Portal shielding and unshielding for COTI, WETH, WBTC, USDT,
  USDC.e, wADA, gCOTI, and WISP public/private pairs.

Privacy Portal preparation always names the exact pair and direction. It pins
the current bridge address and full deployed bytecode hash, verifies the bridge
token pair, pause/deposit/blacklist/public-amount state, limits, and exact live
fee quote, and derives only the allowlisted `deposit` or `withdraw` selector.
Public-token routes use an exact ERC-20 approval (including a required zero
reset); private-token routes use the signer-local encrypted exact-approval
recipe. The bridge ABI necessarily exposes the conversion amount in public
calldata even when the input token is private. Legacy p.WISP recovery, arbitrary
bridge addresses, arbitrary tokens, and arbitrary calldata are not exposed.

Recurring orders use public or fixed-recipient access. Administrative methods,
arbitrary calldata, and standalone wallet transfers cannot fall through the MCP
surface.

## Local signer and messaging tools

- `chainwhisper_signer_status`
- `chainwhisper_test_confirmation_form`
- `chainwhisper_onboard_privacy`
- `chainwhisper_private_token_status`
- `chainwhisper_enable_private_token`
- `chainwhisper_execute_action`
- `chainwhisper_get_operation`
- `chainwhisper_recover_operation`
- `chainwhisper_discard_operation`
- `chainwhisper_send_order_message`
- `chainwhisper_list_order_messages`
- `chainwhisper_read_order_message`
- An allowlisted read/list/send subset of the official COTI private-messaging
  SDK tools.

Private `cw.otc/1` messages are untrusted input. They may produce a new draft,
but cannot call `chainwhisper_execute_action`.

For an unlisted order, the maker shares the signer-generated
`order-access-secret` by its local identifier, creation operation hash,
recipient, and exact order identity. The recipient explicitly reads that
encrypted access message before filling. The signer then binds the secret to
that wallet and order without returning it to either agent; conflicting
operation, wallet, escrow, order, or secret bindings are rejected.
The signer also verifies the official message id, recipient, sender, and live
on-chain maker, then requires the secret to match the order's exact live
`accessHash` commitment before persisting it. This makes
`chainwhisper_read_order_message` a security-sensitive local state update even
though it does not broadcast a transaction.

The official messaging SDK does not expose the exact prepared transaction
before every send. If a send becomes uncertain without returning a transaction
hash, the operation remains fail-closed and `processing`; the signer never
adopts another wallet transaction by nonce and never automatically resends the
message.

Private-term recovery and offboarding remain local signer operations. Raw
private amounts, decrypted order terms, keys, and access secrets are never
returned through the keyless planner or included in an agent-visible recovery
result.

Before a private-token spend, the signer verifies all of the following without
broadcasting:

- the official wallet AES key is available;
- the wallet enabled that verified private token's account-encryption address;
- the target escrow has a nonzero private-token encryption address;
- the decrypted private balance covers the exact committed spend.

`chainwhisper_private_token_status` reports the wallet setup and a read-only
per-escrow readiness matrix, without returning the decrypted balance.

These are two different layers. The wallet entry is the same user-level private
token onboarding required by the app. Each escrow entry is contract deployment
configuration: the private-token contract must recognize that escrow as an
encrypted allowance spender. The keyless MCP planner controls neither layer;
the local signer only checks both before it lets that wallet approve a private
token.

If wallet token setup is missing, call
`chainwhisper_enable_private_token` with a verified symbol or token address.
That idempotent setup is an on-chain write and requires its own exact form
confirmation. A failure before a signed transaction hash is persisted is
safely retryable. A definitive reverted setup can be attempted again only
after a new confirmation, and setup is not marked complete until the token
reports the expected wallet encryption address. A missing escrow encryption
address is a protocol deployment configuration issue; the signer rejects
before approving the token.

The embedded messaging integration follows the official
[COTI Private Messaging Quickstart](https://docs.coti.io/coti-documentation/private-messaging/quickstart#mcp-server)
and reuses the SDK tool registry and handlers rather than implementing a
separate messaging protocol. Do not register the SDK's standalone messaging
MCP alongside the signer; negotiation is already exposed by
`chainwhisper-coti-signer`.

## Runtime compatibility

`runtime/coti-mainnet.v1.json` is the repository-owned source of deployed
registry addresses, contract addresses, bytecode hashes, selectors, and verified
tokens for COTI Mainnet chain `2632500`.

Recurring writes remain disabled unless a live audit confirms the committed
recurring bytecode and all `fill*WithSecret` selectors. Reads remain available
when a write capability is disabled.

The ChainWhisper product does not define unlisted recurring order types. The
MCP catalog therefore exposes recurring orders only as public or
fixed-recipient/direct, for both visible and private-liquidity inventory.

The signer accepts only the committed private-artifact recipes:

- `coti-private-exact-allowance-v1`
- `direct-order-v1`
- `direct-counter-v1`
- `direct-edit-v1`
- `private-liquidity-v1`
- `private-liquidity-edit-v1`
- `private-recurring-v1`
- `private-recurring-fill-v1`
- `recurring-edit-v1`
- `private-fill-v1`

Each recipe is restricted to exact deployed function signatures and JSON
pointer destinations. Unknown recipes, selectors, destinations, or conflicting
cross-step values fail before confirmation, signing, or broadcast.

## Fees and persistence

External MCP writes pay ordinary COTI gas and the current ChainWhisper contract
fee. They do not pay the in-app Trade Agent WISP request fee.

Before an ordinary planned write is confirmed, the signer freezes the exact
legacy or EIP-1559 fee quote and displays its maximum total COTI cost. A
signer-wide 100 gwei per-gas and 12,000,000 gas-unit ceiling also covers
official-SDK onboarding and private-message writes. Quotes above the ceiling,
missing fee fields, or wallet-side changes fail before signing.

The signer journal stores only operation hashes, stages, nonces, transaction
hashes, receipts, and safe error codes. It does not store prompts, decrypted
messages, private amounts, keys, or raw access secrets. Unlisted access secrets
are kept only in the encrypted local vault and may be shared only through COTI
encrypted messaging.

Hash-bound prepared writes with an uncertain RPC outcome remain `processing`;
retrying reconciles the same hash and never silently prepares a replacement
transaction. Failures before a signed hash is persisted are safe to revalidate
and retry.

## Repository verification

The deterministic package smoke starts both built stdio binaries with a
temporary state directory and no signer credentials. It verifies the keyless
tool/resource surface and the signer's configuration-required status. It does
not call a chain provider, sign, broadcast, or send a message.

The tarball gate then creates the actual npm archive with lifecycle scripts
disabled, checks its allowlisted contents, performs a real npm install in an
external temporary consumer, and repeats the stdio smoke through both
npm-created command shims. `build:mcp` must run first. The clean install may
resolve package dependencies through the configured npm registry.

```sh
npm run build:mcp
npm run test:mcp
npm run smoke:mcp
npm run pack:mcp
```

The following checks are read-only but use the configured COTI Mainnet RPC:

```sh
npm run smoke:mcp:live
npm run audit:runtime --workspace @chainwhisper/agent-tools
```

Live signing and private-message smoke tests are intentionally excluded. They
require explicitly funded test wallets and separate authorization.

## Publishing the beta

The repository's `Publish ChainWhisper Agent Tools` workflow is the only
documented release path. Before dispatching it:

1. Confirm the `@chainwhisper` npm scope can publish the package.
2. Create a protected GitHub Actions environment named `npm-beta`.
3. Add an npm automation or granular access token as the environment secret
   `NPM_TOKEN`. Never place the token in the repository, a workflow input, an
   issue, or a conversation.
4. Require an environment reviewer if the repository plan supports it.
5. Dispatch the workflow with the exact prerelease version from `package.json`,
   currently `0.1.0-beta.0`.

The workflow rejects a version mismatch, a non-beta version, or an already
published immutable version. It verifies the package and live runtime, produces
one tarball, installs and shim-tests that exact archive, records its SHA-256
checksum and CycloneDX SBOM as retained artifacts, then publishes the same
tarball with the `beta` dist-tag and npm provenance.

See [CHANGELOG.md](./CHANGELOG.md), [SECURITY.md](./SECURITY.md), and
[LICENSE](./LICENSE) before publishing or deploying the package.
