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
requires MCP form elicitation. Clients without elicitation remain read-only.
Private values are elicited directly into the signer process, committed to the
paired envelope, and never returned to the planner.

Both processes share a locally generated pairing secret in the ChainWhisper
state directory. The pairing secret is not a tool argument and is never returned
to the model.

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

`mcp` remains the default channel for clients that reliably surface MCP
elicitation. Restart the signer MCP after changing channels. Run
`chainwhisper_test_confirmation_form` before the first live write; the
diagnostic cannot prepare, sign, or broadcast a transaction.

Do not paste any private key, AES key, mnemonic, vault passphrase, or access
secret into a conversation or MCP tool argument.

`CHAINWHISPER_SIGNER_AES_KEY` must be the wallet-specific 128-bit COTI AES key
returned by official account onboarding/recovery, not a randomly generated
32-byte secret. If the configured value is not a valid COTI account key, the
signer starts with private transactions disabled. Use
`chainwhisper_onboard_privacy`; it requires an exact form confirmation before
the official SDK performs an on-chain onboarding write and stores the recovered
AES key only in the encrypted signer vault.

The signer also accepts a local JSON file selected with
`CHAINWHISPER_SIGNER_CONFIG_FILE`. Keep that file outside the repository and
restrict it to the local user. The documented `CHAINWHISPER_SIGNER_*` names are
preferred over generic wallet environment names.

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
local permissions when they do not exist. If either MCP entry uses a custom
state directory or pairing file, configure the same location for both entries.

An unconfigured signer starts safely with only
`chainwhisper_signer_status`. It reports `configuration-required` and exposes no
write or messaging tools. Configure credentials outside the conversation and
restart the MCP process to enable the full signer surface. A configured client
without MCP form elicitation is still unable to write.

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

`chainwhisper_order_types` is the canonical decision catalog. It explains all
10 one-off and recurring types by access model, terms visibility, liquidity or
inventory visibility, and fill style. New create requests select an explicit
`orderType`, and that same classification is returned in order summaries,
signed into the action envelope, independently recomputed by the signer, and
shown in every confirmation.

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

Unlisted recurring orders remain intentionally unsupported. The deployed
reusable fill ABI would reveal their reusable access secret in public calldata.
Public or fixed-recipient recurring access remains available. Administrative
methods, arbitrary calldata, and standalone wallet transfers cannot fall
through the MCP surface.

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
confirmation. A missing escrow encryption address is a protocol deployment
configuration issue; the signer rejects before approving the token.

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

The signer journal stores only operation hashes, stages, nonces, transaction
hashes, receipts, and safe error codes. It does not store prompts, decrypted
messages, private amounts, keys, or raw access secrets. Unlisted access secrets
are kept only in the encrypted local vault and may be shared only through COTI
encrypted messaging.

## Repository verification

The deterministic package smoke starts both built stdio binaries with a
temporary state directory and no signer credentials. It verifies the keyless
tool/resource surface and the signer's configuration-required status. It does
not call a chain provider, sign, broadcast, or send a message.

The tarball gate then creates the actual npm archive with lifecycle scripts
disabled, checks its allowlisted contents, unpacks it into an isolated
`node_modules` layout, and repeats the stdio smoke against both binaries from
that packed copy. This gate is network-free; `build:mcp` must run first.

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
