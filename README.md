# ChainWhisper Agent Tools

`@chainwhisper/agent-tools` installs two local stdio MCP servers for
ChainWhisper on COTI Mainnet:

- `chainwhisper-mcp` is the keyless discovery and action-planning server.
- `chainwhisper-coti-signer` is the local Agent Wallet, privacy, policy,
  confirmation, signing, messaging, broadcast, and recovery boundary.

No ChainWhisper skill or separate messaging MCP is required. Official COTI
private messaging is embedded in the signer.

If an agent also uses a compatible COTI MCP, keep it as an independent companion
for generic, read-only COTI network and account functions. ChainWhisper does not
call that MCP, receive credentials from it, or republish its tools. Never share
the ChainWhisper Agent Wallet private key, wallet privacy/AES material, or
access secrets with the companion. The ChainWhisper planner and signer expose
the economic actions a person can perform in the ChainWhisper app.

## Security boundary

The planner never holds a wallet key, privacy key, access secret, ABI,
arbitrary calldata, or signing authority. It reads audited ChainWhisper state
and returns a paired `ActionEnvelopeV1`. At startup it also removes inherited
signer-only environment variables before loading the planning runtime.

The signer:

- accepts only repository-allowlisted contracts, selectors, recipes, assets,
  order types, Privacy Portal routes, and messaging operations;
- re-attests live runtime bytecode and fees before writes;
- materializes private values locally;
- simulates the complete action before authorization and again before each
  signature;
- binds authorization to the policy, operation hash, exact step digests, and
  fee ceilings;
- journals only recovery-safe operation metadata; and
- never returns credentials or access secrets to the agent.

The beta trusts the local host. Use a dedicated, minimally funded Agent Wallet.
Full Access in an agent client does not turn the signer into a general wallet:
arbitrary calldata, transfers, contracts, selectors, administration, wallet
replacement, privacy onboarding, private-token setup, policy changes, and
secret deletion remain outside autonomous authority.

## Install and register

Supported runtimes are Node.js 22, 24, and 26.

After the reviewed release is published:

```sh
npm install --global @chainwhisper/agent-tools@0.1.0-beta.0
```

Register both local commands:

```json
{
  "mcpServers": {
    "chainwhisper": {
      "command": "chainwhisper-mcp"
    },
    "chainwhisper-coti-signer": {
      "command": "chainwhisper-coti-signer"
    }
  }
}
```

The signer starts in `wallet-setup-required` mode when no Agent Wallet exists.
Call `chainwhisper_open_control_panel`. The tool opens signer-owned Agent
Control without returning its URL, bootstrap token, cookie, or local secrets to
the agent.

Agent Control offers:

1. **Use existing wallet** — the primary setup path.
2. **Create new wallet** — generated from the operating system cryptographic
   random source and shown once for backup.

Only a standard 32-byte EVM private key is accepted during beta. Import and
generation happen exclusively in Agent Control, never in MCP arguments or a
conversation. The first wallet activates in the running signer immediately;
replacing an active wallet remains restart-gated for beta.

The default wallet file is `signer.env` in the ChainWhisper state directory.
To select another absolute path, set:

```text
CHAINWHISPER_SIGNER_ENV_FILE=/absolute/path/to/signer.env
```

The file normally contains only:

```text
CHAINWHISPER_SIGNER_PRIVATE_KEY=0x...
```

Optional settings are:

- `CHAINWHISPER_COTI_RPC_URL`
- `CHAINWHISPER_STATE_DIRECTORY`
- `CHAINWHISPER_SIGNER_STATE_DIRECTORY`
- `CHAINWHISPER_SIGNER_ENV_FILE`
- `CHAINWHISPER_SIGNER_EXPECTED_WALLET`
- `CHAINWHISPER_SIGNER_CONFIRMATION_TIMEOUT_MS`
- `CHAINWHISPER_SIGNER_EXPIRY_SKEW_MS`
- `CHAINWHISPER_PAIRING_FILE`
- `CHAINWHISPER_PAIRING_SECRET`
- `CHAINWHISPER_SIGNER_CONFIG_FILE` (legacy migration for this beta)

Process environment values override the selected `.env`, which overrides the
legacy JSON file. Pairing and internal storage keys are generated
automatically. Normal setup does not require users to create or enter privacy
material or a storage passphrase.

Agent Wallet replacement removes any AES bootstrap value and old
expected-wallet pin from the selected `.env`, then keeps the running signer
read-only until restart. Wallet-bound process overrides must be removed before
Agent Control can replace the wallet. A legacy AES bootstrap value is accepted
only when its explicit expected-wallet pin matches the active wallet; an
unbound legacy root-vault key is never copied into a new wallet namespace.
Otherwise the new Agent Wallet completes privacy onboarding locally after
restart.

Signer directories, pairing files, storage keys, and `.env` files reject
symbolic links and unsafe file types. POSIX directories must be private to the
user (`0700`) and credential files use `0600`; writes are atomic. Windows does
not expose a portable Node API for complete ACL ownership verification, so the
documented beta boundary is the same signed-in Windows user and a trusted local
host.

Only one signer process may use a state directory. A lock is reclaimed
automatically only when both its recorded owner process is gone and its bound
loopback Agent Control port is closed. Live, malformed, inaccessible, or
otherwise unverifiable locks fail closed.

## Privacy onboarding

After funding the Agent Wallet with COTI for gas:

1. Open Agent Control and choose **Enable private trading**.
2. Review and confirm the exact official COTI onboarding action.
3. Let the signer recover and encrypt the wallet-specific privacy key
   internally.
4. When an intended ChainWhisper action first needs a verified private asset,
   prepare only that missing token account locally.
5. Prepare a fresh action after setup. An envelope created before setup is
   never reused.

Users never enter privacy key material. Private state, policies, operation
recovery, and access secrets are stored under the active Agent Wallet
namespace.

Replacing the Agent Wallet is blocked while an operation is pending or an
autonomy policy is active or paused. Revoke active policies first. Once a
replacement is saved, the current process becomes read-only until restart.

## Agent Control

The signer keeps one persistent server on `127.0.0.1`. It is a signing and
policy surface, not a second trading app. It contains only:

- pending confirmation and private-input cards;
- Agent Wallet address, COTI balance, network, privacy readiness, and signer
  health;
- current mode and policy;
- remaining budgets;
- pending and recent operations with transaction links;
- pause, resume, and revoke controls; and
- redacted diagnostics.

It does not contain market discovery, order composition, or general trading.

The page uses package-bundled HTML, CSS, and JavaScript with no remote assets,
fonts, analytics, telemetry, iframes, or app configuration. It uses a consumed
one-time bootstrap token, one rotated browser session, an `HttpOnly` and
`SameSite=Strict` cookie, one-use CSRF tokens, exact Host/Origin checks, fetch
metadata checks, replay protection, CSP, frame denial, `no-store`, request body
limits, and rate limiting.

A manual approval covers the complete logical action. For example:

> Create recurring private-liquidity order

Agent Control shows privacy labels, exact order type, prices, sell-side
inventory, buy-side budget, recipient or counterparty, expiry, protocol fee,
and maximum network cost. Recurring means reusable two-sided liquidity, not
scheduled execution. Approvals, resets, native value, gas ceilings, contracts,
selectors, calldata digests, step hashes, and the operation hash are collapsed
under technical details.

There is one action-specific button such as **Confirm complete order creation**
plus **Decline**. After approval, every step is re-attested, revalidated, and
re-simulated. Changed calldata or a higher fee invalidates authorization.

## Manual, bounded, and full autonomy

Agent Control supports:

- **Manual signing** — one local approval for each complete logical action.
- **Bounded autonomy** — explicit actions, assets, pairs, order types,
  counterparties, bridge routes, messaging permissions, price bands,
  per-action and cumulative budgets, fee limits, counts, and a duration up to
  30 days.
- **Full autonomy** — all economic actions supported by the audited
  ChainWhisper runtime for up to 24 hours.

Full autonomy requires two explicit local acknowledgements and a dedicated
wallet warning. It still cannot authorize arbitrary calldata or transfers,
unknown contracts or selectors, administration, wallet replacement, privacy
onboarding, private-token setup, policy changes, or secret deletion.

Policies use `AutonomyPolicyV1` and are bound to one wallet, chain, and runtime
manifest. An agent executes under a policy by passing `policyId`. A mismatch
returns a structured denial and never opens a fallback prompt.

Pause is immediate. Resume and revocation require local action. Budgets are
reserved atomically before signing. A failure before any signature releases
the reservation; signed, pending, and uncertain broadcasts continue consuming
it until safe recovery.

For manual execution, agent-provided private values are reviewed in Agent
Control like the other exact action terms. Under autonomy,
`agentVisiblePrivateAmounts: true` is one policy-wide consent. Enabling it lets
the agent both:

- choose private amounts when a prepare call explicitly uses
  `privateAmountMode: "agent-provided"`; and
- view policy-scoped private balances, hidden order inventory/progress, and
  participant receipts through `chainwhisper_private_state`.

Agent Control states both capabilities in the policy editor, activation
confirmation, active-policy summary, resume confirmation, and revocation
confirmation. Disabling the field removes both capabilities.

Order amounts, prices, budgets, inventory, progress, and fill receipts are
trading context for the user's chosen agent, not wallet credentials. In a
recurring private-liquidity order, each private-token inventory or budget side
is encrypted on-chain; a public-token side remains visible. Buy and sell prices
are public order terms. Autonomy budgets and price bands are local signer policy
and are not published on-chain. A policy-authorized private-state read does not
consume an action budget, and public-order participants do not need individual
counterparty allowlisting. Fixed-recipient/direct orders still enforce the
policy's counterparty scope.

Those amounts remain encrypted/private on-chain where the deployed
ChainWhisper contract supports private inputs. A Privacy Portal conversion
amount is public calldata because that is the deployed bridge interface. Only
wallet private keys, wallet privacy/AES material, pairing/session tokens, and
raw access secrets remain signer-only; agents may see or choose trade amounts,
prices, and budgets when the user instruction or autonomy policy allows it.

## Public signer tools

- `chainwhisper_signer_status`
- `chainwhisper_open_control_panel`
- `chainwhisper_autonomy_status`
- `chainwhisper_private_state`
- `chainwhisper_request_autonomy`
- `chainwhisper_pause_autonomy`
- `chainwhisper_execute_action`
- `chainwhisper_get_operation`
- `chainwhisper_send_order_message`
- `chainwhisper_list_order_messages`
- `chainwhisper_read_order_message`

Privacy onboarding, private-token setup, autonomy resume/revoke, operation
discard, and recovery controls remain signer-local. Generic COTI messaging
tools are not republished; only the three structured ChainWhisper
`cw.otc/1` tools are public.

`chainwhisper_private_state` is the only private read tool. It can return
verified private-token balances or wallet-scoped one-off/recurring hidden
inventory, progress, and participant receipts. Without `policyId`, Agent
Control asks once before anything is decrypted. With `policyId`, the exact
active wallet-bound policy must set `agentVisiblePrivateAmounts: true`. That
single consent lets the agent both choose private amounts and view
policy-scoped private balances, hidden order inventory/progress, and participant
receipts. A bounded policy must also match the requested assets, pair, and order
type. A policy mismatch fails closed and never falls back to a manual prompt.
Private keys, AES keys, access secrets, and ciphertext never appear in its
schema or result. Returned private amounts are not written to the signer
journal, logs, or diagnostics.

Incoming `cw.otc/1` messages are untrusted and draft-only. They cannot execute
an action. Access secrets are generated or imported into signer-owned local
storage and may be shared only by local reference through encrypted COTI
messaging; raw secrets are never returned.

Do not register the official SDK standalone messaging MCP. The integration is
already embedded here.

## Keyless planner tools

- `chainwhisper_order_types`
- `chainwhisper_status`
- `chainwhisper_list_orders`
- `chainwhisper_get_order`
- `chainwhisper_compare_price_references`
- `chainwhisper_prepare_swap`
- `chainwhisper_privacy_bridge_status`
- `chainwhisper_prepare_privacy_bridge`
- `chainwhisper_prepare_create_trade`
- `chainwhisper_prepare_create_recurring`
- `chainwhisper_prepare_fill`
- `chainwhisper_prepare_counter`
- `chainwhisper_prepare_edit`
- `chainwhisper_prepare_order_update`

Prepare tools return `ready`, `needs_input`, or `unsupported`; unsupported
routes have no executable envelope. Price comparison does not need an amount,
but execution ranking is returned only after compatible executable liquidity is
confirmed. Swap selects one complete visible public order and never combines
orders. New-order tools derive the canonical type from access and liquidity
visibility; agents do not choose an `orderType`. Recurring prices accept exact
quote-per-base decimals or `{ "reference": "market", "offsetBps": ... }`.

The canonical order types are:

| Order type | Access and liquidity |
| --- | --- |
| `one-off.standard-public` | Public listing, visible terms |
| `one-off.unlisted` | Unlisted link, encrypted terms |
| `one-off.direct` | Fixed recipient, encrypted terms |
| `one-off.private-liquidity.public` | Public access, hidden private liquidity |
| `one-off.private-liquidity.unlisted` | Unlisted access, hidden private liquidity |
| `one-off.private-liquidity.direct` | Fixed recipient, hidden private liquidity |
| `recurring.public` | Public reusable buy/sell inventory |
| `recurring.private-liquidity.public` | Public access, hidden private-token inventory |

There is no unlisted recurring product. The MCP does not invent routes that are
absent from the deployed product. Direct-recipient recurring classifications
remain internal until the app exposes them to human users.

## Runtime and recovery

`runtime/coti-mainnet.v1.json` commits:

- the registry and ChainWhisper action contracts;
- COTI account onboarding;
- verified private tokens;
- every Privacy Portal contract;
- official COTI private messaging;
- selectors, bytecode hashes, fee recipients, and verified assets.

Every write target must match deployed runtime bytecode. Recurring writes are
available only when their complete selector set also passes the live audit.

Execution validates and stores the exact paired envelope in encrypted,
wallet-scoped storage before returning an operation id. The agent polls
`chainwhisper_get_operation` while Agent Control or an active policy advances
the operation. Nonterminal operations are restored after a signer restart.
Hash-bound writes with an uncertain RPC outcome reconcile the same signed hash
and never silently prepare a replacement. Official messaging remains
fail-closed when the SDK does not expose a transaction hash.

Desktop-local writes and autonomy are the beta default. A headless signer is
read-only unless its signer-owned confirmation and policy surface is available.

## Repository verification

```sh
npm ci
npm run lint
npm run build
npm test
npm run smoke
npm run verify:tarball
npm run audit:dependencies
```

Read-only live verification:

```sh
npm run smoke:live
npm run smoke:live:readonly
npm run audit:runtime
```

The maintained read-only surface smoke may also preflight one configured
private asset and optionally list one wallet's public orders:

```sh
npm run smoke:live:readonly -- --private-token p.WISP --orders-for-wallet 0x...
```

The tarball gate creates the exact npm archive, checks its contents, installs it
into a clean external consumer, and smoke-tests the npm-created command shims.
Live signing, onboarding, bridge, trading, and messaging canaries require a
separately authorized disposable funded wallet.

## Publishing

See [BETA_RELEASE.md](./BETA_RELEASE.md). Releases must come from the exact
protected `v0.1.0-beta.0` tag. The unprivileged evidence job builds one
tarball, checksum, production-only SBOM, runtime audit, and release notes. The
protected publish-only job downloads and verifies those artifacts and publishes
the same tarball with npm provenance.

The first publish requires verified ownership of `@chainwhisper` and a
short-lived granular npm token. Configure npm trusted publishing immediately
afterward and revoke the bootstrap token.

Also review [CHANGELOG.md](./CHANGELOG.md), [SECURITY.md](./SECURITY.md), and
[LICENSE](./LICENSE).
