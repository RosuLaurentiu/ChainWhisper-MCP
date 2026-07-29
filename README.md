# ChainWhisper Agent Tools

`@chainwhisper/agent-tools` installs two local stdio MCP servers for
ChainWhisper on COTI Mainnet:

- `chainwhisper-mcp` is the keyless discovery and action-planning server.
- `chainwhisper-coti-signer` is the local Agent Wallet, privacy, policy,
  confirmation, signing, messaging, broadcast, and recovery boundary.

No ChainWhisper skill or separate messaging MCP is required. Official COTI
private messaging is embedded in the signer.

## Security boundary

The planner never holds a wallet key, privacy key, access secret, ABI,
arbitrary calldata, or signing authority. It reads audited ChainWhisper state
and returns a paired `ActionEnvelopeV1`.

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
conversation. Restart the signer after saving or replacing the wallet.

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

Only one signer process may use a state directory. If the process terminates
uncleanly, verify no signer remains before removing only the exact
`signer.instance.lock` inside that state directory.

## Privacy onboarding

After funding the Agent Wallet with COTI for gas:

1. Open Agent Control.
2. Choose **Set up wallet privacy**.
3. Review and confirm the exact official COTI onboarding action.
4. Let the signer recover and encrypt the wallet-specific privacy key
   internally.
5. Enable each verified private token when first needed; this remains a
   separately confirmed setup action.

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

Agent Control shows send and receive amounts, privacy labels, exact order type,
prices, recurring inventory, recipient or counterparty, expiry, protocol fee,
and maximum network cost. Approvals, resets, contracts, selectors, calldata
digests, step hashes, and the operation hash are collapsed under technical
details.

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

Private amounts may be selected by the agent only when:

- the prepare call explicitly uses
  `privateAmountMode: "agent-provided"`; and
- the active policy records `agentVisiblePrivateAmounts: true`.

Those amounts remain encrypted/private on-chain where the deployed
ChainWhisper contract supports private inputs. A Privacy Portal conversion
amount is public calldata because that is the deployed bridge interface.

## Public signer tools

- `chainwhisper_signer_status`
- `chainwhisper_open_control_panel`
- `chainwhisper_autonomy_status`
- `chainwhisper_request_autonomy`
- `chainwhisper_pause_autonomy`
- `chainwhisper_resume_autonomy`
- `chainwhisper_revoke_autonomy`
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
- the allowlisted official COTI private-messaging read/list/send subset

`chainwhisper_discard_operation` requires the exact operation hash and local
confirmation. It can never be approved by an autonomy policy.

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
confirmed.

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
| `recurring.direct` | Fixed-recipient reusable inventory |
| `recurring.private-liquidity.public` | Public access, hidden private-token inventory |
| `recurring.private-liquidity.direct` | Fixed recipient, hidden private-token inventory |

There is no unlisted recurring product. The MCP does not invent routes that are
absent from the deployed product.

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

Hash-bound writes with an uncertain RPC outcome remain `processing`. Recovery
reconciles the same signed hash and never silently prepares a replacement.
Official messaging remains fail-closed when the SDK does not expose a
transaction hash.

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
npm run audit:runtime
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
