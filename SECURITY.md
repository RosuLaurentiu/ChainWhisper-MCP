# Security policy

## Supported versions

`@chainwhisper/agent-tools` is a beta. Security fixes are provided only for the
latest published `0.1.0-beta.x` release.

Install exact versions, review release evidence, restart both MCP processes,
and run the two read-only status checks after every update.

## Private reporting

Use [GitHub private vulnerability reporting](https://github.com/RosuLaurentiu/ChainWhisper-MCP/security/advisories/new).
Do not open a public issue for a suspected vulnerability.

Include the affected version, operating system, Node.js version, MCP client,
expected behavior, redacted reproduction, and impact.

Never include:

- Agent Wallet private keys or recovery phrases;
- recovered COTI privacy key material;
- internal storage or pairing keys;
- order access secrets;
- credential-bearing `.env` or legacy configuration files.

If a real secret may have been exposed, stop the signer, move funds to a new
wallet, revoke active policies, and do not reuse the value.

## Security boundary

`chainwhisper-mcp` is keyless. Only the local
`chainwhisper-coti-signer` may hold Agent Wallet credentials, privacy material,
policies, and signing authority.

Manual writes require one complete signer-owned local authorization. Autonomous
writes require an exact active wallet/chain/manifest-bound policy. Both paths
remain restricted to the audited ChainWhisper economic surface.

Order amounts, prices, budgets, inventory, and participant receipts may be
shown to the user's chosen agent after an exact local disclosure confirmation
or an active policy with `agentVisiblePrivateAmounts=true`. These trading terms
are not wallet credentials. Private keys, recovered privacy/AES material,
pairing/session tokens, and raw access secrets remain signer-only.

Order-linked private negotiation uses the official COTI private-messaging SDK
embedded in `chainwhisper-coti-signer`. No ChainWhisper skill, COTI skill, or
standalone messaging MCP is part of the trusted path. A separate COTI MCP is an
independent generic companion and must not receive ChainWhisper Agent Wallet
credentials.

The beta trusts the local host and same signed-in OS user. A dedicated,
minimally funded Agent Wallet is strongly recommended.

High-priority report areas include:

- pairing or policy bypass;
- confirmation/session/CSRF/origin bypass;
- wallet replacement during pending work or active autonomy;
- budget races or reservation release after signing;
- selector, contract, bytecode, fee, or calldata-binding bypass;
- private amount, access-secret, or generated-key exposure;
- transaction recovery or nonce confusion;
- untrusted message content causing execution;
- symlink, junction, permission, or unsafe-file bypass; and
- arbitrary calldata, transfers, or administration reachable through MCP.

Incoming private messages are untrusted and draft-only. They may never execute
an action directly.
