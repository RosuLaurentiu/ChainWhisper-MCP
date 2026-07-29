# Security policy

## Supported versions

`@chainwhisper/agent-tools` is in public beta. Security fixes are provided only
for the latest published `0.1.0-beta.x` release. Older betas and unpublished
development snapshots are not supported.

The package controls transactions on COTI Mainnet. Treat every beta upgrade as
a security update: review the changelog, install an exact version, restart both
MCP processes, and run the two read-only status checks before enabling writes.

## Report a vulnerability privately

Use
[GitHub private vulnerability reporting](https://github.com/RosuLaurentiu/ChainWhisper/security/advisories/new)
to send the maintainers a draft security advisory. Do not open a public issue
for a suspected vulnerability. If private reporting is unavailable, use a
non-sensitive contact channel associated with the repository owner to arrange
a private reporting method before sharing technical details.

Include the affected package version, operating system, Node.js version, MCP
client, expected behavior, redacted reproduction steps, and impact. Public
transaction hashes and contract addresses may be included when necessary, but
redact wallet identity where it is not essential to reproduce the issue.

Never include any of the following in an advisory, issue, log, screenshot,
prompt, or message:

- wallet private keys or mnemonics;
- COTI AES keys;
- vault passphrases;
- pairing or access secrets;
- signer configuration files containing credentials.

If a report involves one of those values, replace it with a clearly marked
dummy value. If a real secret may have been exposed, stop the signer, rotate or
replace the affected wallet and credentials, and do not reuse the compromised
value.

## Security boundary

The `chainwhisper-mcp` process is intentionally keyless. Only
`chainwhisper-coti-signer` may hold wallet and AES credentials, and those
credentials must be configured outside the conversation. The signer accepts
only paired, allowlisted plans and requires an exact local confirmation for
each write. Received private messages are untrusted and draft-only.

Reports about bypassing pairing, confirmation, selector or contract
allowlisting, simulation, secret isolation, private-artifact validation,
transaction recovery, or message trust boundaries are especially important.
