# Security policy

Report vulnerabilities privately — open a
[security advisory](https://github.com/MartinRougeron2/HQCAT/security/advisories/new)
on the monorepo rather than a public issue here.

This server's whole claim is that it cannot read messages. Anything undermining
that is the most serious class of bug we have: recovering plaintext or key
material from what the server holds; publishing to or subscribing to a
conversation you are not a member of (the per-topic ACL is the only barrier, and
topic names are derivable from two public keys); authenticating as another public
key; or replaying a handshake or token.

Known open findings — including a live-session revocation gap — are tracked in
[docs/audits](https://github.com/MartinRougeron2/HQCAT/tree/main/docs/audits).
Please check there before reporting.

Full policy: [SECURITY.md](https://github.com/MartinRougeron2/HQCAT/blob/main/SECURITY.md).
