# Security policy

## Reporting a vulnerability

Report privately — open a
[security advisory](https://github.com/MartinRougeron2/HQChat-Server/security/advisories/new)
on this repository rather than a public issue.

Tell us what you can reproduce and how. A working proof of concept is welcome but
not required; a clear description of the flaw is worth more than a script.

We aim to acknowledge within a few days. This is a small project — there is no
bounty programme, and no legal threat either: research reported in good faith is
welcome.

## Scope

In scope: the services in `services/server/`, the EMQX authn/authz configuration
in `infra/deploy/emqx/`, the deploy agent and NixOS host definitions in
`infra/deploy/agent/` and `infra/nixos/`, and the Terraform in `infra/`.

The macOS and iOS clients are not published here, but findings in the protocol
they speak — the handshake, the ratchet, the wire format — are in scope and can
be reported against the server side of it.

Out of scope: findings that require a compromised device or a user's unlocked
Keychain, and denial of service by brute volume.

## What we consider serious

This is a messenger whose whole claim is that the server cannot read messages.
Anything that undermines that claim is the most serious class of bug we have:

- Recovering plaintext or key material from anything the server holds.
- Reading, publishing to or subscribing to a conversation you are not a member
  of — the per-topic ACL is the only barrier, and the topic name is derivable
  from two public keys, so a broken ACL is a full compromise of confidentiality.
- Authenticating as another public key, or replaying a handshake or a token.
- Persuading a client to accept a public key for a contact that the contact does
  not hold (the key-change path exists precisely to make this visible).

Below that, and still worth reporting: anything that gets code or a shell onto a
host. The deploy path is built so that nothing in CI can reach a server — hosts
pull, CI never connects — and a way around that is a finding even if it touches
no ciphertext.

## What we already know

Findings from the standing audits (ASVS, MASVS, latency/architecture, and one on
everything that runs as root on a host) are tracked in the private monorepo, not
here: an open list of unfixed weaknesses next to the code that has them helps the
wrong reader first. The conclusion they share is that server-side compromise
costs metadata and ciphertext but not plaintext, and that the remaining risk sits
on endpoint compromise and on first-contact key exchange.

If you report something already on that list we will say so, and say when it is
expected to close.
