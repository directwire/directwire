# Security Policy

Directwire is a network protocol whose entire point is trust. We take
security reports seriously and respond to them in the open.

## Reporting a vulnerability

**Do not open a public issue** for security problems.

Report privately via GitHub's private vulnerability reporting:

1. Go to <https://github.com/directwire/directwire/security/advisories>
2. Click **New draft security advisory** and fill in the details.
3. If you cannot use the advisory form, open a **discussion** titled `[SECURITY]`
   with a one-line summary only (no details) and a maintainer will set up a
   private channel.

Please include, when you have them:

- A summary of the impact (what an attacker can do, and under what preconditions).
- A minimal reproduction (inputs, steps, and observed vs. expected behavior).
- The affected versions and whether a workaround exists.
- If the finding is a protocol-design issue rather than an implementation bug,
  say so — design findings are still valued and may be credited in the SPEC.

## Response expectations

| Timeframe | What happens |
|---|---|
| 48 h | A maintainer acknowledges the report and begins triage |
| 1 week | Initial severity assessment and a plan (fix, or reasoned won't-fix) |
| Fixed | A patched release is cut; the advisory is published |

If a fix cannot be produced within a reasonable window, the report is treated
as a **coordinated disclosure**: we publish a patch + advisory, and agree a
release date with the reporter before public disclosure. The default embargo
is 90 days after the fix lands.

## Supported versions

Security fixes target the current release line. We do not backport to older
minor versions unless a consumer explicitly needs it.

## Scope

In scope — anything that could compromise the security properties the protocol
claims:

- `gm-pq-stack` — SM2/ML-KEM-768/SM4-GCM handshake, KEM combiner, replay
  protection, cookie anti-DoS, PSK resumption.
- `p2p-mesh` — identity (ed25519 NodeId, BIND binding), relay-path and
  QUIC-direct session establishment, path-selection logic, relay server
  (e.g. a relay that crashes, spoofs, or corrupts forwarded traffic).
- Spec-vs-implementation discrepancies in `SPEC.md` that weaken the stated
  security model.

Out of scope:

- **The reference crypto stack is not production-certified.** It is an
  architecture-validation skeleton. Bugs there are fixed, but the repository
  explicitly does not claim formal certification (see `gm-pq-stack` README for
  the compliance red lines).
- Issues that require the attacker to already hold a victim's private keys, or
  physical/administrative access to a trusted endpoint.

## Coordinated disclosure & credit

We publish advisories in the open repository. Reporters are credited unless
they ask to remain anonymous.

## Hall of fixes

- None yet. This section will be updated as advisories are published.
