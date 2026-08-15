# Governance

Directwire follows a staged governance model. The goal is to move from
founder-led stewardship to a maintainer council as the contributor base grows —
the same path taken by healthy infrastructure projects (cf. the Ethereum
client ecosystem).

## Stage 1 — Benevolent Steward (current, v0.x)

- The founding maintainer(s) hold final say on protocol design and merges.
- Decisions are made in the open: protocol changes go through the
  `protocol_review` issue template; breaking changes require a SPEC.md update.
- Rationale: at research-preview stage, coherent protocol design beats
  committee design.

## Stage 2 — Maintainer Council (v1.0 target)

- A council of 3–5 maintainers with merge rights, selected by sustained
  contribution quality (code review, protocol work, community support).
- Protocol changes require council majority; cryptographic changes require
  unanimity among maintainers with crypto review track record.

## Stage 3 — Standards Track (post-v1)

- Stable protocol versions are proposed to relevant standards bodies
  (IETF drafts, national cryptography standards alignment) so that
  independent implementations can interoperate.

## Becoming a Maintainer

Consistent, high-quality contributions over time: reviewed PRs, thoughtful
protocol discussion, reproducible benchmarks, helping other contributors.
There is no committee application — maintainers emerge.

## Decision Log

Significant protocol decisions are recorded as GitHub Discussions and linked
from SPEC.md changelog entries.
