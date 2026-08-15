# Contributing to Directwire

Thanks for taking the time to contribute.

## Ground rules

- **Code is review-first.** Security-sensitive code (crypto, transport, identity) gets extra scrutiny — this is a network protocol, not a CRUD app.
- **No unreviewed dependencies** without discussion. Supply-chain hygiene matters for a project whose whole point is trust.
- Keep the public spec and the implementation honest: if the code and the spec disagree, that's a bug in one of them, not a feature.

## Getting started

1. Fork the repo and create a feature branch.
2. Run the test suite (`cargo test --all-features`) before and after your change.
3. Open a PR with a clear description of the problem and the fix.

## What we're looking for

- Protocol review and adversarial analysis of the spec.
- Ports / bindings (Python, Go, JS) once the core is stable.
- Benchmarks and reproducible measurement harnesses.
- Documentation, examples, and integrations.

## Code of conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md). In
short: behave like you're building infrastructure other people will rely on.
No gatekeeping, no hype, no shortcuts on security.

## Governance

See [GOVERNANCE.md](GOVERNANCE.md) for how the project is run — including the
wire-format authority rule, which is the most important governance constraint.
