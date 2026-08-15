## What does this change, and why?

<!-- One or two sentences. For protocol-impacting changes, link the SPEC section. -->

## Does it touch the wire format?

- [ ] Yes — I have updated `SPEC.md` and this is a **breaking change** (version bump / label change required).
- [ ] No.

<!-- Wire constants (HS_TAG, GM_TAG, frame subtypes, magic bytes, ALPN) are the public contract.
     A change to any of them without a SPEC update will be rejected in review. -->

## Verification

- [ ] `cargo test --workspace --all-features` passes.
- [ ] `cargo fmt --all -- --check` passes (CI enforces both).
- [ ] New behavior is covered by a test (loopback-only, no network required).

## Security-sensitive?

- [ ] Yes (crypto, transport, identity, relay) — expected extra review scrutiny.
- [ ] No.

## Release note

<!-- A short, user-facing sentence for the changelog. "None" is fine. -->
