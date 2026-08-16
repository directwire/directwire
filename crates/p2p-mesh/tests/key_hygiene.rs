//! Key-hygiene contract: secrets that hold private key material must zeroize.
//!
//! Compile-time gate, not a runtime test. Two guarantees are enforced, each
//! reflecting what the upstream crates actually provide:
//!
//! - `ed25519_dalek::SigningKey` implements `ZeroizeOnDrop` (the trait contract:
//!   drop always clears the key bytes).
//! - `x25519_dalek::StaticSecret` / `SharedSecret` implement `Zeroize` (explicit
//!   `.zeroize()`) and carry the derive attribute `#[zeroize(drop)]`, so each also
//!   clears in its `Drop` impl — but they do **not** implement the `ZeroizeOnDrop`
//!   marker trait, so that half of the guarantee is source-level (verified against
//!   x25519-dalek 2.0.1 `src/x25519.rs`) rather than a bound we can assert here.
//!
//! If either dalek crate ever drops the `zeroize` feature or its drop behavior,
//! the feature flags on `x25519-dalek` / `ed25519-dalek` in Cargo.toml are the
//! enforcement point; these bounds make the contract visible at compile time.

use zeroize::ZeroizeOnDrop;

/// Compile-time assertion: `T` must implement `ZeroizeOnDrop`.
fn assert_zd<T: ZeroizeOnDrop>() {}

/// Compile-time assertion: `T` must implement `Zeroize` (explicit `.zeroize()`).
fn assert_z<T: zeroize::Zeroize>() {}

#[test]
fn relay_path_secrets_zeroize() {
    // Both clear in their Drop impls via the derived `#[zeroize(drop)]`
    // (x25519-dalek 2.0.1), and expose explicit `Zeroize` for manual clearing.
    assert_z::<x25519_dalek::StaticSecret>();
    assert_z::<x25519_dalek::SharedSecret>();
}

#[test]
fn identity_key_zeroizes_on_drop() {
    assert_zd::<ed25519_dalek::SigningKey>();
}
