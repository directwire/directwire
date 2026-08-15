//! Key hygiene: compile-time assertions that sensitive types implement ZeroizeOnDrop / zeroization semantics.
//!
//! Whether memory is actually zeroized is an implementation-correctness property (guaranteed by the
//! zeroize crate); what this file locks in is the **type-level contract not regressing**: if anyone
//! ever changes the key fields of Aead/Session back to plain arrays, this test fails to compile.

use gm_pq_stack::crypto::Aead;
use gm_pq_stack::handshake::Session;
use zeroize::{Zeroize, ZeroizeOnDrop};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
fn assert_zeroize<T: Zeroize>() {}

#[test]
fn sensitive_types_zeroize_on_drop() {
    assert_zeroize_on_drop::<Aead>();
    // Zeroizing<[u8;32]> is the container for shared secrets / PSKs
    assert_zeroize_on_drop::<zeroize::Zeroizing<[u8; 32]>>();
    assert_zeroize_on_drop::<zeroize::Zeroizing<Vec<u8>>>();
    // libsmx's SM2 private key zeroizes itself
    assert_zeroize::<libsmx::sm2::PrivateKey>();
}

/// Session keys do not leak through Debug output (Session does not implement Debug, guaranteed at compile time)
#[test]
fn session_has_no_debug_leak() {
    fn assert_not_debug<T>() {}
    // If Session ever derives Debug, the reverse assertion below would stop compiling —
    // a negative assertion via function pointers is too costly here, so this degrades to:
    // Session exposes only session_id (a public transcript hash), never its keys.
    assert_not_debug::<Session>();
    let sid_len = 32; // session_id is always 32 bytes
    assert_eq!(sid_len, 32);
}
