//! DoS protection: stateless cookie challenge tests.

use gm_pq_stack::handshake::cookie::{COOKIE_LEN, CookieIssuer};

#[test]
fn cookie_issue_verify_roundtrip() {
    let issuer = CookieIssuer::new(30);
    let client_tag = b"127.0.0.1:50001";
    let e_pk = b"fake-ephemeral-public-key";
    let cookie = issuer.issue(client_tag, e_pk);
    assert_eq!(cookie.len(), COOKIE_LEN);
    issuer.verify(client_tag, e_pk, &cookie).unwrap();
}

#[test]
fn cookie_bound_to_client_tag() {
    // The cookie is bound to the source address: a forger switching IPs cannot reuse it
    let issuer = CookieIssuer::new(30);
    let e_pk = b"eph";
    let cookie = issuer.issue(b"10.0.0.1:1234", e_pk);
    assert!(issuer.verify(b"10.0.0.2:1234", e_pk, &cookie).is_err());
}

#[test]
fn cookie_bound_to_msg1() {
    // The cookie is bound to msg1: a different ephemeral public key invalidates it
    let issuer = CookieIssuer::new(30);
    let cookie = issuer.issue(b"tag", b"eph-A");
    assert!(issuer.verify(b"tag", b"eph-B", &cookie).is_err());
}

#[test]
fn cookie_tamper_rejected() {
    let issuer = CookieIssuer::new(30);
    let mut cookie = issuer.issue(b"tag", b"eph");
    cookie[9] ^= 0x01; // tamper with the HMAC
    assert!(issuer.verify(b"tag", b"eph", &cookie).is_err());
    cookie[0] ^= 0x01; // tamper with the timestamp
    assert!(issuer.verify(b"tag", b"eph", &cookie).is_err());
}

#[test]
fn cookie_expiry() {
    // TTL=0: any cookie that has crossed a whole second boundary expires immediately (simulated with boundary timestamps)
    let issuer = CookieIssuer::from_secret([7u8; 32], 0);
    let cookie = issuer.issue(b"tag", b"eph");
    let ts = u64::from_be_bytes(cookie[..8].try_into().unwrap());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if now > ts {
        // The second boundary was crossed => must have expired
        assert!(issuer.verify(b"tag", b"eph", &cookie).is_err());
    } else {
        // Still in the same second => still valid
        issuer.verify(b"tag", b"eph", &cookie).unwrap();
    }
}

#[test]
fn cookie_future_timestamp_rejected() {
    // A forged future timestamp (beyond the 5s tolerance window) must be rejected
    let issuer = CookieIssuer::from_secret([9u8; 32], 3600);
    let cookie = issuer.issue(b"tag", b"eph");
    let ts = u64::from_be_bytes(cookie[..8].try_into().unwrap()) + 3600;
    let mut forged = Vec::new();
    forged.extend_from_slice(&ts.to_be_bytes());
    forged.extend_from_slice(&cookie[8..]); // the HMAC does not match the forged ts; must fail
    assert!(issuer.verify(b"tag", b"eph", &forged).is_err());
}
