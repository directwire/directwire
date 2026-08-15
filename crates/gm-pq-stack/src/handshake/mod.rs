//! Noise XX three-message handshake (hybrid-KEM variant).
//!
//! ## Correspondence with Noise XX
//!
//! Noise XX: `-> e` / `<- e, ee, s, es` / `-> s, se`; replacing DH with KEM:
//!
//! ```text
//!   Message 1 (-> e)         : e_i                                    — initiator ephemeral public key
//!   Message 2 (<- e, ee, s)  : e_r || ct_ee || AEAD(s_r)              — ee = KEM encapsulate to e_i
//!   Message 3 (-> se, ss, s) : ct_se || ct_ss || AEAD(s_i)            — se/ss = encapsulate to e_r / s_r
//! ```
//!
//! - Each of `ee/se/ss` is one KEM encapsulation (ECDH for SM2; semantically equivalent to
//!   Noise's DH tokens);
//! - The static public key s is AEAD-encrypted with a handshake key; the tag simultaneously
//!   authenticates the peer (can't decapsulate ⇒ can't derive the key ⇒ tag check fails ⇒
//!   handshake rejected);
//! - The rolling transcript hash h mixes in all public parameters and ultimately becomes the
//!   session_id and binds key derivation;
//! - Optional PSK mode (session resumption): the PSK is mixed into the chaining key before any
//!   handshake secret (Noise `psk` token position 0), and supports 0-RTT early data.
//!
//! Trust anchoring of static public keys is provided by [`crate::trust::TrustAnchor`]
//! (public-key pinning and similar implementations).

pub mod cookie;
pub mod psk;
pub mod session;

use zeroize::Zeroizing;

use crate::crypto::{Aead, hkdf_expand, hkdf_extract, sm3};
use crate::kem::Kem;
use crate::rng::SysRng;
use crate::{Error, Result};

pub use session::{ReplayWindow, Session};

/// Transcript initial label
const PROLOGUE: &[u8] = b"gm-pq-stack-handshake/v1";
const INFO_STATIC_ENC: &[u8] = b"static-key-enc";
const INFO_SPLIT: &[u8] = b"transport-split";
const INFO_EARLY: &[u8] = b"early-data";
/// PSK mixing label (domain separation for the Noise `psk` token)
const PSK_LABEL: &[u8] = b"psk";

/// Symmetric state shared by both handshake parties (a simplified Noise SymmetricState)
struct SymmetricState {
    /// Chaining key (secret; zeroized on drop)
    ck: Zeroizing<[u8; 32]>,
    /// Transcript hash (hash of public parameters; no zeroization needed)
    h: [u8; 32],
}

impl SymmetricState {
    fn new(proto_name: &str) -> Self {
        let h = sm3(&[PROLOGUE, proto_name.as_bytes()]);
        SymmetricState {
            ck: Zeroizing::new(h),
            h,
        }
    }

    /// PSK-mode initialization (Noise `psk` token position 0: mixed in before any handshake secret)
    fn new_with_psk(proto_name: &str, psk: &[u8; 32]) -> Self {
        let mut s = Self::new(proto_name);
        let mut ikm = Zeroizing::new(Vec::with_capacity(36));
        ikm.extend_from_slice(PSK_LABEL);
        ikm.extend_from_slice(psk);
        s.mix_key(&ikm);
        s
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = sm3(&[&self.h, data]);
    }

    /// Noise's MixKey: ck = HKDF-Extract(ck, ikm)
    fn mix_key(&mut self, ikm: &[u8]) {
        self.ck = Zeroizing::new(hkdf_extract(Some(&*self.ck), ikm));
    }

    /// Derive a 16-byte handshake encryption key (used for AEAD-encrypting static keys)
    fn encryption_key(&self, info: &[u8]) -> [u8; 16] {
        hkdf_expand(&self.ck, info, 16).try_into().unwrap()
    }

    /// 0-RTT early-data encryption key (meaningful only in PSK mode)
    fn early_data_aead(&self) -> Aead {
        Aead::new(self.encryption_key(INFO_EARLY))
    }

    /// End of handshake: split out the two directional transport keys + session identifier
    fn split(&self) -> ([u8; 16], [u8; 16], [u8; 32]) {
        let material = hkdf_expand(&self.ck, INFO_SPLIT, 32);
        let mut k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        k1.copy_from_slice(&material[..16]);
        k2.copy_from_slice(&material[16..]);
        (k1, k2, self.h)
    }
}

/// Initiator state machine (Noise role: initiator)
pub struct Initiator<K: Kem> {
    ss: SymmetricState,
    /// Option-ified: taken out at the msg3 stage for signing (terminal consumption)
    static_sk: Option<K::SecretKey>,
    static_pk: Vec<u8>,
    eph_sk: Option<K::SecretKey>,
    /// AEAD(s_r) from message 2, decrypted at the msg3 stage
    enc_peer_static: Option<Vec<u8>>,
    peer_eph_pk: Option<Vec<u8>>,
    peer_ct_ee: Option<Vec<u8>>,
    /// Responder static public key, decrypted and authenticated at the msg3 stage
    peer_static: Option<Vec<u8>>,
}

/// Responder state machine (Noise role: responder)
pub struct Responder<K: Kem> {
    ss: SymmetricState,
    static_sk: K::SecretKey,
    static_pk: Vec<u8>,
    eph_sk: Option<K::SecretKey>,
    peer_eph_pk: Option<Vec<u8>>,
    done: Option<([u8; 16], [u8; 16], [u8; 32])>,
}

impl<K: Kem> Initiator<K> {
    pub fn new(static_sk: K::SecretKey, static_pk: Vec<u8>) -> Self {
        Initiator {
            ss: SymmetricState::new(K::NAME),
            static_sk: Some(static_sk),
            static_pk,
            eph_sk: None,
            enc_peer_static: None,
            peer_eph_pk: None,
            peer_ct_ee: None,
            peer_static: None,
        }
    }

    /// Take out the static key material (used when PSK resumption falls back to a full handshake; unavailable after msg3)
    pub fn into_static_keys(self) -> Result<(K::SecretKey, Vec<u8>)> {
        let sk = self
            .static_sk
            .ok_or(Error::HandshakeState("static secret key already consumed"))?;
        Ok((sk, self.static_pk))
    }

    /// After msg3 completes: the authenticated responder static public key
    pub fn peer_static(&self) -> Option<&[u8]> {
        self.peer_static.as_deref()
    }

    /// PSK-mode constructor (session resumption): the PSK enters the chaining key before any handshake secret
    pub fn new_with_psk(static_sk: K::SecretKey, static_pk: Vec<u8>, psk: &[u8; 32]) -> Self {
        let mut init = Self::new(static_sk, static_pk);
        init.ss = SymmetricState::new_with_psk(K::NAME, psk);
        init
    }

    /// Message 1: `-> e`
    pub fn write_msg1(&mut self, rng: &mut SysRng) -> Result<Vec<u8>> {
        if self.eph_sk.is_some() {
            return Err(Error::HandshakeState("msg1 can only be written once"));
        }
        let (e_sk, e_pk) = K::keypair(rng)?;
        self.ss.mix_hash(&e_pk);
        self.eph_sk = Some(e_sk);
        Ok(e_pk)
    }

    /// 0-RTT: after writing msg1, encrypt early data with the PSK-derived key (safe only in PSK mode).
    ///
    /// **Replay and forward-secrecy note**: early data is transmitted before the responder's msg2,
    /// so it enjoys no forward secrecy from ephemeral keys and can be replayed — the application
    /// MUST guarantee idempotency. On the server side, [`psk::TicketCache`] intercepts one-time
    /// tickets (see the psk module docs).
    pub fn seal_early_data(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.eph_sk.is_none() {
            return Err(Error::HandshakeState("must write msg1 first"));
        }
        let aead = self.ss.early_data_aead();
        let packet = aead.seal_with_seq(0, &self.ss.h, plaintext);
        Ok(packet[8..].to_vec()) // the in-handshake sequence number is always 0; strip the prefix
    }

    /// Message 2: `<- e || ct_ee || AEAD(s_r)`
    pub fn read_msg2(&mut self, msg: &[u8]) -> Result<()> {
        let expect = K::PUBLIC_KEY_LEN + K::CIPHERTEXT_LEN;
        if msg.len() < expect + 16 {
            return Err(Error::InvalidEncoding("invalid msg2 length"));
        }
        let eph_pk = &msg[..K::PUBLIC_KEY_LEN];
        let ct_ee = &msg[K::PUBLIC_KEY_LEN..expect];
        let enc_static = msg[expect..].to_vec();

        K::validate_public(eph_pk)?;
        self.ss.mix_hash(eph_pk);
        self.ss.mix_hash(ct_ee);

        // ee: decapsulate with our own ephemeral secret key (under ML-KEM implicit rejection,
        // a tampered ciphertext ⇒ AEAD necessarily fails)
        let eph_sk = self
            .eph_sk
            .as_ref()
            .ok_or(Error::HandshakeState("missing ephemeral secret key"))?;
        let ss_ee = Zeroizing::new(K::decapsulate(eph_sk, ct_ee)?);
        self.ss.mix_key(&*ss_ee);

        self.enc_peer_static = Some(enc_static);
        self.peer_eph_pk = Some(eph_pk.to_vec());
        self.peer_ct_ee = Some(ct_ee.to_vec());
        Ok(())
    }

    /// Message 3: `-> ct_se || ct_ss || AEAD(s_i)`, returning the message bytes and the final session.
    ///
    /// **Note**: this variant does not attach an initiator proof of possession; only the
    /// responder is authenticated (equivalent to server one-way authentication in TLS 1.3
    /// hybrid modes). For mutual authentication use [`Initiator::write_msg3_with_auth`]
    /// (requires K: StaticAuth).
    pub fn write_msg3(&mut self, rng: &mut SysRng) -> Result<(Vec<u8>, Session)> {
        self.write_msg3_inner(rng, None, None)
    }

    /// msg3 internals; `signer` is an optional transcript-signature closure, `peer_check` an
    /// optional responder public-key trust-anchor check closure
    fn write_msg3_inner(
        &mut self,
        rng: &mut SysRng,
        signer: Option<&dyn Fn(&[u8; 32]) -> Result<Vec<u8>>>,
        peer_check: Option<&dyn Fn(&[u8]) -> Result<()>>,
    ) -> Result<(Vec<u8>, Session)> {
        let enc_static = self
            .enc_peer_static
            .take()
            .ok_or(Error::HandshakeState("must read msg2 first"))?;
        let peer_eph_pk = self.peer_eph_pk.take().unwrap();

        // Decrypt the peer's static public key (the AEAD tag authenticates the peer; the aad binds the transcript)
        let key_s = self.ss.encryption_key(INFO_STATIC_ENC);
        let aead = Aead::new(key_s);
        let aad = self.ss.h;
        let (_, s_r_pk) = open_static(&aead, &aad, &enc_static)?;
        K::validate_public(&s_r_pk)?;
        // Trust anchor: a public key not in the pin list is rejected (better to fail than to connect to the wrong server)
        if let Some(check) = peer_check {
            check(&s_r_pk)?;
        }
        self.peer_static = Some(s_r_pk.clone());
        self.ss.mix_hash(&enc_static);

        // se: encapsulate to the peer's ephemeral public key
        let (ct_se, ss_se) = K::encapsulate(rng, &peer_eph_pk)?;
        // ss: encapsulate to the peer's static public key
        let (ct_ss, ss_ss) = K::encapsulate(rng, &s_r_pk)?;

        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(&ss_se);
        ikm.extend_from_slice(&ss_ss);
        self.ss.mix_key(&ikm);
        drop(Zeroizing::new(ss_se));
        drop(Zeroizing::new(ss_ss));

        self.ss.mix_hash(&ct_se);
        self.ss.mix_hash(&ct_ss);

        // Encrypt our own static public key (optionally appending a transcript signature as proof of possession)
        let mut plaintext = self.static_pk.clone();
        if let Some(sign) = signer {
            let sig = sign(&self.ss.h)?;
            plaintext.extend_from_slice(&sig);
        }
        let key3 = self.ss.encryption_key(INFO_STATIC_ENC);
        let aead3 = Aead::new(key3);
        let enc_si = seal_static(&aead3, &self.ss.h, &plaintext);
        self.ss.mix_hash(&enc_si);

        let mut msg = Vec::with_capacity(2 * K::CIPHERTEXT_LEN + enc_si.len());
        msg.extend_from_slice(&ct_se);
        msg.extend_from_slice(&ct_ss);
        msg.extend_from_slice(&enc_si);

        let (k_i2r, k_r2i, session_id) = self.ss.split();
        Ok((msg, Session::new(k_i2r, k_r2i, session_id)))
    }
}

impl<K: Kem + crate::kem::StaticAuth> Initiator<K> {
    /// Message 3 (mutual-authentication variant): attaches an SM2 transcript signature as proof
    /// of possession and validates the responder's static public key against `anchor` (trust
    /// anchor, prevents connecting to the wrong server).
    pub fn write_msg3_with_auth(
        &mut self,
        rng: &mut SysRng,
        anchor: &dyn crate::trust::TrustAnchor,
    ) -> Result<(Vec<u8>, Session)> {
        let sk = self
            .static_sk
            .take()
            .ok_or(Error::HandshakeState("static secret key already consumed"))?;
        let signer = |h: &[u8; 32]| K::sign(&sk, h);
        let peer_check = |pk: &[u8]| anchor.verify(crate::trust::Role::Responder, pk);
        self.write_msg3_inner(rng, Some(&signer), Some(&peer_check))
    }
}

impl<K: Kem> Responder<K> {
    pub fn new(static_sk: K::SecretKey, static_pk: Vec<u8>) -> Self {
        Responder {
            ss: SymmetricState::new(K::NAME),
            static_sk,
            static_pk,
            eph_sk: None,
            peer_eph_pk: None,
            done: None,
        }
    }

    /// PSK-mode constructor (session resumption)
    pub fn new_with_psk(static_sk: K::SecretKey, static_pk: Vec<u8>, psk: &[u8; 32]) -> Self {
        let mut resp = Self::new(static_sk, static_pk);
        resp.ss = SymmetricState::new_with_psk(K::NAME, psk);
        resp
    }

    /// Message 1: `-> e`
    pub fn read_msg1(&mut self, msg: &[u8]) -> Result<()> {
        K::validate_public(msg)?;
        self.ss.mix_hash(msg);
        self.peer_eph_pk = Some(msg.to_vec());
        Ok(())
    }

    /// 0-RTT: decrypt early data after reading msg1 (PSK mode only).
    /// The caller MUST first intercept replayed tickets with [`psk::TicketCache`] before calling this.
    pub fn open_early_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        if self.peer_eph_pk.is_none() {
            return Err(Error::HandshakeState("must read msg1 first"));
        }
        let aead = self.ss.early_data_aead();
        let mut packet = Vec::with_capacity(8 + data.len());
        packet.extend_from_slice(&0u64.to_be_bytes());
        packet.extend_from_slice(data);
        let (_, pt) = aead.open(&self.ss.h, &packet).map_err(|e| match e {
            Error::AuthFailed => Error::PeerAuth,
            other => other,
        })?;
        Ok(pt)
    }

    /// Message 2: `<- e || ct_ee || AEAD(s_r)`
    pub fn write_msg2(&mut self, rng: &mut SysRng) -> Result<Vec<u8>> {
        let peer_eph = self
            .peer_eph_pk
            .clone()
            .ok_or(Error::HandshakeState("must read msg1 first"))?;

        let (e_sk, e_pk) = K::keypair(rng)?;
        self.ss.mix_hash(&e_pk);

        // ee: encapsulate to the initiator's ephemeral public key
        let (ct_ee, ss_ee) = K::encapsulate(rng, &peer_eph)?;
        self.ss.mix_hash(&ct_ee);
        self.ss.mix_key(&ss_ee);
        drop(Zeroizing::new(ss_ee));

        // Encrypt our own static public key
        let key_s = self.ss.encryption_key(INFO_STATIC_ENC);
        let aead = Aead::new(key_s);
        let enc_static = seal_static(&aead, &self.ss.h, &self.static_pk);
        self.ss.mix_hash(&enc_static);

        self.eph_sk = Some(e_sk);

        let mut msg = Vec::with_capacity(K::PUBLIC_KEY_LEN + K::CIPHERTEXT_LEN + enc_static.len());
        msg.extend_from_slice(&e_pk);
        msg.extend_from_slice(&ct_ee);
        msg.extend_from_slice(&enc_static);
        Ok(msg)
    }

    /// Message 3: `-> ct_se || ct_ss || AEAD(s_i)`, returning the final session.
    ///
    /// Does not validate the initiator's proof of possession (one-way authentication). For
    /// mutual authentication use [`Responder::read_msg3_with_auth`].
    pub fn read_msg3(&mut self, msg: &[u8]) -> Result<Session> {
        let (session, static_plain, _h_sign) = self.read_msg3_inner(msg)?;
        if static_plain.len() != K::PUBLIC_KEY_LEN {
            return Err(Error::InvalidEncoding(
                "invalid msg3 static public key length",
            ));
        }
        K::validate_public(&static_plain)?;
        Ok(session)
    }

    /// msg3 internals, returning (session, static public key plaintext, transcript hash at signing time)
    fn read_msg3_inner(&mut self, msg: &[u8]) -> Result<(Session, Vec<u8>, [u8; 32])> {
        let expect = 2 * K::CIPHERTEXT_LEN;
        if msg.len() < expect + 16 {
            return Err(Error::InvalidEncoding("invalid msg3 length"));
        }
        let ct_se = &msg[..K::CIPHERTEXT_LEN];
        let ct_ss = &msg[K::CIPHERTEXT_LEN..expect];
        let enc_static = &msg[expect..];

        // se: decapsulate with the ephemeral secret key; ss: decapsulate with the static secret key
        let eph_sk = self
            .eph_sk
            .take()
            .ok_or(Error::HandshakeState("msg3 read twice"))?;
        let ss_se = K::decapsulate(&eph_sk, ct_se)?;
        let ss_ss = K::decapsulate(&self.static_sk, ct_ss)?;

        let mut ikm = Zeroizing::new(Vec::with_capacity(64));
        ikm.extend_from_slice(&ss_se);
        ikm.extend_from_slice(&ss_ss);
        self.ss.mix_key(&ikm);
        drop(Zeroizing::new(ss_se));
        drop(Zeroizing::new(ss_ss));

        self.ss.mix_hash(ct_se);
        self.ss.mix_hash(ct_ss);

        // Decrypt the peer's static public key (the AEAD tag protects both confidentiality and integrity)
        let h_sign = self.ss.h;
        let key3 = self.ss.encryption_key(INFO_STATIC_ENC);
        let aead = Aead::new(key3);
        let (_, static_plain) = open_static(&aead, &self.ss.h, enc_static)?;
        self.ss.mix_hash(enc_static);

        let (k_i2r, k_r2i, session_id) = self.ss.split();
        // Direction is swapped for the responder
        self.done = Some((k_r2i, k_i2r, session_id));
        Ok((Session::new(k_r2i, k_i2r, session_id), static_plain, h_sign))
    }
}

impl<K: Kem + crate::kem::StaticAuth> Responder<K> {
    /// Message 3 (mutual-authentication variant): validates the initiator's SM2 transcript
    /// signature and checks its static public key against `anchor`,
    /// returning (session, authenticated initiator static public key)
    pub fn read_msg3_with_auth(
        &mut self,
        msg: &[u8],
        anchor: &dyn crate::trust::TrustAnchor,
    ) -> Result<(Session, Vec<u8>)> {
        let (session, static_plain, h_sign) = self.read_msg3_inner(msg)?;
        if static_plain.len() != K::PUBLIC_KEY_LEN + K::SIGNATURE_LEN {
            return Err(Error::InvalidEncoding("msg3 missing initiator signature"));
        }
        let (pk, sig) = static_plain.split_at(K::PUBLIC_KEY_LEN);
        K::validate_public(pk)?;
        // Signature verification failure ⇒ the initiator does not hold the static secret key ⇒ reject the handshake
        K::verify(pk, &h_sign, sig)?;
        // Trust anchor: client public keys not on the whitelist are always rejected
        anchor.verify(crate::trust::Role::Initiator, pk)?;
        Ok((session, pk.to_vec()))
    }
}

/// Static public key encryption wrapper: `ciphertext || tag(16B)` (the nonce is fixed at seq=0 during the handshake)
fn seal_static(aead: &Aead, aad: &[u8; 32], pk: &[u8]) -> Vec<u8> {
    let packet = aead.seal_with_seq(0, aad, pk);
    packet[8..].to_vec()
}

/// Static public key decryption: `ciphertext || tag` after stripping the seq prefix
fn open_static(aead: &Aead, aad: &[u8; 32], data: &[u8]) -> Result<(u64, Vec<u8>)> {
    let mut packet = Vec::with_capacity(8 + data.len());
    packet.extend_from_slice(&0u64.to_be_bytes());
    packet.extend_from_slice(data);
    aead.open(aad, &packet).map_err(|e| match e {
        Error::AuthFailed => Error::PeerAuth,
        other => other,
    })
}
