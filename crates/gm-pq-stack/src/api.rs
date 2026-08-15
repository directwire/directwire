//! Minimal integration API for downstream projects.
//!
//! **Contract**: given any established bidirectional byte stream
//! (`Read + Write`; TCP, QUIC stream, or reliable message channel all work),
//! run the SM2 + ML-KEM-768 hybrid handshake and return an encrypted session
//! channel [`SecureChannel`]. See docs/INTEGRATION.md for integration details.
//!
//! ## On-the-wire frame format
//! `type(1B) || len(u32 BE) || payload`, types:
//! - `0x01` MSG1: e_i
//! - `0x02` COOKIE: stateless server cookie (DoS challenge)
//! - `0x03` MSG1_RETRY: cookie || e_i
//! - `0x04` MSG2: full handshake = `e_r || ct_ee || AEAD(s_r)`;
//!   resumption handshake = `early_accepted(1B) || e_r || ct_ee || AEAD(s_r)`
//! - `0x05` MSG3: ct_se || ct_ss || AEAD(s_i || sig)
//! - `0x06` MSG1_PSK: ticket || e_i || AEAD_psk(early_data) (session resumption, 0-RTT)
//! - `0x07` PSK_REJECT: invalid ticket; the client automatically falls back to a full handshake (including cookie challenge)
//!
//! After the session is established, the server's first encrypted message is
//! always a ticket push (`b"TKT1" || u16 ticket_len || ticket || psk(32B)`),
//! which the client stores as (ticket, psk) for the next 0-RTT resumption.

use std::io::{Read, Write};

use crate::crypto::sm3;
use crate::handshake::cookie::{COOKIE_LEN, CookieIssuer};
use crate::handshake::psk::{TICKET_LEN, TicketCache, TicketIssuer};
use crate::handshake::{Initiator, Responder, Session};
use crate::kem::{DefaultHybrid, Kem};
use crate::rng::SysRng;
use crate::trust::TrustAnchor;
use crate::{Error, Result};

const T_MSG1: u8 = 0x01;
const T_COOKIE: u8 = 0x02;
const T_MSG1_RETRY: u8 = 0x03;
const T_MSG2: u8 = 0x04;
const T_MSG3: u8 = 0x05;
const T_MSG1_PSK: u8 = 0x06;
const T_PSK_REJECT: u8 = 0x07;

/// Application-layer prefix for the ticket-push message
const TICKET_PUSH_PREFIX: &[u8] = b"TKT1";

/// Per-frame size cap (protects against memory flooding; the largest handshake
/// frame is ~3.4 KB, leaving generous headroom)
const MAX_FRAME: usize = 1 << 20;

type HybridSecret = <DefaultHybrid as Kem>::SecretKey;

// ───────────────────────────── frame I/O ─────────────────────────────

fn write_frame<S: Write>(s: &mut S, ty: u8, payload: &[u8]) -> Result<()> {
    s.write_all(&[ty])?;
    s.write_all(&(payload.len() as u32).to_be_bytes())?;
    s.write_all(payload)?;
    s.flush()?;
    Ok(())
}

fn read_frame<S: Read>(s: &mut S) -> Result<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr)?;
    let n = u32::from_be_bytes(hdr[1..].try_into().unwrap()) as usize;
    if n > MAX_FRAME {
        return Err(Error::InvalidEncoding("frame length exceeds limit"));
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok((hdr[0], buf))
}

fn expect_frame<S: Read>(s: &mut S, want: u8) -> Result<Vec<u8>> {
    let (got, payload) = read_frame(s)?;
    if got != want {
        return Err(Error::HandshakeState("unexpected frame type (protocol disorder or injection)"));
    }
    Ok(payload)
}

// ───────────────────────────── session channel ─────────────────────────────

/// Encrypted session channel: an underlying byte stream + transport session (SM4-GCM + replay window)
pub struct SecureChannel<S> {
    stream: S,
    session: Session,
    /// Authenticated (signature + trust anchor, both checked) peer static public key
    peer_static: Vec<u8>,
}

impl<S: Read + Write> SecureChannel<S> {
    /// Send an encrypted message (frame = len || seq || ct || tag)
    pub fn send_msg(&mut self, data: &[u8]) -> Result<()> {
        let packet = self.session.send(data);
        self.stream.write_all(&(packet.len() as u32).to_be_bytes())?;
        self.stream.write_all(&packet)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive an encrypted message; authentication failure / replay both error out
    pub fn recv_msg(&mut self) -> Result<Vec<u8>> {
        let mut hdr = [0u8; 4];
        self.stream.read_exact(&mut hdr)?;
        let n = u32::from_be_bytes(hdr) as usize;
        if n > MAX_FRAME {
            return Err(Error::InvalidEncoding("message length exceeds limit"));
        }
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf)?;
        self.session.recv(&buf)
    }

    /// Session identifier (identical on both sides; useful for log correlation / key confirmation)
    pub fn session_id(&self) -> &[u8; 32] {
        self.session.session_id()
    }

    /// Authenticated peer static public key
    pub fn peer_static_key(&self) -> &[u8] {
        &self.peer_static
    }

    /// Release the underlying stream (the session is dropped with it; key material is zeroized)
    pub fn into_inner(self) -> S {
        self.stream
    }
}

// ───────────────────────────── client ─────────────────────────────

/// Client handshake outcome
pub struct ClientOutcome<S> {
    pub channel: SecureChannel<S>,
    /// The (ticket, PSK) pair issued by the server this time; store together for the next 0-RTT resumption
    pub resumption: Option<(Vec<u8>, [u8; 32])>,
    /// Whether this session was resumed
    pub resumed: bool,
    /// Whether 0-RTT early data was accepted by the server (meaningful only for a resumed session)
    pub early_data_accepted: bool,
}

/// Client full handshake (including the cookie challenge response)
pub fn client_connect_full<S: Read + Write>(
    mut stream: S,
    static_sk: HybridSecret,
    static_pk: Vec<u8>,
    anchor: &dyn TrustAnchor,
) -> Result<ClientOutcome<S>> {
    let mut rng = SysRng::new();
    let mut init = Initiator::<DefaultHybrid>::new(static_sk, static_pk);
    let e_pk = init.write_msg1(&mut rng)?;
    write_frame(&mut stream, T_MSG1, &e_pk)?;

    // The server answers with a stateless cookie challenge (DoS protection) and only
    // allocates session state after the echo is validated.
    let cookie = expect_frame(&mut stream, T_COOKIE)?;
    let mut retry = cookie;
    retry.extend_from_slice(&e_pk);
    write_frame(&mut stream, T_MSG1_RETRY, &retry)?;

    let m2 = expect_frame(&mut stream, T_MSG2)?;
    init.read_msg2(&m2)?;
    let (m3, session) = init.write_msg3_with_auth(&mut rng, anchor)?;
    write_frame(&mut stream, T_MSG3, &m3)?;

    let peer_static = init.peer_static().unwrap_or_default().to_vec();
    let mut channel = SecureChannel {
        stream,
        session,
        peer_static,
    };
    let resumption = recv_ticket_push(&mut channel)?;
    Ok(ClientOutcome {
        channel,
        resumption,
        resumed: false,
        early_data_accepted: false,
    })
}

/// Client resumption handshake (0-RTT); **automatically falls back** to a full handshake if the ticket is rejected
pub fn client_connect_resume<S: Read + Write>(
    mut stream: S,
    static_sk: HybridSecret,
    static_pk: Vec<u8>,
    anchor: &dyn TrustAnchor,
    ticket: &[u8],
    psk: &[u8; 32],
    early_data: Option<&[u8]>,
) -> Result<ClientOutcome<S>> {
    let mut rng = SysRng::new();
    let mut init = Initiator::<DefaultHybrid>::new_with_psk(static_sk, static_pk, psk);
    let e_pk = init.write_msg1(&mut rng)?;

    let mut payload = Vec::with_capacity(ticket.len() + e_pk.len() + 128);
    payload.extend_from_slice(ticket);
    payload.extend_from_slice(&e_pk);
    if let Some(ed) = early_data {
        payload.extend_from_slice(&init.seal_early_data(ed)?);
    }
    write_frame(&mut stream, T_MSG1_PSK, &payload)?;

    let (ty, m2_raw) = read_frame(&mut stream)?;
    match ty {
        T_PSK_REJECT => {
            // Invalid ticket: fall back to a full handshake (the server then runs the cookie flow)
            let (sk, pk) = init.into_static_keys()?;
            client_connect_full(stream, sk, pk, anchor)
        }
        T_MSG2 => {
            let (&accepted, m2) = m2_raw
                .split_first()
                .ok_or(Error::InvalidEncoding("MSG2 missing early_accepted flag"))?;
            init.read_msg2(m2)?;
            let (m3, session) = init.write_msg3_with_auth(&mut rng, anchor)?;
            write_frame(&mut stream, T_MSG3, &m3)?;
            let peer_static = init.peer_static().unwrap_or_default().to_vec();
            let mut channel = SecureChannel {
                stream,
                session,
                peer_static,
            };
            let resumption = recv_ticket_push(&mut channel)?;
            Ok(ClientOutcome {
                channel,
                resumption,
                resumed: true,
                early_data_accepted: accepted == 1,
            })
        }
        _ => Err(Error::HandshakeState("expected MSG2 or PSK_REJECT")),
    }
}

/// Receive the server's ticket push (the first encrypted message after the session is established)
fn recv_ticket_push<S: Read + Write>(
    channel: &mut SecureChannel<S>,
) -> Result<Option<(Vec<u8>, [u8; 32])>> {
    let msg = channel.recv_msg()?;
    let body = msg
        .strip_prefix(TICKET_PUSH_PREFIX)
        .ok_or(Error::HandshakeState("expected ticket push"))?;
    if body.len() < 2 + 32 {
        return Err(Error::InvalidEncoding("ticket push too short"));
    }
    let tlen = u16::from_be_bytes(body[..2].try_into().unwrap()) as usize;
    if body.len() != 2 + tlen + 32 {
        return Err(Error::InvalidEncoding("ticket push length mismatch"));
    }
    let ticket = body[2..2 + tlen].to_vec();
    let psk: [u8; 32] = body[2 + tlen..].try_into().unwrap();
    Ok(Some((ticket, psk)))
}

// ───────────────────────────── server ─────────────────────────────

/// Server configuration
pub struct ServerConfig<'a> {
    /// Cookie challenge issuer (DoS protection, required)
    pub cookie: &'a CookieIssuer,
    /// Resumption ticket issuer (required; [`TicketIssuer::new`] with process-level randomness suffices)
    pub tickets: &'a TicketIssuer,
    /// One-time ticket cache (replay interception; must be shared across connections)
    pub cache: &'a mut TicketCache,
    /// Client public-key trust anchor
    pub anchor: &'a dyn TrustAnchor,
    /// Transport-layer client identity tag (peer IP:port bytes over TCP)
    pub client_tag: &'a [u8],
    /// Ticket validity period (seconds)
    pub ticket_ttl_secs: u64,
}

/// Server handshake outcome
pub struct ServerOutcome<S> {
    pub channel: SecureChannel<S>,
    /// 0-RTT early data (present only for a resumed session where the client sent it; **the application MUST treat it as idempotent**)
    pub early_data: Option<Vec<u8>>,
    /// Whether this session was resumed
    pub resumed: bool,
}

/// Server: accept a byte stream and complete the hybrid handshake (cookie challenge / PSK resumption auto-dispatched)
pub fn server_accept<S: Read + Write>(
    mut stream: S,
    static_sk: HybridSecret,
    static_pk: Vec<u8>,
    cfg: &mut ServerConfig<'_>,
) -> Result<ServerOutcome<S>> {
    let mut rng = SysRng::new();

    let (ty, payload) = read_frame(&mut stream)?;
    match ty {
        // ── full handshake: cookie challenge first ──
        T_MSG1 => {
            let e_pk = payload;
            let cookie = cfg.cookie.issue(cfg.client_tag, &e_pk);
            write_frame(&mut stream, T_COOKIE, &cookie)?;
            let e_pk = cookie_roundtrip(&mut stream, cfg, e_pk)?;
            // Cookie passed — only from here on may session state be allocated
            // (KEM key generation and similar expensive work).
            full_handshake(stream, &mut rng, static_sk, static_pk, cfg, e_pk)
        }
        // ── resumption handshake: ticket validation (symmetric-only, very cheap) ──
        T_MSG1_PSK => {
            match try_resume(stream, &mut rng, &static_sk, &static_pk, cfg, &payload)? {
                ResumeAttempt::Done(out) => Ok(out),
                ResumeAttempt::Fallback(mut stream) => {
                    // Invalid / replayed ticket: reject and wait for the client to fall back to a full handshake
                    write_frame(&mut stream, T_PSK_REJECT, &[])?;
                    let e_pk = expect_frame(&mut stream, T_MSG1)?;
                    let cookie = cfg.cookie.issue(cfg.client_tag, &e_pk);
                    write_frame(&mut stream, T_COOKIE, &cookie)?;
                    let e_pk = cookie_roundtrip(&mut stream, cfg, e_pk)?;
                    full_handshake(stream, &mut rng, static_sk, static_pk, cfg, e_pk)
                }
            }
        }
        _ => Err(Error::HandshakeState("expected MSG1 or MSG1_PSK")),
    }
}

/// Cookie echo validation (no expensive work is done before the challenge passes)
fn cookie_roundtrip<S: Read + Write>(
    stream: &mut S,
    cfg: &ServerConfig<'_>,
    e_pk: Vec<u8>,
) -> Result<Vec<u8>> {
    let retry = expect_frame(stream, T_MSG1_RETRY)?;
    if retry.len() < COOKIE_LEN {
        return Err(Error::InvalidEncoding("MSG1_RETRY too short"));
    }
    let (cookie_echo, e_pk2) = retry.split_at(COOKIE_LEN);
    if e_pk2 != e_pk.as_slice() {
        return Err(Error::HandshakeState("echoed e_i differs from msg1"));
    }
    cfg.cookie.verify(cfg.client_tag, &e_pk, cookie_echo)?;
    Ok(e_pk)
}

/// Second half of the full handshake (cookie already passed; state allocation is now allowed)
fn full_handshake<S: Read + Write>(
    mut stream: S,
    rng: &mut SysRng,
    static_sk: HybridSecret,
    static_pk: Vec<u8>,
    cfg: &ServerConfig<'_>,
    e_pk: Vec<u8>,
) -> Result<ServerOutcome<S>> {
    let mut resp = Responder::<DefaultHybrid>::new(static_sk, static_pk);
    resp.read_msg1(&e_pk)?;
    let m2 = resp.write_msg2(rng)?;
    write_frame(&mut stream, T_MSG2, &m2)?;
    let m3 = expect_frame(&mut stream, T_MSG3)?;
    let (session, client_pk) = resp.read_msg3_with_auth(&m3, cfg.anchor)?;
    let channel = finish_server(stream, session, client_pk, cfg)?;
    Ok(ServerOutcome {
        channel,
        early_data: None,
        resumed: false,
    })
}

enum ResumeAttempt<S> {
    Done(ServerOutcome<S>),
    /// Fall back: hand the stream ownership back to the caller
    Fallback(S),
}

/// Resumption handshake attempt; returns Fallback on an invalid ticket so the caller runs the full handshake
fn try_resume<S: Read + Write>(
    mut stream: S,
    rng: &mut SysRng,
    static_sk: &HybridSecret,
    static_pk: &[u8],
    cfg: &mut ServerConfig<'_>,
    payload: &[u8],
) -> Result<ResumeAttempt<S>> {
    if payload.len() < TICKET_LEN + DefaultHybrid::PUBLIC_KEY_LEN {
        return Ok(ResumeAttempt::Fallback(stream));
    }
    let (ticket, rest) = payload.split_at(TICKET_LEN);
    let (e_pk, enc_early) = rest.split_at(DefaultHybrid::PUBLIC_KEY_LEN);

    // Ticket decryption + one-time check (symmetric-only; the reject path does zero expensive work)
    let ticket_payload = match cfg.tickets.open(ticket) {
        Ok(p) => p,
        Err(_) => return Ok(ResumeAttempt::Fallback(stream)),
    };
    if cfg
        .cache
        .check_and_insert(ticket_payload.ticket_id, ticket_payload.expires_at)
        .is_err()
    {
        return Ok(ResumeAttempt::Fallback(stream)); // replayed ticket
    }

    let mut resp = Responder::<DefaultHybrid>::new_with_psk(
        static_sk.clone(),
        static_pk.to_vec(),
        &ticket_payload.psk,
    );
    if resp.read_msg1(e_pk).is_err() {
        return Ok(ResumeAttempt::Fallback(stream));
    }
    let early_data = if enc_early.is_empty() {
        None
    } else {
        match resp.open_early_data(enc_early) {
            Ok(ed) => Some(ed),
            Err(_) => return Ok(ResumeAttempt::Fallback(stream)),
        }
    };

    let m2 = resp.write_msg2(rng)?;
    let mut m2_out = Vec::with_capacity(1 + m2.len());
    m2_out.push(if early_data.is_some() { 1 } else { 0 });
    m2_out.extend_from_slice(&m2);
    write_frame(&mut stream, T_MSG2, &m2_out)?;

    let m3 = expect_frame(&mut stream, T_MSG3)?;
    let (session, client_pk) = resp.read_msg3_with_auth(&m3, cfg.anchor)?;
    // Ticket identity binding: a public-key fingerprint mismatch means the ticket was stolen
    if sm3(&[&client_pk]) != ticket_payload.client_pk_fingerprint {
        return Err(Error::PeerAuth);
    }
    let channel = finish_server(stream, session, client_pk, cfg)?;
    Ok(ResumeAttempt::Done(ServerOutcome {
        channel,
        early_data,
        resumed: true,
    }))
}

/// Finalize: build the channel and push a fresh ticket (the first encrypted message)
fn finish_server<S: Read + Write>(
    stream: S,
    session: Session,
    client_pk: Vec<u8>,
    cfg: &ServerConfig<'_>,
) -> Result<SecureChannel<S>> {
    let mut channel = SecureChannel {
        stream,
        session,
        peer_static: client_pk.clone(),
    };
    let (ticket, psk) = cfg.tickets.issue(&client_pk, cfg.ticket_ttl_secs);
    let mut push = Vec::with_capacity(4 + 2 + ticket.len() + 32);
    push.extend_from_slice(TICKET_PUSH_PREFIX);
    push.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    push.extend_from_slice(&ticket);
    push.extend_from_slice(&*psk);
    channel.send_msg(&push)?;
    Ok(channel)
}
