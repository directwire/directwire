# INTEGRATION.md — downstream integration guide (object-stream / p2p-mesh)

**The contract in one sentence**: you have an established bidirectional byte stream (`Read + Write`);
gm-pq-stack runs the SM2+ML-KEM-768 hybrid handshake over it and returns an encrypted session channel.
You never touch any cryptography details.

## Minimal integration (5 steps)

```rust
use gm_pq_stack::api::{client_connect_full, client_connect_resume, server_accept, ServerConfig};
use gm_pq_stack::handshake::cookie::CookieIssuer;
use gm_pq_stack::handshake::psk::{TicketCache, TicketIssuer};
use gm_pq_stack::kem::{DefaultHybrid, Kem};
use gm_pq_stack::rng::SysRng;
use gm_pq_stack::trust::PinFileAnchor;

// -- server side (once at process startup) --
let mut rng = SysRng::new();
let (server_sk, server_pk) = DefaultHybrid::keypair(&mut rng)?;
let cookie   = CookieIssuer::new(30);        // DoS challenge, process-level
let tickets  = TicketIssuer::new();          // resumption-ticket key, process-level
let mut cache = TicketCache::new();          // ticket replay interception, shared across connections
let server_anchor = PinFileAnchor::from_keys([("client-01", &client_pk)]);
//                                        ↑ production: use PinFileAnchor::from_file("pins.txt")

// -- per connection --
let out = server_accept(stream, server_sk.clone(), server_pk.clone(), &mut ServerConfig {
    cookie: &cookie, tickets: &tickets, cache: &mut cache,
    anchor: &server_anchor,
    client_tag: peer_addr_string.as_bytes(),  // TCP: the peer "IP:port"
    ticket_ttl_secs: 3600,
})?;
let mut ch = out.channel;                    // SecureChannel<S>
ch.send_msg(b"...")?; let msg = ch.recv_msg()?;

// -- client side --
let (client_sk, client_pk) = DefaultHybrid::keypair(&mut rng)?;
let client_anchor = PinFileAnchor::from_keys([("server", &server_pk)]);

// first connection (full handshake, auto-answers the cookie challenge)
let out = client_connect_full(stream, client_sk.clone(), client_pk.clone(), &client_anchor)?;
let (ticket, psk) = out.resumption.unwrap(); // save as a pair (memory or encrypted at rest)

// reconnect (0-RTT: early_data arrives with the first message at the server; on ticket expiry
// auto-falls back to the full handshake)
let out = client_connect_resume(stream2, client_sk, client_pk, &client_anchor,
                                &ticket, &psk, Some(b"idempotent-op"))?;
```

## API-shape cheat sheet

| entry | inputs | output |
|---|---|---|
| `client_connect_full(stream, sk, pk, anchor)` | bidirectional byte stream + static keys + trust anchor | `ClientOutcome { channel, resumption, resumed, .. }` |
| `client_connect_resume(stream, sk, pk, anchor, ticket, psk, early_data)` | + last-saved (ticket, psk) | same; on ticket rejection auto-falls back to the full handshake |
| `server_accept(stream, sk, pk, &mut ServerConfig)` | + cookie/tickets/anchor/client tag | `ServerOutcome { channel, early_data, resumed }` |
| `channel.send_msg(&[u8])` / `recv_msg() -> Vec<u8>` | message | SM4-GCM encryption + sequence + replay window |

## The three red lines integrators must know

1. **`client_tag` must bind to the transport-layer source identity** (TCP: the peer `IP:port` string bytes);
   otherwise the cookie challenge cannot defend against spoofed source addresses — that is the entire point of the DoS protection.
2. **0-RTT early data must be idempotent.** The ticket cache intercepts same-ticket replay, but there is a theoretical
   replay window across server restarts (ticket-key rotation); and 0-RTT data has no full forward secrecy.
   Do non-idempotent operations (debits, counters) after the handshake completes (`out.resumed` onward, as normal messages).
3. **`TicketCache` must be shared across connections** (one instance per server process). Multi-instance deployments
   need a shared-storage implementation, or ticket-replay interception breaks.

## Adapting non-TCP byte streams

Any `std::io::Read + Write` works: a QUIC stream via an adapter, an in-memory duplex pair for message channels.
If your transport is already a reliable in-order message channel (e.g. an object-stream transport), just wrap it in a
length-prefixed Read/Write adapter — the handshake frames carry their own type + length and don't depend on TCP framing.

## Internal state machines (only if you need to customize)

`handshake::{Initiator, Responder}` are pure in-memory state machines (write_msgN → bytes,
read_msgN(bytes)), touching no IO — if p2p-mesh wants to stuff them into a pocket-hole-punch signaling channel,
use this layer directly and bypass the `api` module. The cookie/ticket logic lives in
`handshake::{cookie, psk}`, likewise purely functional.
