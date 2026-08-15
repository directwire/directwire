//! Client-server loopback handshake + encrypted echo demo.
//!
//! Usage:
//!   cargo run --example handshake_echo            # run all three modes and compare timings
//!   cargo run --example handshake_echo -- hybrid  # hybrid mode only
//!
//! Architecture: the main thread starts a TCP loopback listener (server); a client thread
//! connects, runs the Noise-XX hybrid handshake (three messages), then exchanges SM4-GCM
//! encrypted echoes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use gm_pq_stack::handshake::{Initiator, Responder, Session};
use gm_pq_stack::kem::{DefaultHybrid, Kem, MlKem768Kem, Mode, Sm2Kem};
use gm_pq_stack::rng::SysRng;

/// Frame format: u32 BE length || payload
fn write_frame(s: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    s.write_all(&(data.len() as u32).to_be_bytes())?;
    s.write_all(data)?;
    s.flush()
}

fn read_frame(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok(buf)
}

/// Server: accept one connection, complete the handshake, then echo 3 encrypted messages
fn run_server<K: Kem>(listener: TcpListener) -> std::io::Result<()> {
    let (mut stream, _) = listener.accept()?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut rng = SysRng::new();
    let (sk, pk) = K::keypair(&mut rng).expect("server key generation failed");

    let mut resp = Responder::<K>::new(sk, pk);
    resp.read_msg1(&read_frame(&mut stream)?).expect("msg1");
    let m2 = resp.write_msg2(&mut rng).expect("msg2");
    write_frame(&mut stream, &m2)?;
    let mut session: Session = resp.read_msg3(&read_frame(&mut stream)?).expect("msg3");

    for _ in 0..3 {
        let pt = session
            .recv(&read_frame(&mut stream)?)
            .expect("decrypt failed");
        write_frame(&mut stream, &session.send(&pt))?;
    }
    Ok(())
}

/// Client: connect + time the handshake + verify encrypted echo
fn run_client<K: Kem>(addr: std::net::SocketAddr) -> (Duration, Duration) {
    let mut rng = SysRng::new();
    let (sk, pk) = K::keypair(&mut rng).expect("client key generation failed");

    let mut stream = TcpStream::connect(addr).expect("connection failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let t0 = Instant::now();
    let mut init = Initiator::<K>::new(sk, pk);
    let m1 = init.write_msg1(&mut rng).unwrap();
    write_frame(&mut stream, &m1).unwrap();
    let m2 = read_frame(&mut stream).unwrap();
    init.read_msg2(&m2).unwrap();
    let (m3, mut session) = init.write_msg3(&mut rng).unwrap();
    write_frame(&mut stream, &m3).unwrap();
    let handshake_time = t0.elapsed();

    let t1 = Instant::now();
    for i in 0..3u8 {
        let msg = format!("loopback echo message #{i}");
        write_frame(&mut stream, &session.send(msg.as_bytes())).unwrap();
        let reply = session.recv(&read_frame(&mut stream).unwrap()).unwrap();
        assert_eq!(reply, msg.as_bytes(), "echo content must match");
    }
    (handshake_time, t1.elapsed())
}

fn bench<K: Kem>(mode: Mode) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = std::thread::spawn(move || run_server::<K>(listener));
    let (hs, echo) = run_client::<K>(addr);
    handle.join().unwrap().unwrap();

    println!(
        "  {:<22} handshake {:>8.2?}   3 encrypted echoes {:>8.2?}   ✅ echoes match",
        mode.name(),
        hs,
        echo
    );
}

fn main() {
    let mode_arg = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    println!("gm-pq-stack loopback handshake + encrypted echo demo (127.0.0.1)");
    println!(
        "mode comparison: pure SM2 (compliant) / pure ML-KEM (post-quantum) / hybrid (recommended)\n"
    );

    match mode_arg.as_str() {
        "sm2" => bench::<Sm2Kem>(Mode::Sm2Only),
        "mlkem" => bench::<MlKem768Kem>(Mode::MlKemOnly),
        "hybrid" => bench::<DefaultHybrid>(Mode::Hybrid),
        _ => {
            bench::<Sm2Kem>(Mode::Sm2Only);
            bench::<MlKem768Kem>(Mode::MlKemOnly);
            bench::<DefaultHybrid>(Mode::Hybrid);
        }
    }
    println!(
        "\nNote: the hybrid mode's cost is roughly the sum of both, buying the double insurance that the session stays secure even if one national algorithm standard is broken."
    );
}
