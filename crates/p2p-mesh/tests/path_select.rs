//! Path-selection logic tests: RTT+loss combined effective score, switching, hysteresis, dwell, direct-down fallback

use std::time::{Duration, Instant};

use p2p_mesh::path::{PathKind, PathManager, PathSample};

const MS: Duration = Duration::from_millis(1); // Duration * u32 uses MS * n

fn rtt(ms: u64) -> PathSample {
    PathSample { rtt: Some(MS * ms as u32), loss: Some(0.0) }
}

fn rtt_loss(ms: u64, loss: f64) -> PathSample {
    PathSample { rtt: Some(MS * ms as u32), loss: Some(loss) }
}

#[test]
fn starts_on_relay_then_upgrades_to_direct() {
    let t0 = Instant::now();
    let mut pm = PathManager::new(t0);
    assert_eq!(pm.active(), PathKind::Relay);

    // relay probed at 20ms
    assert!(pm.on_sample(PathKind::Relay, rtt(20), t0).is_none());
    // direct not yet up: no switch
    assert!(pm.on_sample(PathKind::Direct, rtt(1), t0).is_none());
    assert_eq!(pm.active(), PathKind::Relay);

    // direct up + sample far better than relay => switch to direct
    pm.on_direct_up();
    let sw = pm.on_sample(PathKind::Direct, rtt(1), t0 + Duration::from_secs(1));
    assert!(sw.is_some());
    let sw = sw.unwrap();
    assert_eq!(sw.from, PathKind::Relay);
    assert_eq!(sw.to, PathKind::Direct);
    assert_eq!(pm.active(), PathKind::Direct);
}

#[test]
fn hysteresis_prevents_flap() {
    let t0 = Instant::now();
    let mut pm = PathManager::new(t0);
    pm.on_direct_up();
    pm.on_sample(PathKind::Relay, rtt(20), t0);
    pm.on_sample(PathKind::Direct, rtt(1), t0 + Duration::from_secs(1));
    assert_eq!(pm.active(), PathKind::Direct);

    // direct degrades to 15ms, relay 20ms: relay still worse, no switch
    let t = t0 + Duration::from_secs(2);
    pm.on_sample(PathKind::Relay, rtt(20), t);
    assert!(pm.on_sample(PathKind::Direct, rtt(15), t).is_none());
    assert_eq!(pm.active(), PathKind::Direct);

    // relay becomes better than direct but not 2x better (hysteresis threshold 0.5): still no switch
    pm.on_sample(PathKind::Relay, rtt(10), t + Duration::from_secs(1));
    pm.on_sample(PathKind::Relay, rtt(9), t + Duration::from_secs(2));
    assert_eq!(pm.active(), PathKind::Direct);
}

#[test]
fn loss_metric_triggers_fallback() {
    let t0 = Instant::now();
    let mut pm = PathManager::new(t0);
    pm.on_direct_up();
    // both sides at 10ms RTT with zero loss: direct wins (relay has a +5ms cost penalty)
    pm.on_sample(PathKind::Relay, rtt(10), t0);
    assert!(pm
        .on_sample(PathKind::Direct, rtt(10), t0 + Duration::from_secs(1))
        .is_some());
    assert_eq!(pm.active(), PathKind::Direct);

    // direct loss spikes to 30% (EWMA ramps up): effective = rtt*(1+10*loss),
    // when loss_ewma exceeds ~0.207, eff_direct≈30.7 > 2*relay(15) => switch back to relay
    let t = t0 + Duration::from_secs(2);
    pm.on_sample(PathKind::Relay, rtt(10), t);
    let mut sw = None;
    for i in 1..=4 {
        sw = pm.on_sample(
            PathKind::Direct,
            rtt_loss(10, 0.3),
            t + Duration::from_millis(100 * i),
        );
    }
    assert!(sw.is_some_and(|s| s.to == PathKind::Relay), "high loss should switch back to relay");
    assert_eq!(pm.active(), PathKind::Relay);
}

#[test]
fn min_dwell_blocks_immediate_switch() {
    let t0 = Instant::now();
    let mut pm = PathManager::new(t0);
    pm.on_direct_up();
    pm.on_sample(PathKind::Relay, rtt(5), t0);
    // first complete a real switch to direct (last_switch updated to t1)
    let t1 = t0 + Duration::from_secs(1);
    assert!(pm.on_sample(PathKind::Direct, rtt(1), t1).is_some());
    assert_eq!(pm.active(), PathKind::Direct);

    // direct degrades to 40ms, relay is very fast (0ms + 5ms penalty): should switch back to relay,
    // but the dwell period (500ms) must suppress it
    pm.on_sample(PathKind::Relay, rtt(0), t1 + Duration::from_millis(100));
    pm.on_sample(PathKind::Relay, rtt(0), t1 + Duration::from_millis(250));
    assert!(pm
        .on_sample(PathKind::Direct, rtt(40), t1 + Duration::from_millis(200))
        .is_none());
    assert!(pm
        .on_sample(PathKind::Direct, rtt(40), t1 + Duration::from_millis(300))
        .is_none());
    assert_eq!(pm.active(), PathKind::Direct);

    // after the dwell period, the same degraded samples trigger the switch back to relay
    assert!(pm
        .on_sample(PathKind::Direct, rtt(40), t1 + Duration::from_secs(2))
        .is_some_and(|sw| sw.to == PathKind::Relay));
    assert_eq!(pm.active(), PathKind::Relay);
}

#[test]
fn direct_down_falls_back_to_relay() {
    let t0 = Instant::now();
    let mut pm = PathManager::new(t0);
    pm.on_direct_up();
    pm.on_sample(PathKind::Relay, rtt(20), t0);
    pm.on_sample(PathKind::Direct, rtt(1), t0 + Duration::from_secs(1));
    assert_eq!(pm.active(), PathKind::Direct);

    // direct dropped => immediate fallback to relay (seamless switch)
    let sw = pm.on_direct_down(t0 + Duration::from_secs(2)).unwrap();
    assert_eq!(sw.to, PathKind::Relay);
    assert_eq!(pm.active(), PathKind::Relay);
}

#[test]
fn relay_only_when_no_direct_ever() {
    let t0 = Instant::now();
    let mut pm = PathManager::new(t0);
    pm.on_sample(PathKind::Relay, rtt(30), t0);
    pm.on_sample(PathKind::Relay, rtt(25), t0 + Duration::from_secs(1));
    assert_eq!(pm.active(), PathKind::Relay);
}
