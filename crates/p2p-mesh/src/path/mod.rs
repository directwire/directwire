//! Path manager: direct + relay paths coexist, periodic probing, seamless switching (simplified multipath)
//!
//! Metrics: RTT (EWMA) + loss rate (EWMA, 0..1), combined into an effective score:
//!   eff = rtt_ms * (1 + LOSS_WEIGHT * loss)   (relay adds a fixed cost penalty)
//! Rules (mirroring iroh's best-path policy, plus hysteresis to avoid flapping):
//! - direct unavailable => relay
//! - currently relay, direct has sampled and beats relay * margin => switch to direct
//! - currently direct, relay is still significantly better (< direct * 0.5) => switch back to relay (strong hysteresis)
//! - min_dwell dwell time between switches prevents flapping
//! - relay is compared with a fixed cost penalty (RELAY_PENALTY_MS): relay is a paid, scarce resource; direct is preferred

use std::time::{Duration, Instant};

/// Cost penalty for the relay path (ms): direct wins even at a slightly higher RTT —
/// relay is a paid/scarce resource (bandwidth cost) plus an extra forwarding hop. iroh likewise
/// unconditionally prefers direct.
const RELAY_PENALTY_MS: f64 = 5.0;

/// Loss-rate penalty weight: at loss=10% the effective score doubles (packet loss hurts
/// throughput/latency tails non-linearly)
const LOSS_WEIGHT: f64 = 10.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSwitch {
    pub from: PathKind,
    pub to: PathKind,
}

/// One path measurement sample (rtt/loss can update independently)
#[derive(Debug, Clone, Copy, Default)]
pub struct PathSample {
    pub rtt: Option<Duration>,
    /// Loss rate 0.0..=1.0 (interval measurement)
    pub loss: Option<f64>,
}

/// f64 exponential moving average
#[derive(Debug, Clone, Copy)]
struct Ewma(f64);

impl Ewma {
    fn sample(&mut self, v: f64) {
        self.0 = 0.7 * self.0 + 0.3 * v;
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PathMetrics {
    rtt_ms: Option<Ewma>,
    loss: Option<Ewma>,
}

impl PathMetrics {
    /// Effective score (ms equivalent); an unsampled RTT means unavailable
    fn effective(&self, penalty_ms: f64) -> Option<f64> {
        let rtt = self.rtt_ms?.0;
        let loss = self.loss.map(|l| l.0.clamp(0.0, 1.0)).unwrap_or(0.0);
        Some(rtt * (1.0 + LOSS_WEIGHT * loss) + penalty_ms)
    }
}

pub struct PathManager {
    active: PathKind,
    direct_up: bool,
    relay: PathMetrics,
    direct: PathMetrics,
    /// Direct must beat relay * margin before switching in (default 0.8)
    switch_margin: f64,
    /// Minimum dwell time
    min_dwell: Duration,
    last_switch: Instant,
}

impl PathManager {
    /// Starts on the relay path only (a node is always reachable via the relay first)
    pub fn new(now: Instant) -> Self {
        Self {
            active: PathKind::Relay,
            direct_up: false,
            relay: PathMetrics::default(),
            direct: PathMetrics::default(),
            switch_margin: 0.8,
            min_dwell: Duration::from_millis(500),
            last_switch: now - Duration::from_secs(3600), // treat as having dwelled long ago
        }
    }

    pub fn active(&self) -> PathKind {
        self.active
    }

    /// Observable query (for display): returns (rtt_ms, loss)
    pub fn metrics(&self, kind: PathKind) -> (Option<f64>, Option<f64>) {
        let m = match kind {
            PathKind::Direct => &self.direct,
            PathKind::Relay => &self.relay,
        };
        (m.rtt_ms.map(|e| e.0), m.loss.map(|e| e.0))
    }

    /// Direct path established (hole punch succeeded)
    pub fn on_direct_up(&mut self) {
        self.direct_up = true;
    }

    /// Direct path dropped
    pub fn on_direct_down(&mut self, now: Instant) -> Option<PathSwitch> {
        self.direct_up = false;
        self.direct = PathMetrics::default();
        if self.active == PathKind::Direct {
            return Some(self.switch_to(PathKind::Relay, now));
        }
        None
    }

    /// Measurement sample input (RTT/loss); returns whether a switch happened
    pub fn on_sample(
        &mut self,
        kind: PathKind,
        sample: PathSample,
        now: Instant,
    ) -> Option<PathSwitch> {
        let m = match kind {
            PathKind::Direct => &mut self.direct,
            PathKind::Relay => &mut self.relay,
        };
        if let Some(rtt) = sample.rtt {
            let ms = rtt.as_secs_f64() * 1000.0;
            match &mut m.rtt_ms {
                Some(e) => e.sample(ms),
                None => m.rtt_ms = Some(Ewma(ms)),
            }
        }
        if let Some(loss) = sample.loss {
            match &mut m.loss {
                Some(e) => e.sample(loss),
                None => m.loss = Some(Ewma(loss)),
            }
        }
        self.decide(now)
    }

    fn decide(&mut self, now: Instant) -> Option<PathSwitch> {
        if now.duration_since(self.last_switch) < self.min_dwell {
            return None;
        }
        match self.active {
            PathKind::Relay => {
                if !self.direct_up {
                    return None;
                }
                let d = self.direct.effective(0.0)?;
                // Direct can switch in by default when relay is unsampled; otherwise compare
                // effective scores (relay includes the cost penalty)
                let better = match self.relay.effective(RELAY_PENALTY_MS) {
                    Some(r) => d < r * self.switch_margin,
                    None => true,
                };
                better.then(|| self.switch_to(PathKind::Direct, now))
            }
            PathKind::Direct => {
                if !self.direct_up {
                    return Some(self.switch_to(PathKind::Relay, now));
                }
                let d = self.direct.effective(0.0)?;
                let r = self.relay.effective(RELAY_PENALTY_MS)?;
                // Strong hysteresis: switch back only if relay (after its penalty) is still
                // more than twice as good as direct
                (r < d * 0.5).then(|| self.switch_to(PathKind::Relay, now))
            }
        }
    }

    fn switch_to(&mut self, to: PathKind, now: Instant) -> PathSwitch {
        let sw = PathSwitch {
            from: self.active,
            to,
        };
        self.active = to;
        self.last_switch = now;
        sw
    }
}
