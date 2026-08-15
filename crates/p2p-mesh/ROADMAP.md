# ROADMAP — 12 months (2026-09 → 2027-08)

## Q1 (2026-09 ~ 11) MVP hardening → internal alpha
**Goal**: the current skeleton is "demoable to a customer, works on real NAT environments"
- M1: ~~STUN-like address discovery~~ ✅ (observed echo + multi-NIC candidates); residual: real STUN + NAT-type probing + real-NAT punch measurements (home/enterprise/4G), success-rate baseline report
- M2: ~~Noise IK forward secrecy~~ ✅ (ephemeral X25519 + identity signature); residual: x509-parser, private-key zeroize
- M3: ~~concurrent multi-peer + unified peer table~~ ✅; residual: unify punch/QUIC socket (real-NAT semantics), IPv6 candidates, punch telemetry
- M4: ~~loss-rate in path selection~~ ✅; residual: bandwidth/jitter metrics
- Headcount: 2 × 3 months (1 protocol + 1 test/infra)

## Q2 (2026-12 ~ 2027-02) alpha → pilot customers
**Goal**: 2-3 toB pilots (enterprise networking / IoT direct)
- M1: multi-instance relay redundancy + client failover (multi-peer concurrency already done early in Q1 ✅)
- M2: path-manager upgrade: multi-metric selection (RTT+loss+bandwidth), evaluate QUIC multipath (RFC draft tracking)
- M3: private-deployment package (one-click relay deploy, node SDK, audit logs)
- M4: pilot delivery + on-site NAT environment adaptation
- Headcount: 4 × 3 months (2 protocol + 1 backend + 1 delivery)

## Q3 (2027-03 ~ 05) beta → productization
**Goal**: a self-service deployable product
- M1: management plane: node admission/revocation (certificate pinning lists), ACLs, traffic audit reports
- M2: weak-network optimization: fast punch-failure detection, relay congestion-control tuning, mobile (Android/iOS) SDK
- M3: performance: single relay 100k connections, direct throughput saturating gigabit
- M4: third-party security audit + MLPS (grading protection) compliance materials
- Headcount: 6 × 3 months (+1 mobile +1 security/compliance)

## Q4 (2027-06 ~ 08) commercialization
**Goal**: scaled sales
- M1: billing/licensing (per-node subscription); channel delivery docs and certified training
- M2: industry templates: manufacturing IoT, retail-chain networking, remote-ops jump host
- M3: SLA framework: relay availability 99.9%, hole-punch success SLA ≥90% (vs iroh's 92% benchmark)
- Headcount: 8 (+2 pre-sales/delivery)

## Key milestones & risks
| milestone | date | acceptance | risk |
|---|---|---|---|
| real-NAT punch baseline | 2026-10 | success-rate report | China's high share of symmetric NAT → reserve relay capacity plan |
| first pilot live | 2027-02 | customer acceptance form | on-site network adaptation effort |
| third-party security audit | 2027-05 | audit report passed | self-built crypto modules are the focus |
| commercial GA | 2027-08 | ≥5 paying customers | sales cycle |

**Red line**: no public-internet P2P bandwidth business; relays are customer-private deployments or enterprise-dedicated instances we host.
