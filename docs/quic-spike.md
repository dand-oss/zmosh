# Q1 QUIC feasibility spike report

**Verdict: GO** — both hard gates pass — **conditional on three named upstream
landings** before any production pin advances (the mechanism the plan itself
prescribes). No gate was weakened. Spike branch: `8sd1-quic-q1-spike` from
plan commit `d3cd508`.

## Inputs (exact)

| Input | Value |
|---|---|
| plan commit | `d3cd508e8f9b0c9edc050b04cd0f386eb9da0276` |
| code baseline | `6f4c4d19fd5143e13c71ddefb0c2e1023d56d4bf` (unmodified; spike only adds `spike/` + this report) |
| quicz pin | `b4352201f1217bbc4538e379be0f68f783558070` (fetched 2026-08-17, shallow) |
| Ghostty audited tree | `b97b17f06b1ffd694f80edd3df5dd2134a0bcb9e` (unrelated i18n commit; tree contains Snapshot v1) |
| Ghostty snapshot content ref | `1359973aefb37a9beaa2ec3e8f79df78290ea6f5` (last `src/terminal/snapshot/` change) |
| Ghostty main at spike time | `6c30dc1bfff7e22a9198931411ae862a6bb6277b` — still no snapshot re-export |
| Zig | `0.16.0` |
| quicz license | MIT (verified in tree) |

## Gate 1 — Ghostty public snapshot API: PASS (one-line upstream delta required)

- `ghostty_vt.snapshot` does **not** exist at the audited tree, at current
  main, or anywhere in `src/lib_vt.zig` history. The `ghostty-vt` module root
  never re-exports the snapshot package; only C exports
  (`ghostty_snapshot_*`, gated behind `features.snapshot`, which defaults ON)
  exist. The C path is not a fallback: it binds the C `TerminalWrapper` while
  zmosh owns a native Zig `ghostty_vt.Terminal`.
- `spike/patches/ghostty-snapshot-reexport.patch` adds the required public
  alias plus a compile-time alias check inside lib_vt's own test block.
- Proven by `spike/src/snapshot_access.zig` (2/2 tests): full
  encode → spool-first decode (`ready()` once → continuation replayed once →
  `next()` per history page → FINISH with zero trailing bytes) against a
  zmosh-style `Terminal` + `TerminalStream` (`vtHandler()`,
  `continuation_max_bytes`), with scrollback, title, and an unfinished CSI;
  **and** the Q4-critical semantic: post-cut output applied after READY but
  before any history page yields a terminal identical to an uninterrupted one.
- Ghostty's own `test-lib-vt` suite passes with the patch applied (exit 0).

## Gate 2 — certificate-free external-PSK TLS 1.3 (quicz): PASS, zero patches

The fail-first hard gate. quicz's TLS 1.3 already implements the external-PSK
path as an intended feature (`initClientWithPsk`, `initServerWithPsk`,
`setServerPskIdentity` documented as "preserves the external-PSK behavior";
with PSK selected the server flight is EncryptedExtensions + Finished with no
Certificate; with no certificate configured, an unmatched PSK cannot fall
back — `BadCertificate` internally).

Proven by `spike/src/quic_psk_gate.zig` (4/4 tests) over the **unmodified**
pin, through public APIs only (backend constructors + public
`hs.session_ticket` identity seeding, the same seeding quicz's own
connection tests perform):

- full handshake + 1-RTT stream echo, zero certificate material, PSK derived
  exactly per plan (HKDF-SHA256, context `zmosh quic psk v1`, identity
  `zmosh-ssh-bootstrap-v1`, ALPN `zmosh/1`), `zeroRttAccepted == false`
  both sides;
- wrong PSK → loud failure (binder check, `BadFinished` internally);
- wrong identity → loud failure (`BadCertificate` internally — no silent
  downgrade); ALPN mismatch → loud failure (`NoApplicationProtocol`
  internally). The sans-I/O CryptoBackend boundary reports all three as
  `error.CryptoError`; the specific internal errors are pinned by the test
  stack traces recorded in the run output.

## Transport, resource, and fault proofs: PASS (`quic_transport_proofs.zig`, 8/8)

Deterministic impairment wire (drop / duplicate / adjacent-swap reorder /
corrupt-last-byte / timed blackout) under the sans-I/O lifecycle layer:

- **Handshake packet loss**: dropped Initial recovered via PTO under the
  manual clock (`completeHandshakeWithRecovery`); handshake confirmed.
- **Reordering + duplication**: held datagram overtaken by the next; each
  stream's bytes delivered exactly once, in order; duplicated datagrams
  deduped by packet number.
- **Corruption**: AEAD-failed datagram discarded, connection stays active,
  subsequent traffic delivers exactly (retransmission rides the PTO path
  proven by the loss case and quicz's own suite).
- **Blackout** (10 s outage scaled to 100 ms): everything dropped during the
  window; data flows immediately after.
- **Stream isolation**: with per-stream credit exhausted
  (`FlowControlBlocked` on the stalled stream), a second stream and control
  PING still deliver — the Q4/Q5 stalled-output invariant.
- **Negotiated bounds**: advertised 4 MiB connection credit, 4 bidi / 8 uni
  streams; the fifth bidi open is refused (`FlowControlBlocked`).
- **RESET_STREAM / STOP_SENDING observable** via `StreamState`
  (`receive_reset_error_code`, `receive_stop_sending_sent`).
- **Idle/keepalive**: 24 h `max_idle_timeout` negotiated (asserted effective
  value; no 24 h wall-clock run, per plan), scaled 100 ms idle expiry closes
  the connection after servicing, scaled keepalive PINGs hold it open.
- **Migration**: upstream `connection_migration` demo executed green
  (PATH_CHALLENGE → PATH_RESPONSE, route update via `updateRoutePath`);
  in-spike migration with active migration enabled is deferred to Q2's
  poll()-loop integration (the lifecycle path-update API family is present:
  `feedDatagramWithInstalledKeysAndUpdatePathOrClose*`).
- **Per-stream outstanding bytes / oldest-unacked age**: required for Q5's
  bounded output replacement; quicz upstream lacks it. Patch
  `spike/patches/quicz-stream-inflight-metrics.patch` (61 lines, read-only
  queries over `send_queue` + in-flight `sent_packets`, which ACKs empty)
  adds `streamSendOutstandingBytes` + `streamSendOldestUnackedSentTimeNanos`;
  proven 0 → N → 0 across an ACK round trip; **quicz's own suite passes
  1883/1883 with the patch applied.**

## quicz upstream suite at the pin

`zig build quicz-suite`: **1883/1883 pass** (patched tree; the suite also
passed 1883/1883 before the patch when first invoked from this spike).

## Measurements (Linux x86_64)

| Metric | Value |
|---|---|
| zmosh `6f4c4d1`, stripped ReleaseSafe | 2,573,800 B (2.46 MiB) |
| quicz size probe, stripped ReleaseSafe | 366,040 B |
| projected `zmosh + quicz` growth | ≈ +0.37 MiB (gate: ≤ 5 MiB) — PASS |
| zmosh baseline clean build (ReleaseSafe) | ~2 m 54 s user |
| quicz marginal compile (probe exe) | ~12 s (gate: ≤ 2× `zig build check`) — PASS |
| new dynamic libraries | none (static, pure Zig + std) |

Caveat: the true like-for-like binary/build gate re-runs at Q2 integration;
these numbers bound the dependency's marginal cost.

## Platform gates

- Linux Debug + ReleaseSafe: all spike builds green.
- **aarch64-macos cross-compile: PASS** (probe built, 271,856 B).
- Apple execution: not run (remains a release gate per plan).

## Required upstream landings before the production pin advances

1. **Ghostty** `pub const snapshot = terminal.snapshot;` in `src/lib_vt.zig`
   (patch attached; suite-green). Blocks both the QUIC and fallback branches.
2. **quicz** per-stream outstanding-byte/oldest-unacked queries (patch
   attached; suite-green). Required for Q5's 1 MiB / 5 s output replacement.
3. **quicz sans-I/O IPv6 routing**: the routing layer is IPv4-typed
   (`Udp4Tuple`/`Udp4Address`); `udp_event_loop` provides dual-stack sockets
   (`bindIpv6DualStack`, v4-mapped peers) but **native IPv6 peers cannot be
   represented** in the sans-I/O route types. Q2 keeps zmosh's dual-stack
   bind, so this needs a small upstreamable widening (v6 tuple or
   address-agnostic routing). Not implemented in this spike — the one
   transport-proof item not demonstrated end-to-end.

Ergonomic (optional) upstream nicety: a PSK field on the QUIC-layer transport
config instead of public-field identity seeding.

## Not covered by the spike (recorded, not silently dropped)

- Real-socket behavior: PMTU/DPLPMTUD 1200→1350, IPv6 on-wire, Retry token
  issuance (spike models validated addresses via `validatePeerAddress()`;
  upstream ships retry_token + udp_retry_loopback demos), 30-minute soak,
  real SSH smoke — all Q2+ / release gates.
- Process cleanup (orphan SSH/gateway/session): sans-I/O has no processes;
  proven at Q2 integration via Bats.
- Key-material zeroization inside quicz internals; zmosh-side bootstrap/PSK
  zeroization is Q2 code. No qlog enabled; no secrets logged by the spike.
- Second-client rejection is an application policy (one authenticated
  connection per ephemeral gateway) enforced at Q2/Q3; QUIC-level connection
  isolation is inherent (separate CIDs/connections).

## Reproduction

```
# deps (gitignored): shallow-fetch ghostty b97b17f... into spike/deps/ghostty
#                     (apply spike/patches/ghostty-snapshot-reexport.patch)
#                     shallow-fetch quicz b4352201... into spike/deps/quicz-upstream
#                     (apply spike/patches/quicz-stream-inflight-metrics.patch)
cd spike
zig build spike-test --summary all   # 14/14: snapshot 2, PSK 4, proofs 8
zig build quicz-suite --summary all  # 1883/1883
zig build size-probe -Doptimize=ReleaseSafe          # 366,040 B stripped
zig build size-probe -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
zig fmt --check build.zig build.zig.zon src/*.zig
```

## Recommendation

Proceed to review. On acceptance, upstream the three deltas (Ghostty
re-export; quicz metrics; quicz IPv6 routing) and advance both production
pins to the exact reviewed commits containing them, per plan Phase Q1/Q4. If
any landing is refused, the documented fallback activates without weakening
any gate.
