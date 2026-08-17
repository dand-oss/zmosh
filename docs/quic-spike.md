# Q1 QUIC feasibility spike report — FINAL GO (fork-based)

**Verdict: GO.** Both hard gates pass against the pinned dand-oss forks.
Every gate in this report is demonstrated by a committed, reproducible
command. Spike branch: `8sd1-quic-q1-spike` (from plan commit `d3cd508`).

## Exact dependency pins (frozen)

| Dependency | Pin | Base | Immutable tag |
|---|---|---|---|
| Ghostty | `git+https://github.com/dand-oss/ghostty#6361b2eac73e8243a7042f517ea95ab87165f105` (hash `ghostty-1.3.2-dev-5UdBC5L2RQWfmtJwTX8gKITqL4rOJteCksb42xxDS9bD`) | upstream `56e1f3a62` | `zmosh-snapshot-v1` |
| quicz | `git+https://github.com/dand-oss/quicz#3a75a8b63dd4137f07932d3d85ee773b24ad80c1` (hash `quicz-0.1.0-g2J97wnalQAlU1OTFc0pxSqOUiss5nIF4aujfx6zy09C`) | upstream `b4352201` | `zmosh-quic-q1-2` |

Both forks keep their original projects configured as upstream remotes
(`ghostty-org/ghostty`, `venjiang/quicz`) for future synchronization. zmosh
pins exact fork commits; branch heads are never pins, and tags never move.
`zmosh-quic-q1` (at `77b5007`, the first five quicz commits) is also
immutable history.

## Gate 1 — Ghostty public snapshot API: PASS

- Upstream has no `ghostty_vt.snapshot` (verified at the audited tree
  `b97b17f`, at main `6c30dc1b`, and across `lib_vt.zig` history). The C
  API is not a fallback: it binds the C `TerminalWrapper` while zmosh owns
  a native Zig `ghostty_vt.Terminal`.
- Fork commit `6361b2eac` adds the public alias
  `pub const snapshot = terminal.snapshot;` plus a compile-time alias
  check in lib_vt's own test block. Snapshot content reference is still
  `1359973ae` (last `src/terminal/snapshot/` change).
- Ghostty's `test-lib-vt` suite passes at the pin (exit 0).
- Spike proof (2/2): full encode → spool-first decode round trip with
  scrollback, title, unfinished-CSI continuation, zero trailing bytes;
  and post-cut output applied after READY but before any history page
  yielding a terminal identical to an uninterrupted one.

## Gate 2 — certificate-free external-PSK TLS 1.3: PASS

Fork APIs make the zmosh configuration public and explicit
(`setClientPskIdentity`, `disable_session_resumption = true`); no
handshake-field mutation and no certificate material anywhere.

4/4 gate tests, all through the pinned fork:

- full handshake + 1-RTT stream echo; PSK derived per plan
  (HKDF-SHA256, context `zmosh quic psk v1`, identity
  `zmosh-ssh-bootstrap-v1`, ALPN `zmosh/1`);
- **no resumption state after application crypto**: no ticket stored, no
  derived PSK (`resumption_psk == null`), 0-RTT never offered or accepted
  (enforced by the fork's explicit disable, tested in-quicz as well);
- wrong PSK / wrong identity / ALPN mismatch all fail loudly (binder
  failure, certificate-path rejection with no certificate configured,
  no-application-protocol; surfaced as `CryptoError` at the sans-I/O
  boundary with the specific internal errors pinned by stack traces);
- **secure teardown demonstrably zeroizes**: both backends wiped, key
  schedule early secrets, the external PSK, and the ephemeral X25519
  private key verified all-zero afterwards (quicz's `secureWipe`, called
  by `Connection.deinit` and tested in-fork for handshake/0-RTT/1-RTT key
  phases including retained key-update generations).

## Transport, resource, and fault proofs: PASS (10/10)

In-process deterministic wire (drop / duplicate / adjacent-swap reorder /
corrupt-last-byte / timed delay / timed blackout) with a recovery pump
that arms endpoint recovery timers from connection loss state, jumps the
manual clock to due recovery deadlines, and services the Initial /
Handshake / 1-RTT recovery bridges:

- **Handshake packet loss**: dropped Initial recovered via PTO; handshake
  confirmed both sides (client confirmation included via HANDSHAKE_DONE).
- **Corruption**: the AEAD-failed datagram is discarded without killing
  the connection and its bytes are still delivered **exactly once, in
  order** ("AAAA" lost to corruption, "BBBB" survives, loss detection
  requeues A, server assembles exactly `AAAABBBB`).
- **Blackout** (10 s scaled to 100 ms): nothing delivers during the
  outage; the lost bytes are delivered exactly once afterwards; fresh
  traffic flows immediately.
- **Delay**: datagrams held two pump cycles deliver exactly once.
- **Reordering + duplication**: overtaken datagram still arrives exactly
  once; duplicated datagrams deduped by packet number.
- **Keepalive across multiple original idle deadlines**: 500 ms idle with
  20 ms PINGs survives 1.2 s (>2 deadlines) and then actually closes once
  keepalives stop — the deadlines were real.
- **STOP_SENDING** observed by the peer producing **RESET_STREAM with the
  same code** (7777) — quicz's native reaction, proven end to end.
- **streamSendProgress** end to end: logical offsets 0 → N → 0 across an
  ACK round trip; in-fork stress additionally covers in-order, partial,
  out-of-order, and duplicate ACKs, retransmitted copies, FIN completion,
  and reset (1889/1889 fork tests).
- **Slow reader**: unread stream bounds sender memory at the negotiated
  256-byte credit (`FlowControlBlocked`), other streams unaffected.
- **NAT rebinding**: data from the new source port is accepted and flows
  (routing by DCID), while the committed route moves only after path
  validation — the plan's validation-before-commit discipline.
- **Negotiated bounds**: 4 MiB connection credit, 4 bidi / 8 uni streams
  advertised and enforced (fifth open refused).

## Real-socket proofs: PASS (3/3)

Actual UDP sockets, poll()-driven exchange, PSK handshake plus 1-RTT echo:

- **IPv4** loopback;
- **native IPv6** loopback — end to end through the fork's
  address-neutral routing and process entries;
- **dual-stack**: an IPv6 server socket on `::` serving an IPv4-mapped
  client, with the route keyed on the kernel-reported v4-mapped peer;
- datagram sizes: client Initials padded to exactly 1200 bytes; nothing
  exceeds the configured 1200-byte cap in either direction.

## Upstream fork commits (each atomic, full suite green per commit)

dand-oss/quicz, from `b4352201`:

1. `e8f721e` backend: `setClientPskIdentity` for external-PSK offers
2. `de10701` tls: explicit `disable_session_resumption` flag
3. `3525ad5` endpoint: address-family-neutral UDP routing + IPv4 helpers
4. `f8950a0` connection: `streamSendProgress` send-side accounting
5. `77b5007` crypto: `secureWipe` zeroization (tag `zmosh-quic-q1`)
6. `3a75a8b` lifecycle: address-neutral route/process entries
   (tag `zmosh-quic-q1-2`)

dand-oss/ghostty, from `56e1f3a62`:

1. `6361b2eac` libghostty-vt: public Zig-native snapshot re-export
   (tag `zmosh-snapshot-v1`)

## Measurements (Linux x86_64, Zig 0.16.0)

| Metric | Value |
|---|---|
| quicz suite at the pin | **1891/1891** (each fork commit suite-green) |
| Ghostty `test-lib-vt` at the pin | exit 0 |
| spike `zig build test` | **19/19** (Debug and ReleaseSafe) |
| zmosh on the spike branch | check ✓, unit 134/134 ✓, full Bats ✓ |
| stripped zmosh baseline (`6f4c4d1`, ReleaseSafe) | 2,573,800 B |
| quicz size probe, stripped ReleaseSafe | 366,408 B |
| projected binary growth | ≈ +0.37 MiB (gate ≤ 5 MiB) |
| aarch64-macos cross-compile | PASS (271,856 B probe) |
| new dynamic libraries | none |

## Verification commands

```
cd spike
zig build test --summary all              # 19/19
zig build test -Doptimize=ReleaseSafe     # 19/19
zig build quicz-suite --summary all       # 1891/1891 at the pin
zig build size-probe -Doptimize=ReleaseSafe
zig build size-probe -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
zig fmt --check build.zig build.zig.zon src/*.zig
cd .. && zig build check && zig build test && bats test
```

Dependencies reproduce from the exact URLs and hashes in
`spike/build.zig.zon`; no local trees or patch files remain.

## Deferred to release-only gates (recorded, not silently dropped)

- Real macOS/iOS execution (cross-compile only here).
- 30-minute impaired-network soak, real SSH smoke, DPLPMTUD growth probes
  beyond the 1200 cap on live paths, and Retry/token issuance on real
  sockets (upstream `tls13-retry-loopback` and
  `tls13-path-validation-loopback` examples run green at the pin as
  mechanism evidence; zmosh's single-client-per-gateway Retry policy is
  Q2).
- Process-cleanup Bats (no orphan SSH/gateway/session) — Q2 integration.
- ECN per-path policy and address-validation token binding remain
  IPv4-shaped in quicz; they do not affect zmosh's dual-stack data paths.

## Recommendation

Proceed to the Q1 review. On acceptance, Q2 integrates the pinned fork
commits exactly as recorded here; the production pins advance only by
adding new reviewed fork commits with new immutable tags.
