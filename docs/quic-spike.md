# Q1 QUIC feasibility spike report — resubmission (bounded candidate)

**Verdict: GO.** Both hard gates pass against the pinned dand-oss forks
under the approved bounded-candidate contract, with the five follow-up
review blockers corrected. Spike branch: `8sd1-quic-q1-spike`, governed
by the canonical plan synced from `replant-zmx0.7` at `20db9b4`.

## Exact dependency pins (frozen)

| Dependency | Pin | Base | Immutable tag |
|---|---|---|---|
| Ghostty | `git+https://github.com/dand-oss/ghostty#6361b2eac73e8243a7042f517ea95ab87165f105` (hash `ghostty-1.3.2-dev-5UdBC5L2RQWfmtJwTX8gKITqL4rOJteCksb42xxDS9bD`) | upstream `56e1f3a62` | none (SHA-only; the `zmosh-snapshot-v1` tag is retired — Ghostty's own build permits only its `vX.Y.Z` tags at HEAD, verified: `test-lib-vt` exit 0 from an ordinary untagged checkout) |
| quicz | `git+https://github.com/dand-oss/quicz#238a57b9d93344bfbd098bcde865450adeba9274` (hash `quicz-0.1.0-g2J97yxrlgBCQxYnbJBVx1V05SbJqCBuUiA4707_924f`) | upstream `b4352201` | `zmosh-quic-q1-4` (`zmosh-quic-q1-3` at `fa6c4c0e` superseded, immutable history) |

Forks keep upstream remotes for synchronization; zmosh pins exact
commits; tags never move.

## Follow-up review corrections (all five blockers)

1. **IPv6 Retry test now completes client-side** — the real quicz
   sequence over the same IPv6 sockets: the client receives the Retry,
   `processRetryDatagram` records token + Retry SCID, `retryReceived()`
   re-caches the ClientHello, `resetInitialCryptoSendForRetry()` rewinds
   Initial send state, and the re-drive emits the follow-up Initial
   protected with Retry-SCID Initial keys. The follow-up is
   authenticated (server handshake drive — PSK binder) before
   publication; the PSK handshake then completes over those sockets and
   a 1-RTT echo returns `v6-retry-echo`.
2. **PendingRetrySlot hardened** (`653d247`): occupied/unexpired
   required for both retransmissions and follow-ups; tokenless
   retransmissions must match path/version/ODCID/client-SCID exactly;
   token-bearing follow-ups must match the Retry SCID (as destination
   CID), client SCID, and the exact stored token bytes; `commit()`
   consumes only that exact token; misleading global counters removed;
   the single bounded `open()` internal allocation (integrity-tag
   pseudo-packet) is documented — `classify()`/`commit()` never
   allocate.
3. **Path validation bound to the candidate path** (`238a57b`):
   challenges record their candidate UDP path; every validated feed
   records the arrival path; a matching response from any other path is
   ignored (neither consumes nor commits); packet-level tests inject
   wrong-path, old-path, mismatched, duplicate, and valid responses.
4. **Secret cleanup complete**: the gate's `Pair.deinit()` wipes both
   TLS backends, Initial secrets, and its PSK copies on every path; the
   in-process harness and socket harness do the same; the IPv6 test
   wipes bootstrap, derived-PSK, and token-secret copies via defers
   (success, failure, and initialization-error paths alike); quicz
   owners (`Tls13ServerTransport`, `Tls13ClientTransport`,
   `AddressValidationPolicy`) wipe in `deinit()` with idempotent
   `wipeSecrets()` test hooks (assert-after-wipe-before-reuse).
5. **Governance**: the spike branch carries the canonical plan synced
   from `replant-zmx0.7` (`20db9b4`), which records the
   bounded-candidate contract and the exact `zmosh-quic-q1-4` pin;
   this report matches it.

## Bounded-candidate flow (proven over real IPv6 sockets)

First Initial → slot (path/version/ODCID/SCID; one bounded token/Retry
buffer; ≥1200-byte floor) → failure matrix (short, non-Initial,
unrelated SCID, wrong path, wrong Retry SCID, mutated token — all
refused with zero allocation delta) → client Retry sequence → exact
stored-exchange validation without consuming replay state → ONE
unpublished bounded candidate (Connection + TLS backend) →
authentication of the follow-up Initial → publication (one route under
the Retry-SCID DCID) + token consumption + slot cleared → PSK handshake
→ 1-RTT echo. Baseline-relative counters: every malformed/expired/
replayed/wrong-path/unrelated/unauthenticated attempt leaves
Connection/TLS/stream/route counts at zero delta; one valid follow-up
creates exactly one candidate (2 total connections including the client,
2 backends, 1 route).

## Gate 1 — Ghostty public snapshot API: PASS

Upstream has no `ghostty_vt.snapshot`; fork commit `6361b2eac` adds the
public alias plus a compile-time alias check. `test-lib-vt` passes from
an ordinary untagged checkout at the SHA (exit 0). Spike proofs: full
encode → spool-first decode round trip; decoded-continuation equality
with the source stream's export; replay of ONLY `decoded.continuation`;
complete primary-screen `.screen` dump comparison including history;
error-safe continuation ownership (single `defer decoded.deinit` covers
all paths, including failures between `toOwned` and FINISH); post-cut
output before history pages matches an uninterrupted terminal.

## Gate 2 — certificate-free external-PSK TLS 1.3: PASS

`disable_session_resumption` on both sides, `setClientPskIdentity()`,
no handshake-field mutation anywhere; wrong PSK / wrong identity / ALPN
mismatch fail loudly; no ticket, no resumption state, 0-RTT never
offered or accepted; PSK = HKDF-SHA256(salt `zmosh quic psk v1`, IKM
bootstrap) → expand(info `zmosh-ssh-bootstrap-v1`); token secret =
extract(salt `zmosh quic token v1`) → expand(info
`zmosh-address-validation-v1`).

## Transport, resource, and fault proofs: PASS (11/11 in-process)

Conservative backlog metric end to end (queued/in-flight/acked;
earliest-packet loss holds the prefix; loss-requeue → retransmission →
settle); keepalive across multiple original idle deadlines then real
closure; STOP_SENDING → RESET_STREAM with the same code; corruption and
blackout bytes delivered exactly once via retransmission; delay;
reordering; duplication; negotiated 4 MiB / 4 bidi / 8 uni bounds
enforced; real PATH_CHALLENGE/RESPONSE migration committing only from
the candidate path, with old-path traffic never reverting the committed
route; slow-reader backpressure blocks writes, spares control traffic,
and resumes after drain; datagrams respect the fixed 1200-byte payload.

## Real-socket proofs: PASS (4/4)

IPv4 loopback; native IPv6 loopback; dual-stack (IPv6 `::` server
serving an IPv4-mapped peer with the kernel-reported mapped route); and
the full native-IPv6 Retry/bounded-candidate/handshake/echo proof.
Client Initials padded to exactly 1200 bytes; nothing exceeds the cap.

## Verification commands

```
cd spike
zig build test --summary all               # 21/21 (Debug)
zig build test -Doptimize=ReleaseSafe --summary all   # 21/21
zig build quicz-suite --summary all        # 1900/1900 at the pin
zig build size-probe -Doptimize=ReleaseSafe
zig build size-probe -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
zig fmt --check build.zig build.zig.zon src/*.zig
cd .. && zig build check && zig build test && bats test
```

Dependencies reproduce from the exact URLs and hashes in
`spike/build.zig.zon`; no local trees or patch files remain.

## Deferred to release-only gates

Real macOS/iOS execution; 30-minute impaired-network soak; real SSH
smoke; process-cleanup Bats (Q2/Q8); HELLO authorization and
authenticated second-client rejection (Q3); DPLPMTUD (deferred
entirely — v1 fixes the 1200-byte payload).

## Recommendation

Proceed to the Q1 review. On acceptance, Q2 integrates the pinned fork
commits exactly as recorded; pins advance only by adding new reviewed
fork commits with new immutable tags.
