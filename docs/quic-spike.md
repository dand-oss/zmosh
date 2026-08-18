# Q1 QUIC feasibility spike report — round-3 resubmission

**Verdict: GO, pending re-review.** Both hard gates pass against the
pinned dand-oss forks under the frozen round-3 rules: fail-closed
candidate-path validation, the adoption-transaction rollback, and the
single secret-ownership rule. Spike branch: `8sd1-quic-q1-spike`,
governed by the canonical plan synced from `replant-zmx0.7` at
`f6c4454`. **No production tag exists yet**: the quicz dependency below
is an untagged review dependency, and the production pin (immutable
`zmosh-quic-q1-5` at the reviewed SHA) is created only after re-review
approval. Q2 remains locked until that closure completes.

## Exact dependency pins

| Dependency | Pin | Base | Tag status |
|---|---|---|---|
| Ghostty | `git+https://github.com/dand-oss/ghostty#6361b2eac73e8243a7042f517ea95ab87165f105` (hash `ghostty-1.3.2-dev-5UdBC5L2RQWfmtJwTX8gKITqL4rOJteCksb42xxDS9bD`) | upstream `56e1f3a62` | SHA-only (the `zmosh-snapshot-v1` tag is retired — Ghostty's own build permits only its `vX.Y.Z` tags at HEAD, verified: `test-lib-vt` exit 0 from an ordinary untagged checkout) |
| quicz | `git+https://github.com/dand-oss/quicz#470c4bddb55d5f6978a612b46104df9edcf8d2f6` (hash `quicz-0.1.0-g2J978KqlgDLjnnKtgUqCIwprxe2Tqx1AMBF1PkacaC3`) | upstream `b4352201` | **untagged review dependency** — `zmosh-quic-q1-4` (`238a57b`) is superseded, immutable history; no production tag until re-review approval |

Forks keep upstream remotes for synchronization; zmosh pins exact
commits; tags never move. The provisional SHA recorded in the plan
(Step 0) became this concrete pin in spike commit 1/4 (`9b92f03`).

## Round-3 corrections (all four blockers)

1. **Path validation is fail-closed** (quicz `470c4bd`): a bound
   challenge is consumed only when the arrival hint is present AND
   equals the binding — a null hint ignores the frame and the challenge
   stays outstanding. One neutral implementation
   (`…UpdatePathOrCloseAddress(UdpTuple)`) is the only body that sets
   the hint and performs the route update; the IPv4 entry is a pure
   `.toUdp()` delegate, and every other routed short-datagram entry
   brackets the hint the same way. Route commit is path-specific
   (`outstandingPathChallengeCountForPath`): legacy unbound challenges
   never authorize migration. Four in-fork tests cover the matrix;
   1904/1904 at the pin.
2. **Rollback is an adoption transaction, not a pre-adoption check**
   (spike commit 3/4, `412e04b`): the candidate is adopted into a
   private capacity-one `EndpointConnectionRegistry` with its route
   installed; wrong-PSK binder failure — and any `commit()` failure
   after successful authentication — calls `registry.retire()` and
   returns `count()`/`activeCount()`/`routeCount()` to the pre-adoption
   baseline; `deinit_record` `secureWipe()`s the backend and asserts
   the wipe landed before any storage is freed. Full evidence below.
3. **Secret ownership under one rule** (spike commit 3/4):
   `PairOptions` carries PSK pointers; callers own and wipe the
   mutable bootstrap/PSK/token originals via defers; the Pair retains
   no redundant PSK arrays; `derivePsk(out: *[32]u8, bootstrap:
   *const [32]u8)` writes the derived PSK in place; every backend
   teardown is `secureWipe()` then `destroy()` (the backends' retained
   copies are wiped by `secureWipe`; no claim is made about transient
   ABI copies inside quicz's by-value PSK constructors); constructors
   (`quic_harness.initInto`, `quic_psk_gate.Pair.init`,
   `socketPairOver`) build each resource as a local with an adjacent
   errdefer and assign the pair only after all steps succeed — no
   partially initialized pair is ever observable.
4. **Governance**: the canonical plan on `replant-zmx0.7` (`f6c4454`)
   records q1-4 superseded, the provisional-then-concrete SHA, and the
   four frozen rules above; the bead (`zmosh-8sd.1`) description and
   acceptance criteria are reconciled to the fork-pin strategy; this
   report matches both. The minor stale `zmosh-snapshot-v1` zon comment
   was fixed in spike commit 1/4.

## Fail-closed path-validation matrix (frozen, all asserted)

Fresh pairs wherever the `OrClose` entry could queue a close:

1. bound challenge + **null hint** (decoded frames driven directly on
   the connection, no feed) — ignored, still outstanding;
2. **wrong path** — ignored, still outstanding, no commit;
3. **correct candidate path** — consumed, route committed exactly once;
4. **exact-datagram replay including the packet number** —
   packet-number deduplication, no second commit;
5. **fresh stale and wrong-data responses** (fresh packet numbers) —
   rejected, the live bound challenge stays outstanding.

Plus a source-**address** migration case (127.0.0.1 → 127.0.0.2, not
just a port change) committing only the bound candidate path, and
old-path traffic never reverting the committed route.

## Adoption-transaction rollback (evidence)

Proven over a genuine follow-up Initial (real client Retry sequence —
`processRetryDatagram`, `retryReceived`, initial-send rewind, re-drive —
no sockets), against a private capacity-one registry:

- **Pre-adoption failure matrix, zero candidates**: expired slot (both
  tokenless `RetryExpired` and token-bearing `UnrelatedInitial`), wrong
  tuple, wrong token bytes, wrong client SCID — all refused, nothing
  allocated, under `std.testing.allocator` leak detection.
- **Adoption**: `registry.adopt()` + candidate-route install; counts
  elevate by one each (private ownership is not publication — endpoint
  dispatch never consults this registry).
- **Wrong PSK**: the follow-up Initial is delivered and the TLS drive
  fails at the binder (`error.CryptoError`); `registry.retire()` returns
  `count()`/`activeCount()`/`routeCount()` to baseline; replay state
  unconsumed, slot still occupied.
- **Commit failure after authentication**: the candidate authenticates
  (ServerHello exists), then `commit()` fails on a mutated token
  (`error.InvalidToken`) — rollback stays armed through `commit()`:
  retire returns everything to baseline with replay state unconsumed and
  the slot intact.
- **Valid path**: exactly one record and one route retained;
  `commit()` consumes exactly once (`replayFilterEntryCount` 0 → 1,
  slot cleared); a second commit is refused; classification after
  commit is rejected with zero delta against the retained candidate.
- **`deinit_record`**: `secureWipe()` the backend, assert the wipe
  landed while the object still exists, then release contents — the
  registry destroys the record allocation itself.

## Bounded-candidate flow (proven over real IPv6 sockets)

First Initial → slot (path/version/ODCID/SCID; one bounded token/Retry
buffer; ≥1200-byte floor) → failure matrix → client Retry sequence →
exact stored-exchange validation without consuming replay state → ONE
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

## Transport, resource, and fault proofs: PASS (13 in-process)

Conservative backlog metric end to end (queued/in-flight/acked;
earliest-packet loss holds the prefix; loss-requeue → retransmission →
settle); keepalive across multiple original idle deadlines then real
closure; STOP_SENDING → RESET_STREAM with the same code; corruption and
blackout bytes delivered exactly once via retransmission; delay;
reordering; duplication; negotiated 4 MiB / 4 bidi / 8 uni bounds
enforced; slow-reader backpressure blocks writes, spares control
traffic, and resumes after drain; datagrams respect the fixed
1200-byte payload. Migration coverage lives in the frozen fail-closed
matrix above.

## Real-socket proofs: PASS (5)

IPv4 loopback; native IPv6 loopback; dual-stack (IPv6 `::` server
serving an IPv4-mapped peer with the kernel-reported mapped route); the
full native-IPv6 Retry/bounded-candidate/handshake/echo proof; and the
adoption-transaction rollback proof (sans-I/O, listed above). Client
Initials padded to exactly 1200 bytes; nothing exceeds the cap.

## Verification commands

```
cd spike
zig build test --summary all                            # 24/24 (Debug)
zig build test -Doptimize=ReleaseSafe --summary all     # 24/24
zig build quicz-suite --summary all                     # 1904/1904 at the pin
zig build size-probe -Doptimize=ReleaseSafe
zig build size-probe -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
zig fmt --check build.zig build.zig.zon src/*.zig
cd .. && zig build check && zig build test && bats test
```

zmosh gates: `zig build check` green; `zig build test` 134/134;
`zig fmt --check` and `git diff --check` clean. **`bats test` has one
intermittent pre-existing failure** outside Q1 scope:
`test/write.bats` test 4 ("write accepts exactly 128 KiB and rejects
one byte more") failed 1 of 6 isolated runs plus the full-suite run —
the chunked PTY drain of an exactly-at-cap write occasionally stalls
around 90 KiB. The daemon write path is untouched since `6f4c4d1`
(all later `replant-zmx0.7` commits are plans-only, and the Q1 spike
never modifies zmosh `src/`); flagged for a follow-up bead rather
than silently re-run until green.

Dependencies reproduce from the exact URLs and hashes in
`spike/build.zig.zon`; no local trees or patch files remain.

## Deferred to release-only gates

Real macOS/iOS execution; 30-minute impaired-network soak; real SSH
smoke; process-cleanup Bats (Q2/Q8); HELLO authorization and
authenticated second-client rejection (Q3); DPLPMTUD (deferred
entirely — v1 fixes the 1200-byte payload).

## Recommendation

Proceed to the round-3 re-review. On approval only: create the
immutable `zmosh-quic-q1-5` tag at the reviewed quicz SHA (verify the
tag object peels to the pinned commit), land the pin-only plan/report
commit recording SHA + hash, rerun the exact-pin gates, and close Q1.
Q2 remains locked until all of that completes; pins advance only by
adding new reviewed fork commits with new immutable tags.
