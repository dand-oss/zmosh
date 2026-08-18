# Q1 QUIC feasibility spike report — round-4 resubmission (APPROVED)

**Verdict: GO — approved 2026-08-18 at the exact untagged-then-tagged
SHA `d854133`.** Both hard gates pass against the
pinned dand-oss forks under the frozen round-4 rules: fail-closed
candidate-path validation with the ReceivePathHintScope guard at every
PATH_RESPONSE-capable receive root, the adoption-transaction rollback,
fresh-packet-number proofs, and complete secret wipes. Spike branch:
`8sd1-quic-q1-spike`, governed by the canonical plan synced from
`replant-zmx0.7` (plan pin row at `b860063`). **The production pin now
exists**: the reviewed SHA below is tagged immutable `zmosh-quic-q1-5`
(annotated tag object verified to peel to the exact commit), and Q1's
post-approval closure completes with the bead closed and Q2 unlocked.

## Exact dependency pins

| Dependency | Pin | Base | Tag status |
|---|---|---|---|
| Ghostty | `git+https://github.com/dand-oss/ghostty#6361b2eac73e8243a7042f517ea95ab87165f105` (hash `ghostty-1.3.2-dev-5UdBC5L2RQWfmtJwTX8gKITqL4rOJteCksb42xxDS9bD`) | upstream `56e1f3a62` | SHA-only (the `zmosh-snapshot-v1` tag is retired — Ghostty's own build permits only its `vX.Y.Z` tags at HEAD, verified: `test-lib-vt` exit 0 from an ordinary untagged checkout) |
| quicz | `git+https://github.com/dand-oss/quicz#d854133d39b8d024e0b19ac34f84ef821d7766b9` (hash `quicz-0.1.0-g2J9778GlwAog98LXhKJ_bcuXttrr2432UdJ9T3scPsp`) | upstream `b4352201` | **production pin — immutable `zmosh-quic-q1-5`** (approved 2026-08-18; annotated tag peels to the exact SHA); `zmosh-quic-q1-4` (`238a57b`), the round-3 tip `470c4bd`, and the round-4 tip `7093988` are superseded, immutable history |

Forks keep upstream remotes for synchronization; zmosh pins exact
commits; tags never move. The provisional SHA recorded in the plan
became concrete in spike commits and is re-recorded here each round
(round 4: `7093988` in the repair commit `b698c76`, superseded within
the round by `d854133` after the feed path-commit fix).

## Round-4 corrections (all six blockers)

1. **Arrival-path coverage now matches the frozen contract** (quicz
   `d854133`, guard introduced in `7093988`): a tiny private `ReceivePathHintScope` guard (set on
   init, clear on deinit; NEVER nested — exactly one per processing
   path, delegating wrappers never create one, and the six
   pre-existing manual brackets were REPLACED, not wrapped) now runs
   at every public application/short-packet receive root capable of
   decoding PATH_RESPONSE: `processRoutedProtectedShortDatagram`,
   `…OrClose`, `…WithKeyUpdate`, `…WithKeyPhaseState`,
   `…WithInstalledKeysOrCloseAndPollDatagram`, and BOTH installed-key
   feed roots — `feedDatagramWithInstalledKeys` and
   `feedDatagramWithInstalledKeysAcrossConnections`. The feed roots
   guard only the `.application` processor (Handshake and 0-RTT cannot
   decode PATH_RESPONSE). Route mutation remains solely in the
   UpdatePath implementations, authorized only by a decrease of the
   candidate path's own bound-challenge count — enforced in the
   UpdatePath entries AND in `feedDatagramWithInstalledKeysAndUpdatePathOrClose`
   (`d854133`: the feed previously compared TOTAL outstanding counts,
   letting a legacy unbound challenge consumed from any path authorize
   the route update; a regression test proves an unbound challenge may
   be consumed via the feed while the route stays on the old path, and
   that test fails against the previous comparison). In-fork per-root
   tests prove each root consumes a bound response only from the bound
   path; 1907/1907 at the pin.
2. **No test-only fns in the production API** (quicz `7093988`):
   `processDecodedFramesForTest` is removed; the null-hint proof — in
   fork and spike alike — drives a crafted protected PATH_RESPONSE
   through the connection-level entry
   `processProtectedShortDatagramWithInstalledKeys`, a real production
   packet entry that is hint-free by design (lifecycle layers bracket
   around it).
3. **False-positive coverage closed** (spike `b698c76`): every crafted
   injection draws its packet number from
   `server.nextPeerPacketNumber(.application)` — genuinely fresh after
   the handshake and seeded traffic — so packet-number dedup can no
   longer pass a wrong-path or stale case; only the exact-replay case
   reuses a datagram. The stale and wrong-data cases run on separate
   fresh pairs.
4. **Secret wipes complete** (spike `b698c76`): the token-secret tests
   wipe the actual mutable ORIGINAL in place (the `secret_original`
   copies are gone), and both `derivePsk` implementations wipe the
   HKDF PRK with an immediate `defer`. Round-3's pointer-PSK rule,
   in-place derivation, wipe-then-destroy backends, and
   locals-with-adjacent-errdefer constructors are unchanged.
5. **Real state, not counters** (spike `b698c76`): `AllocCounters` is
   deleted; the bounded-candidate assertions use
   `policy.replayFilterEntryCount()` and `router.routeCount()`.
6. **Bats gate amended, evidence-first** (see the Bats section below):
   the flake is proven pre-existing at the frozen baseline `6f4c4d1`,
   tracked as `zmosh-r3b` blocking `zmosh-pnf`, and Q1's criterion is
   no-regression-versus-baseline — not silently waived.

The round-3 adoption-transaction rollback (spike `412e04b`) is
unchanged and remains the strongest evidence; see its section below.
The canonical plan is synced from `replant-zmx0.7` at `ad86781`
(round-4 frozen rules + the amended Bats criterion).

## Fail-closed path-validation matrix (frozen, all asserted)

Every crafted datagram carries a fresh packet number from
`server.nextPeerPacketNumber(.application)`; only the exact-replay
case reuses a datagram. Fresh pairs wherever the `OrClose` entry
could queue a close (the stale and wrong-data cases each get their
own):

1. bound challenge + **null hint** (a crafted protected response
   driven through the connection-level packet entry — no lifecycle
   feed, so no arrival hint can be recorded) — ignored, still
   outstanding;
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
→ 1-RTT echo. Real state, not self-reported counters: every
malformed/expired/replayed/wrong-path/unrelated/unauthenticated
attempt leaves the token's replay filter unconsumed and no server
lifecycle or route in existence; one valid follow-up publishes exactly
one route (`router.routeCount()` == 1) and consumes the replay filter
exactly once.

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

## Real-socket proofs: PASS (4) plus one sans-I/O adoption proof

Four proofs run over actual UDP: IPv4 loopback; native IPv6 loopback;
dual-stack (IPv6 `::` server serving an IPv4-mapped peer with the
kernel-reported mapped route); and the full native-IPv6
Retry/bounded-candidate/handshake/echo proof. Client Initials are
padded to exactly 1200 bytes; nothing exceeds the cap. The
adoption-transaction rollback proof is sans-I/O by design and is NOT
counted as a real-socket test.

## Verification commands

```
cd spike
zig build test --summary all                            # 24/24 (Debug)
zig build test -Doptimize=ReleaseSafe --summary all     # 24/24
zig build quicz-suite --summary all                     # at the pin
zig build size-probe -Doptimize=ReleaseSafe
zig build size-probe -Dtarget=aarch64-macos -Doptimize=ReleaseSafe
zig fmt --check build.zig build.zig.zon src/*.zig
cd .. && zig build && zig build check && zig build test
```

## Bats gate: no regression versus the frozen baseline

The exact-128 KiB boundary test in `test/write.bats` ("write accepts
exactly 128 KiB and rejects one byte more") flakes in the daemon
chunked-PTY-write path, which Q1 never touches. Evidence-first
amendment (Q1 criterion 5, `zmosh-8sd.1`):

- **Baseline first**: temp worktree at `6f4c4d1` (the last commit
  touching `src/`, `test/`, or build inputs — every later
  `replant-zmx0.7` commit is plans-only), fresh `zig build`, then 20
  isolated runs of
  `bats --filter '^write accepts exactly 128 KiB and rejects one byte more$' test/write.bats`
  on Linux 7.1.7+deb14-amd64, Zig 0.16.0, baseline binary sha256
  `186817f403d6908e78ae7647fc1508b1e75e3cc7c3b2ebcbe5402a4e01d6075d`.
  **10/20 failed**: 9× the drain-stall signature (`write.bats:96`,
  size ≠ 131072, stuck around 90 KiB) and 1× the rejection signature
  (`write.bats:75`, the capped write itself returned nonzero). The
  flake is proven pre-existing and outside Q1.
- **Tracked, not waived**: bead `zmosh-r3b` (labels bug, write,
  replant) carries the fix — its acceptance requires a real daemon
  fix, repeated boundary-test success, and full Bats green — and it
  BLOCKS the final replant verification bead `zmosh-pnf`
  (`bd dep zmosh-r3b --blocks zmosh-pnf`), so replant cannot verify
  with the flake outstanding.
- **Candidate protocol**: `candidate_sha` is frozen immediately after
  the round-4 plan commit (`ad86781…`, recorded here and in the Bead
  comment — the plan commit cannot contain its own SHA);
  `git diff --exit-code 6f4c4d1..<candidate_sha> -- src test
  build.zig build.zig.zon flake.nix` is empty (`build_support` does
  not exist in this tree). The candidate runs execute exactly that
  SHA: fresh build, the same 20 filtered runs (no NEW failure
  signature; the two baseline signatures above may recur), and one
  complete `bats test` in which only those tracked signatures are
  permitted. Candidate results are recorded in the round-4 gate
  evidence comment on the bead.

zmosh gates: `zig build check` green; `zig build test` 134/134;
`zig fmt --check` and `git diff --check` clean.

Dependencies reproduce from the exact URLs and hashes in
`spike/build.zig.zon`; no local trees or patch files remain.

## Deferred to release-only gates

Real macOS/iOS execution; 30-minute impaired-network soak; real SSH
smoke; process-cleanup Bats (Q2/Q8); HELLO authorization and
authenticated second-client rejection (Q3); DPLPMTUD (deferred
entirely — v1 fixes the 1200-byte payload).

## Recommendation

Proceed to the round-4 re-review. On approval only: create the
immutable `zmosh-quic-q1-5` tag at the reviewed quicz SHA (verify the
tag object peels to the pinned commit), land the pin-only plan/report
commit recording SHA + hash, rerun the exact-pin gates, and close Q1.
Q2 remains locked until all of that completes; pins advance only by
adding new reviewed fork commits with new immutable tags.
