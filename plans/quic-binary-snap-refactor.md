# Plan: QUIC transport and Ghostty binary snapshot refactor

## Summary

This plan replaces the custom UDP reliability and command-framing portions of
`plans/zmosh-replant.md`. Completed replant work remains valid: the frozen zmx
v0.7.0 base, branding, local command parity, remote SSH bootstrap behavior,
public C ABI, and Phase 4A write-safety work are retained.

The desired result is one zmosh binary with:

- SSH-authenticated bootstrap and roaming QUIC transport;
- Ghostty's official binary Snapshot v1 for terminal state;
- reliable, isolated QUIC streams for input, control, snapshots, output, and
  one-shot commands;
- remote semantic parity for send, print, write, labels, tail, and kill;
- no custom packet ACK, retransmission, reordering, congestion, heartbeat, or
  command-chunk reassembly layer;
- no daemon threads and no redesign of ordinary local session IPC;
- the existing public `libzmosh` C ABI unchanged.

The refactor has two independent feasibility gates: public access to Ghostty's
snapshot API and an isolated quicz spike. If both pass, QUIC replaces the
custom transport in this replant. If only the QUIC gate fails, no quicz
dependency lands: zmosh instead ports the proven custom-transport fixes from
`master` and still adopts Ghostty binary snapshots. If the Ghostty API gate
fails, both transport branches stop because binary snapshots are required.

No merge or push to `master` is permitted without explicit landing
authorization.

## Frozen starting points

Record these inputs before coding and do not silently advance them:

| Input | Frozen value | Purpose |
|---|---|---|
| replant branch | `replant-zmx0.7` at `6f4c4d19fd5143e13c71ddefb0c2e1023d56d4bf` | reviewed implementation base through Phase 4A cleanup |
| zmx base | `cd88d1b` | zmx v0.7.0 replant base |
| custom fallback | `master` at `db4661c02965733d5975011e92875e3c639cac87` | zmosh 0.5.3 reliable snapshot/reordering implementation |
| quicz spike | `b4352201f1217bbc4538e379be0f68f783558070` | only QUIC candidate admitted to the spike |
| Ghostty audited tree | `b97b17f06b1ffd694f80edd3df5dd2134a0bcb9e` | frozen 2026-08-17 tree containing the reviewed Snapshot v1 Zig and C APIs; the commit itself is an unrelated i18n change |
| Ghostty snapshot content | `1359973aefb37a9beaa2ec3e8f79df78290ea6f5` | last commit touching `src/terminal/snapshot/` as of the audited tree, 2026-08-15 |
| **Ghostty production pin** | dand-oss/ghostty `6361b2eac73e8243a7042f517ea95ab87165f105` | fork of upstream `56e1f3a62` plus the public `lib_vt` snapshot re-export; pinned by SHA only (the `zmosh-snapshot-v1` tag is retired: Ghostty's build permits only its own matching `vX.Y.Z` tags at HEAD, so custom tags break a normal checkout) |
| **quicz remediation base** | dand-oss/quicz `3a75a8b63dd4137f07932d3d85ee773b24ad80c1` | fork of upstream `b4352201` plus the six reviewed Q1 commits; tags `zmosh-quic-q1`/`zmosh-quic-q1-2` |
| **quicz production pin** | dand-oss/quicz `d854133d39b8d024e0b19ac34f84ef821d7766b9`, immutable tag `zmosh-quic-q1-5` (approved 2026-08-18; annotated tag object verified to peel to this exact SHA) | upstream `b4352201` + the reviewed Q1 chain through the round-4 corrections: exact stored-exchange slot contract; fail-closed bound-challenge consumption; `ReceivePathHintScope` guard at every PATH_RESPONSE-capable receive root (never nested; feed roots application-space only); path-specific route commit everywhere including `feedDatagramWithInstalledKeysAndUpdatePathOrClose` (legacy unbound challenges never authorize migration, regression-tested); `processDecodedFramesForTest` removed. Zig package hash `quicz-0.1.0-g2J9778GlwAog98LXhKJ_bcuXttrr2432UdJ9T3scPsp`. Suite 1907/1907 at the pin; spike 24/24 Debug and ReleaseSafe. `zmosh-quic-q1` through `-q1-4` and the untagged round tips (`470c4bd`, `7093988`) remain immutable, superseded history |
| Zig | `0.16.0` | project and dependency toolchain |

The current Ghostty dependency (`aa21cae...`) has no snapshot module and must
not be used for the production snapshot path. Snapshot v1 is explicitly work
in progress, so its numeric version is not a compatibility boundary. The
production dependency is the dand-oss fork pin above. That commit and its Zig
package hash are part of the application handshake. The dand-oss forks keep
their original projects configured as upstream remotes for future
synchronization; zmosh pins exact fork commits, never moving branch heads, and
existing tags are immutable.

## Non-negotiable constraints

- Keep the binary/package name `zmosh`, all existing `ZMX_*` variables,
  serve/s and send/se aliases, socket/log conventions, and SSH alias resolution.
- Keep the daemon single-threaded and `poll()`-driven.
- Keep existing local command syntax and successful behavior. The bounded,
  acknowledged send/print and label-safety changes explicitly listed in Phase
  Q6 are the only authorized local semantic changes. Existing IPC tag values
  remain frozen; existing `.Ack` carries the new outcomes.
- Keep every exported C symbol, enum value, callback, and header declaration
  unchanged.
- Use quicz only as QUIC/TLS transport. Do not add HTTP/3, WebTransport, an
  async runtime, OpenSSL, or another crypto dependency.
- Use Ghostty's encoder and decoder directly. Do not define a competing
  terminal-state format or parse Ghostty snapshot records in zmosh.
- Do not retain a runtime switch between custom UDP and QUIC. The custom stack
  remains recoverable in Git, not as dead production code.
- Do not automatically retry a finite side-effecting command after connection
  loss. Report an unknown outcome with exit code 3.
- Do not start post-spike production work until the spike report is reviewed
  and explicitly accepted.

## Ownership boundaries

### quicz owns

- TLS 1.3 key agreement and authenticated encryption;
- packet numbers, ACKs, replay rejection, retransmission, loss detection, PTO,
  congestion control, pacing, flow control, packetization, and PMTU handling;
- ordered stream delivery, stream reset, connection IDs, path validation, and
  NAT/network migration;
- QUIC PING and idle timers.

### Ghostty Snapshot v1 owns

- terminal state encoding and decoding;
- envelope and record validation, CRC32C, terminal/screen/page data,
  continuation state, READY, history pages, and FINISH;
- reconstruction of unfinished VT/UTF-8 parser state.

### zmosh owns

- SSH bootstrap and exact-session selection;
- the QUIC event-loop adapter and small application protocol;
- stream roles and command semantics;
- snapshot capture requests across local daemon IPC;
- snapshot/output epoch coordination and bounded slow-consumer recovery;
- CLI rendering, C callback compatibility, diagnostics, deadlines, and child
  cleanup.

There is still a small application state machine. QUIC removes the network
packet state machine; Ghostty removes the terminal serialization state
machine. zmosh must still coordinate connection negotiation, stream roles,
snapshot installation, output replacement, command completion, and shutdown.

## SSH resumption, Mosh, and terminal continuity

Decision: zmosh does not depend on Mosh or implement Mosh's State
Synchronization Protocol, but it retains the user-visible properties that
make Mosh valuable: roaming, tolerance of intermittent connectivity, visible
staleness, responsive control traffic, and deterministic terminal recovery.

As of OpenSSH 10.4, OpenSSH has no reconnectable interactive-session
resumption. `ControlMaster` and `ControlPersist` multiplex sessions over, and
retain, an existing TCP connection; they do not recover its channels after
that connection dies. OpenSSH's old experimental roaming client was disabled
and then removed in 7.2, and matching server code was never shipped. An
automatic SSH reconnect or a fresh SSH login is therefore a new transport and
new channel. A program under tmux or screen may survive independently. zmosh
instead has a detached owner process per live session; it owns that session's
PTY master and shell child and survives ordinary client disconnect. Neither
mechanism is SSH channel resumption, and SSH does not reconstruct terminal
state or prove which output was displayed before the break.

Keep these layers distinct:

- **SSH bootstrap** authenticates the host and user, applies existing SSH
  configuration, and launches/owns the ephemeral zmosh gateway. It is not the
  terminal data transport.
- **QUIC path migration** preserves the same authenticated QUIC connection
  through address and port changes while its connection state remains alive.
- **QUIC TLS resumption** would only accelerate creation of a new connection;
  it would not resume zmosh stream state, terminal state, or uncertain command
  outcomes. Session tickets, resumption, and 0-RTT remain disabled in v1 so a
  new connection always receives a fresh SSH-delivered secret and cannot
  replay application work.
- **zmosh reattachment** reconnects to the existing detached per-session owner
  while it is alive, installs a Ghostty binary snapshot, and crosses an
  explicit output-epoch boundary before live output resumes. This is the
  actual terminal-session continuation mechanism.

The per-session owner is not a global service or durable store. Its lifetime is
bounded by the PTY child: it ends when the shell exits, the session is killed,
or the owner fails, and it does not survive a host reboot. "Persistence" in
this plan means continuity across client detach and network loss only.

Mosh remains a behavior and qualification reference, not a component. Mosh
uses SSH bootstrap followed by UDP, synchronizes terminal screen state instead
of replaying a byte stream, supports roaming and local prediction, and keeps
control responsive under loss. zmosh obtains those correctness properties
from QUIC plus Ghostty Snapshot v1, while also preserving scrollback and parser
continuation. Predictive local echo is optional latency UX, not required for
session continuity, and remains outside v1.

If a future OpenSSH release ships authenticated reconnection of live channels,
re-evaluate whether SSH can replace part of the bootstrap/transport layer. It
still does not replace zmosh's detached per-session PTY owner, binary terminal
snapshot, output epochs, remote command semantics, or C ABI without explicit
proof of equivalent behavior under loss, migration, and detached
reattachment.

## Phase Q0: reconcile the checkpoint and freeze recovery

1. Re-run `zig build`, `zig build check`, `zig build test`, full Bats,
   `zig fmt --check`, and `git diff --check` at `6f4c4d1`.
2. Confirm the repository-root artifact regression is fixed and no `one.bin`
   or other test artifact remains.
3. Verify that Phase 4A bead `zmosh-126` is already closed at `6f4c4d1` with
   the recorded gate counts; do not close it again.
4. Create and push a recovery branch at the exact pre-QUIC replant tip.
5. Record `db4661c` as the custom-transport fallback; do not merge its custom
   transport into the replant before the QUIC decision.
6. Commit this plan separately from all implementation changes and record the
   resulting plan commit SHA.

Checkpoint: clean worktree, exact recovery refs, Phase 4A closed, and no QUIC
code yet.

## Phase Q1: isolated quicz feasibility gate

Run the spike in a separate worktree and branch based on the plan-only commit
created in Phase Q0. The code baseline remains `6f4c4d1`, but the spike branch
must carry its governing plan. The spike may modify only spike code,
dependency metadata, and its report. It must not delete the custom transport
or begin the command gateway.

### Phase ownership (frozen)

- Q1 owns dependency and transport feasibility: fork pins, the PSK gate,
  Retry before client state, real PATH_CHALLENGE/PATH_RESPONSE migration, the
  fault matrix, the conservative backlog metric, secure teardown, and the
  real-socket family proofs.
- Q2 owns production zmosh integration (poll() loop, sockets, bootstrap,
  process cleanup) together with Q8's process-cleanup release gates.
- Q3 owns HELLO authorization, replay and pre-handshake rejection, and the
  one-client-per-gateway policy including authenticated second-client
  rejection.
- Q5 owns visible disconnect/reconnect behavior and output replacement.
- DPLPMTUD is deferred entirely: v1 fixes a 1200-byte UDP payload.

### Independent Ghostty snapshot API prerequisite

- Require this upstream addition to `src/lib_vt.zig`:

      pub const snapshot = terminal.snapshot;

- The re-export landed in the dand-oss Ghostty fork (upstream `56e1f3a62`
  plus one reviewed commit); the production pin is that exact fork commit,
  SHA-only. No upstream acceptance is required for Q1/Q2.
- Do not use the Ghostty C snapshot API as a fallback. It owns a C
  `TerminalWrapper`, while zmosh owns a native Zig `ghostty_vt.Terminal`; using
  it would require an unrelated terminal-ownership rewrite.
- Snapshot support defaults on in the audited tree, but pass
  `vt-features=+snapshot` explicitly so a future default change cannot silently
  remove it.
- Track this prerequisite independently of the quicz decision. It blocks both
  the QUIC production path and the custom-transport fallback. The fork must
  build and pass its own `test-lib-vt` suite from an ordinary untagged
  checkout at the pinned SHA.

### Dependency and API proof

- Pin quicz to `b4352201f1217bbc4538e379be0f68f783558070` and verify its
  complete upstream test suite under Zig 0.16.0.
- Use the low-level/sans-I/O TLS endpoint and caller-owned UDP socket. Do not
  use quicz's threaded runtime.
- Drive receive, outbound datagram drain, and `nextDeadline()` from one zmosh
  `poll()` loop.
- Prove IPv4, IPv6, and dual-stack operation without regressing current zmosh
  behavior.
- Prove all required behavior through public quicz APIs of the dand-oss fork.
  The production pin is the `zmosh-quic-q1-4` tip: upstream `b4352201` plus
  the reviewed remediation commits (conservative stream-progress metric;
  address-neutral paths across routing, Initial acceptance, Retry, token
  policy, migration, and route updates; secret ownership and teardown; the
  hardened bounded-candidate slot; candidate-path-bound validation). Each
  commit passes the full quicz suite; the fork tracks upstream
  `venjiang/quicz` for future synchronization. `zmosh-quic-q1-3` and every
  earlier tag remain immutable history.
- Keep the production compatibility adapter below 500 non-test lines. This
  excludes zmosh's application protocol but includes all quicz-specific
  lifecycle glue.

### Authentication proof

- Make a certificate-free external-PSK TLS 1.3 handshake the first Q1
  go/no-go checkpoint. Do not build the transport fault matrix until this
  succeeds through the fork's public quicz API.
- Generate the existing 32-byte bootstrap secret with `std.crypto.random`.
- Frozen derivations: the external PSK is HKDF-SHA256 extract with salt
  `zmosh quic psk v1` and the bootstrap secret as IKM, expanded with info
  `zmosh-ssh-bootstrap-v1` to 32 bytes; the address-validation token secret
  is extract with salt `zmosh quic token v1`, expanded with info
  `zmosh-address-validation-v1` to 32 bytes.
- Use ALPN `zmosh/1` and the fixed non-secret PSK identity
  `zmosh-ssh-bootstrap-v1`.
- Use quicz's certificate-free, PSK-selected TLS 1.3 handshake. Do not use
  `insecure_skip_verify`, a static certificate, or an external certificate
  generator.
- Disable session tickets, resumption, and 0-RTT. No application stream is
  accepted before `handshakeConfirmed()` and successful application HELLO.
  This is QUIC/TLS handshake resumption, not zmosh terminal reattachment; the
  latter remains supported through a fresh authenticated connection followed
  by snapshot installation.
- Require QUIC Retry/address validation before published client state,
  using the approved **bounded-candidate** contract. The first Initial
  allocates no connection-sized or unbounded per-client state; one bounded
  token/Retry buffer is permitted. The pending-Retry slot matches on the
  full UDP path, QUIC version, original DCID, and client SCID — never
  byte-identical datagrams; tokenless retransmissions matching that tuple
  reissue the same Retry without extending the absolute ten-second expiry;
  unrelated Initials are dropped while the slot is occupied. A token-bearing
  follow-up is accepted only when the slot is occupied and unexpired and its
  path, version, Retry SCID, client SCID, and token match the stored
  exchange exactly. After that exact validation, at most one bounded,
  unpublished candidate connection is created; the follow-up Initial is
  authenticated and processed against the candidate, and only on success is
  the candidate published and the token consumed (clearing the slot). Any
  parse or authentication failure wipes the candidate and rolls every
  allocation back to the pre-Initial baseline. `commit()` consumes only the
  exact stored token. Assertions compare against the pre-Initial baseline:
  every malformed, expired, replayed, wrong-path, unrelated, or
  unauthenticated attempt leaves candidate/Connection/TLS/stream/route
  counts at zero delta, and one valid follow-up creates exactly one
  candidate. QUIC Initial protection is not client authentication — the
  keys derive from the public destination CID — so the boundary is the
  token-gated candidate, not strict pre-allocation packet authentication.
  The Retry response stays within the received-byte amplification allowance.
  Four implementation rules are frozen for the remediation:

  - **Fail-closed path validation**: a PATH_RESPONSE for a bound
    challenge is consumed only when the arrival path is recorded AND
    equals the binding; a null arrival hint leaves the challenge
    outstanding. Every public application/short-packet receiver
    capable of decoding PATH_RESPONSE records the arrival hint — not
    every API that accepts a path — with one guard mechanism as the
    single source of truth and IPv4 wrappers as pure `.toUdp()`
    delegates.
  - **Path-specific route commit**: route mutation is authorized only
    by a decrease in the candidate path's own bound-challenge count
    (`outstandingPathChallengeCountForPath`), never by total-count
    comparison; legacy unbound challenges never authorize migration.
  - **Adopted-candidate rollback**: the bounded candidate is adopted
    into a private capacity-one registry with its route installed
    (private ownership is not publication); authentication failure — or
    a `commit()` failure after adoption — retires the record and
    returns registry/connection/route counts to the pre-adoption
    baseline, with the registry's `deinit_record` wiping the backend
    before destruction. Replay semantics: repeated classification
    before commit is idempotent; commit consumes exactly once;
    classification after commit is rejected.
  - **Secret ownership**: `PairOptions` carries PSK pointers; callers
    own and wipe the mutable bootstrap/PSK/token-secret originals;
    `derivePsk(out: *[32]u8, bootstrap: *const [32]u8)` writes in
    place; the harness retains no redundant copies; every backend is
    `secureWipe()`d before destruction; constructors build resources as
    locals with adjacent errdefers and assign the Pair only on success.

  Round-4 frozen rules (review of the round-3 resubmission):

  - **Fresh packet numbers for every crafted injection**: the spike
    migration matrix derives each injected packet number from
    `server.nextPeerPacketNumber(.application)`; only the exact-replay
    case reuses the identical protected datagram bytes. The stale and
    wrong-data cases run on separate fresh pairs, as does any case
    that could close the connection.
  - **Guard mechanism, never nested**: quicz gains a tiny private
    `ReceivePathHintScope` (set on init, clear on deinit). Exactly one
    guard per processing path; delegating wrappers never create
    guards; the existing manual `setReceivePathHint` brackets are
    replaced by the single guard, not wrapped. Scoped receive roots
    that must guard:
    `processRoutedProtectedShortDatagram` (9951), `…OrClose` (10073),
    `…WithKeyUpdate` (10378), `…WithKeyPhaseState` (10683),
    `…WithInstalledKeysOrCloseAndPollDatagram` (12763), and BOTH feed
    roots — `feedDatagramWithInstalledKeys` (1743) and
    `feedDatagramWithInstalledKeysAcrossConnections` (1991). Feed
    roots guard only the `.application` processor: Handshake and 0-RTT
    cannot decode PATH_RESPONSE. Route mutation stays solely in the
    existing UpdatePath implementations.
  - **No test-only fns in the production API**:
    `processDecodedFramesForTest` is removed; the null-hint proof
    exercises the connection-level entry
    `processProtectedShortDatagramWithInstalledKeys` with a crafted
    protected PATH_RESPONSE datagram.
  - **Secret wipe completeness**: the actual mutable token-secret
    original is wiped (no `secret_original` copies), and each mutable
    HKDF PRK is wiped with an immediate `defer` right after
    extraction, in every `derivePsk`.
  - **Real state, not counters**: the fake `AllocCounters` proof is
    deleted; bounded-candidate assertions use lifecycle/registry
    state (`router.routeCount()`, `replayFilterEntryCount()`,
    `slot.occupied`, registry counts).
  - **Report taxonomy**: 4 real-socket proofs + 1 sans-I/O adoption
    proof; the adoption test is not counted as real-socket.
  - **Bats gate amendment (evidence-first)**: baseline runs at
    `6f4c4d1` precede any amendment. Baseline evidence 2026-08-18:
    fresh `zig build` in a temp worktree, 20 isolated filtered runs
    (`bats --filter '^write accepts exactly 128 KiB and rejects one
    byte more$' test/write.bats`), Linux 7.1.7+deb14-amd64, Zig
    0.16.0, binary sha256 `186817f4…d6075d` — **10/20 failed**
    (9× `write.bats:96` size assert; 1× `write.bats:75` status
    assert), so the flake is proven pre-existing and outside Q1. The
    write flake is tracked as **zmosh-r3b** (labels bug, write,
    replant) which **blocks zmosh-pnf** (`bd dep zmosh-r3b --blocks
    zmosh-pnf`); its acceptance requires a real daemon fix, repeated
    boundary-test success, and full Bats green. `zmosh-8sd.1`
    criterion 5 is amended to no-regression-versus-baseline:
    identical filtered command, 20 runs per side at the frozen
    candidate SHA (recorded in the evidence report and Bead comment —
    the plan commit cannot contain its own SHA), tracked root inputs
    identical via `git diff --exit-code 6f4c4d1..<candidate_sha> --
    src test build.zig build.zig.zon build_support flake.nix`
    (omitting only nonexistent paths), no new failure signature, and
    one complete `bats test` at that SHA permitting only the two
    tracked known signatures.

  The one-client-per-gateway policy and authenticated second-client
  rejection are Q3.
- Prove that a wrong PSK, wrong identity, replayed Initial, and pre-handshake
  application data cannot reach application dispatch.
- Zeroize secrets in their real owners: `Tls13ServerTransport.deinit()`
  wipes its TLS backend; `Tls13ClientTransport.deinit()` wipes its backend
  and retained Initial keys; `AddressValidationPolicy.deinit()` wipes token
  secrets before freeing; stored `InitialSecrets` are wiped explicitly;
  `Connection.deinit()` keeps wiping packet keys; temporary bootstrap and
  derived copies use `defer`/`errdefer` secure wipes. Never log key material
  or enable qlog by default.

### Transport proof

- v1 fixes the UDP payload at 1200 bytes and never emits an IP-fragmenting
  datagram. DPLPMTUD is deferred entirely; paths that cannot carry the
  1200-byte QUIC minimum fail loudly.
- Prove stream isolation under loss: delayed snapshot/output bytes must not
  block input or control on another stream.
- Prove connection migration after source-port and source-address changes
  through real path validation: authenticated data from the new path queues
  an unpredictable PATH_CHALLENGE that is sent on the candidate path; the
  matching PATH_RESPONSE must come from that path; the route commits only
  afterward. Wrong, stale, and old-path responses cannot commit the route,
  and traffic returning to the old path requires fresh validation.
- Prove RESET_STREAM and STOP_SENDING are observable by the application.
- Expose only the conservative per-stream backlog metric:
  `accepted_offset`, `oldest_unsettled_offset` (the minimum STREAM offset
  present in the application send queue or sent packets, equal to
  `accepted_offset` when none exists), and derived `outstandingBytes()`. No
  age API: zmosh Q5 owns `{last_offset, no_progress_since}` and starts its
  timer on the 0-to-nonzero backlog transition.
- Prove a 24-hour negotiated idle lifetime through negotiated-parameter
  assertions and scaled-down timer tests, not a literal 24-hour run. Prove a
  1-second keepalive while attach or tail is active and visible
  disconnected/reconnected transitions after five seconds without an
  authenticated packet.

### Resource and platform proof

- Bound one connection to 4 MiB connection credit, at most four bidirectional
  and eight unidirectional streams, and bounded receive/send queues.
- Measure stripped binary growth and clean build time against `6f4c4d1`.
  Adoption requires no new dynamic library and no more than 5 MiB stripped
  binary growth or 2x clean `zig build check` time.
- Pass Linux Debug and ReleaseSafe builds, the full zmosh test suite, and the
  quicz suite.
- Compile-gate the host static C library and Apple targets. A real macOS/iOS
  run remains a release gate, not something inferred from Linux compilation.
- Verify quicz's MIT license and include its required notice in release source
  and binary attribution.

### Spike fault matrix

The deterministic harness must inject loss, duplication, reordering,
corruption, delay, NAT rebinding, a ten-second outage, and a slow receiver,
and must fail loudly on paths that cannot carry the fixed 1200-byte payload.
It must demonstrate successful PSK handshake, stream echo, timer recovery,
migration, bounded memory, reset observability, and clean shutdown. Process
cleanup (no orphan socket, SSH child, or gateway process) is proven at Q2
integration and gated again at Q8.

### Go/no-go decision

Write `docs/quic-spike.md` with exact SHAs, patches/API gaps, test output,
binary/build measurements, platform results, and residual risks.

QUIC is accepted only if every hard gate above passes. On acceptance, the
production quicz pin is the reviewed untagged dependency SHA recorded in
the frozen-inputs table, tagged immutable `zmosh-quic-q1-5` only after
re-review approval. The full-Bats gate is the amended
no-regression-versus-`6f4c4d1` criterion (round-4 rules above); if a
hard gate fails, stop and follow the fallback section; do not weaken
the gate during implementation.

Checkpoint: Q1 approved and closed 2026-08-18 — spike report committed
and pushed; the reviewed SHA is tagged immutable `zmosh-quic-q1-5`
(peel-verified at `d854133`); implementation is unlocked and Q2 begins
from that pin.

## Phase Q2: production QUIC foundation

After spike approval:

1. Add the exact reviewed quicz dependency and package hash.
2. Add a thin `quic_transport.zig` adapter around the accepted sans-I/O API.
   It owns no terminal or command semantics.
3. Integrate the UDP fd and QUIC deadline into the existing `poll()` loop.
   A single poll timeout is the minimum of QUIC recovery, keepalive,
   application deadline, SSH shutdown, and signal work.
4. Keep current dual-stack bind and `ZMX_UDP_PORT_RANGE` behavior. Keep
   `ssh -G` host resolution and document that ProxyJump still requires direct
   UDP reachability.
5. Change successful bootstrap to:

       ZMX_CONNECT quic PORT KEY

   The field count and key encoding remain unchanged; the transport token
   changes from `udp` to `quic` so mixed binaries fail visibly instead of
   misinterpreting packets. `ZMX_ERROR CODE MESSAGE` remains bounded.
6. Keep the 10-second SSH/bootstrap and QUIC-handshake deadline. Preserve
   inherited SSH stderr, isolated stdin, shell quoting, ownership, and reaping.
7. Add connection diagnostics using counters and durations only. Do not log
   session content, command bodies, labels, paths, snapshot bytes, or secrets.

Do not remove the custom modules until the PSK QUIC loopback, migration, and
shutdown tests pass in zmosh. Then remove custom XChaCha framing, packet ACKs,
retransmission windows, replay window, heartbeat packets, reorder buffers, and
the generic reliable sender as one reviewed checkpoint. Keep only reusable
socket/address helpers.

## Phase Q3: minimal zmosh-over-QUIC protocol

QUIC streams are already ordered, reliable, flow-controlled byte streams. The
application protocol therefore contains only role identification and semantic
message boundaries.

### Common stream preface

Every application stream begins with eight bytes:

| Offset | Field | Value |
|---|---|---|
| 0..3 | magic | ASCII `ZMQ1` |
| 4 | role | enum below |
| 5 | flags | role-specific, otherwise zero |
| 6..7 | reserved | zero |

Roles are frozen as control=1, input=2, snapshot=3, output=4, command=5.
Unknown roles, flags, or nonzero reserved bytes are protocol errors.

### Control stream

The client opens exactly one bidirectional control stream before any other
stream. Control frames use an eight-byte header:

| Field | Encoding |
|---|---|
| type | u8 |
| flags | u8 |
| reserved | u16 big-endian, zero |
| payload length | u32 big-endian, maximum 64 KiB |

Control types are HELLO=1, HELLO_ACK=2, RESIZE=3, DETACH=4,
SNAPSHOT_REQUEST=5, SNAPSHOT_INSTALLED=6, SESSION_END=7, ERROR=8. QUIC PING
provides transport liveness; there is no application heartbeat message.

HELLO and HELLO_ACK carry:

- application major and minor versions (`1.0` initially);
- mode (`attach=1`, `command=2`);
- required capability bits;
- a 32-byte `snapshot_abi_id`;
- negotiated snapshot and command size limits.

The required capabilities are binary_snapshot, resettable_output,
remote_commands, tail, and dual_stack. Construct `snapshot_abi_id` over these
exact bytes, with no textual dependency URL:

    SHA-256(
        "zmosh-snapshot-abi-v1\0" ||
        ghostty_commit_ascii[40] ||
        u16_be(zig_package_hash_utf8.len) ||
        zig_package_hash_utf8 ||
        u32_be(adapter_version)
    )

`ghostty_commit_ascii` is the lowercase 40-byte SHA of the production pin.
`zig_package_hash_utf8` is the exact `.hash` string in `build.zig.zon`.
`adapter_version` starts at 1 and increments for any zmosh-side snapshot
adapter or wire change. A major-version, required-feature, or fingerprint
mismatch sends ERROR and closes before session data moves.

RESIZE carries rows, columns, xpixel, and ypixel as four big-endian u16 values.
Resize events received while installing a snapshot are coalesced; only the
latest is applied after installation.

### Stream cardinality

- Attach: one control stream, one client input stream, and one current server
  snapshot/output epoch.
- One-shot command: one control stream and exactly one command stream.
- A second control, input, or command stream is rejected.
- Stream and connection errors use stable application error codes documented
  in `docs/quic-wire.md`.

Keep parsing allocation-free for fixed headers and validate all lengths before
allocation. Unknown control messages are rejected rather than ignored in v1.

## Phase Q4: Ghostty binary snapshot export

The daemon owns the authoritative `ghostty_vt.Terminal`; the gateway cannot
create a faithful binary snapshot by wrapping the old VT replay. This phase is
the one authorized exception to the gateway-only networking rule: add an
additive local snapshot-export IPC path. It is terminal serialization support,
not network logic.

### Ghostty pin and continuation

- Advance Ghostty to the dand-oss fork pin (`6361b2eac...`, upstream
  `56e1f3a62` plus the reviewed `pub const snapshot = terminal.snapshot;`
  re-export; SHA-only, no custom tag), then regenerate and record the Zig
  package hash. The audited `b97b17f...` tree and snapshot content reference
  `1359973a...` are review inputs, not the production pin.
- Pass `vt-features=+snapshot` explicitly and, only after the re-export lands,
  use the public `ghostty_vt.snapshot` encoder and Decoder. Do not copy or
  reinterpret Ghostty record definitions, use the C wrapper, or carry a
  zmosh-only Ghostty patch.
- Create one persistent continuation-tracking VT stream before the first PTY
  byte reaches the terminal. Bound retained unfinished VT/UTF-8 input to
  64 MiB. At each snapshot cut, export that stream's continuation once and
  pass it unchanged to Ghostty's encoder; do not reconstruct continuation
  state from serialized terminal output.
- Bound a complete snapshot to 128 MiB and fail atomically if exceeded.

### Additive daemon IPC

Retain tags 0..19 and add frozen tags:

| Tag | Value | Direction | Meaning |
|---|---:|---|---|
| InitSnapshot | 20 | client to daemon | become terminal client, apply target Resize, request binary snapshot |
| SnapshotBegin | 21 | daemon to client | one-byte `present` flag |
| SnapshotChunk | 22 | daemon to client | up to 32 KiB opaque Ghostty bytes |
| SnapshotEnd | 23 | daemon to client | total encoded byte count u64 big-endian |
| SnapshotError | 24 | daemon to client | bounded code and diagnostic |

Normal `.Init` and `.Output` behavior stays unchanged for local clients.
Unknown tags remain ignored through the non-exhaustive IPC enum.

For `InitSnapshot`, establish leadership and resize the PTY and Ghostty
terminal first, then capture the binary snapshot before the event loop reads
the shell's resulting SIGWINCH output. This differs intentionally from the old
VT replay path: binary state preserves the post-reflow cursor and dimensions,
while subsequent shell redraw is unambiguously post-cut output.

The encoder writes through a 32 KiB chunking writer directly into the
requesting client's IPC write queue. Record the queue length before appending
`SnapshotBegin`; treat `SnapshotBegin`, every `SnapshotChunk`, and
`SnapshotEnd` as one transaction. On any encode, limit, or allocation failure,
roll the queue back to that exact length and append only one `SnapshotError`.
The event loop cannot flush partial data during the synchronous encode, so the
operation is atomic without a second full-snapshot allocation.

Synchronous encoding blocks only the target session's daemon. Measure encoder
wall time and peak RSS on the large-scrollback fixture and record explicit
acceptance bounds before production adoption. Do not promise incremental
encoding unless Ghostty exposes a resumable encoder upstream.

Only one snapshot export may be active for a client. Validate IPC header
lengths before buffer growth. Snapshot errors affect only the requesting
gateway, never the daemon or local clients.

### Snapshot stream and epoch

A server snapshot stream contains the common preface followed by:

- epoch: u64 big-endian;
- flags: PRESENT=1 when Ghostty bytes follow;
- seven reserved zero bytes;
- the unmodified Ghostty Snapshot v1 byte stream;
- QUIC FIN immediately after Ghostty FINISH.

The client requires both a valid Ghostty FINISH and QUIC FIN, with no trailing
bytes. A missing marker, trailing byte, CRC/record error, size violation, or
fingerprint mismatch rejects the epoch.

For a new empty session, PRESENT is clear and no Ghostty bytes follow. Epochs
start at 1, increase monotonically, and never wrap; stale epoch streams are
discarded. Only one epoch may install at a time.

### Client installation

Ghostty's `ready()` is a synchronous, first-call-only transactional pull. It
cannot consume a snapshot that is still arriving, so installation is
spool-first:

1. If PRESENT is clear, require immediate QUIC FIN and install the empty epoch
   without invoking Ghostty's decoder.
2. Otherwise spool the complete snapshot through QUIC FIN into one bounded
   in-memory buffer. Reject more than 128 MiB before growing the buffer. Do not
   parse or inspect Ghostty records while receiving them.
3. Construct the Decoder over a fixed reader on the completed spool and call
   `ready()` exactly once. A failure rejects the epoch without modifying the
   active terminal.
4. Transfer the decoded terminal to its final address and restore the returned
   continuation exactly once.
5. Call `next()` at most once per client event-loop turn. After READY,
   post-cut output for the same epoch may be applied between history pages;
   Ghostty owns the history/live-output interaction and may discard history
   pages invalidated by terminal mutation.
6. Keep the output stream flow-controlled and unread until READY succeeds so
   post-cut bytes cannot overtake the snapshot. The Q1 spike must prove that a
   blocked output stream cannot starve snapshot or control progress.
7. When `next()` reports completion, Ghostty has validated FINISH. Require the
   fixed reader to have no unread trailing bytes.
8. Serialize the resulting terminal once to VT for the existing CLI and C
   output callback, then switch future output to direct forwarding.

No resumable decoder API is required: decoding never waits for network input
because the spool is complete. `ready()` and each `next()` call still perform
synchronous CPU work, so their wall time and peak RSS are measured alongside
encoding rather than described as non-blocking.

Bytes applied to the temporary decoded terminal are not emitted a second time.
Coalesced resize is sent only after installation so history is not discarded by
a mid-snapshot width change.

The public C ABI remains unchanged. `zmosh_output_fn` still receives VT bytes;
binary snapshot exposure would require a future additive API and is out of
scope.

## Phase Q5: reliable output epochs and remote attach

Input uses one client unidirectional reliable stream. Raw terminal input is
written in order; resize and detach remain framed control messages.

Output uses one server unidirectional reliable stream per epoch. Its common
preface is followed by the epoch u64 and raw PTY bytes. There are no zmosh
output packet sequence numbers or reorder windows.

Normal packet loss never requests a snapshot: QUIC retransmits it. A new
snapshot is required only for initial attach, an explicitly replaced output
epoch, or a rejected/corrupt snapshot.

### Slow-consumer replacement

The gateway enforces both limits on the current output stream:

- at most 1 MiB queued plus unacknowledged output;
- no contiguous progress on the output stream for at most five seconds,
  measured by zmosh from the backlog metric's 0-to-nonzero transition and
  subsequent lack of `oldest_unsettled_offset` advancement (no age API in
  quicz).

Crossing either limit resets that output stream with OUTPUT_STALE, stops
forwarding stale daemon `.Output`, increments the epoch, and requests a fresh
binary snapshot. Snapshot requests are coalesced and rate-limited to one per
second with retry delays of 250 ms, 500 ms, 1 s, 2 s, then 4 s. Thirty seconds
without a valid replacement snapshot closes the connection with permanent-loss
exit semantics.

The gateway continues polling QUIC, signals, and the daemon throughout. It
drains and discards stale `.Output` until SnapshotBegin marks the new cut. It
never lets a slow remote reader grow daemon, gateway, quicz, or client memory
without a fixed bound.

The client freezes stdout when it observes OUTPUT_STALE, reports temporary
resynchronization on stderr, installs the replacement epoch, and resumes.
Temporary QUIC path loss reports disconnected after five seconds and connected
on recovery without contaminating stdout.

Reapply and preserve remote argument forwarding, prefix-once semantics,
visible connect/loss errors, session-end propagation, terminal pixel size,
Kitty restoration, SSH cleanup, and existing attach Bats coverage.

Checkpoint: encrypted QUIC remote attach passes local SSH-shim and real-host
smokes before command work begins.

## Phase Q6: remote commands over QUIC streams

Delete the custom 20-byte command chunk envelope, request reassembler,
sequence-span sender, and response retransmission cache. Preserve opcode,
status, body validation, and semantic tests in a smaller
`remote_protocol.zig`.

### Shared local and remote command safety

Define one set of semantic limits in the local IPC layer and reuse it in the
CLI, daemon, gateway, and remote protocol:

- write: 128 KiB, retaining the completed Phase 4A atomic enqueue and Ack
  behavior;
- send: 128 KiB, with an all-or-nothing daemon enqueue and `.Ack` success or
  rejection instead of today's fire-and-forget write that may be dropped when
  the 256 KiB PTY queue fills;
- print: 1 MiB;
- label requests: 64 KiB.

Validate the complete operation before mutating a daemon queue or session
state. This is a deliberate local and remote behavior change: an oversized
operation, and a send that cannot be enqueued atomically, now fail visibly
instead of possibly truncating or disappearing. Raising any limit requires a
streamed daemon IPC design, not a larger allocation.

### Command stream format

The client opens one bidirectional command stream after HELLO_ACK. After the
common preface, the request is:

| Field | Encoding |
|---|---|
| opcode | u8: send=1, print=2, write=3, label_get=4, label_set=5, label_clear=6, tail=7, kill=8 |
| flags | u8: FORCE=1 only for kill |
| reserved | u16 big-endian, zero |
| body | role-specific bytes through client FIN |

The response begins with status u8, flags u8, and reserved u16, followed by
response bytes through server FIN. Status values remain ok=0,
invalid_request=1, unsupported_version=2, unsupported_opcode=3,
session_not_found=4, session_unresponsive=5, timeout=6, too_large=7,
cancelled=8, backpressure=9, and internal_error=255.

Body shapes remain:

- send/print: raw bytes;
- write: path length u32 big-endian, path, then file bytes;
- label_get: optional key;
- label_set: validated key=value pairs;
- label_clear and tail: empty;
- kill: empty, with FORCE carried in flags.

QUIC FIN replaces total length, offsets, FIRST/LAST, chunk ordering, and
request IDs. Validate incrementally while reading and reject excess data
before growing buffers.

### Execution semantics

- send, print, labels, tail, and kill require an existing session;
- only write may create a missing session;
- write uses the Phase 4A atomic enqueue and Ack error convention;
- send reports success only after its complete payload is atomically queued
  and acknowledged by the daemon;
- print and label operations use the shared bounds and return their existing
  local success output or a bounded rejection;
- kill waits for daemon EOF; `--force` also removes a stale socket when no
  daemon is reachable;
- tail connects as an ordinary daemon client and forwards future `.Output`
  only; it never sends `.Init` or replays a snapshot;
- `roundTripForTag()` is forbidden inside the gateway event loop;
- command execution continues servicing QUIC timers, ACK generation, signals,
  and daemon I/O.

One ephemeral gateway accepts one command stream. QUIC handles byte
retransmission, so the client never resubmits the operation automatically. If
the connection dies after dispatch but before the response, print one concise
“outcome unknown” error and exit 3; this prevents duplicate write or kill.

Tail uses the response side of its command stream. SIGINT/SIGTERM sends
STOP_SENDING with CANCELLED, the gateway closes the daemon socket, and the
client exits 0 after a short graceful deadline. Tail backpressure returns
BACKPRESSURE instead of allocating indefinitely. Tail bytes remain raw at the
gateway and ANSI stripping remains client-side.

Preserve the established CLI grammar, stdin distinctions, success output, and
exit codes:

- 0: success, normal session end, or user-cancelled tail;
- 1: command/session error;
- 2: SSH, bootstrap, or QUIC-handshake failure;
- 3: permanent connection loss or unknown side-effect outcome.

Finite command deadline remains 30 seconds through
`ZMX_REMOTE_COMMAND_TIMEOUT_MS`. Keep `ZMX_SSH` and
`ZMX_UDP_PORT_RANGE`; QUIC still uses UDP.

## Phase Q7: build, ABI, documentation, and removal audit

- Complete host `libzmosh.a`, release, macOS, iOS, xcframework, and flake
  branding on the Zig 0.16 build structure.
- Ensure the C library links Ghostty and quicz statically and exposes no new
  dynamic dependency.
- Compile and run an unchanged-header C consumer against
  `include/zmosh/zmosh.h`.
- Update AGENTS.md only after QUIC acceptance: quicz becomes the second
  reviewed runtime source dependency, and the additive snapshot IPC tags are
  documented as the narrow terminal-export exception.
- Add `docs/quic-wire.md` and `docs/quic-threat-model.md`; create or update
  `docs/upstream-sync.md` with dependency SHAs, ALPN, bootstrap token, stream
  roles, IPC tags, fingerprint construction, limits, and upgrade procedure.
- Reconcile every old networking file and commit in the replant ledger. Mark
  custom transport and command framing as superseded, not silently lost.
- Remove dead custom crypto/reliability code and tests only after equivalent
  QUIC/snapshot behavior is green.
- Retain the terminal fixes and newer zmx behavior already required by the
  original replant plan.

## Phase Q8: verification gates

### Unit and property tests

- Golden common-preface, control-frame, HELLO, snapshot-header, command-header,
  enum, reserved-bit, limit, and mismatch tests. Construct the
  `snapshot_abi_id` from the exact canonical bytes specified in Q3 and prove
  that changing the commit, package hash, or adapter version rejects HELLO.
- Pure transition tests for connection negotiation, one-stream cardinality,
  snapshot epochs, stale streams, output replacement, coalesced resize,
  command completion, cancellation, and shutdown.
- PSK match/mismatch, no-certificate PSK selection, 0-RTT rejection, Retry
  validation, second-client rejection, migration, key update, and key cleanup.
- Ghostty encode/decode round trips for normal screen, alternate screen,
  scrollback, styles, title, OSC 7, synchronized output, Kitty keyboard state,
  resize, nested zmosh, and unfinished ESC/CSI/OSC/DCS/APC/UTF-8 continuation.
- Feed network snapshot bytes into the bounded spool at every boundary from
  one byte through large random chunks, but invoke Ghostty's decoder only
  after QUIC FIN. Reject truncation, trailing bytes, CRC failure, malformed
  order, excessive continuation, and oversized total data through the
  Ghostty adapter without duplicating its record parser.
- Decode through READY, feed post-cut PTY bytes, finish history, and verify the
  final terminal and subsequent behavior match an uninterrupted terminal.
- Measure encode, READY, and per-page decode wall time plus peak RSS on the
  large-scrollback fixture; record and enforce reviewed acceptance bounds.
- Fuzz the zmosh stream/control parsers, daemon snapshot IPC adapter, and
  Ghostty adapter boundary. Do not duplicate Ghostty's internal parser.

### Deterministic network tests

Use an in-process datagram harness below QUIC to inject:

- loss of handshake and 1-RTT packets;
- heavy reordering and duplication;
- corruption and truncation;
- MTU 1200 and failed larger probes;
- delayed ACK/PTO recovery;
- source-port and source-address rebinding;
- ten-second blackout and recovery;
- slow output until the 1 MiB/five-second replacement threshold;
- control/input traffic while snapshot or output packets are lost.

Assert bounded memory, no custom resync on ordinary packet loss, exact output,
successful migration, one replacement snapshot on stale output, and no orphan
processes.

### Bats and end-to-end tests

Extend the deterministic `ZMX_SSH` shim to cover QUIC bootstrap and all remote
forms. Preserve all local zmx tests and existing remote attach tests. Cover:

- new and existing remote sessions, exact prefixing, and forwarded commands;
- visible bootstrap, PSK, protocol, fingerprint, timeout, and permanent-loss
  failures;
- large binary snapshot with scrollback and continuation;
- attach through loss/reordering and deterministic migration;
- every finite command, missing-session behavior, write creation, stdin
  semantics, labels, live/stale kill, and exact stdout/stderr/exit status;
- local and remote write, send, print, and label requests immediately below,
  exactly at, and immediately above each shared limit; prove oversized and
  queue-full send operations leave the PTY queue unchanged and report error;
- tail future-only output, cancellation, backpressure, and session end;
- no orphan SSH/gateway/session process after every path.

Run a real SSH smoke before release and a 30-minute impaired-network soak with
loss, reordering, delay, and at least one NAT-rebinding event. Retain dated
known-good 0.5.3 binaries during deployment qualification.

### Required automated gates

- `zig build`
- `zig build check`
- `zig build test`
- full `bats test`
- `zig build lib`
- `zig build release`
- `zig fmt --check`
- `git diff --check`
- quicz upstream suite at the pinned production SHA, as a separate gate
  outside the 2x zmosh `zig build check` time budget
- C ABI symbol/header/consumer smoke
- no tracked or untracked test artifacts

Apple execution gates may be reported as pending only on Linux; they must pass
on macOS before a release, not merely before branch review.

## Fallback if the QUIC gate fails

The binary snapshot work remains required. Do not improvise a second QUIC
library.

1. Remove the spike dependency and retain `docs/quic-spike.md` as evidence.
2. Hand-port `7404914` and `db4661c` from the frozen fallback master.
3. Allocate custom `Channel.snapshot = 4` and move
   `Channel.command = 5`; freeze both values in tests.
4. Keep master's authenticated reorder window, reliable generation-framed
   snapshots, output suppression until snapshot installation, immediate mixed
   transport-version failure, and loss/reverse-order regression tests.
5. Replace only the snapshot payload with the official Ghostty binary stream
   and use the additive daemon IPC export defined in Phase Q4.
6. Resume the custom command-gateway phases from
   `plans/zmosh-replant.md`, retaining the 16-sequence-span flow-control rule.

The fallback is a deliberate branch in the plan, not a runtime compatibility
mode.

## Beads reconciliation

Do not mutate Beads until this plan is reviewed. Then run plan-to-beads against
this file and reconcile the existing graph as follows:

1. Verify `zmosh-126` remains closed as completed at `6f4c4d1` with its full
   gate counts; do not close it again.
2. Keep closed historical beads `zmosh-b00` and `zmosh-fu5`; add notes that
   their custom transport/framing code is superseded only if QUIC passes.
3. Close open `zmosh-7ru`, `zmosh-7ag`, `zmosh-65k`, and umbrella
   `zmosh-bu1` as **superseded by the QUIC plan**, not completed.
4. Create one new QUIC/snapshot refactor epic named `<quic-epic-id>` with
   tasks:
   Q1 feasibility gate; Q2 production foundation; Q3 wire protocol; Q4 binary
   snapshot IPC; Q5 attach/output epochs; Q6 remote commands; Q7 build/docs;
   Q8 tests and qualification.
5. Chain dependencies in that order. Make existing CLI parity bead
   `zmosh-57w` depend on Q6; make Q7 depend on `zmosh-57w`; make Q8 depend on
   Q7; make existing Phase 6 `zmosh-jpl` depend on Q8.
6. Add the dependency `zmosh-710 -> <quic-epic-id>` so the existing root epic
   is blocked by the new epic. Never reuse `zmosh-710` as the new epic ID.
7. If Q1 fails, close the QUIC production tasks as not adopted and generate
   the fallback tasks from the fallback section; never mark unimplemented QUIC
   work complete.

Every bead must cite its exact heading in this file and contain its focused
acceptance tests. Push no bead-generated code or branch change automatically.

## Commit and review discipline

- Commit the plan alone.
- Commit at every compiling or green vertical checkpoint.
- Keep fixes separate from feature commits even when they touch the same file.
- Push only `replant-zmx0.7` or the explicit spike branch, fast-forward only.
- Stop for review after Q1, Q2/Q3, Q4, Q5, Q6, and final qualification.
- Before deleting the custom stack or rewriting history, create and push a
  backup ref.
- At landing, report exact upstream/dependency SHAs, every gate result,
  dependency/API delta, replant-ledger disposition, skipped platform work, and
  rollback binaries.

## Explicit non-goals

- No HTTP/3, WebTransport, QUIC DATAGRAM live-output path, KCP, or second QUIC
  implementation.
- No Mosh dependency, Mosh SSP implementation, or predictive local echo in v1.
- No runtime custom-UDP fallback after QUIC acceptance.
- No public C ABI change and no native binary-snapshot callback in v1.
- No remote list, history, run, wait, switch, wildcard, or multi-session
  operation.
- No automatic retry of side-effecting commands after uncertain completion.
- No daemon thread, general daemon IPC redesign, Rust rewrite, or hosted
  service.
- No backward compatibility between pre-QUIC and QUIC gateway/client binaries.

## Evaluated prior art

Evaluated 2026-08-17. These projects are design references, not proposed
runtime dependencies. The decision remains to use the forked Zig `quicz`
transport with Ghostty Snapshot v1; none of the projects below replaces both
halves of that design.

- **[p2sh](https://github.com/eskimor/p2sh) — future discovery/relay reference,
  not an implementation candidate.** Its intended model is a stable node ID,
  NAT traversal, relay fallback, QUIC, and eventually terminal-state
  synchronization, but the repository describes itself as a crude proof of
  concept: it still invokes ordinary SSH and has not implemented QUIC or NAT
  traversal. Retain its node-addressing and relay roadmap as input to a future
  direct-UDP-reachability project; do not add those concerns to this refactor.

- **[quicssh-rs](https://github.com/oowl/quicssh-rs) — transparent-tunnel
  reference.** It puts an unmodified SSH byte stream through QUIC by using
  OpenSSH `ProxyCommand`, Quinn, and Tokio. This usefully demonstrates that
  connection migration can be hidden behind conventional SSH tooling, but it
  has no terminal snapshot, output-epoch, or session-state semantics. Its Rust
  async stack also conflicts with zmosh's Zig-only, single-threaded `poll()`
  architecture. Borrow lifecycle and interoperability test ideas, not its
  runtime or proxy architecture.

- **[tsshd](https://github.com/trzsz/tsshd) and its
  [Show HN report](https://news.ycombinator.com/item?id=46680813) — primary
  operational reference for bootstrap and roaming.** It uses ordinary SSH to
  start a temporary server, moves traffic to QUIC or KCP, authenticates a new
  address before replacing the active path, and preserves full OpenSSH
  behavior. This is strong evidence for the SSH-bootstrap UX and for tests of
  authenticated rebinding, one-client ownership, reconnect visibility, and
  orphan-free process cleanup. It is nevertheless a Go SSH proxy with its own
  reconnect/heartbeat layer; zmosh should let QUIC own path migration and let
  Ghostty snapshots/output epochs own terminal recovery. The HN post is an
  author deployment report, useful corroboration rather than independent
  protocol evidence.

- **[Latch](https://github.com/unixshells/latch) — product and trust-boundary
  reference.** Its single binary exposes shared terminal sessions through
  standard SSH, native Mosh, a web terminal, and an encrypted relay. Its useful
  lessons are consistent session naming across transports, explicit relay
  trust claims, and simple one-binary remote-access UX. Its multiplexer,
  windowing, hosted relay, web client, and multi-transport scope are outside
  this refactor, and it offers no QUIC plus Ghostty binary-snapshot path.

- **[RoSE](https://github.com/nikhiljha/rose) — closest architectural
  comparison.** RoSE combines QUIC streams and RFC 9221 datagrams, SSH
  bootstrap, roaming, local prediction, scrollback, and a terminal-state
  synchronization protocol. It validates the broad direction and is valuable
  for fault-matrix and stream/datagram-separation test ideas. Do not adopt its
  Rust/GPL implementation, X.509/TOFU identity model, terminal emulator, or
  state-synchronization protocol: those duplicate the selected SSH-delivered
  PSK, native Zig Ghostty terminal, and Snapshot v1 design. QUIC migration
  should also avoid an application-level reconnect state machine where the
  library can preserve the connection.

- **[libghostty-rs](https://github.com/uzaaft/libghostty-rs) — binding and
  packaging reference only.** It provides generated raw FFI plus safe Rust
  wrappers over `libghostty-vt`, pins the Ghostty source, supports local and
  network-free source overrides, and tests Rust-owned unsafe boundaries. Those
  are useful precedents for pin discipline, static-library packaging, and C ABI
  smoke tests. It does not remove zmosh's need for a native Zig Snapshot v1
  re-export: its documented render snapshots are not the binary continuation
  protocol, and adopting it would add Rust and transfer terminal ownership
  through the C ABI. Keep it as C-library/build-system prior art, not a
  dependency or fallback.

The concrete additions to qualification are therefore limited to test ideas:
authenticated path replacement must reject the old path; SSH bootstrap and
gateway teardown must leave no orphan; transport migration must not create a
second application session; stream backpressure must not block control traffic;
and snapshot/output-epoch recovery must remain byte-correct through loss,
reordering, and address changes. No new feature scope or dependency follows
from this survey.

## References

- quicz: <https://github.com/venjiang/quicz>
- quicz API layers: <https://github.com/venjiang/quicz/blob/main/docs/en/api-layers.md>
- Ghostty Snapshot v1 discussion: <https://github.com/ghostty-org/ghostty/discussions/11998>
- Ghostty remote-state discussion: <https://github.com/ghostty-org/ghostty/discussions/12176>
- Ghostty snapshot source: <https://github.com/ghostty-org/ghostty/tree/main/src/terminal/snapshot>
- Ghostty C snapshot API: <https://github.com/ghostty-org/ghostty/blob/main/include/ghostty/vt/snapshot.h>
- Paneflow Ghostty integration lessons: <https://github.com/arthjean/paneflow/blob/main/BUILD_WEEK.md>
- OpenSSH release notes, including 10.4 and removal of experimental roaming in
  7.2: <https://www.openssh.com/releasenotes.html>
- OpenSSH `ControlMaster`/`ControlPersist` semantics:
  <https://man.openbsd.org/ssh_config.5>
- Mosh behavior and State Synchronization Protocol overview:
  <https://mosh.org/>
- zmosh custom fallback commits: `7404914`, `db4661c`
