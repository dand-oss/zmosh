# Plan: Q3 correction round r8 — hierarchical client protocol FSM

Status: frozen (approved 2026-08-19 after review rounds r8.1–r8.5).
Baselines: zmosh `replant-zmx0.7` at `76ab014`; quicz pinned at
`zmosh-quic-q2-2` = `067e7bab687536c1327fb436484dee85d5368318`. Governing
heading: Phase Q3 of `plans/quic-binary-snap-refactor.md`. This file is the
authoritative r8 contract; the r4-frozen Q3 text above it stands except
where a checkpoint below amends it.

## Context

r7 landed at `76ab014` (q2-2 repin clean) but review found six P1
client/driver defects, a constructor-cleanup P2, and an inaccurate r7
evidence record. Root cause: client/driver protocol state is an enum
plus interacting booleans (`.ended` while output must drain,
`input_preface_pending` never set, parked first RESIZE without
transition metadata, terminal/FIN/reset/close tracked independently).
The complexity is real but concealed; this round uncovers and deals
with it via one hierarchical FSM with typed stream substates — not a
flat cross-product (streams genuinely advance independently). Bead
`zmosh-8sd.9`; Q4 stays locked.

## Summary

Implement against `76ab014`, retaining the existing zmosh-quic-q2-2
pin unchanged.

Replace the flag-oriented client logic with:

- One authoritative hierarchical application-protocol FSM in
  `ClientSession`.
- One small I/O lifecycle FSM in the socket-owning `Client`.
- Typed stream substates embedded in live protocol states.
- Exhaustive switch transitions instead of independently mutated
  phase flags.

The server's existing `QuicSession.Phase` (quic_session.zig:90)
remains; only terminal-ERROR flag emission and constructor cleanup
change there.

Out of scope: remote.zig, Q4, daemon core, IPC, quicz source or refs,
backup deletion, and quic_transport.zig (adapter SLOC stays 467).

## State model

### Application protocol FSM

```zig
const ProtocolState = union(enum) {
    awaiting_ack: AwaitingAck,
    awaiting_first_resize: Authorized,
    active: Active,
    draining: Draining,
    failed: Failure,
    closed: CloseKind,
};
```

| State                  | Permitted nested state                          |
| ---------------------- | ----------------------------------------------- |
| `awaiting_ack`         | HELLO sent or pending; control receive active; output unauthorized; no input |
| `awaiting_first_resize`| Control receive active; output header/body authorized; first RESIZE idle or pending |
| `active`               | Ordinary control writes, input stream lifecycle, control receive, output receive |
| `draining`             | Terminal marker recorded; no new sends; control FIN validation and output draining continue |
| `failed`               | One local/protocol failure recorded; application close initiated |
| `closed`               | Peer connection close recorded; no further transport operations |

Typed substates:

```zig
const ControlTx = union(enum) {
    idle,
    pending: struct {
        kind: enum { hello, first_resize, ordinary },
        len: usize,
        bytes: [client_max_frame]u8,
    },
    closed,
};

const InputTx = union(enum) {
    unopened,
    preface_pending: [quic_wire.preface_len]u8,
    open,
    closed,
};

const ControlRx = enum {
    preface,
    frames,
    terminal_wait_fin,
    finished,
    reset,
};

const OutputRx = union(enum) {
    unauthorized,
    header,
    body: struct { epoch: u64 },
    finished: struct { epoch: u64 },
    reset,
    unavailable_after_close,
};
```

`Draining` carries `peer: enum { open, closed }` alongside its
preserved stream substates.

Parser allocations and bounded storage remain stable members of
`ClientSession`; state variants carry only semantic state and owned
fixed-size pending data.

All lifecycle transitions go through five helpers:

- `acceptHelloAck`
- `acceptFirstResize`
- `beginDrain`
- `failProtocol`
- `recordPeerClose`

No method assigns protocol state directly outside those helpers.

### Driver lifecycle FSM

```zig
const DriverState = union(enum) {
    handshaking: struct { deadline_ns: i64 },
    running,
    draining: TerminalMeta,
    event_ready: TerminalMeta,
    terminal_delivered,
    closed,
};
```

The driver does not duplicate application phases. It reacts to
`ClientSession` events and owns only transport timing, socket failure,
output accumulation, and terminal-event delivery.

Deferred reason bytes live OUTSIDE `DriverState`: a fixed `[256]u8`
reason buffer is a stable member of `Client`, and state payloads carry
only event metadata (code, kind) and length. If the reason slice were
inside `event_ready` and `pump()` immediately rewrote the union to
`terminal_delivered`, the returned slice would lose a sound lifetime.
The slice remains valid until the next `pump()`.

## Protocol and API behavior

- Introduce ZMQ1 control flag FINAL = 0x01:
  - Legal only on ERROR.
  - Fatal ERROR uses FINAL and control FIN.
  - Snapshot ERROR(unimplemented) uses flags zero and no FIN.
  - SESSION_END remains terminal with flags zero.
  - Unknown bits or FINAL on another type produce
    `protocol_violation`.
- Keep protocol version 1.0 because Q3 has no released consumer.
- Return frame type and flags from `ControlParser` (flags byte exists
  at bytes[1], currently "zero in v1" — quic_wire.zig:179).
- Extend `ControlEvent.err` (quic_client.zig:31) with `terminal: bool`.
- Update the living wire documentation and append a historical
  amendment; do not rewrite frozen records.

Protocol transitions:

- Valid HELLO_ACK: `awaiting_ack` → `awaiting_first_resize`.
- First RESIZE accepted immediately or after retry:
  `awaiting_first_resize` → `active`, exactly once.
- SESSION_END or FINAL ERROR after authorization: live state →
  `draining`.
- Terminal rejection before authorization: `awaiting_ack` → `failed`,
  surfaced immediately.
- Malformed frame, illegal transition, truncation, or reset: any
  live/draining state → `failed`.
- Peer connection close: live state → `closed` ONLY for non-draining
  closes or after terminal delivery is complete. `recordPeerClose`
  must not erase `.draining` stream evidence by transitioning
  immediately to `.closed`. During `.draining`, peer close changes
  only `Draining.peer` to `closed` and preserves `ControlRx`/`OutputRx`:
  - control FIN missing → `failed(protocol_violation)`;
  - control FIN valid but output FIN now unavailable after peer close →
    output transitions to `.unavailable_after_close` and the original
    terminal event is released after queued output drains.

Write behavior:

- A control frame copied into `ControlTx.pending` returns success.
- A second write while pending returns `ControlWritePending`.
- Stream closure never counts as successful acceptance.
- Retried `first_resize` activates the session exactly once.
- A blocked input preface moves `InputTx.unopened` →
  `preface_pending`; the body remains caller-owned and returns
  WouldBlock.
- Retry sends the same preface on stream 2 and moves to `open`; it
  never opens stream 6 or duplicates body bytes.

Receive behavior:

- Output remains unauthorized until HELLO_ACK.
- Output stays readable in `active` and `draining`; terminal control
  reception does not strand it.
- Header completion loops directly into a body read in the same call.
- Control FIN is valid only from `terminal_wait_fin`.
- FIN before a complete preface/frame/output header is a
  truncated-stream violation.
- Any frame after a terminal marker is a violation.
- Stream reset produces one terminal protocol-error event.
- Connection close remains distinct peer-close state.
- Direct `ClientSession.pollControl()` returns each event once. The
  driver copies deferred terminal events into its own fixed 256-byte
  reason storage.

## Driver and UDP behavior

- Drain output before control before receiving, and after every
  replayed or newly received datagram.
- Normal transition to `event_ready` requires ALL of:
  - terminal SESSION_END or FINAL ERROR parsed;
  - `ControlRx.finished` (clean control FIN observed);
  - `OutputRx.finished`; and
  - all output copied into the bounded local queue.
  A delayed control FIN keeps the driver in `draining` until it
  arrives.
- A full 64 KiB output queue blocks ONLY while `OutputRx` is not
  finished: stop receiving, remain `draining`, and wait for
  `pollOutput` to create space. If FIN is already consumed and all
  output is queued — even exactly 64 KiB — `event_ready` is valid.
- Output reset replaces the deferred event with a protocol failure.
- Peer close releases a deferred event only after all still-readable
  state is drained. Peer close WITHOUT the promised control FIN is
  `protocol_violation`; an output FIN unavailable after peer close maps
  to `OutputRx.unavailable_after_close`, releasing the original
  terminal event once queued output drains.
- `event_ready` → `terminal_delivered` occurs atomically when `pump()`
  returns the event, preventing duplicate delivery.

Packet handling:

- Replace the parallel parked arrays (`parked` + `parked_short`) with
  a bounded FIFO of `ParkedDatagram { bytes, arrival, gate }` entries
  — owned bytes, actual arrival tuple, `handshake_keys` or
  `one_rtt_keys` gate.
- Empty packets are counted and discarded.
- Short packets wait for `connection().hasOneRttProtectionKeys()`
  (quicz connection.zig:1799), never handshake confirmation —
  HANDSHAKE_DONE is itself short-form.
- Handshake packets wait for handshake keys.
- Retry packets rejected by protected-long peeking as
  `UnsupportedPacketType` are passed once to the adapter for
  validation.
- Other malformed long packets are counted and discarded.
- Replay NEVER stops behind an unopened gate — QUIC packet-number
  spaces advance independently, and an early 1-RTT packet must not
  block a later Handshake packet that installs the very 1-RTT keys
  needed to unblock it. Instead: scan in arrival order, skip unready
  entries, process ready entries (feed exactly once), remove without
  incrementing the index, then RESTART from index 0 because feeding
  may open another gate. Ordering is preserved within each gate.
- Drop obsolete handshake-space entries using public
  `packetNumberSpaceDiscarded(.handshake)` (quicz connection.zig:1373)
  once that space is discarded.
- Socket receives and replay share one 64-datagram inbound budget.
- Feed quicz the actual `recvFrom().addr` source (converted via the
  helper moving to `udp.zig`). The configured address is used ONLY for
  initial route registration — never for ordinary output. Every
  normal, retry, and deadline datagram is sent to
  `TaggedDatagram.dst.remote`, including pending-egress retries.
  Rotate consumed migration challenges with `io.random`, matching the
  gateway.
- Move both sockaddr/QUIC address-conversion directions into
  `udp.zig`; gateway, server, and client use that single
  implementation (currently `sockaddrToUdpAddress` lives in
  quic_gateway.zig:77).

Egress and failures:

- Use `pollOutboundPath()` (quic_transport.zig:624) and retain the
  complete `TaggedDatagram { dg, dst, emitted_ping }` (:607) — path
  binding, ping metadata, and caller ownership.
- One pending-egress slot preserves bytes, destination, path override,
  ping metadata, and ownership across WouldBlock.
- Retry pending egress before polling new output.
- Normal, retry, and deadline output share one 64-datagram outbound
  budget.
- Route deadline output through the same send-or-park helper and
  preserve deadline retirement outcomes.
- First permanent socket failure transitions to `event_ready`,
  initiates best-effort shutdown, frees pending egress, and disables
  subsequent socket I/O (a latched no-more-I/O state).
- WouldBlock only ends the current direction's drain.
- Unexpected errors and OOM propagate.
- Deadline composition frozen by driver state:
  - `handshaking`: min(handshake anchor, transport deadline);
  - `running` or `draining`: transport deadline only;
  - `event_ready`, `terminal_delivered`, `closed`: null.
  Handshake timeout transitions once to `event_ready`; subsequent
  deadlines are null and cannot busy-loop (the expired handshake
  anchor leaves `nextDeadline()`).
- While `draining`, `pump()` continues ACK/PTO egress and socket
  receives; only new application writes stop.
- Add complete errdefer cleanup to all partially fallible
  constructors (`ClientSession.init`, `Client.connect`,
  `QuicSession.init`).

## Tests

Add table-driven transition tests for every legal and illegal
operation in each protocol state, followed by wired tests covering:

- FINAL flag acceptance, rejection, terminal/nonterminal ERROR, and
  delayed FIN.
- Immediate and retried first RESIZE, overlap rejection, one
  activation, and one `.Init`.
- Blocked input preface, same-stream retry, caller-owned body, and no
  duplication.
- Control/output truncation, reset, post-terminal frames, and clean
  FIN.
- Output-before-terminal, terminal-before-output, queue-full
  deferral, and deferred-reason lifetime.
- Key-gated short/Handshake packet parking, FIFO replay, obsolete
  entries, and the combined 64-packet budget — including the
  gate-skip case where a parked 1-RTT datagram sits ahead of the
  Handshake datagram that installs its keys (replay must process the
  later Handshake entry, not stall behind the earlier one).
- Delayed control FIN keeping the driver in `draining`; peer close
  without the promised control FIN producing `protocol_violation`; and
  one transition test proving peer close cannot discard the
  missing-control-FIN evidence (drain-state preservation across
  `recordPeerClose`).
- Alternate authenticated source paths and migration-challenge
  rotation.
- Full tagged-egress retention across WouldBlock and
  retry-before-new-output.
- One-shot send/receive failure, propagated OOM, one-shot timeout,
  and no deadline loop.
- Bounded output suspension and lossless resumption, plus the
  exact-capacity case: output FIN already consumed with exactly 64 KiB
  queued → `event_ready` is valid without further draining.
- Transport versus application peer close (transport via quicz
  `connection().closeConnection(code, frame_type, reason)`,
  connection.zig:7644; adapter `Transport.connection()` at
  quic_transport.zig:266).
- Wrong-role prefaces, exact split regressions, SNAPSHOT_INSTALLED
  payload rules, oversized ERROR reason, and illegal server RESIZE.
- Failure-point iteration proving leak-free `ClientSession`, `Client`,
  and `QuicSession` construction.

Public peer transport-parameter mutation may be used only as fixture
fault injection to force blocked first-RESIZE and input-preface
transitions (the frozen production 2 KiB stream credit cannot
naturally block those first 8–16 bytes). Restore valid parameters
immediately and retain real flow-control integration tests. Use public
quicz APIs only; never inspect or mutate quicz internal stream arrays.

Retain every r7 test.

## Landing

Land four green FF checkpoints:

1. FINAL wire amendment, hierarchical `ClientSession` FSM, constructor
   cleanup, and transition tests.
2. Driver lifecycle FSM, UDP helpers, parking/replay, tagged egress,
   error/deadline handling, and focused tests.
3. Complete deterministic integration matrix and strictly in-scope
   corrections it exposes (a materially new issue requires stopping
   and amending the plan).
4. Historical addendum superseding the inaccurate r7 evidence claim
   (plans/quic-binary-snap-refactor.md ≈ line 1212), mirrored on bead
   `zmosh-8sd.9`.

Each commit uses `Changed:` and `Refs: zmosh-8sd.9`.

Final gates:

- Debug and ReleaseSafe tests pass with no regression from the
  219-test baseline; record the new total.
- `zig build check`.
- ReleaseSafe build followed by Debug rebuild.
- `zig fmt --check build.zig build.zig.zon src`.
- `git diff --check`.
- quic_transport.zig remains unchanged at 467 SLOC.
- Bats: 58 passed, 0 failed, exactly four Q5 skips; isolate only the
  known r3b flake if encountered.
- q2-2 pin, tag, and backup remain unchanged.
- Stop for review with Q4 locked.

## r8.5 amendment (review findings on the r8 landing — frozen contract)

The r8 audit found the landing at `544d952` not sign-off ready. This
amendment freezes the correction contract; the sections above stand
except where amended here.

1. **Egress-retry ownership (P1).** One latch path, one owner per
   datagram: an idempotent `latchSocketFailure(context)` (still calling
   `ClientSession.failLocal()` so session shutdown/state stay
   consistent) sets `io_failed`, frees `pending_egress` exactly once,
   stores the reason in the stable buffer, and sets
   `dstate = .event_ready{err, internal_error}`. `sockSend` never
   frees; `sendOrPark` frees its own not-yet-parked datagram on
   failure; `retryPendingEgress` propagates without freeing.
   `failSocket`, `failSocketNoDatagram`, `returned_event`, and the
   unused public `Client.failLocal()` are deleted.
2. **Typed `.detaching` (P1).** `ProtocolState.detaching{control_tx,
   control_rx, output_rx}` — `control_tx` RETAINED so a parked DETACH
   survives; `PendingKind.detach`; entered by `beginDetach()` after
   ownership transfers (sent or parked whole). The server's bare FIN is
   clean only at `control_tx == .idle` (a parked DETACH has not reached
   quicz — FIN before flush is a protocol violation). With
   `InputTx == .preface_pending`, `sendDetach()` returns
   `error.WouldBlock` without queueing or transitioning. All application
   writes reject in `.detaching`. A peer close while detaching (before
   the required control FIN) is a protocol violation; terminal frames
   still transition to normal draining.
3. **Complete path binding.** The pending-egress slot stores the whole
   `UdpTuple` (`dst`), not `dst.remote` alone.
4. **Classifier.** Only `error.UnsupportedPacketType` peek failures
   pass to the adapter (Retry validation); every other peek error is
   counted and discarded at the driver boundary.
5. **Driver FSM authority.** `.event_ready` is actually assigned and
   all terminal delivery flows through one `deliverTerminal()`;
   `io_failed` remains solely the socket-I/O latch.
6. **Restored proofs** (deterministic fixtures, private machinery
   stays private, no test-only gateway API): permanent send failure
   during retry via an `egress_fail_n` fixture (no fd manipulation);
   the DETACH matrix; feed-OOM through the public `pump()` with a
   toggle allocator armed around one known authenticated packet
   (counter-proven inside feed); handshake-space pruning; live
   gate-skip replay on an in-file `QuicGateway` peer — capture the real
   server Initial and Handshake, insert a SYNTHETIC short-form junk
   packet first (parks behind the one-RTT gate; the gateway cannot
   emit a valid short-form packet ahead of the server Handshake),
   park the real Handshake second, feed the real Initial directly;
   assert the Handshake processed despite the earlier short entry,
   `datagrams_received` +2, `junk_received` +1, `parked_len == 0`,
   one-RTT keys available, remaining rounds complete.
7. **Records.** The r8 addendum's chain SHA `01a4c84` is corrected to
   the actual `249d01c` (the r8.2 amend renamed it); git history
   untouched.
