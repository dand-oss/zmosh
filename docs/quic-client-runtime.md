# zmosh QUIC client runtime — design notes

This document records the stable runtime decisions behind the client
half of the ZMQ1 stack: `src/quic_client.zig`'s two state machines,
their ownership rules, and their failure behavior. The wire contract
itself lives in `docs/quic-wire.md`; the architecture decision behind
the Zig/quicz stack lives in `docs/decisions/0001-zig-quicz-network-stack.md`.

## Two state machines, two responsibilities

- **`ClientSession`** owns the application protocol. Its top-level
  state is the lifecycle — `awaiting_ack` → `awaiting_first_resize` →
  `active` → (`detaching` | `draining`) → terminal — and each live
  variant embeds only the stream substates possible there
  (`ControlTx`, `InputTx`, `ControlRx`, `OutputRx`). Invalid
  combinations (output readable before authorization, input before
  the first RESIZE, a parked first RESIZE without its transition
  metadata) are unrepresentable. Top-level transitions go through
  named helpers only (`acceptHelloAck`, `acceptFirstResize`,
  `beginDetach`, `beginDrain`, `failProtocol`, `recordPeerClose`).
- **`Client`** (the socket-owning driver) owns transport timing,
  socket failure, output accumulation, and terminal-event delivery.
  Its `DriverState` (`handshaking` → `running` → `draining` →
  `event_ready` → `terminal_delivered`/`closed`) never duplicates
  application phases. `dstate` is the sole lifecycle authority;
  `io_failed` is exactly the socket-I/O disable latch.

## Ownership rules

- **Control writes**: one all-or-nothing `sendOnStream` per frame. A
  flow-control block parks the COMPLETE encoded copy and the call
  succeeds — ownership transferred. A second write while parked is
  `error.ControlWritePending`. Stream closure never counts as
  acceptance. `retryPendingSends()` retries parked frames; a retried
  first RESIZE activates the session exactly once.
- **Input**: the preface is staged on first send; if it blocks, the
  body stays caller-owned and the call returns `error.WouldBlock`,
  and the same stream (never a second one) is retried. While the
  preface is staged, `sendDetach()` returns `error.WouldBlock`
  without queueing anything — the caller retries DETACH after the
  preface flushes.
- **Egress datagrams**: every datagram leaves through one send-or-park
  path addressed to its own `TaggedDatagram.dst` (the configured peer
  is used only for the initial route registration). ONE owned
  pending-egress slot retains the complete datagram — bytes, the
  whole destination tuple, and ping metadata — across `WouldBlock`,
  and is retried before any new QUIC output is polled. A permanent
  send failure latches through the shared failure path.
- **Inbound**: packets are classified BEFORE the long-header parser;
  short-form packets park only while one-RTT protection keys are
  absent (never on handshake confirmation — HANDSHAKE_DONE itself is
  short-form), Handshake packets while Handshake keys are absent.
  Only Retry-shaped peek failures (`UnsupportedPacketType`) reach the
  adapter for validation; other malformed long headers are counted
  and discarded at the boundary. Replay scans in arrival order,
  SKIPS closed gates (an early 1-RTT packet never blocks a later
  Handshake packet that installs its keys), removes without advancing
  the index, and restarts from index zero. Socket receives and
  replays share one 64-datagram inbound budget per pump; the
  handshake-space discard prunes obsolete parked entries.

## Terminal-event precedence and reason lifetime

Deferred reason bytes live in a stable driver buffer (never inside
`DriverState`), so the returned slice stays valid until the next
pump. Terminal events are staged (`stageTerminal`) and delivered
(`deliverTerminal`) — the driver never returns an event whose reason
points into session storage, and `deliverTerminal()` is the only
event-return path. Frozen failure precedence:

1. An existing stored session/protocol failure wins with its
   matching code and reason.
2. An already-deferred FINAL ERROR wins over a later socket failure.
3. A socket failure while draining a clean SESSION_END — or with no
   prior failure — becomes `internal_error`: output completeness is
   no longer provable.
4. A failed session with no stored event is an invariant failure
   (`internal_error("failed session missing terminal event")`);
   stale deferred metadata is never released.

After terminal delivery, later settling-socket errors only disable
I/O and close — no second, undeliverable event is created. The socket
latch is idempotent and single-owner: it frees the pending egress
exactly once and never replaces an already-owned terminal.

## Draining, output, and deadlines

A terminal event is deferred until the output side is safely
accumulated: `ControlRx.finished` AND `OutputRx.finished` AND all
output copied into the bounded 64 KiB local queue. A full queue
blocks receiving only while the output side is unfinished; with the
FIN consumed and everything queued — even exactly 64 KiB — the
release stands (a zero-length read observes the FIN without consuming
data). A full queue never blocks the in-flight FINs once a terminal
is deferred. While draining, the pump continues ACK/PTO egress and
socket receives; only new application writes stop. Deadline
composition is frozen by driver state: handshaking composes the
handshake anchor with the transport deadline; running/draining use
the transport deadline alone; terminal and closed states return
`null` (an expired anchor can never busy-loop).
