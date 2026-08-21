# zmosh QUIC client runtime — design notes

This document records the stable runtime decisions behind the client
half of the ZMQ1 stack: `src/quic_client.zig`'s two state machines,
their ownership rules, and their failure behavior. The wire contract
itself lives in `docs/quic-wire.md`; the architecture decision behind
the Zig/quicz stack lives in `docs/decisions/0001-zig-quicz-network-stack.md`.

## Two state machines, two responsibilities

- **`ClientSession`** owns the application protocol. Its top-level
  state is the lifecycle — `awaiting_ack` → `awaiting_first_resize` →
  `installing_snapshot` → `active` → (`detaching` | `draining`) →
  terminal — and each live variant embeds only the stream substates
  possible there (`ControlTx`, `InputTx`, `ControlRx`, `OutputRx`).
  Invalid combinations (output readable before authorization, input
  before the first RESIZE, a parked first RESIZE without its
  transition metadata) are unrepresentable. Top-level transitions go
  through named helpers only (`acceptHelloAck`, `acceptFirstResize`,
  `finishInstallation`, `beginDetach`, `beginDrain`, `failProtocol`,
  `recordPeerClose`).

### installing_snapshot (Q4 stage 5)

HELLO_ACK validation stores the negotiated snapshot limit and
PREPARES the heap-stable installer (src/quic_installer.zig) before
any first RESIZE can be sent; the first accepted RESIZE transfers it
into `installing_snapshot`. A typed `InstallState` (owned installer,
replay done, installed sent, provisional stream-7 reset, aborted)
rides through every live and draining variant — the installer
SURVIVES activation and is destroyed only once its replay is fully
copied to the driver queue. During installation a RESIZE coalesces to
one latest `ResizeWire` (sent on activation through the normal atomic
path) and input, DETACH, and SNAPSHOT_REQUEST return `error.NotActive`.

The driver services stream 7 BEFORE output inside ONE shared 64 KiB
installation budget per public pump: header-exact reads, body capped
at `negotiated_limit − received + 1` (one excess byte detectable
without allocating), decoding only after a clean FIN, at most one
history page per pump starting the pump after READY, and post-cut
output applied to the temporary stream (its 16-byte epoch header
parsed first — framing, never content) before that pump's page and
never returned separately. `pollOutput` serves replay bytes first;
live stream-3 bytes flow only after replay exhaustion;
`outputSettled` includes replay exhaustion, so a terminal event can
never overtake replay still owned by the installer.

Terminal behavior: a clean SESSION_END during a valid installation
still COMPLETES it through the existing `deferTerminal` deferral;
installer failure surfaces through ORDINARY `failProtocol` (the
driver already consumed the deferred SESSION_END, so the existing
failure-replacement path carries the installer's code and reason —
no special exception exists). A FINAL ERROR BEFORE replay preparation
aborts the installation (never sends SNAPSHOT_INSTALLED, never
exposes orphaned stream-3 bytes); AFTER replay preparation the valid
replay is retained and drained before the terminal event is
delivered. A stream-7 reset with a prepared replay is provisional
until the matching terminal ERROR arrives — a SESSION_END or peer
close without it is a protocol_violation. Once terminal draining
begins, a newly prepared SNAPSHOT_INSTALLED is never sent.
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
terminal-event return path (nonterminal events still return normally
through the pump). Frozen failure precedence, applied by the
socket-failure latch in this order:

1. An already-staged terminal (`.event_ready`) is preserved — never
   polled, never replaced.
2. An existing stored session/protocol failure wins with its
   matching code and reason.
3. An already-deferred FINAL ERROR wins over a later socket failure;
   the session's event slot is empty in that case, because the
   deferral consumed it when copying the failure.
4. A failed session with neither representation is an invariant
   failure (`internal_error("failed session missing terminal event")`);
   stale deferred metadata is never released.
5. Otherwise the socket failure itself becomes `internal_error`:
   while draining a clean SESSION_END, output completeness is no
   longer provable.

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
