# zmosh QUIC wire protocol (ZMQ1)

Status: authoritative ZMQ1 v1, amended (Q3 2026-08-19; Q4 2026-08-20).
The FINAL flag and the DETACH/terminal-FIN rules postdate the original
v1 freeze; Q4 amends the attach path to the transactional binary
snapshot (stream 7, `.InitSnapshot`, SNAPSHOT_INSTALLED) and bumps the
adapter version to 2 with a new frozen `snapshot_abi_id`. With no
released v1 consumer the wire version number is unchanged.
This document is the authoritative
wire specification for the zmosh application protocol carried over QUIC.
Implementation: `src/quic_wire.zig` (framing), `src/quic_session.zig`
(gateway side), `src/quic_client.zig` (client side). QUIC provides
ordered, reliable, flow-controlled streams; the application protocol
adds only role identification and semantic message boundaries.

## Common stream preface (8 bytes)

| Offset | Field | Value |
|---|---|---|
| 0..3 | magic | ASCII `ZMQ1` |
| 4 | role | enum below |
| 5 | flags | role-specific; **zero for every role in v1** |
| 6..7 | reserved | u16 big-endian, zero |

Roles: control=1, input=2, snapshot=3, output=4, command=5.

Rejections: unknown role → `unknown_role`; nonzero flags or reserved →
`protocol_violation`. Every rejection is terminal except where noted.

## Streams and cardinality

| Role | Direction | Stream | Opened |
|---|---|---|---|
| control | bidirectional | client bidi id 0 | client, first |
| input | client → server | client uni id 2 | client, after HELLO_ACK |
| output | server → client | server uni id 3 | server, at HELLO_ACK |
| snapshot | server → client | server uni id 7 | server, at SnapshotBegin (Q4, epoch 1) |
| command | bidirectional | client bidi id ≥ 4 | Q6 |

Attach uses one control stream, one input stream, and one current
output epoch. A second control, input, or command stream is rejected
with `stream_cardinality`. A preface declaring the wrong role for its
stream id is `unknown_role`. The gateway detects unexpected streams by
scanning the finite peer stream-id space allowed by the frozen transport
limits (4 bidirectional, 8 unidirectional).

The output stream begins with the common preface (role=output) followed
by an epoch u64 big-endian (16 header bytes total), then raw PTY bytes.
Epochs start at 1; Q4 always uses 1. Epoch replacement is Q5.

The snapshot stream (7) begins with its own 24-byte header, then the
Ghostty binary snapshot bytes, then the FIN:

| Offset | Field | Value |
|---|---|---|
| 0..7 | preface | role=snapshot |
| 8..15 | epoch | u64 big-endian; 1 (Q4 permits only epoch 1) |
| 16 | flags | PRESENT=0x01 only; zero means an empty snapshot |
| 17..23 | reserved | seven zero bytes |

PRESENT=0 means no body: the FIN follows the header immediately.
Invalid role, flags, reserved bytes, or a non-1 epoch are rejected by
the client parser. The header is incremental-resume (arbitrary QUIC
chunking). Explicit replacement epochs remain Q5.

## Ordering across streams

QUIC does not order bytes across streams, only within one:

- The client sends ONLY the control stream (preface + HELLO) first.
  Non-control data before HELLO is a terminal `protocol_violation`.
- After the gateway validates HELLO (and the client receives
  HELLO_ACK), input on stream 2 may legitimately arrive before the
  client's RESIZE is processed. The gateway MUST NOT deliver any
  stream-2 input to the daemon session before the first RESIZE has
  queued the session-initialization message; early-arriving input is
  buffered, and its delivery follows strictly after initialization.
- Symmetrically, the server's output header may arrive at the client
  before the HELLO_ACK packet; the client MUST NOT process stream-3
  bytes before HELLO_ACK validates.
- The client's first control frame after HELLO_ACK MUST be RESIZE. The
  gateway maps that first RESIZE to the daemon `.InitSnapshot` (Q4:
  session initialization with the client's size plus one transactional
  binary snapshot; before Q4 it mapped to the legacy `.Init` VT
  replay). During installation further RESIZEs never reach the daemon:
  they coalesce to one latest value, forwarded as daemon `.Resize`
  only after SNAPSHOT_INSTALLED activates the session. Input on
  stream 2 is accepted once `.InitSnapshot` is ahead of it in the
  ordered daemon-bound buffer.
- The daemon transaction is strict: SnapshotBegin opens stream 7 and
  stages the snapshot header (below); between Begin and End ONLY
  SnapshotChunk/SnapshotEnd/SnapshotError are legal (any interleaved
  daemon frame — Output, Resize, Switch, unknown — is a terminal
  `internal_error`); PRESENT=0 admits no chunks and requires End(0);
  PRESENT=1 requires at least one byte; the End count must equal the
  chunk bytes exactly; the accumulated total must stay within the
  HELLO-negotiated snapshot limit. Every violation — and any daemon
  SnapshotError (known code, unknown code, or malformed) — resets an
  unfinished stream 7 before the bounded terminal settlement. Daemon
  Output before Begin predates the authoritative cut: discarded and
  counted. Output AFTER a validated End is legal post-cut output,
  relayed on the epoch-1 output stream even while the stream-7 FIN is
  still pending.
- The gateway FINs stream 7 only after the validated End count AND
  full acceptance of every pending snapshot byte; the client's empty
  SNAPSHOT_INSTALLED is accepted only in that post-FIN state
  (premature, nonempty, or post-activation INSTALLED is a
  `protocol_violation`, as are DETACH and SNAPSHOT_REQUEST during
  installation).

## Control frames (on the control stream)

Header (8 bytes): type u8 | flags u8 | reserved u16
big-endian (zero) | payload length u32 big-endian (maximum 64 KiB).

The flags byte defines exactly one bit: FINAL = 0x01, legal on ERROR
alone. A fatal ERROR carries FINAL and arrives with the control-stream
FIN; a nonterminal ERROR — the SNAPSHOT_REQUEST response — carries
flags zero and no FIN, and the session continues. SESSION_END is
intrinsically terminal and also carries flags zero (it too arrives
with the FIN). Client-sent frames never carry FINAL. Any other flag
bit, or FINAL on another frame type, is `protocol_violation`.

| Type | Name | Payload |
|---|---|---|
| 1 | HELLO | 48 bytes, below |
| 2 | HELLO_ACK | 48 bytes, same shape |
| 3 | RESIZE | rows, cols, xpixel, ypixel — four u16 big-endian |
| 4 | DETACH | empty |
| 5 | SNAPSHOT_REQUEST | empty (ACTIVE: nonterminal ERROR, replacement snapshots are Q5; during installation: `protocol_violation`) |
| 6 | SNAPSHOT_INSTALLED | empty (accepted only in the post-stream-7-FIN state; premature/nonempty/duplicate: `protocol_violation`) |
| 7 | SESSION_END | empty |
| 8 | ERROR | code u32 big-endian + printable reason ≤ 256 bytes |

Unknown type → `unknown_frame` (rejected, not ignored, in v1). Payload
lengths are validated before any allocation; fixed headers parse
allocation-free; parsers are incremental and resume mid-field (QUIC
delivers arbitrary chunks). A FIN that truncates an expected structure
is `protocol_violation`.

### HELLO / HELLO_ACK payload (48 bytes)

| Offset | Field | Width | v1 value |
|---|---|---|---|
| 0 | version_major | u8 | 1 |
| 1 | version_minor | u8 | 0 |
| 2 | mode | u8 | attach=1, command=2 |
| 3 | reserved | u8 | 0 |
| 4 | required_capabilities | u32 BE | 0x1F |
| 8 | snapshot_abi_id | 32 B | SHA-256 below |
| 40 | snapshot_limit | u32 BE | 128 MiB |
| 44 | command_limit | u32 BE | 1 MiB |

Capability bits: binary_snapshot 0x01, resettable_output 0x02,
remote_commands 0x04, tail 0x08, dual_stack 0x10. v1 has exactly one
profile — the mask must equal 0x1F (no subset negotiation). HELLO_ACK
carries the server's values; limits negotiate as min(client, server).

Validation order: parse validity → version_major (≠1 →
`version_mismatch`) → capabilities (≠0x1F → `capability_mismatch`) →
snapshot_abi_id (≠ → `fingerprint_mismatch`) → mode (2 →
`unimplemented`; other unknown values → `protocol_violation`). A HELLO
rejection sends ERROR and closes BEFORE any session data moves: the
daemon is never initialized for a rejected peer.

### snapshot_abi_id

    SHA-256(
        "zmosh-snapshot-abi-v1\0" ||
        ghostty_commit_ascii[40] ||
        u16_be(zig_package_hash_utf8.len) ||
        zig_package_hash_utf8 ||
        u32_be(adapter_version)
    )

`ghostty_commit_ascii` is the lowercase 40-hex commit of the Ghostty
dependency pin; `zig_package_hash_utf8` is the exact `.hash` string of
that dependency in `build.zig.zon`; both enter the binary as build
options and the id is computed at comptime. `adapter_version` is 2
since Q4 and increments for any zmosh-side snapshot adapter or wire
change. The id deliberately changes when the pin advances (Q4):
mixed-version peers fail the fingerprint check.

Frozen Q4 value of the exact production inputs — Ghostty commit
`6361b2eac73e8243a7042f517ea95ab87165f105`, package hash
`ghostty-1.3.2-dev-5UdBC5L2RQWfmtJwTX8gKITqL4rOJteCksb42xxDS9bD`
(62 bytes, u16 big-endian length prefix), adapter_version 2:

    7698150409ab3681797355e5ba819898a422283b3f3ce8eee7cb15f6fb18d9ad

This literal is pinned by the "snapshot abi id: frozen Q4 golden
literal" test in `src/quic_wire.zig`: any pin advance or construction
drift fails the suite until this record and the test are re-frozen
together.

## Error codes

One table; the same numeric value appears as u32 in the ERROR payload
and as u64 in QUIC APPLICATION_CLOSE / RESET_STREAM / STOP_SENDING.

| Code | Name | Meaning |
|---|---|---|
| 0 | none | clean close (detach) |
| 1 | protocol_violation | malformed frame, illegal flag bits (FINAL off-ERROR), nonzero reserved, ordering violation, unknown mode |
| 2 | version_mismatch | HELLO version_major ≠ 1 |
| 3 | capability_mismatch | capability mask ≠ 0x1F |
| 4 | fingerprint_mismatch | snapshot_abi_id differs |
| 5 | unknown_role | preface role not in 1..5, or wrong role for the stream id |
| 6 | unknown_frame | control type not in 1..8 |
| 7 | stream_cardinality | second control/input/command stream |
| 8 | unimplemented | known-but-deferred (snapshot before Q4; command mode before Q6) |
| 9 | session_ended | daemon exit; also carried by the SESSION_END frame |
| 10 | internal_error | local failure (allocation, invariant) |

## Closure and terminal behavior

A final control frame is never followed immediately by
CONNECTION_CLOSE (the close suppresses stream output). The closing side
enters a bounded terminal state: stop application work, drain pending
output, FIN the output stream only after every pending byte is
accepted, send the final control frame with FIN, and wait — for both
streams to be fully acknowledged or a one-second deadline, whichever
comes first — before closing. QUIC retransmission makes a dropped final
packet recover like any other; the deadline bounds the wait.

Two fatal-error arms: when the control stream exists, the bounded
ERROR+FIN sequence above; when no control stream was ever observed
(e.g. data on stream 2 before any HELLO), an immediate application
close with the correct code and a bounded reason — no stream write is
attempted, since no send side exists.

SNAPSHOT_REQUEST in the ACTIVE phase is answered by a NONTERMINAL
ERROR(unimplemented) — replacement snapshots are deferred to Q5 — no
FIN, the session continues serving. During snapshot installation the
same frame is a `protocol_violation` (unavailable until the initial
snapshot completes).

### DETACH sequencing (normative)

DETACH is a client-only frame carrying no payload. A client MUST NOT
send any further application frame (RESIZE, DETACH,
SNAPSHOT_REQUEST) or any further input-stream bytes after DETACH.
The server, on receiving a complete DETACH, MUST flush the
corresponding daemon-side `.Detach` and then close the control
stream with a bare FIN — no final frame accompanies a clean detach.

Framing is atomic: a sender MUST NOT interleave the bytes of
distinct control frames and MUST NOT abandon a partially sent frame
— a control frame reaches the stream whole or not at all.

The server's bare FIN is valid ONLY after the client's DETACH bytes
reached the wire in full. A client that observes the control-stream
FIN (or a peer connection close) while its own DETACH has not been
sent in full MUST treat it as a `protocol_violation` ("FIN before
DETACH flush") — the FIN cannot legitimately precede bytes the peer
never sent. A terminal frame received during this window still ends
the session through the normal draining sequence.

A client MUST NOT send DETACH until its input-stream preface has
been sent in full: the wire never sees a DETACH interleaved with an
abandoned input-stream opening.

### Terminal FIN classes (normative)

| Terminal | Control-stream FIN | Notes |
|---|---|---|
| SESSION_END (daemon EOF) | yes, with the frame | flags zero; intrinsically terminal |
| fatal ERROR | yes, with the frame | FINAL flag set |
| nonterminal ERROR (snapshot response) | no | flags zero; session continues |
| clean DETACH completion | yes, bare | no final frame |

Any frame after a terminal marker, any FIN before a complete
preface/frame/output header, and any stream reset are
`protocol_violation`s. On the receiving side, a terminal frame enters
the drain state: control FIN validation and output draining continue
until both streams settle (or the peer closes after everything
readable was drained). ZMQ1 v1 is AMENDED status: the FINAL flag and
the DETACH/FIN rules above postdate the original v1 freeze; Q3 has no
released consumer, so the version number is unchanged.

## Flow control and backpressure

QUIC flow control (2 KiB initial per-stream credit, 4 MiB connection
credit) is the transport for end-to-end backpressure; zmosh adds no
custom windows:

- A receiver consumes stream bytes only when it can forward them;
  unconsumed bytes stay in QUIC with credit withheld, blocking the
  sender.
- A sender chunks application data to available credit (an all-or-nothing
  blocked send retains the unsent tail locally, bounded at 64 KiB).
- One bounded in-flight response per control stream: while a response
  is blocked, no further control frames are consumed.
- Per event-loop turn: 64 KiB of control+input bytes together, at most
  64 control frames, at most 64 KiB read from the daemon socket.

## Daemon-side mapping (gateway only)

The gateway bridges ZMQ1 to the existing daemon Unix-socket IPC: input
bytes → `.Input` frames; the first RESIZE → `.InitSnapshot` (Q4);
installation-phase RESIZEs coalesce (forwarded as one `.Resize` after
SNAPSHOT_INSTALLED); later RESIZEs → `.Resize`; DETACH → `.Detach`.
Daemon → client: the SnapshotBegin/Chunk/End/Error transaction relays
to stream 7 as epoch 1 (one bounded header-plus-32-KiB pending unit at
a time, serviced before output; FIN only after the validated End count
and full pending acceptance); pre-Begin `.Output` is discarded and
counted; Output between Begin and a validated End is a terminal
interleave; Output after the validated End relays as post-cut epoch-1
output even before the FIN; a daemon `.Resize` is answered with
`.Resize` carrying the last client size (never a second
initialization, which would re-trigger terminal replay); `.Switch`
terminates the session with `unimplemented` until Q5; any other tag
during an active transaction is a terminal interleave, and outside one
is counted and ignored. Daemon EOF produces SESSION_END and closes
with `session_ended`. Daemon frames are bounded (header + 64 KiB); an
oversized declared frame is rejected before payload accumulation. The
daemon read gate is header-aware: each read is capped to the pending
frame's unread header bytes until the header is inspectable, and once
a buffered header declares a frame the session cannot accept (its
bounded relay storage is occupied) no further bytes of that frame are
read — but discard-only and terminal-error frames are always
consumable, so withheld snapshot credit can never delay fail-closed
handling or starve SnapshotBegin.
