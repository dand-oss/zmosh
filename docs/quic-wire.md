# zmosh QUIC wire protocol (ZMQ1)

Status: frozen at Q3 (2026-08-19). This document is the authoritative
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
| snapshot | server → client | server uni id ≥ 7 | Q4 |
| command | bidirectional | client bidi id ≥ 4 | Q6 |

Attach uses one control stream, one input stream, and one current
output epoch. A second control, input, or command stream is rejected
with `stream_cardinality`. A preface declaring the wrong role for its
stream id is `unknown_role`. The gateway detects unexpected streams by
scanning the finite peer stream-id space allowed by the frozen transport
limits (4 bidirectional, 8 unidirectional).

The output stream begins with the common preface (role=output) followed
by an epoch u64 big-endian (16 header bytes total), then raw PTY bytes.
Epochs start at 1; Q3 always uses 1. Epoch replacement is Q5.

## Ordering across streams

QUIC does not order bytes across streams, only within one:

- The client sends ONLY the control stream (preface + HELLO) first.
  Non-control data before HELLO is a terminal `protocol_violation`.
- After the gateway validates HELLO (and the client receives
  HELLO_ACK), input on stream 2 may legitimately arrive before the
  client's RESIZE is processed. The gateway parks it — without
  consuming and without granting flow-control credit — until the first
  RESIZE queues the daemon session-initialization message; parked input
  then flows strictly after initialization.
- Symmetrically, the server's output header may arrive at the client
  before the HELLO_ACK packet; the client parks stream-3 bytes until
  HELLO_ACK validates.
- The client's first control frame after HELLO_ACK MUST be RESIZE. The
  gateway maps that first RESIZE to the daemon `.Init` (session
  initialization with the client's size); subsequent RESIZEs forward as
  daemon `.Resize`.

## Control frames (on the control stream)

Header (8 bytes): type u8 | flags u8 (zero in v1) | reserved u16
big-endian (zero) | payload length u32 big-endian (maximum 64 KiB).

| Type | Name | Payload |
|---|---|---|
| 1 | HELLO | 48 bytes, below |
| 2 | HELLO_ACK | 48 bytes, same shape |
| 3 | RESIZE | rows, cols, xpixel, ypixel — four u16 big-endian |
| 4 | DETACH | empty |
| 5 | SNAPSHOT_REQUEST | empty (served from Q4; nonterminal ERROR before) |
| 6 | SNAPSHOT_INSTALLED | empty (Q4; from a client before that: `protocol_violation`) |
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
options and the id is computed at comptime. `adapter_version` is 1 and
increments for any zmosh-side snapshot adapter or wire change. The id
deliberately changes when the pin advances (Q4): mixed-version peers
fail the fingerprint check.

## Error codes

One table; the same numeric value appears as u32 in the ERROR payload
and as u64 in QUIC APPLICATION_CLOSE / RESET_STREAM / STOP_SENDING.

| Code | Name | Meaning |
|---|---|---|
| 0 | none | clean close (detach) |
| 1 | protocol_violation | malformed frame, nonzero flags/reserved, ordering violation, unknown mode |
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

SNAPSHOT_REQUEST before Q4 is answered by a NONTERMINAL
ERROR(unimplemented): no FIN, the session continues serving.

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
bytes → `.Input` frames; the first RESIZE → `.Init`; later RESIZEs →
`.Resize`; DETACH → `.Detach`. Daemon → client: `.Output` relays to the
output stream; a daemon `.Resize` is answered with `.Resize` carrying
the last client size (the local attach client's behavior — never a
second `.Init`, which would re-trigger terminal replay); `.Switch`
terminates the session with `unimplemented` until Q5; any other tag is
counted and ignored. Daemon EOF produces SESSION_END and closes with
`session_ended`. Daemon frames are bounded (header + 64 KiB); an
oversized declared frame is rejected before payload accumulation —
a large legacy VT replay therefore fails closed until Q4 introduces
chunked snapshots.
