# ADR 0001: Zig plus pinned quicz for the zmosh network stack

- Status: accepted (Q3, 2026-08)
- Context: `plans/quic-binary-snap-refactor.md` (governing plan) and
  `docs/quic-wire.md` (wire contract).

## Context and decision

zmosh is a single Zig binary whose daemon, gateway, and client share
one `poll()` event loop and one allocator discipline. Replanting the
network layer onto QUIC required a QUIC implementation usable as a
library from Zig with: PSK-authenticated handshakes, Retry/address
validation, stream flow control with all-or-nothing sends,
connection-level close semantics distinguishable from stream resets,
and a recovery timer drivable from a single-threaded loop.

We chose **Zig plus the pinned `quicz` Zig package** over wrapping a
Rust QUIC implementation (quinn/quiche) behind a C ABI.

The Rust alternatives differ from each other, and neither cost is
zero. quinn's high-level API is built on Tokio — embedding it would
add a second scheduler to a deliberately scheduler-free binary.
quiche is caller-driven: it leaves sockets, event-loop integration,
and timers to the application and already exposes a C API, so it
needs no async runtime — but consuming it from Zig still crosses a
C ABI, flattens errors and ownership into C shapes, and builds its
own native/C (BoringSSL-derived) cryptography into the toolchain.

Why Zig plus quicz won:

1. **No FFI boundary.** A Rust wrapper would impose a C ABI over
   ownership-sensitive operations (datagram buffers, stream reads,
   timers). Every buffer would cross the boundary twice and every
   error would flatten to an integer, defeating Zig's error unions
   and allocator tracking. quicz is consumed as a Zig module with
   native types (`UdpTuple`, `TaggedDatagram`, `Error!` sets) and
   no translation layer for lifetimes, errors, or allocators.
2. **Single-threaded, scheduler-free integration.** quicz exposes
   exactly the primitives a `poll()` loop needs — `handleDatagram`,
   `pollOutboundPath`, `serviceDueDeadline`, `nextDeadlineNanos` —
   with no internal threads or io_uring entanglement and no runtime
   of its own to embed.
3. **Auditability at the pin.** The dependency is a content-hashed
   pin (`zmosh-quic-q2-2`) with immutable tags; the compatibility
   adapter (`src/quic_transport.zig`) is frozen below 500 production
   SLOC, giving a bounded, reviewable surface between zmosh and the
   QUIC implementation.

References: quiche's application-owned I/O model and C API are
documented in its README (https://github.com/cloudflare/quiche);
quinn's Tokio-based high-level API in its introduction
(https://quinn-rs.github.io/quinn/quinn.html).

## Consequences and current costs

- The adapter must express zmosh's needs within quicz's public API;
  where quicz's semantics are unusual (lazy send-side stream state,
  post-close read unavailability), the adapter carries the
  compensation, and the client driver parks and replays datagrams
  that race key installation itself.
- Upstream quicz changes require a re-pin and an adapter re-audit;
  the pin advances only through reviewed checkpoints (q2-1 → q2-2).
- Some behaviors are only exercisable through deterministic
  fixtures (`egress_block_n`, `egress_fail_n`, `recv_fail_n`,
  peer transport-parameter injection) because loopback UDP never
  blocks and credit only grows in production.

## Reconsideration triggers

Revisit this decision if any of the following holds:

- quicz cannot provide a needed QUIC feature (datagrams, migration
  at scale, ACK frequency tuning) without forking it;
- the adapter outgrows its 500-SLOC bound more than transiently;
- a maintained Rust QUIC implementation ships a C ABI whose error,
  buffer-ownership, and polling semantics map onto Zig without a
  compensation layer (quiche already ships a C API; the open
  question is ergonomics, not existence);
- QUIC qualification (Phase Q8) exposes correctness gaps whose fixes
  upstream will not take.
