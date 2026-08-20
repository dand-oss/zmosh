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

We chose **Zig plus the pinned `quicz` crate** over wrapping a Rust
QUIC implementation (quinn/quiche) behind a C ABI.

Why:

1. **No FFI boundary.** A Rust wrapper would impose a C ABI over
   ownership-sensitive operations (datagram buffers, stream reads,
   timers). Every buffer would cross the boundary twice and every
   error would flatten to an integer, defeating Zig's error unions
   and allocator tracking. quicz is consumed as a Zig module with
   native types (`UdpTuple`, `TaggedDatagram`, `Error!` sets).
2. **Single-threaded integration.** quicz exposes exactly the
   primitives a `poll()` loop needs — `handleDatagram`,
   `pollOutboundPath`, `serviceDueDeadline`, `nextDeadlineNanos` —
   with no internal threads or io_uring entanglement. Rust QUIC
   stacks assume their own async runtime; embedding one would add a
   second scheduler to a deliberately scheduler-free binary.
3. **Auditability at the pin.** The dependency is a content-hashed
   pin (`zmosh-quic-q2-2`) with immutable tags; the compatibility
   adapter (`src/quic_transport.zig`) is frozen below 500 production
   SLOC, giving a bounded, reviewable surface between zmosh and the
   QUIC implementation.

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
- a maintained Rust QUIC implementation ships a C ABI that preserves
  buffer ownership and single-threaded polling semantics;
- QUIC qualification (Phase Q8) exposes correctness gaps whose fixes
  upstream will not take.
