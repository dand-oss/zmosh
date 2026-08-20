//! `zmx serve` — the ephemeral QUIC gateway.
//!
//! One poll() loop bridges the daemon's Unix socket to the client's
//! QUIC connection. QUIC is this branch's active transport; the custom
//! UDP transport files stay untouched until the reviewed removal
//! checkpoint. The Q4 relay carries application data both ways: the
//! first client RESIZE maps to daemon `.InitSnapshot`, whose
//! transactional Begin/Chunk/End/Error reply streams to the client on
//! server uni stream 7 (24-byte epoch-1 snapshot header with the
//! PRESENT flag, then Ghostty bytes, then the FIN — see
//! docs/quic-wire.md); installation-phase RESIZEs coalesce to one
//! latest value forwarded after SNAPSHOT_INSTALLED; daemon `.Output`
//! before SnapshotBegin is discarded as pre-cut, after the validated
//! End it flows to the epoch-1 output stream, and between the two it
//! is a terminal interleave; later RESIZEs forward as `.Resize`,
//! DETACH → `.Detach`; daemon `.Resize` is answered locally with the
//! last client size, and daemon EOF sends SESSION_END then settles
//! both streams before closing (code 9). All daemon I/O is bounded
//! and header-aware: the reader caps one frame (header + 64 KiB,
//! oversized declarations rejected before accumulation) and caps
//! every read to the pending frame's unread header bytes until the
//! header is inspectable, so an unacceptable frame's payload cannot
//! ride in behind its header — while discard-only and terminal-error
//! frames stay always-consumable so withheld snapshot credit can
//! neither starve SnapshotBegin nor delay fail-closed handling; the
//! writer is a 64 KiB buffer flushed on a dynamic POLL.OUT arm.
//!
//! Bootstrap ordering is contract: EVERY fallible initialization
//! completes before the success line prints; pre-success failures emit
//! a bounded `ZMX_ERROR 1 gateway-init-failed`. The absolute ten-second
//! handshake deadline is anchored at the moment the success line is
//! emitted. The loop is compute timeout → poll → resample the clock →
//! `processReadyAndDue(now)` — only the poll wrapper reads real time,
//! so tests drive the processing helper with synthetic timestamps.

const std = @import("std");
const crypto = @import("crypto.zig");
const udp = @import("udp.zig");
const ipc = @import("ipc.zig");
const cfg_mod = @import("cfg.zig");
const socket = @import("socket.zig");
const signal = @import("signal.zig");
const lib_posix = @import("posix.zig");
const quicz = @import("quicz");
const quic_transport = @import("quic_transport.zig");
const quic_gateway = @import("quic_gateway.zig");
const quic_session = @import("quic_session.zig");
const quic_client = @import("quic_client.zig");
const quic_wire = @import("quic_wire.zig");

const Cfg = cfg_mod.Cfg;

const log = std.log.scoped(.serve);

/// Bounded `ZMX_ERROR` emission: numeric code, sanitized single line,
/// capped at this many bytes.
const max_error_line = 256;
/// Bounded daemon discard per event-loop turn.
const max_daemon_discard_per_turn = 64 * 1024;

pub const PortRange = struct { start: u16, end: u16 };

const default_port_range = PortRange{ .start = 60000, .end = 61000 };

/// `ZMX_UDP_PORT_RANGE` is decimal, END-EXCLUSIVE, and requires
/// `1 <= start < end <= 65535`.
pub fn parsePortRange(spec: []const u8) !PortRange {
    const colon = std.mem.indexOfScalar(u8, spec, ':') orelse return error.InvalidPortRange;
    const start = std.fmt.parseInt(u16, spec[0..colon], 10) catch return error.InvalidPortRange;
    const end = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.InvalidPortRange;
    if (start < 1 or end <= start) return error.InvalidPortRange;
    return .{ .start = start, .end = end };
}

fn portRangeFromEnv() PortRange {
    const spec = lib_posix.getenv("ZMX_UDP_PORT_RANGE") orelse return default_port_range;
    return parsePortRange(spec) catch blk: {
        log.warn("invalid ZMX_UDP_PORT_RANGE={s}; using default {d}:{d}", .{ spec, default_port_range.start, default_port_range.end });
        break :blk default_port_range;
    };
}

/// The frozen pre-bootstrap failure line: the exact static literal,
/// sanitized by construction, 32 bytes — well inside the 256-byte cap.
const init_error_line = "ZMX_ERROR 1 gateway-init-failed\n";

fn emitInitError() void {
    _ = lib_posix.write(lib_posix.STDOUT_FILENO, init_error_line) catch return;
}

fn emitBootstrapLine(port: u16, encoded_key: []const u8) !void {
    var out_buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&out_buf, "ZMX_CONNECT quic {d} {s}\n", .{ port, encoded_key });
    _ = try lib_posix.write(lib_posix.STDOUT_FILENO, line);
}

pub const Gateway = struct {
    alloc: std.mem.Allocator,
    udp_sock: udp.UdpSocket,
    unix_fd: i32,
    quic: quic_gateway.QuicGateway,
    unix_read_buf: ipc.SocketBuffer,
    /// The ZMQ1 application session, attached exactly once when the
    /// QUIC connection establishes. This Gateway owns it; the quic
    /// gateway stays connection-lifecycle only.
    session: ?quic_session.QuicSession = null,
    /// Bounded daemon-bound writes, flushed on the dynamic POLL.OUT arm.
    unix_out: quic_session.UnixWriteBuf,
    daemon_frames_ignored: usize = 0,
    daemon_oversized_frames: usize = 0,
    running: bool,

    /// The real constructor: serveMain and tests alike pass the
    /// already-connected daemon fd and the bound UDP socket.
    pub fn init(
        alloc: std.mem.Allocator,
        io: std.Io,
        unix_fd: i32,
        udp_sock: udp.UdpSocket,
        psk: *const [32]u8,
        token_secret: *const [32]u8,
    ) !Gateway {
        const local = localIdentity(&udp_sock) catch |err| {
            log.err("failed to read local socket identity: {s}", .{@errorName(err)});
            return err;
        };
        var unix_read_buf = try ipc.SocketBuffer.initBounded(alloc, ipc.gateway_frame_cap);
        errdefer unix_read_buf.deinit();
        var unix_out = try quic_session.UnixWriteBuf.init(alloc);
        errdefer unix_out.deinit();
        var quic = try quic_gateway.QuicGateway.init(alloc, io, psk, token_secret, local, 0);
        // Deinit in place: a copy would wipe only the copy's PSK.
        errdefer quic.deinit();
        return .{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .quic = quic,
            .unix_read_buf = unix_read_buf,
            .unix_out = unix_out,
            .running = true,
        };
    }

    /// The stable local socket identity: getsockname on the wildcard
    /// bind yields 0.0.0.0/:: — used identically for route
    /// registration and arrival construction. It is NOT the concrete
    /// per-packet destination (no IP_PKTINFO in Q2).
    fn localIdentity(sock: *const udp.UdpSocket) !quicz.endpoint.UdpAddress {
        var addr: lib_posix.Address = std.mem.zeroes(lib_posix.Address);
        var len: lib_posix.socklen_t = @sizeOf(lib_posix.Address);
        try lib_posix.getsockname(sock.getFd(), &addr.any, &len);
        return quic_gateway.sockaddrToUdpAddress(addr) orelse error.UnsupportedAddressFamily;
    }

    pub fn run(self: *Gateway) !void {
        // SIGTERM wakes poll() through the shared self-pipe. The
        // gateway closes a pipe IT created — never one an owner
        // elsewhere is responsible for.
        const owns_signal = try signal.acquireSignalPipe();
        defer if (owns_signal) signal.closeSignalPipe();
        signal.installWakeHandler(@intFromEnum(lib_posix.SIG.TERM));
        while (self.running) {
            if (!try self.runOnce(self.computePollTimeoutMs())) break;
        }
        log.info("gateway stopped counters received={d} sent={d} discarded={d} challenges={d} confirmed={d}", .{
            self.quic.counters.datagrams_received,
            self.quic.counters.datagrams_sent,
            self.quic.counters.datagrams_discarded,
            self.quic.counters.challenges_issued,
            self.quic.counters.handshakes_confirmed,
        });
    }

    /// One event-loop turn: compute timeout → poll → resample the
    /// monotonic clock → process ready fds and due work. Only this
    /// wrapper reads real time.
    pub fn runOnce(self: *Gateway, poll_timeout_ms: i32) !bool {
        var poll_fds: [3]lib_posix.pollfd = undefined;
        poll_fds[0] = .{ .fd = self.udp_sock.getFd(), .events = lib_posix.POLL.IN, .revents = 0 };
        poll_fds[1] = .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = 0 };
        // The daemon fd: POLL.IN only while a bounded read could
        // discover or finish an acceptable frame (frame-aware
        // backpressure stops the reads), plus a dynamic POLL.OUT arm
        // while daemon-bound writes are pending.
        const daemon_in = self.daemonReadEligible();
        const daemon_events: i16 = if (daemon_in) @as(i16, lib_posix.POLL.IN) else 0;
        poll_fds[2] = .{
            .fd = self.unix_fd,
            .events = daemon_events | (if (self.unix_out.empty()) @as(i16, 0) else @as(i16, lib_posix.POLL.OUT)),
            .revents = 0,
        };
        _ = try lib_posix.poll(&poll_fds, poll_timeout_ms);
        const now: i64 = lib_posix.nowNs();
        return self.processReadyAndDue(now, poll_fds);
    }

    /// The production processing helper: the signal fd FIRST (bounded
    /// network work can never starve shutdown), then bounded network
    /// work, then due QUIC work — all sharing ONE outbound turn
    /// budget. Tests drive this with synthetic timestamps and inert
    /// revents.
    pub fn processReadyAndDue(self: *Gateway, now: i64, poll_fds: [3]lib_posix.pollfd) !bool {
        var budget = quic_gateway.TurnBudget{};
        if (poll_fds[1].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            log.info("SIGTERM received, shutting down gateway", .{});
            self.running = false;
            return false;
        }
        if (poll_fds[0].revents & lib_posix.POLL.IN != 0) {
            if (!try self.quic.receive(&self.udp_sock, now, &budget)) {
                self.running = false;
                return false;
            }
        }
        // The session attaches exactly once, at establishment; its
        // turn runs after the daemon relay so this turn's daemon
        // output is pumped in the same pass.
        try self.ensureSession();
        // Buffered daemon frames progress EVERY turn — no new POLL.IN
        // required — starting with whatever last turn's credit left
        // parked.
        try self.pumpDaemonFrames(now);
        if (poll_fds[2].revents & (lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR) != 0) {
            try self.relayDaemon(now, &budget);
            if (!self.running) return false;
        }
        if (poll_fds[2].revents & lib_posix.POLL.OUT != 0) {
            try self.flushUnix(now);
        }
        if (self.session) |*s| {
            try s.processTurn(now, &self.unix_out);
        }
        // Once more after the session turn: a relay unit the turn just
        // cleared releases buffered frames NOW, not at some unrelated
        // future event. This pump may run the immediate snapshot/
        // output QUIC pumps, but is NOT a second session turn (no
        // control/input processing, no per-turn budget resets).
        try self.pumpDaemonFrames(now);
        const alive = try self.quic.serviceDue(&self.udp_sock, now, &budget);
        if (!alive) {
            self.running = false;
            return false;
        }
        // Stream egress queued by the session leaves THIS turn — no
        // waiting for the next inbound datagram or PTO.
        try self.quic.drainEgress(&self.udp_sock, now, &budget);
        return self.running;
    }

    /// The single composed timeout: the earliest QUIC deadline (recovery/
    /// idle/close, slot expiry, the absolute handshake deadline, the
    /// one-second keepalive) as milliseconds remaining, bounded above
    /// by one second so staleness cannot accumulate.
    fn computePollTimeoutMs(self: *const Gateway) i32 {
        const now: i64 = lib_posix.nowNs();
        // The session's terminal deadline composes with the QUIC
        // deadlines so it fires even when no fd is ready.
        var deadline: ?i64 = self.quic.nextDeadline();
        if (self.session) |*s| {
            if (s.nextDeadline(now)) |sd| {
                deadline = if (deadline) |d| @min(d, sd) else sd;
            }
        }
        const d = deadline orelse return 1000;
        const remaining_ns = d - now;
        if (remaining_ns <= 0) return 0;
        const ms = @divFloor(remaining_ns, std.time.ns_per_ms);
        return @intCast(@min(ms, 1000));
    }

    /// The ONE authoritative daemon read-cap calculation: how many
    /// bytes the next daemon read may admit, clamped by the remaining
    /// turn budget. Zero means no read. A blocked output frame can
    /// never starve SnapshotBegin or snapshot chunks (unacceptable
    /// frames cap reads, they never block the pump).
    ///   no session          — up to 4096: pre-session traffic is
    ///                         closed and counted, never relayed;
    ///   terminal            — zero;
    ///   incomplete header   — exactly its remaining bytes, so a
    ///                         coalesced header+payload arrival cannot
    ///                         admit the payload before the header is
    ///                         inspectable;
    ///   unacceptable
    ///   declared frame      — zero;
    ///   acceptable
    ///   incomplete frame    — min(frame remaining, 4096, budget);
    ///   complete buffered
    ///   frame               — zero: pumpDaemonFrames owns consumption
    ///                         of a whole buffered unit.
    fn daemonReadCap(self: *const Gateway, budget_left: usize) usize {
        const s = if (self.session) |*sp| sp else return @min(@as(usize, 4096), budget_left);
        if (s.closedOrEnding()) return 0;
        const bytes = self.unix_read_buf.buf.items[self.unix_read_buf.head..];
        const total = ipc.expectedLength(bytes) orelse
            return @min(@sizeOf(ipc.Header) - bytes.len, budget_left);
        if (bytes.len >= total) return 0;
        const hdr = std.mem.bytesToValue(ipc.Header, bytes[0..@sizeOf(ipc.Header)]);
        if (!s.canConsumeDaemonFrame(hdr.tag, total - @sizeOf(ipc.Header))) return 0;
        return @min(total - bytes.len, @min(@as(usize, 4096), budget_left));
    }

    /// Frame-aware daemon-read eligibility: the read cap is non-zero —
    /// tests and poll arming decide through the same calculation the
    /// read loop uses.
    fn daemonReadEligible(self: *const Gateway) bool {
        return self.daemonReadCap(max_daemon_discard_per_turn) > 0;
    }

    /// Processes COMPLETE buffered daemon IPC frames with NO new
    /// POLL.IN, peeking before consuming: a frame the session cannot
    /// currently consume stays buffered untouched (one blocked unit
    /// ends the pass), and every accepted relay unit immediately
    /// attempts its QUIC pump. Runs before daemon reads, after each
    /// read, and once after the session turn.
    fn pumpDaemonFrames(self: *Gateway, now: i64) !void {
        while (true) {
            const bytes = self.unix_read_buf.buf.items[self.unix_read_buf.head..];
            const total = ipc.expectedLength(bytes) orelse return;
            if (bytes.len < total) return;
            const hdr = std.mem.bytesToValue(ipc.Header, bytes[0..@sizeOf(ipc.Header)]);
            if (self.session) |*s| {
                if (s.closedOrEnding()) return;
                if (!s.canConsumeDaemonFrame(hdr.tag, total - @sizeOf(ipc.Header))) return;
            }
            const msg = self.unix_read_buf.next().?;
            if (self.session) |*s| {
                switch (msg.header.tag) {
                    .Output => try s.offerDaemonOutput(msg.payload, now),
                    .Resize => try s.onDaemonResize(now, &self.unix_out),
                    .Switch => try s.onDaemonSwitch(now, &self.unix_out),
                    .SnapshotBegin => try s.onDaemonSnapshotBegin(msg.payload, now),
                    .SnapshotChunk => try s.onDaemonSnapshotChunk(msg.payload, now),
                    .SnapshotEnd => try s.onDaemonSnapshotEnd(msg.payload, now),
                    .SnapshotError => try s.onDaemonSnapshotError(msg.payload, now),
                    else => {
                        try s.onDaemonOtherFrame(now);
                        self.daemon_frames_ignored += 1;
                    },
                }
                // A frame that drove the session terminal ends the
                // batch: later coalesced frames belong to a session
                // that is no longer serving.
                if (s.closedOrEnding()) return;
                // Immediate QUIC pump of the accepted unit; the next
                // iteration's precheck enforces the one-blocked-unit
                // stop.
                try s.pumpRelayUnits();
            } else {
                // Pre-session daemon traffic is closed and counted.
                self.daemon_frames_ignored += 1;
            }
        }
    }

    /// The daemon read path: capped reads through the bounded reader
    /// (an oversized DECLARED frame fails closed), re-deriving the
    /// frame-aware read cap before EVERY read — a read never admits
    /// more than the authorized cap, so an unacceptable frame's
    /// payload cannot ride in behind its header — pumping buffered
    /// frames after each. The session dispatch itself lives in
    /// pumpDaemonFrames. Daemon EOF runs the SESSION_END terminal
    /// sequence when a session exists; the pre-session fallback keeps
    /// the Q2 CONNECTION_CLOSE path (through the shared TurnBudget).
    fn relayDaemon(self: *Gateway, now: i64, budget: *quic_gateway.TurnBudget) !void {
        // Exact bound: every read is capped to min(read cap, remaining
        // turn budget), so the loop consumes the 64 KiB turn limit
        // exactly — never overshooting, and never stopping early by
        // pre-reserving a full 4096 B it may not need.
        var read_total: usize = 0;
        while (read_total < max_daemon_discard_per_turn) {
            const cap = self.daemonReadCap(max_daemon_discard_per_turn - read_total);
            if (cap == 0) return;
            const n = self.unix_read_buf.readAtMost(self.unix_fd, cap) catch |err| switch (err) {
                error.WouldBlock => return,
                error.FrameTooLarge => {
                    log.warn("oversized daemon frame rejected at the cap", .{});
                    self.daemon_oversized_frames += 1;
                    if (self.session) |*s| {
                        try s.onDaemonOversizedFrame(now);
                    } else {
                        self.running = false;
                    }
                    return;
                },
                else => {
                    log.warn("unix read error: {s}", .{@errorName(err)});
                    self.running = false;
                    return;
                },
            };
            if (n == 0) {
                log.info("daemon closed connection", .{});
                if (self.session) |*s| {
                    try s.onDaemonEof(now);
                } else {
                    self.quic.closeForDaemonExit(&self.udp_sock, now, budget) catch |err| {
                        log.warn("daemon-close drain failed: {s}", .{@errorName(err)});
                    };
                }
                return;
            }
            read_total += n;
            try self.pumpDaemonFrames(now);
            if (self.session != null and self.session.?.closedOrEnding()) return;
        }
    }

    /// Flush daemon-bound writes on writability; when the buffer
    /// empties, an ending_unix session advances to stream settlement.
    fn flushUnix(self: *Gateway, now: i64) !void {
        while (!self.unix_out.empty()) {
            const n = lib_posix.write(self.unix_fd, self.unix_out.bytes()) catch |err| switch (err) {
                error.WouldBlock => return,
                // A permanent write error (EPIPE/EBADF/…) must not
                // leave POLL.OUT armed forever: fail closed.
                else => {
                    log.warn("unix write error, failing closed: {s}", .{@errorName(err)});
                    self.running = false;
                    return;
                },
            };
            if (n == 0) return;
            self.unix_out.consume(n);
        }
        if (self.session) |*s| {
            if (s.phase == .ending_unix) try s.onUnixFlushed(now);
        }
    }

    /// Attaches the ZMQ1 session exactly once, when the QUIC
    /// connection establishes. The fallible (pre-allocating) session
    /// construction failing is a local hard error: stop the gateway
    /// rather than run an application-less connection.
    fn ensureSession(self: *Gateway) !void {
        if (self.session != null) return;
        const t = self.quic.establishedTransport() orelse return;
        self.session = quic_session.QuicSession.init(self.alloc, t) catch |e| {
            log.err("session allocation failed: {s}", .{@errorName(e)});
            self.running = false;
            return e;
        };
    }

    pub fn deinit(self: *Gateway) void {
        lib_posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
        if (self.session) |*s| s.deinit();
        self.session = null;
        self.unix_out.deinit();
        // In place: deinitning a copy would wipe only the copy's PSK.
        self.quic.deinit();
    }
};

/// Entry point for `zmx serve <session>`: every fallible step precedes
/// the bootstrap line; pre-success failures emit the bounded
/// `ZMX_ERROR`. FD ownership transfers to the Gateway exactly once —
/// the errdefers here are disarmed at that point — and every secret
/// original (key, derived PSK, token secret, encoded key) is wiped on
/// EVERY path.
pub fn serveMain(alloc: std.mem.Allocator, io: std.Io, cfg: *const Cfg, session_name: []const u8) !void {
    const socket_path = socket.getSocketPath(alloc, cfg.socket_dir, session_name) catch |err| {
        log.err("failed to resolve daemon socket path: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };
    defer alloc.free(socket_path);

    const unix_fd = socket.sessionConnect(socket_path) catch |err| {
        log.err("failed to connect to daemon socket={s} err={s}", .{ socket_path, @errorName(err) });
        emitInitError();
        return err;
    };
    // Disarmed the moment Gateway.init succeeds: from there `gw.deinit`
    // is the sole closer of both descriptors.
    var gateway_owns_fds = false;
    errdefer if (!gateway_owns_fds) lib_posix.close(unix_fd);
    const flags = lib_posix.fcntl(unix_fd, lib_posix.F.GETFL, 0) catch |err| {
        log.err("fcntl GETFL failed: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };
    _ = lib_posix.fcntl(unix_fd, lib_posix.F.SETFL, flags | lib_posix.O_NONBLOCK) catch |err| {
        log.err("fcntl SETFL failed: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };

    const range = portRangeFromEnv();
    var udp_sock = udp.UdpSocket.bind(range.start, range.end) catch |err| {
        log.err("udp bind failed: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };
    errdefer if (!gateway_owns_fds) udp_sock.close();

    var key = crypto.generateKey(io) catch |err| {
        log.err("key generation failed: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };
    defer std.crypto.secureZero(u8, &key);
    var psk: [32]u8 = undefined;
    quic_transport.derivePsk(&psk, &key);
    defer std.crypto.secureZero(u8, &psk);
    var token_secret: [32]u8 = undefined;
    quic_gateway.deriveTokenSecret(&token_secret, &key);
    defer std.crypto.secureZero(u8, &token_secret);

    var gw = Gateway.init(alloc, io, unix_fd, udp_sock, &psk, &token_secret) catch |err| {
        log.err("gateway init failed: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };
    gateway_owns_fds = true;
    defer gw.deinit();
    // The derived originals are dead: the gateway holds the sole
    // copies and wipes them in its deinit (the defers above still run).

    // Success: print, anchor the absolute handshake deadline at this
    // emission, close stdout so the SSH capture can finish.
    var encoded_key = crypto.keyToBase64(&key);
    defer std.crypto.secureZero(u8, &encoded_key);
    emitBootstrapLine(udp_sock.bound_port, &encoded_key) catch |err| {
        log.err("bootstrap write failed: {s}", .{@errorName(err)});
        emitInitError();
        return err;
    };
    gw.quic.bootstrap_emitted_ns = lib_posix.nowNs();
    lib_posix.close(lib_posix.STDOUT_FILENO);

    log.info("gateway started session={s} transport=quic udp_port={d}", .{ session_name, udp_sock.bound_port });
    try gw.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "bootstrap line format" {
    var key = try crypto.generateKey(testing.io);
    defer std.crypto.secureZero(u8, &key);
    const encoded = crypto.keyToBase64(&key);
    const port: u16 = 60042;

    var buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "ZMX_CONNECT quic {d} {s}\n", .{ port, encoded });

    try testing.expect(std.mem.startsWith(u8, line, "ZMX_CONNECT quic "));

    var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\n"), ' ');
    try testing.expectEqualStrings("ZMX_CONNECT", it.next().?);
    try testing.expectEqualStrings("quic", it.next().?);
    const port_str = it.next().?;
    try testing.expectEqual(port, try std.fmt.parseInt(u16, port_str, 10));
    const key_str = it.next().?;
    try testing.expectEqual(key, try crypto.keyFromBase64(key_str));
}

test "ZMX_UDP_PORT_RANGE parsing: decimal, end-exclusive, bounds" {
    const ok = try parsePortRange("60000:61000");
    try testing.expectEqual(@as(u16, 60000), ok.start);
    try testing.expectEqual(@as(u16, 61000), ok.end);
    try testing.expectEqual(@as(u16, 1), (try parsePortRange("1:2")).start);
    try testing.expectEqual(@as(u16, 2), (try parsePortRange("1:2")).end);

    try testing.expectError(error.InvalidPortRange, parsePortRange("61000:60000"));
    try testing.expectError(error.InvalidPortRange, parsePortRange("60000:60000"));
    try testing.expectError(error.InvalidPortRange, parsePortRange("0:61000"));
    try testing.expectError(error.InvalidPortRange, parsePortRange("60000:65536"));
    try testing.expectError(error.InvalidPortRange, parsePortRange("60000"));
    try testing.expectError(error.InvalidPortRange, parsePortRange("abc:61000"));
    try testing.expectError(error.InvalidPortRange, parsePortRange(""));
}

test "sockaddr conversions: IPv4, native IPv6, mapped, port, scope" {
    // IPv4 roundtrip with port.
    const v4 = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, 4433);
    const v4a = quic_gateway.sockaddrToUdpAddress(v4).?;
    try testing.expect(v4a.family == .ipv4);
    try testing.expectEqual(@as(u16, 4433), v4a.port);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &v4a.v4);
    const v4back = quic_gateway.udpAddressToSockaddr(v4a);
    try testing.expectEqualSlices(u8, &[_]u8{ 127, 0, 0, 1 }, &@as([4]u8, @bitCast(v4back.in.addr)));
    try testing.expectEqual(@as(u16, 4433), std.mem.bigToNative(u16, v4back.in.port));

    // Native IPv6 with scope id, preserved exactly.
    var v6bytes: [16]u8 = @splat(0xfd);
    v6bytes[15] = 0x09;
    const v6 = lib_posix.Address.initIp6(v6bytes, 51000, 0, 7);
    const v6a = quic_gateway.sockaddrToUdpAddress(v6).?;
    try testing.expect(v6a.family == .ipv6);
    try testing.expectEqual(@as(u16, 51000), v6a.port);
    try testing.expectEqual(@as(u32, 7), v6a.scope_id);
    try testing.expectEqualSlices(u8, &v6bytes, &v6a.v6);
    const v6back = quic_gateway.udpAddressToSockaddr(v6a);
    const v6a2 = quic_gateway.sockaddrToUdpAddress(v6back).?;
    try testing.expect(v6a.eql(v6a2));

    // Kernel-reported IPv4-mapped IPv6 is preserved as reported, never
    // normalized.
    var mapped: [16]u8 = @splat(0);
    mapped[10] = 0xff;
    mapped[11] = 0xff;
    mapped[12] = 127;
    mapped[13] = 0;
    mapped[14] = 0;
    mapped[15] = 1;
    const m = lib_posix.Address.initIp6(mapped, 60000, 0, 0);
    const ma = quic_gateway.sockaddrToUdpAddress(m).?;
    try testing.expect(ma.family == .ipv6);
    try testing.expectEqualSlices(u8, &mapped, &ma.v6);
}

test "emitInitError is the frozen literal line" {
    // The exact static bytes the pre-bootstrap failure path writes:
    // numeric code 1, the literal gateway-init-failed message, one
    // newline, 32 bytes — well inside the 256-byte cap, printable
    // ASCII by construction.
    try testing.expectEqualStrings("ZMX_ERROR 1 gateway-init-failed\n", init_error_line);
    try testing.expectEqual(@as(usize, 32), init_error_line.len);
    try testing.expect(init_error_line.len <= max_error_line);
    for (init_error_line[0 .. init_error_line.len - 1]) |c| {
        try testing.expect(c >= 0x20 and c <= 0x7e);
    }
    try testing.expectEqual(@as(u8, '\n'), init_error_line[init_error_line.len - 1]);
}

// ─── Loop-level integration: real sockets, real poll turns ───────────

const quic_test = struct {
    const Transport = quic_transport.Transport;
    const challenge = [_]u8{ 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88 };

    const Loop = struct {
        alloc: std.mem.Allocator,
        gw: Gateway,
        daemon_fd: i32,
        client_sock: udp.UdpSocket,
        client: *Transport,
        gw_addr: lib_posix.Address,
        gw_port: u16,
        parked: std.ArrayList([]u8),
        parked_ready: std.ArrayList(bool),
        /// Explicit signal-pipe ownership: this fixture closes only a
        /// pipe it created — repeated fixtures never replace or leak
        /// descriptor pairs.
        owns_signal: bool,
        /// Native-IPv6 identities both sides (dual-stack sockets).
        v6: bool,

        fn init(alloc: std.mem.Allocator, psk: *const [32]u8, v6: bool) !Loop {
            // A bidirectional nonblocking Unix socketpair stands in for
            // the daemon's connected session socket: the relay writes
            // daemon-bound frames and reads daemon output on the same
            // descriptor.
            const fds = try lib_posix.socketpairNonBlock();
            const gw_sock = try udp.UdpSocket.bind(60400, 60500);
            const client_sock = try udp.UdpSocket.bind(60600, 60700);
            var token_secret: [32]u8 = undefined;
            quic_gateway.deriveTokenSecret(&token_secret, psk);
            defer std.crypto.secureZero(u8, &token_secret);
            var gw = try Gateway.init(alloc, testing.io, fds[0], gw_sock, psk, &token_secret);
            const client = try Transport.createClient(alloc, .{
                .psk = psk,
                .scid = .{ 0x21, 0x22, 0x23, 0x24 },
                .original_dcid = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
            });
            errdefer client.destroy();
            const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
            const client_local = if (v6)
                quicz.endpoint.UdpAddress.init6Scoped(loopback6, client_sock.bound_port, 0)
            else
                quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, client_sock.bound_port);
            const gw_remote = if (v6)
                quicz.endpoint.UdpAddress.init6Scoped(loopback6, gw_sock.bound_port, 0)
            else
                quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, gw_sock.bound_port);
            try client.registerRoute(client_local, gw_remote);
            const owns_signal = try signal.acquireSignalPipe();
            // Anchor on the local var — one struct, no copies.
            gw.quic.bootstrap_emitted_ns = lib_posix.nowNs();
            return .{
                .alloc = alloc,
                .gw = gw,
                .daemon_fd = fds[1],
                .client_sock = client_sock,
                .client = client,
                .gw_addr = if (v6)
                    lib_posix.Address.initIp6(loopback6, gw_sock.bound_port, 0, 0)
                else
                    lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, gw_sock.bound_port),
                .gw_port = gw_sock.bound_port,
                .parked = .empty,
                .parked_ready = .empty,
                .owns_signal = owns_signal,
                .v6 = v6,
            };
        }

        fn clientArrival(self: *const Loop) quicz.endpoint.UdpTuple {
            if (self.v6) {
                const loopback6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
                return .{
                    .local = quicz.endpoint.UdpAddress.init6Scoped(loopback6, self.client_sock.bound_port, 0),
                    .remote = quicz.endpoint.UdpAddress.init6Scoped(loopback6, self.gw_port, 0),
                };
            }
            return .{
                .local = quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, self.client_sock.bound_port),
                .remote = quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, self.gw_port),
            };
        }

        fn deinit(self: *Loop) void {
            for (self.parked.items) |dg| self.alloc.free(dg);
            self.parked.deinit(self.alloc);
            self.parked_ready.deinit(self.alloc);
            self.client.destroy();
            self.client_sock.close();
            if (self.daemon_fd != -1) lib_posix.close(self.daemon_fd);
            self.gw.deinit();
            if (self.owns_signal) signal.closeSignalPipe();
        }

        fn clientPump(self: *Loop, now: i64) !void {
            var sent: usize = 0;
            while (sent < 8) : (sent += 1) {
                const dg = (try self.client.pollOutbound(now)) orelse break;
                defer self.alloc.free(dg);
                try self.client_sock.sendTo(dg, self.gw_addr);
            }
        }

        fn clientDrain(self: *Loop, now: i64) !void {
            return self.clientDrainFor(self.client, now);
        }

        /// Phase-scoped drain: the wrong-PSK rollback test drives a
        /// second client transport over the SAME socket, so the
        /// receiving transport is a parameter.
        fn clientDrainFor(self: *Loop, target: *Transport, now: i64) !void {
            var turns: usize = 0;
            while (turns < 8) : (turns += 1) {
                var buf: [quic_transport.max_udp_payload]u8 = undefined;
                const r = self.client_sock.recvFrom(&buf) catch |err| switch (err) {
                    error.WouldBlock => break,
                    else => return err,
                };
                // Park Handshake-space datagrams that race key
                // installation — the same recovery the fixtures use.
                const info = quicz.protection.peekProtectedLongPacketInfo(buf[0..r.len]) catch {
                    _ = try target.handleDatagram(self.clientArrival(), now, buf[0..r.len], &challenge);
                    continue;
                };
                if (info.packet_type == .handshake and !target.conn.hasHandshakeProtectionKeys()) {
                    try self.parked.append(self.alloc, try self.alloc.dupe(u8, buf[0..r.len]));
                    try self.parked_ready.append(self.alloc, true);
                    continue;
                }
                _ = try target.handleDatagram(self.clientArrival(), now, buf[0..r.len], &challenge);
            }
            try self.flushParkedFor(target, now);
        }

        fn flushParkedFor(self: *Loop, target: *Transport, now: i64) !void {
            var i: usize = 0;
            while (i < self.parked.items.len) {
                if (!target.conn.hasHandshakeProtectionKeys()) {
                    i += 1;
                    continue;
                }
                _ = try target.handleDatagram(self.clientArrival(), now, self.parked.items[i], &challenge);
                self.alloc.free(self.parked.items[i]);
                _ = self.parked.orderedRemove(i);
                _ = self.parked_ready.orderedRemove(i);
            }
        }
    };

    fn driveHandshake(loop: *Loop) !void {
        var attempt: usize = 0;
        while (attempt < 64 and loop.gw.quic.state != .established) : (attempt += 1) {
            const now: i64 = lib_posix.nowNs();
            try loop.client.driveCrypto(.initial, now);
            try loop.clientPump(now);
            _ = try loop.gw.runOnce(0);
            try loop.clientDrain(now);
            try loop.client.driveCrypto(.handshake, now);
            try loop.clientPump(now);
            _ = try loop.gw.runOnce(0);
            try loop.clientDrain(now);
        }
        if (loop.gw.quic.state != .established) return error.HandshakeNotEstablished;
    }

    // ── ZMQ1 session fixtures ─────────────────────────────────────

    /// One borrowed frame view into the daemon-bound write buffer.
    const UnixFrame = struct {
        tag: ipc.Tag,
        payload: []const u8,
        total: usize,
    };

    /// Reads the daemon side of the fixture socketpair and yields one
    /// complete frame per call (payload borrowed until the next call).
    const DaemonReader = struct {
        alloc: std.mem.Allocator,
        buf: ipc.SocketBuffer,

        fn init(alloc: std.mem.Allocator) !DaemonReader {
            return .{ .alloc = alloc, .buf = try ipc.SocketBuffer.init(alloc) };
        }

        fn deinit(self: *DaemonReader) void {
            self.buf.deinit();
        }

        fn next(self: *DaemonReader, fd: i32) !?UnixFrame {
            while (true) {
                _ = self.buf.read(fd) catch break;
            }
            const bytes = self.buf.buf.items[self.buf.head..];
            const total = ipc.expectedLength(bytes) orelse return null;
            if (bytes.len < total) return null;
            const hdr = std.mem.bytesToValue(ipc.Header, bytes[0..@sizeOf(ipc.Header)]);
            self.buf.head += total;
            return .{ .tag = hdr.tag, .payload = bytes[@sizeOf(ipc.Header)..total], .total = total };
        }
    };

    /// Feeds client datagrams, interleaving control-stream reads after
    /// EACH datagram: terminal control bytes (ERROR/SESSION_END) must be
    /// consumed before a later datagram — the CONNECTION_CLOSE of a
    /// settled terminal sequence — makes buffered stream reads
    /// unavailable. The Q5 attach client polls streams the same way.
    fn clientDrainInterleaved(
        loop: *Loop,
        client: *quic_client.ClientSession,
        now: i64,
        ev: *?quic_client.ControlEvent,
        out_acc: ?*std.ArrayList(u8),
    ) !void {
        // Drain BEFORE receiving (the driver contract): a header pass
        // may consume the output header alone; the next pass drains
        // body bytes even when no further datagram arrives.
        while (try client.pollControl()) |e| ev.* = e;
        if (out_acc) |acc| {
            var ob: [256]u8 = undefined;
            while (try client.pollOutput(&ob, null)) |n| {
                try acc.appendSlice(loop.alloc, ob[0..n]);
            }
        }
        var buf: [quic_transport.max_udp_payload]u8 = undefined;
        while (true) {
            const r = loop.client_sock.recvFrom(&buf) catch break;
            _ = try loop.client.handleDatagram(loop.clientArrival(), now, buf[0..r.len], &challenge);
            while (try client.pollControl()) |e| ev.* = e;
            if (out_acc) |acc| {
                var ob: [256]u8 = undefined;
                while (try client.pollOutput(&ob, null)) |n| {
                    try acc.appendSlice(loop.alloc, ob[0..n]);
                }
            }
        }
    }

    /// One full exchange round at a synthetic timestamp: pump client
    /// egress, run the wired gateway turn (relay + session + the
    /// post-session egress drain), feed the client — twice. Returns
    /// the last control event observed (terminal frames must surface
    /// even when they race the settled CONNECTION_CLOSE).
    fn sessionRound(loop: *Loop, client: *quic_client.ClientSession, now: i64) !?quic_client.ControlEvent {
        return sessionRoundWith(loop, client, now, null);
    }

    // ── Q4 snapshot-transaction fixtures (daemon + raw-transport) ──

    /// Daemon side of one EMPTY snapshot transaction: Begin(0)+End(0).
    fn daemonSendEmptySnapshot(fd: i32) !void {
        try ipc.send(fd, .SnapshotBegin, &.{0});
        var endp: [8]u8 = undefined;
        std.mem.writeInt(u64, &endp, 0, .big);
        try ipc.send(fd, .SnapshotEnd, &endp);
    }

    /// Daemon side of one POPULATED transaction (PRESENT=1) carrying
    /// `bytes` as ≤32 KiB chunks plus the exact End count.
    fn daemonSendSnapshotBytes(fd: i32, bytes: []const u8) !void {
        try ipc.send(fd, .SnapshotBegin, &.{1});
        var off: usize = 0;
        while (off < bytes.len) : (off += ipc.snapshot_chunk_max) {
            const n = @min(ipc.snapshot_chunk_max, bytes.len - off);
            try ipc.send(fd, .SnapshotChunk, bytes[off..][0..n]);
        }
        var endp: [8]u8 = undefined;
        std.mem.writeInt(u64, &endp, bytes.len, .big);
        try ipc.send(fd, .SnapshotEnd, &endp);
    }

    /// The client's SNAPSHOT_INSTALLED control frame, crafted directly
    /// on the raw transport — stage 5 gives the real client its
    /// installer; gateway tests must not touch client FSM state.
    fn sendSnapshotInstalledOn(transport: *quic_transport.Transport) !void {
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .snapshot_installed, 0, 0);
        _ = try transport.connection().sendOnStream(quic_client.control_stream_id, &hdr, false);
    }

    /// Caller-owned snapshot-stream observation state: the header
    /// parser survives across rounds (body bytes continue where the
    /// last call stopped — a fresh parser would read them as a header).
    const ClientSnapshotRx = struct {
        hp: quic_wire.SnapshotHeaderParser = .{},
        header: quic_wire.SnapshotHeader = undefined,
    };

    /// OBSERVES the client's snapshot stream (7) through the raw
    /// transport: parses the 24-byte epoch-1 header, optionally
    /// accumulates the body, and returns the header once the FIN
    /// arrived — null while any part is still pending, an error on a
    /// reset or invalid header. Pure observation: nothing is mutated,
    /// no relay is bypassed.
    fn clientObserveSnapshot(
        transport: *quic_transport.Transport,
        alloc: std.mem.Allocator,
        rx: *ClientSnapshotRx,
        body: ?*std.ArrayList(u8),
    ) !?quic_wire.SnapshotHeader {
        const conn = transport.connection();
        const sid = quic_session.snapshot_stream_id;
        var hbuf: [quic_wire.snapshot_header_len]u8 = undefined;
        while (!rx.hp.done) {
            const n = conn.recvOnStream(sid, hbuf[0..rx.hp.remaining()]) catch |e| switch (e) {
                error.StreamClosed => return error.SnapshotStreamReset,
                else => return e,
            } orelse return null;
            if (n == 0) return null;
            switch (rx.hp.feed(hbuf[0..n]).result) {
                .done => |h| rx.header = h,
                .need => {},
                .invalid => return error.BadSnapshotHeader,
            }
        }
        var buf: [quic_session.snapshot_chunk_cap]u8 = undefined;
        while (true) {
            const n = conn.recvOnStream(sid, &buf) catch break orelse 0;
            if (n == 0) break;
            if (body) |b| try b.appendSlice(alloc, buf[0..n]);
        }
        const fin = conn.recvStreamFinished(sid) catch false;
        if (!fin) return null;
        return rx.header;
    }

    fn sessionRoundWith(
        loop: *Loop,
        client: *quic_client.ClientSession,
        now: i64,
        out_acc: ?*std.ArrayList(u8),
    ) !?quic_client.ControlEvent {
        var ev: ?quic_client.ControlEvent = null;
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try clientDrainInterleaved(loop, client, now, &ev, out_acc);
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try clientDrainInterleaved(loop, client, now, &ev, out_acc);
        return ev;
    }
};

test "gateway loop: real-socket Retry transaction commits exactly once" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();

    try quic_test.driveHandshake(&loop);

    // Commit happened exactly once: the slot cleared and the replay
    // filter consumed exactly one token.
    try testing.expect(!loop.gw.quic.slot.occupied);
    try testing.expectEqual(@as(usize, 1), loop.gw.quic.policy.replayFilterEntryCount());
    try testing.expect(loop.client.handshakeConfirmed());
    try testing.expectEqual(@as(usize, 1), loop.gw.quic.counters.handshakes_confirmed);
    try testing.expect(loop.gw.quic.handshake_duration_ns >= 0);

    // No daemon IPC bytes were relayed: the socketpair carries nothing.
    var probe: [64]u8 = undefined;
    const n = std.posix.read(loop.daemon_fd, &probe) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
}

test "gateway loop: ten-second deadline with no first Initial exits" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    loop.gw.quic.bootstrap_emitted_ns = 1_000;

    // No datagram ever arrives; only the synthetic clock advances.
    const inert = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    _ = try loop.gw.processReadyAndDue(1_000 + quic_gateway.handshake_deadline_ns, inert);
    try testing.expect(loop.gw.quic.state == .closed);
    try testing.expect(!loop.gw.running);
}

test "gateway loop: Retry expiry returns to a fresh exchange" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();

    // First flight only: the tokenless Initial opens the slot and the
    // Retry is sent.
    const now: i64 = lib_posix.nowNs();
    try loop.client.driveCrypto(.initial, now);
    const first = (try loop.client.pollOutbound(now)) orelse return error.NoFirstInitial;
    defer alloc.free(first);
    try loop.client_sock.sendTo(first, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    try testing.expect(loop.gw.quic.state == .retry_sent);
    try testing.expect(loop.gw.quic.slot.occupied);
    const sent_after_first = loop.gw.quic.counters.datagrams_sent;

    // A MATCHING tokenless retransmission — the identical datagram
    // bytes, as a lost-packet retransmission appears on the wire —
    // reissues the STORED Retry verbatim: no new exchange, no state
    // change.
    try loop.client_sock.sendTo(first, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    try testing.expect(loop.gw.quic.state == .retry_sent);
    try testing.expect(loop.gw.quic.slot.occupied);
    try testing.expect(loop.gw.quic.counters.datagrams_sent > sent_after_first);

    // Past the slot's absolute expiry the handshake deadline (the same
    // frozen ten seconds, anchored earlier) governs: the gateway
    // cleans up and exits.
    const inert = [3]lib_posix.pollfd{ .{ .fd = 0, .events = 0, .revents = 0 }, .{ .fd = 0, .events = 0, .revents = 0 }, .{ .fd = 0, .events = 0, .revents = 0 } };
    _ = try loop.gw.processReadyAndDue(loop.gw.quic.bootstrap_emitted_ns + quic_gateway.handshake_deadline_ns, inert);
    try testing.expect(loop.gw.quic.state == .closed);
    try testing.expect(!loop.gw.running);
}

test "gateway loop: wrong-PSK follow-up rolls back with the slot reusable" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);
    var other: [32]u8 = undefined;
    var wrong_psk: [32]u8 = undefined;
    try testing.io.randomSecure(&other);
    quic_transport.derivePsk(&wrong_psk, &other);
    defer std.crypto.secureZero(u8, &other);
    defer std.crypto.secureZero(u8, &wrong_psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();

    // The wrong-PSK client shares the correct client's exchange
    // identity (scid, original DCID) AND socket, so the issued token
    // stays path-valid for either.
    const bad = try quic_test.Transport.createClient(alloc, .{
        .psk = &wrong_psk,
        .scid = .{ 0x21, 0x22, 0x23, 0x24 },
        .original_dcid = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
    });
    defer bad.destroy();
    try bad.registerRoute(loop.clientArrival().local, loop.clientArrival().remote);

    // Full failed exchange: Initial → stored Retry → token follow-up.
    var now: i64 = lib_posix.nowNs();
    try bad.driveCrypto(.initial, now);
    const first_bad = (try bad.pollOutbound(now)) orelse return error.NoBadInitial;
    defer alloc.free(first_bad);
    try loop.client_sock.sendTo(first_bad, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    try testing.expect(loop.gw.quic.state == .retry_sent);
    try loop.clientDrainFor(bad, now);
    now += 1;
    try bad.driveCrypto(.initial, now);
    const follow_bad = (try bad.pollOutbound(now)) orelse return error.NoBadFollowup;
    defer alloc.free(follow_bad);
    const scid_before = loop.gw.quic.retry_scid;
    const discarded_before = loop.gw.quic.counters.datagrams_discarded;
    try loop.client_sock.sendTo(follow_bad, loop.gw_addr);
    _ = try loop.gw.runOnce(0);

    // The binder fails against the real PSK: rollback THROUGH THE
    // REGISTRY (the once-armed-errdefer double-free path), state back
    // to retry_sent, slot still occupied, Retry SCID unchanged, the
    // failure counted.
    try loop.clientDrainFor(bad, now);
    try testing.expect(loop.gw.quic.state == .retry_sent);
    try testing.expect(loop.gw.quic.slot.occupied);
    try testing.expectEqual(scid_before, loop.gw.quic.retry_scid);
    try testing.expect(loop.gw.quic.counters.datagrams_discarded > discarded_before);

    // The CORRECT client with the same CIDs/path re-enters through the
    // REISSUED stored Retry and completes on the SAME slot.
    now += 1;
    try loop.client.driveCrypto(.initial, now);
    const first = (try loop.client.pollOutbound(now)) orelse return error.NoInitial;
    defer alloc.free(first);
    try loop.client_sock.sendTo(first, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    try loop.clientDrain(now);
    try testing.expect(loop.gw.quic.state == .retry_sent);

    try quic_test.driveHandshake(&loop);
    try testing.expect(loop.gw.quic.state == .established);
    try testing.expect(!loop.gw.quic.slot.occupied);
    try testing.expectEqual(@as(usize, 1), loop.gw.quic.policy.replayFilterEntryCount());
    try testing.expectEqual(@as(usize, 1), loop.gw.quic.counters.handshakes_confirmed);
}

test "gateway loop: SIGTERM is serviced before network work" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();

    // The udp socket is PRIMED with a datagram and poll reports BOTH
    // the signal fd and the network readable: the signal wins and the
    // network is never read.
    try loop.client_sock.sendTo(&([_]u8{0xff} ** 64), loop.gw_addr);
    _ = lib_posix.write(signal.sig_pipe[1], "x") catch return error.SignalPipeWriteFailed;
    const poll_fds = [3]lib_posix.pollfd{
        .{ .fd = loop.gw.udp_sock.getFd(), .events = lib_posix.POLL.IN, .revents = lib_posix.POLL.IN },
        .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = lib_posix.POLL.IN },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    const received_before = loop.gw.quic.counters.datagrams_received;
    try testing.expect(!try loop.gw.processReadyAndDue(lib_posix.nowNs(), poll_fds));
    try testing.expect(!loop.gw.running);
    try testing.expectEqual(received_before, loop.gw.quic.counters.datagrams_received);
    // The daemon pipe was never touched either.
    var probe: [64]u8 = undefined;
    const n = std.posix.read(loop.daemon_fd, &probe) catch 0;
    try testing.expectEqual(@as(usize, 0), n);
}

test "gateway loop: invalid traffic never resets state or deadlines" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();

    // One real first flight opens the exchange.
    const now: i64 = lib_posix.nowNs();
    try loop.client.driveCrypto(.initial, now);
    const first = (try loop.client.pollOutbound(now)) orelse return error.NoInitial;
    defer alloc.free(first);
    try loop.client_sock.sendTo(first, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    try testing.expect(loop.gw.quic.state == .retry_sent);
    try testing.expect(loop.gw.quic.slot.occupied);
    const expiry_before = loop.gw.quic.slot.expires_nanos;
    const anchor = loop.gw.quic.bootstrap_emitted_ns;

    // Garbage and truncated header-like datagrams: discarded, counted,
    // and never a state or deadline reset.
    const junk = [_][24]u8{
        .{0xff} ** 24, .{0xc0} ** 24, .{0xe0} ** 24,
        .{0x80} ** 24, .{0x40} ** 24, .{0x00} ** 24,
    };
    for (0..24) |i| {
        try loop.client_sock.sendTo(&junk[i % junk.len], loop.gw_addr);
    }
    _ = try loop.gw.runOnce(0);
    try testing.expect(loop.gw.quic.state == .retry_sent);
    try testing.expect(loop.gw.quic.slot.occupied);
    try testing.expectEqual(expiry_before, loop.gw.quic.slot.expires_nanos);
    try testing.expect(loop.gw.quic.counters.datagrams_discarded >= 24);

    // The absolute deadline is untouched by any of it: the gateway
    // still closes at anchor + 10 s.
    const inert = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    _ = try loop.gw.processReadyAndDue(anchor + quic_gateway.handshake_deadline_ns, inert);
    try testing.expect(loop.gw.quic.state == .closed);
    try testing.expect(!loop.gw.running);
}

test "gateway loop: keepalive queues once, retries a full second later, clears on emission" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);
    const conn = loop.gw.quic.registry.get(1).?.transport.connection();

    // Settle: the client answers everything outstanding and the
    // gateway holds no pending emission — the timed stages below then
    // count exactly their own output (an armed PTO would add probes).
    var settled = false;
    for (0..6) |_| {
        const n: i64 = lib_posix.nowNs();
        try loop.clientPump(n);
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(n);
        // Quiescent when the gateway holds no further emission. A
        // residual ACK-only leftover (the handshake tail) is dropped:
        // it is not ack-eliciting, so nothing retrains a PTO on it.
        var pending = false;
        if (try loop.gw.quic.registry.get(1).?.transport.pollOutboundPath(n)) |left| {
            alloc.free(left.dg);
            pending = true;
        }
        if (!pending) {
            settled = true;
            break;
        }
    }
    try testing.expect(settled);
    const sent_base = loop.gw.quic.counters.datagrams_sent;

    // Idle two seconds: exactly one PING leaves, emitted_ping clears
    // the flag, and the output stamp advances. The client then answers
    // it so its PTO cannot fire at the next synthetic stage.
    const t1: i64 = lib_posix.nowNs() + 2 * std.time.ns_per_s;
    var budget = quic_gateway.TurnBudget{};
    try testing.expect(try loop.gw.quic.serviceDue(&loop.gw.udp_sock, t1, &budget));
    try testing.expectEqual(sent_base + 1, loop.gw.quic.counters.datagrams_sent);
    try testing.expect(!loop.gw.quic.keepalive_queued);
    try testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try testing.expectEqual(t1, loop.gw.quic.last_output_ns);
    try loop.clientDrain(t1 + 1);
    try loop.clientPump(t1 + 1);
    _ = try loop.gw.runOnce(0);

    // Half a second later: nothing new.
    var budget_half = quic_gateway.TurnBudget{};
    try testing.expect(try loop.gw.quic.serviceDue(&loop.gw.udp_sock, t1 + 500 * std.time.ns_per_ms, &budget_half));
    try testing.expectEqual(sent_base + 1, loop.gw.quic.counters.datagrams_sent);

    // A PING queued with ONE slot left LEAVES through the RESERVED
    // class — ordinary output stops one short, and the keepalive is
    // exactly the deadline-critical output that slot exists for.
    const t2 = t1 + 2 * std.time.ns_per_s;
    var budget_one = quic_gateway.TurnBudget{ .outbound = 1 };
    try testing.expect(try loop.gw.quic.serviceDue(&loop.gw.udp_sock, t2, &budget_one));
    try testing.expect(!loop.gw.quic.keepalive_queued);
    try testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try testing.expectEqual(sent_base + 2, loop.gw.quic.counters.datagrams_sent);
    try testing.expectEqual(t2, loop.gw.quic.last_output_ns);
    try loop.clientDrain(t2 + 1);
    try loop.clientPump(t2 + 1);
    _ = try loop.gw.runOnce(0);

    // The budget-refused branch: with an EMPTY budget no PING is ever
    // queued (an unsendable PING is never queued) and nothing is sent.
    // The expired deadline deliberately yields an immediate next turn
    // with a FRESH budget — next-turn retry, not a stranded PING.
    const t3 = t2 + 4 * std.time.ns_per_s;
    var budget_zero = quic_gateway.TurnBudget{ .outbound = 0 };
    try testing.expect(try loop.gw.quic.serviceDue(&loop.gw.udp_sock, t3, &budget_zero));
    try testing.expect(!loop.gw.quic.keepalive_queued);
    try testing.expectEqual(@as(usize, 0), conn.pending_ping_count);
    try testing.expectEqual(sent_base + 2, loop.gw.quic.counters.datagrams_sent);
}

test "gateway loop: flood bounds defer inbound without starving output fairness" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    // Distinct client PING datagrams (fresh packet numbers), then
    // duplicates to reach a 100-datagram burst in ONE turn.
    const now: i64 = lib_posix.nowNs();
    var dgs: [100][]u8 = undefined;
    var n_distinct: usize = 0;
    for (0..100) |_| {
        try loop.client.connection().sendPing();
        const dg = (try loop.client.pollOutbound(now)) orelse break;
        dgs[n_distinct] = dg;
        n_distinct += 1;
    }
    defer for (dgs[0..n_distinct]) |dg| alloc.free(dg);
    for (dgs[0..n_distinct]) |dg| try loop.client_sock.sendTo(dg, loop.gw_addr);
    var i: usize = n_distinct;
    while (i < 100) : (i += 1) {
        try loop.client_sock.sendTo(dgs[0], loop.gw_addr);
    }

    const received_before = loop.gw.quic.counters.datagrams_received;
    const sent_before = loop.gw.quic.counters.datagrams_sent;
    _ = try loop.gw.runOnce(0);
    // Exactly 64 inbound processed this turn; the remainder defers
    // (the socket is still readable) and output stays bounded by the
    // turn budget. No exact ACK count: coalescing is nondeterministic.
    try testing.expectEqual(@as(usize, 64), loop.gw.quic.counters.datagrams_received - received_before);
    try testing.expect(loop.gw.quic.counters.datagrams_sent - sent_before <= quic_gateway.max_outbound_per_turn);
    var pfd = [1]lib_posix.pollfd{.{ .fd = loop.gw.udp_sock.getFd(), .events = lib_posix.POLL.IN, .revents = 0 }};
    try testing.expectEqual(@as(usize, 1), try lib_posix.poll(&pfd, 0));
}

test "gateway loop: reserved slot carries the due PTO past ordinary exhaustion" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    // A PING emitted to nowhere arms the application PTO.
    const transport = loop.gw.quic.registry.get(1).?.transport;
    const t: i64 = lib_posix.nowNs() + 1;
    try transport.connection().sendPing();
    const ping = (try transport.pollOutboundPath(t)) orelse return error.NoPingEmission;
    alloc.free(ping.dg);

    // Past the PTO with exactly ONE slot left: the reserved send
    // consumes it while ordinary sends at the same budget are refused.
    const t_due = t + 60 * std.time.ns_per_s;
    var budget = quic_gateway.TurnBudget{ .outbound = 1 };
    const sent_before = loop.gw.quic.counters.datagrams_sent;
    try testing.expect(try loop.gw.quic.serviceDue(&loop.gw.udp_sock, t_due, &budget));
    try testing.expectEqual(@as(usize, 0), budget.outbound);
    try testing.expectEqual(sent_before + 1, loop.gw.quic.counters.datagrams_sent);

    var ordinary = quic_gateway.TurnBudget{ .outbound = 1 };
    try testing.expect(!ordinary.take(.ordinary));
    try testing.expect(ordinary.take(.reserved));
}

test "gateway loop: migration through a second client path" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    // NAT rebinding: the client's traffic now leaves from a second
    // socket. The gateway sees an authenticated changed path.
    var mig_sock = try udp.UdpSocket.bind(60800, 60900);
    defer mig_sock.close();
    const mig_arrival = quicz.endpoint.UdpTuple{
        .local = quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, mig_sock.bound_port),
        .remote = quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, loop.gw_port),
    };
    const now: i64 = lib_posix.nowNs();
    try loop.client.connection().sendPing();
    const migrated = (try loop.client.pollOutboundPath(now)) orelse return error.NoMigratedPing;
    defer alloc.free(migrated.dg);
    try mig_sock.sendTo(migrated.dg, loop.gw_addr);
    _ = try loop.gw.runOnce(0);

    // Exactly one challenge was queued for the candidate path.
    try testing.expectEqual(@as(usize, 1), loop.gw.quic.counters.challenges_issued);

    // The path-bound PATH_CHALLENGE is tagged to the NEW path and
    // arrives on the migration socket (ordinary output — an ACK for
    // the migrated PING — still uses the committed route until the
    // migration validates, and may arrive on the original socket).
    var buf: [quic_transport.max_udp_payload]u8 = undefined;
    var saw_challenge = false;
    while (true) {
        const r = mig_sock.recvFrom(&buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        saw_challenge = true;
        _ = try loop.client.handleDatagram(mig_arrival, now, buf[0..r.len], &quic_test.challenge);
    }
    try testing.expect(saw_challenge);
    // The committed-route leftovers reach the client through the
    // original socket.
    while (true) {
        const r = loop.client_sock.recvFrom(&buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        _ = try loop.client.handleDatagram(loop.clientArrival(), now, buf[0..r.len], &quic_test.challenge);
    }

    // The client's PATH_RESPONSE leaves through the migration path
    // (bound to its arrival) — the pump routes each datagram by its
    // tagged source port — and the gateway accepts the migration.
    var sent: usize = 0;
    while (sent < 8) : (sent += 1) {
        const tagged = (try loop.client.pollOutboundPath(now)) orelse break;
        defer alloc.free(tagged.dg);
        if (tagged.dst.local.port == mig_arrival.local.port) {
            try mig_sock.sendTo(tagged.dg, loop.gw_addr);
        } else {
            try loop.client_sock.sendTo(tagged.dg, loop.gw_addr);
        }
    }
    _ = try loop.gw.runOnce(0);
    try testing.expectEqual(@as(usize, 1), loop.gw.quic.counters.challenges_issued);
    try testing.expect(loop.gw.quic.state == .established);

    // Once validated, ALL gateway output follows the new path: a fresh
    // client PING through the migration socket is answered there and
    // the original socket stays empty.
    const now2: i64 = lib_posix.nowNs();
    try loop.client.connection().sendPing();
    const again = (try loop.client.pollOutboundPath(now2)) orelse return error.NoSecondPing;
    defer alloc.free(again.dg);
    try mig_sock.sendTo(again.dg, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    var answered_on_new_path = false;
    while (true) {
        const r = mig_sock.recvFrom(&buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        answered_on_new_path = true;
        _ = try loop.client.handleDatagram(mig_arrival, now2, buf[0..r.len], &quic_test.challenge);
    }
    try testing.expect(answered_on_new_path);
    const stale = loop.client_sock.recvFrom(&buf) catch |err| switch (err) {
        error.WouldBlock => null,
        else => return err,
    };
    try testing.expect(stale == null);
}

test "gateway loop: native IPv6 loopback handshake" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, true);
    defer loop.deinit();

    try quic_test.driveHandshake(&loop);
    try testing.expect(loop.gw.quic.state == .established);
    try testing.expect(loop.client.handshakeConfirmed());
}

test "gateway loop: daemon EOF close survives the ordinary budget floor" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    // The daemon side is gone and the turn's budget sits at the
    // ordinary floor: the CONNECTION_CLOSE still leaves through the
    // RESERVED slot.
    lib_posix.close(loop.daemon_fd);
    loop.daemon_fd = -1;
    var budget = quic_gateway.TurnBudget{ .outbound = 1 };
    try testing.expect(!budget.take(.ordinary));
    try loop.gw.quic.closeForDaemonExit(&loop.gw.udp_sock, lib_posix.nowNs(), &budget);
    try testing.expectEqual(@as(usize, 0), budget.outbound);
    try testing.expect(loop.gw.quic.state == .closed);
    try testing.expect(!loop.gw.quic.running);

    // The close frame reached the client, whose connection leaves the
    // active state on processing it.
    var buf: [quic_transport.max_udp_payload]u8 = undefined;
    var closed_seen = false;
    while (true) {
        const r = loop.client_sock.recvFrom(&buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        closed_seen = true;
        _ = try loop.client.handleDatagram(loop.clientArrival(), lib_posix.nowNs(), buf[0..r.len], &quic_test.challenge);
    }
    try testing.expect(closed_seen);
    try testing.expect(loop.client.conn.connectionState() != .active);
}

// ─── ZMQ1 session tests: QuicSession + ClientSession on the Loop pair ──

fn zmq1Setup(alloc: std.mem.Allocator, psk: *const [32]u8) !struct {
    loop: quic_test.Loop,
    client: quic_client.ClientSession,

    pub fn session(self: *@This()) !*quic_session.QuicSession {
        return if (self.loop.gw.session) |*s| s else error.NoSession;
    }

    pub fn unixOut(self: *@This()) *quic_session.UnixWriteBuf {
        return &self.loop.gw.unix_out;
    }
} {
    var loop = try quic_test.Loop.init(alloc, psk, false);
    errdefer loop.deinit();
    try quic_test.driveHandshake(&loop);
    // One gateway turn attaches the gateway-owned session.
    _ = try loop.gw.runOnce(0);
    const client = try quic_client.ClientSession.init(alloc, loop.client);
    return .{ .loop = loop, .client = client };
}

/// The HELLO exchange only, ending at awaiting_resize.
fn zmq1HelloAck(z: anytype, base: i64) !void {
    var ev: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try z.client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);
}

/// The full Q4 attach dance: first RESIZE → daemon `.InitSnapshot` →
/// one EMPTY daemon snapshot transaction → the client OBSERVES the
/// real stream-7 header and FIN through the raw transport → crafted
/// SNAPSHOT_INSTALLED → `.active`. No session state is mutated and no
/// relay is bypassed; the observation is pure transport reads.
fn zmq1Dance(z: anytype, dr: *quic_test.DaemonReader, base: i64) !void {
    try zmq1HelloAck(z, base);
    try z.client.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
        try testing.expectEqual(ipc.Tag.InitSnapshot, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 24), rz.rows);
        try testing.expectEqual(@as(u16, 80), rz.cols);
    }
    try quic_test.daemonSendEmptySnapshot(z.loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try testing.expectEqual(quic_wire.snapshot_epoch_v1, observed.?.epoch);
    try testing.expect(!observed.?.present); // the empty transaction
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    const s = try z.session();
    for (0..8) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
        if (s.phase == .active) break;
    }
    try testing.expect(s.phase == .active);
}

test "zmq1 session: HELLO → ACK → RESIZE/.InitSnapshot → install → input relay → output epoch 1" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    // HELLO flows; the client validates HELLO_ACK.
    var ack: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ack = e;
            break;
        }
        ack = try z.client.pollControl();
        if (ack != null) break;
    }
    try testing.expect(ack != null);
    try testing.expect(ack.? == .hello_ack);
    try testing.expect(sess.phase == .awaiting_resize);

    // The output stream opened with its header (epoch 1); the client
    // does NOT expose it until HELLO_ACK validated — which it now has.
    var epoch: u64 = 0;
    var obuf: [64]u8 = undefined;
    const on0 = try z.client.pollOutput(&obuf, &epoch);
    try testing.expect(on0 == null); // header consumed, no body yet
    try testing.expectEqual(@as(u64, 1), epoch);

    // First RESIZE → daemon `.InitSnapshot` with the BE-decoded size,
    // then the transaction: empty snapshot observed on stream 7 with
    // its FIN, SNAPSHOT_INSTALLED, active.
    try z.client.sendResize(37, 101, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
        try testing.expectEqual(ipc.Tag.InitSnapshot, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 37), rz.rows);
        try testing.expectEqual(@as(u16, 101), rz.cols);
    }
    try quic_test.daemonSendEmptySnapshot(z.loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try testing.expectEqual(quic_wire.snapshot_epoch_v1, observed.?.epoch);
    try testing.expect(!observed.?.present);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    try testing.expect(sess.phase == .active);

    // Input bytes → daemon `.Input` frames.
    try z.client.sendInput("hello-zmq1");
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInput;
        try testing.expectEqual(ipc.Tag.Input, f.tag);
        try testing.expectEqualStrings("hello-zmq1", f.payload);
    }

    // Daemon output relays on the epoch-1 output stream.
    try ipc.send(z.loop.daemon_fd, .Output, "relay-me");
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    var got: []const u8 = "";
    for (0..4) |_| {
        const n = (try z.client.pollOutput(&obuf, null)) orelse continue;
        got = obuf[0..n];
        break;
    }
    try testing.expectEqualStrings("relay-me", got);

    // A second RESIZE forwards as `.Resize` — never a second
    // `.InitSnapshot`.
    try z.client.sendResize(40, 120, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 400 + @as(i64, @intCast(i)));
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoSecondResize;
        try testing.expectEqual(ipc.Tag.Resize, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 40), rz.rows);
    }
    try testing.expect(!sess.closedOrEnding());
}

// ─── Q4 snapshot relay: transaction, validation, backpressure ─────────

/// Drives one session to `.InitSnapshot` at the daemon (HELLO + first
/// RESIZE only), returning after the resize rounds.
fn zmq1ToInitSnapshot(z: anytype, dr: *quic_test.DaemonReader, base: i64) !void {
    try zmq1HelloAck(z, base);
    try z.client.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try testing.expectEqual(ipc.Tag.InitSnapshot, f.tag);
}

/// One daemon-side raw frame, for violation fixtures.
fn daemonSendRaw(fd: i32, tag: ipc.Tag, payload: []const u8) !void {
    try ipc.send(fd, tag, payload);
}

test "zmq1 q4: populated stream-7 transaction with exact header, body, FIN, and post-FIN/pre-INSTALLED output" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToInitSnapshot(&z, &dr, base);

    // 40 KiB across the 32 KiB chunk boundary: two chunks (32 KiB +
    // 8 KiB) plus the exact End count.
    var body: [40 * 1024]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 251);
    try quic_test.daemonSendSnapshotBytes(z.loop.daemon_fd, &body);

    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..24) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, alloc, &snap_rx, &acc);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try testing.expectEqual(quic_wire.snapshot_epoch_v1, observed.?.epoch);
    try testing.expect(observed.?.present);
    try testing.expectEqualSlices(u8, &body, acc.items);
    try testing.expectEqual(@as(u64, body.len), sess.snapshot_total);
    try testing.expectEqual(@as(usize, 2), sess.counters.snapshot_chunks);
    // FIN sent, installation phase entered (not yet active).
    try testing.expect(sess.snapshot_fin_sent);
    try testing.expect(sess.phase == .awaiting_snapshot_installed);

    // Post-End output relays as epoch-1 output even before INSTALLED.
    try ipc.send(z.loop.daemon_fd, .Output, "post-cut");
    var got: []const u8 = "";
    for (0..8) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
        var obuf: [64]u8 = undefined;
        if (try z.client.pollOutput(&obuf, null)) |n| {
            got = try alloc.dupe(u8, obuf[0..n]);
            break;
        }
    }
    try testing.expectEqualStrings("post-cut", got);
    alloc.free(got);

    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 400 + @as(i64, @intCast(i)));
    try testing.expect(sess.phase == .active);
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 q4: pre-cut output is discarded in every pre-Begin phase" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    // Output while STILL awaiting_hello (the freshly initialized
    // session, phase untouched): discarded, counted, never relayed.
    try testing.expect(sess.phase == .awaiting_hello);
    try ipc.send(z.loop.daemon_fd, .Output, "no-hello-yet");
    // The client session sends its HELLO eagerly, so the ACK may
    // surface inside these very rounds — capture, never discard.
    var ack: ?quic_client.ControlEvent = null;
    for (0..4) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 10 + @as(i64, @intCast(i)))) |e| {
            ack = e;
            break;
        }
        ack = try z.client.pollControl();
        if (ack != null) break;
    }
    try testing.expectEqual(@as(usize, "no-hello-yet".len), sess.counters.discarded_pre_cut_output);
    try testing.expectEqual(@as(usize, 0), sess.counters.daemon_output_frames);
    for (0..8) |i| {
        if (ack != null) break;
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 1000 + @as(i64, @intCast(i)))) |e| {
            ack = e;
            break;
        }
        ack = try z.client.pollControl();
    }
    try testing.expect(ack != null and ack.? == .hello_ack);

    // Output while awaiting_resize: discarded, counted, never relayed.
    try ipc.send(z.loop.daemon_fd, .Output, "too-early");
    for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 50 + @as(i64, @intCast(i)));
    try testing.expectEqual(@as(usize, "no-hello-yet".len + "too-early".len), sess.counters.discarded_pre_cut_output);
    try testing.expectEqual(@as(usize, 0), sess.counters.daemon_output_frames);
    var obuf: [64]u8 = undefined;
    try testing.expect((try z.client.pollOutput(&obuf, null)) == null);

    // And again in awaiting_snapshot_begin, before Begin.
    try z.client.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 1100 + @as(i64, @intCast(i)));
    _ = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try ipc.send(z.loop.daemon_fd, .Output, "pre-begin");
    for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 1200 + @as(i64, @intCast(i)));
    try testing.expectEqual(@as(usize, "no-hello-yet".len + "too-early".len + "pre-begin".len), sess.counters.discarded_pre_cut_output);
    try testing.expectEqual(@as(usize, 0), sess.counters.daemon_output_frames);
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 q4: PRESENT, count, marker, and length violations all fail terminally" {
    const alloc = testing.allocator;
    // Each violating sequence runs on its own fresh pair: any one of
    // them ends the session, so they cannot share a gateway.
    const Kind = enum {
        present0_chunk,
        present1_zero,
        duplicate_end,
        chunk_after_end,
        count_mismatch,
        bad_begin_len,
        bad_begin_value,
        bad_end_len,
        oversize_chunk,
    };
    const cases = [_]Kind{
        .present0_chunk, .present1_zero, .duplicate_end,   .chunk_after_end,
        .count_mismatch, .bad_begin_len, .bad_begin_value, .bad_end_len,
        .oversize_chunk,
    };
    for (cases) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        const sess = try z.session();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToInitSnapshot(&z, &dr, base);

        var chunk: [33 * 1024]u8 = undefined;
        @memset(&chunk, 'c');
        var endp: [8]u8 = undefined;
        const fd = z.loop.daemon_fd;
        switch (kind) {
            // PRESENT=0 must carry no chunks.
            .present0_chunk => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{0});
                try daemonSendRaw(fd, .SnapshotChunk, "x");
            },
            // PRESENT=1 requires at least one byte: End(0) fails.
            .present1_zero => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{1});
                std.mem.writeInt(u64, &endp, 0, .big);
                try daemonSendRaw(fd, .SnapshotEnd, &endp);
            },
            // Exactly one End.
            .duplicate_end => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{1});
                try daemonSendRaw(fd, .SnapshotChunk, "body");
                std.mem.writeInt(u64, &endp, 4, .big);
                try daemonSendRaw(fd, .SnapshotEnd, &endp);
                try daemonSendRaw(fd, .SnapshotEnd, &endp);
            },
            // No chunk after a validated End.
            .chunk_after_end => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{1});
                try daemonSendRaw(fd, .SnapshotChunk, "body");
                std.mem.writeInt(u64, &endp, 4, .big);
                try daemonSendRaw(fd, .SnapshotEnd, &endp);
                try daemonSendRaw(fd, .SnapshotChunk, "late");
            },
            // The End count must equal the chunk total exactly.
            .count_mismatch => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{1});
                try daemonSendRaw(fd, .SnapshotChunk, "body");
                std.mem.writeInt(u64, &endp, 5, .big);
                try daemonSendRaw(fd, .SnapshotEnd, &endp);
            },
            // Malformed marker payloads.
            .bad_begin_len => try daemonSendRaw(fd, .SnapshotBegin, &.{ 1, 1 }),
            .bad_begin_value => try daemonSendRaw(fd, .SnapshotBegin, &.{2}),
            .bad_end_len => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{1});
                try daemonSendRaw(fd, .SnapshotEnd, &.{ 1, 2, 3, 4 });
            },
            // A chunk over the 32 KiB frame bound fails closed.
            .oversize_chunk => {
                try daemonSendRaw(fd, .SnapshotBegin, &.{1});
                try daemonSendRaw(fd, .SnapshotChunk, &chunk);
            },
        }
        for (0..12) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        try testing.expect(sess.closedOrEnding());
        try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), sess.end_code.code());
        // The unfinished transaction was reset, never FINed — except
        // the two post-completion kinds, whose FIRST End legitimately
        // validated and FINed before the violation arrived.
        const fin_expected = kind == .duplicate_end or kind == .chunk_after_end;
        try testing.expectEqual(fin_expected, sess.snapshot_fin_sent);
    }
}

test "zmq1 q4: interleaved daemon frames during streaming are terminal" {
    const alloc = testing.allocator;
    const Kind = enum { output, resize, switch_frame, history };
    const cases = [_]Kind{ .output, .resize, .switch_frame, .history };
    for (cases) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        const sess = try z.session();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToInitSnapshot(&z, &dr, base);

        // Between Begin and End ONLY Chunk/End/Error are legal.
        try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
        try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, "mid");
        switch (kind) {
            .output => try daemonSendRaw(z.loop.daemon_fd, .Output, "interleave"),
            .resize => {
                var rz: ipc.Resize = .{ .rows = 9, .cols = 9 };
                try daemonSendRaw(z.loop.daemon_fd, .Resize, std.mem.asBytes(&rz));
            },
            .switch_frame => try daemonSendRaw(z.loop.daemon_fd, .Switch, "sw"),
            .history => try daemonSendRaw(z.loop.daemon_fd, .History, "h"),
        }
        for (0..12) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        try testing.expect(sess.closedOrEnding());
        try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), sess.end_code.code());
    }
}

test "zmq1 q4: known, unknown, and malformed SnapshotError all reset stream 7" {
    const alloc = testing.allocator;
    const Kind = enum { known, unknown_code, malformed };
    const cases = [_]Kind{ .known, .unknown_code, .malformed };
    for (cases) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        const sess = try z.session();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToInitSnapshot(&z, &dr, base);

        // An unfinished transaction: header + one chunk on the wire.
        try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
        try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, "partial");
        for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));

        var errp: [4 + 8]u8 = undefined;
        switch (kind) {
            .known => {
                std.mem.writeInt(u32, errp[0..4], ipc.snapshot_error_encode_failed, .big);
                @memcpy(errp[4..8], "boom");
                try daemonSendRaw(z.loop.daemon_fd, .SnapshotError, errp[0..8]);
            },
            .unknown_code => {
                std.mem.writeInt(u32, errp[0..4], 99, .big);
                @memcpy(errp[4..8], "boom");
                try daemonSendRaw(z.loop.daemon_fd, .SnapshotError, errp[0..8]);
            },
            .malformed => {
                // Non-printable diagnostic: rejected by the IPC codec.
                std.mem.writeInt(u32, errp[0..4], ipc.snapshot_error_encode_failed, .big);
                @memset(errp[4..], 0x01);
                try daemonSendRaw(z.loop.daemon_fd, .SnapshotError, errp[0..8]);
            },
        }
        for (0..12) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        try testing.expect(sess.closedOrEnding());
        try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), sess.end_code.code());
        // The unfinished stream 7 was RESET, not FINed: the client's
        // transport (alive for the whole fixture, unlike the gateway
        // record the close retires) saw the RST — the receive side
        // latched the reset state, which a FINed stream never enters.
        const cst = (try z.client.transport.connection().streamState(quic_session.snapshot_stream_id)) orelse return error.NoClientStream7;
        try testing.expect(cst.receive == .reset_received or cst.receive == .reset_read);
        try testing.expect(!sess.snapshot_fin_sent);
    }
}

test "zmq1 q4: installation control matrix — premature/nonempty INSTALLED, DETACH, REQUEST" {
    const alloc = testing.allocator;
    const Kind = enum { premature_installed, nonempty_installed, mid_detach, mid_request };
    const cases = [_]Kind{ .premature_installed, .nonempty_installed, .mid_detach, .mid_request };
    for (cases) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        const sess = try z.session();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToInitSnapshot(&z, &dr, base);

        // Mid-installation: either pre-Begin or mid-streaming.
        if (kind == .premature_installed or kind == .mid_detach) {
            try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
        }
        switch (kind) {
            .premature_installed => try quic_test.sendSnapshotInstalledOn(z.client.transport),
            .nonempty_installed => {
                // Wait for the FIN first: only a NONEMPTY payload makes
                // this frame illegal here.
                var endp: [8]u8 = undefined;
                std.mem.writeInt(u64, &endp, 0, .big);
                try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{0});
                try daemonSendRaw(z.loop.daemon_fd, .SnapshotEnd, &endp);
                for (0..12) |i| {
                    _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
                    if (sess.phase == .awaiting_snapshot_installed) break;
                }
                try testing.expect(sess.phase == .awaiting_snapshot_installed);
                var hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&hdr, .snapshot_installed, 3, 0);
                _ = try z.client.transport.connection().sendOnStream(quic_client.control_stream_id, &hdr, false);
                _ = try z.client.transport.connection().sendOnStream(quic_client.control_stream_id, "bad", false);
            },
            .mid_detach => try z.client.sendDetach(),
            .mid_request => try z.client.sendSnapshotRequest(),
        }
        for (0..12) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        try testing.expect(sess.closedOrEnding());
        try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), sess.end_code.code());
    }
}

test "zmq1 q4: RESIZEs coalesce to the latest value until installation completes" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToInitSnapshot(&z, &dr, base);

    // Two installation-phase RESIZEs: neither reaches the daemon.
    try z.client.sendResize(30, 90, 0, 0);
    try z.client.sendResize(40, 120, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);

    // Complete the transaction; on activation the LATEST value alone
    // forwards as `.Resize`.
    try quic_test.daemonSendEmptySnapshot(z.loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    try testing.expect(sess.phase == .active);
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoCoalescedResize;
        try testing.expectEqual(ipc.Tag.Resize, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 40), rz.rows);
        try testing.expectEqual(@as(u16, 120), rz.cols);
    }
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 q4: zero output credit cannot starve SnapshotBegin or stream 7" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToInitSnapshot(&z, &dr, base);

    // Simulate a fully blocked output stream: pending_output sits at
    // its 64 KiB bound with the client granting no further credit.
    // (Stuffed directly: the relay path cannot produce a FULL buffer
    // pre-Begin because pre-Begin output is discarded.)
    var filler: [32 * 1024]u8 = undefined;
    @memset(&filler, 'F');
    try sess.pending_output.appendSlice(alloc, &filler);
    try sess.pending_output.appendSlice(alloc, &filler);
    try testing.expectEqual(quic_session.pending_output_cap, sess.pending_output.items.len);
    // The frame-aware gate stays eligible: blocked output is NOT read
    // backpressure for snapshot frames.
    try testing.expect(z.loop.gw.daemonReadEligible());

    // The whole transaction completes through the relay regardless.
    try quic_test.daemonSendEmptySnapshot(z.loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    try testing.expect(sess.phase == .active);
}

test "zmq1 q4: snapshot credit exhaustion parks one unit, buffers the next, recovers losslessly" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToInitSnapshot(&z, &dr, base);

    // Backpressure WITHOUT transport surgery: quicz grants receive
    // credit only as the app reads, so withholding stream-7 reads
    // holds the gateway at its ~2 KiB initial window.
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
    var body: [24 * 1024]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast((i * 11 + 1) % 251);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, body[0 .. 8 * 1024]);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, body[8 * 1024 ..]);
    var endp: [8]u8 = undefined;
    std.mem.writeInt(u64, &endp, body.len, .big);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotEnd, &endp);
    for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));

    // ONE snapshot unit is parked (the first chunk's unsent tail), the
    // second chunk AND the End sit buffered behind it, and reads stop.
    try testing.expect(sess.pending_snapshot.items.len > 0);
    try testing.expect(!sess.snapshot_end_validated);
    {
        // The buffered head is the parked chunk's own leading bytes —
        // at most its header: the capped read stops an unacceptable
        // frame at the header boundary, so no payload rides in.
        const rb = z.loop.gw.unix_read_buf;
        const bytes = rb.buf.items[rb.head..];
        const total = ipc.expectedLength(bytes) orelse return error.NoBufferedFrame;
        const hdr = std.mem.bytesToValue(ipc.Header, bytes[0..@sizeOf(ipc.Header)]);
        try testing.expectEqual(ipc.Tag.SnapshotChunk, hdr.tag);
        try testing.expect(bytes.len <= total);
    }
    try testing.expect(!z.loop.gw.daemonReadEligible());
    try testing.expect(!sess.snapshot_fin_sent);

    // Reading the stream releases refill credit: recovery is lossless,
    // the count validates, the FIN leaves, the body is byte-exact.
    var drain: std.ArrayList(u8) = .empty;
    defer drain.deinit(alloc);
    var drain_rx: quic_test.ClientSnapshotRx = .{};
    var observed: ?quic_wire.SnapshotHeader = null;
    for (0..80) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, alloc, &drain_rx, &drain);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try testing.expectEqualSlices(u8, &body, drain.items);
    try testing.expect(sess.snapshot_fin_sent);
    try testing.expect(sess.pending_snapshot.items.len == 0);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 500 + @as(i64, @intCast(i)));
    try testing.expect(sess.phase == .active);
}

test "zmq1 q4: buffered IPC advances without POLL.IN, including post-turn release" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToInitSnapshot(&z, &dr, base);

    // Reach the blocked state by withholding stream-7 reads (no
    // transport surgery): one chunk parked, one chunk + End buffered.
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
    var body: [16 * 1024]u8 = undefined;
    @memset(&body, 'B');
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, body[0 .. 8 * 1024]);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, body[8 * 1024 ..]);
    var endp: [8]u8 = undefined;
    std.mem.writeInt(u64, &endp, body.len, .big);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotEnd, &endp);
    for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
    try testing.expect(sess.pending_snapshot.items.len > 0);
    try testing.expect(!sess.snapshot_end_validated);

    // NOTHING further is ever sent on the daemon socket: the buffered
    // chunk and End must advance purely through the every-turn pump
    // (and the post-session-turn pass) as reading restores credit.
    var drain: std.ArrayList(u8) = .empty;
    defer drain.deinit(alloc);
    var drain_rx: quic_test.ClientSnapshotRx = .{};
    var observed: ?quic_wire.SnapshotHeader = null;
    for (0..80) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, alloc, &drain_rx, &drain);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try testing.expectEqualSlices(u8, &body, drain.items);
    try testing.expect(sess.snapshot_fin_sent);
    try testing.expect(sess.snapshot_end_validated);
    try testing.expect(sess.pending_snapshot.items.len == 0);
    // No daemon frame was waiting and none arrived during recovery:
    // the buffered IPC advanced with no new daemon input at all.
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
}

test "zmq1 q4: negotiated snapshot limit from HELLO is enforced" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    // A silent client session (no HELLO of its own): the test crafts
    // the preface + a HELLO negotiating a 4096-byte snapshot limit —
    // the min of the client's declaration and the server default —
    // exactly like the mismatch fixtures.
    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);
    _ = try loop.gw.runOnce(0); // attach the gateway-owned session
    const sess = if (loop.gw.session) |*x| x else return error.NoSession;
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
    defer client.deinit();
    const base: i64 = lib_posix.nowNs();

    {
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);
        var hello = quic_wire.Hello.serverV1(quic_wire.mode_attach);
        hello.snapshot_limit = 4096;
        var payload: [quic_wire.hello_payload_len]u8 = undefined;
        hello.encode(&payload);
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .hello, payload.len, 0);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &hdr, false);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &payload, false);
    }
    for (0..8) |i| {
        _ = try quic_test.sessionRound(&loop, &client, base + @as(i64, @intCast(i)));
        if ((try client.pollControl()) != null) break;
    }
    try testing.expect(sess.phase == .awaiting_resize);
    try testing.expectEqual(@as(u64, 4096), sess.snapshot_limit);

    // A transaction crossing the negotiated limit (not the 128 MiB
    // constant) fails terminally.
    try client.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&loop, &client, base + 100 + @as(i64, @intCast(i)));
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try daemonSendRaw(loop.daemon_fd, .SnapshotBegin, &.{1});
    var chunk: [8 * 1024]u8 = undefined;
    @memset(&chunk, 'L');
    try daemonSendRaw(loop.daemon_fd, .SnapshotChunk, &chunk);
    for (0..12) |i| _ = try quic_test.sessionRound(&loop, &client, base + 200 + @as(i64, @intCast(i)));
    try testing.expect(sess.closedOrEnding());
    try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), sess.end_code.code());
    try testing.expect(!sess.snapshot_fin_sent);
}

test "zmq1 q4: post-End output relays while the snapshot FIN is still pending" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToInitSnapshot(&z, &dr, base);

    // ONE 8 KiB chunk and NO client stream-7 reads: the ~2 KiB window
    // leaves most of it parked, so End validates with the FIN unsent.
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
    var body: [8 * 1024]u8 = undefined;
    for (&body, 0..) |*b, i| b.* = @intCast((i * 13 + 5) % 251);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, &body);
    var endp: [8]u8 = undefined;
    std.mem.writeInt(u64, &endp, body.len, .big);
    try daemonSendRaw(z.loop.daemon_fd, .SnapshotEnd, &endp);
    for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));

    // BEFORE any client read: End validated, FIN pending, and the
    // post-cut Output must be CONSUMED from IPC (counted), not
    // terminal — this is the race the stage-4 interleave missed.
    try testing.expect(sess.snapshot_end_validated);
    try testing.expect(!sess.snapshot_fin_sent);
    try testing.expect(sess.pending_snapshot.items.len > 0);
    try ipc.send(z.loop.daemon_fd, .Output, "post-end-pre-fin");
    for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
    try testing.expect(!sess.closedOrEnding());
    try testing.expectEqual(@as(usize, 1), sess.counters.daemon_output_frames);

    // Drain: snapshot bytes, the FIN, and the Output all arrive
    // losslessly, in that order of release.
    var drain: std.ArrayList(u8) = .empty;
    defer drain.deinit(alloc);
    var drain_rx: quic_test.ClientSnapshotRx = .{};
    var observed: ?quic_wire.SnapshotHeader = null;
    var got: []const u8 = "";
    var obuf: [64]u8 = undefined;
    for (0..80) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, alloc, &drain_rx, &drain);
        if (got.len == 0) {
            if (try z.client.pollOutput(&obuf, null)) |n| got = try alloc.dupe(u8, obuf[0..n]);
        }
        if (observed != null and got.len > 0) break;
    }
    try testing.expect(observed != null);
    try testing.expectEqualSlices(u8, &body, drain.items);
    try testing.expect(sess.snapshot_fin_sent);
    try testing.expectEqualStrings("post-end-pre-fin", got);
    alloc.free(got);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 500 + @as(i64, @intCast(i)));
    try testing.expect(sess.phase == .active);
}

test "zmq1 q4: malformed chunks fail immediately behind a parked legal unit" {
    const alloc = testing.allocator;
    // Each kind runs on its own fresh pair: any one of them ends the
    // session, and the limit kind needs its own negotiated HELLO.
    const Kind = enum { zero_len, oversize, limit_overflow };
    const cases = [_]Kind{ .zero_len, .oversize, .limit_overflow };
    for (cases) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        if (kind == .limit_overflow) {
            // A negotiated 4096-byte limit: the parked legal chunk must
            // fit under it, the violating chunk must not.
            var loop = try quic_test.Loop.init(alloc, &psk, false);
            defer loop.deinit();
            try quic_test.driveHandshake(&loop);
            _ = try loop.gw.runOnce(0);
            const sess = if (loop.gw.session) |*x| x else return error.NoSession;
            var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
            defer client.deinit();
            const lbase: i64 = lib_posix.nowNs();
            {
                const cconn = client.transport.connection();
                _ = try cconn.openStream();
                var pre: [quic_wire.preface_len]u8 = undefined;
                quic_wire.writePreface(&pre, .control);
                _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);
                var hello = quic_wire.Hello.serverV1(quic_wire.mode_attach);
                hello.snapshot_limit = 4096;
                var payload: [quic_wire.hello_payload_len]u8 = undefined;
                hello.encode(&payload);
                var hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&hdr, .hello, payload.len, 0);
                _ = try cconn.sendOnStream(quic_client.control_stream_id, &hdr, false);
                _ = try cconn.sendOnStream(quic_client.control_stream_id, &payload, false);
            }
            for (0..8) |i| {
                _ = try quic_test.sessionRound(&loop, &client, lbase + @as(i64, @intCast(i)));
                if ((try client.pollControl()) != null) break;
            }
            try testing.expectEqual(@as(u64, 4096), sess.snapshot_limit);
            try client.sendResize(24, 80, 0, 0);
            for (0..8) |i| _ = try quic_test.sessionRound(&loop, &client, lbase + 100 + @as(i64, @intCast(i)));

            // Park a legal 2 KiB chunk (under the limit), no reads.
            try daemonSendRaw(loop.daemon_fd, .SnapshotBegin, &.{1});
            var legal: [2 * 1024]u8 = undefined;
            @memset(&legal, 'P');
            try daemonSendRaw(loop.daemon_fd, .SnapshotChunk, &legal);
            for (0..4) |i| _ = try quic_test.sessionRound(&loop, &client, lbase + 150 + @as(i64, @intCast(i)));
            try testing.expect(sess.pending_snapshot.items.len > 0);

            // The violating chunk exceeds the negotiated limit. NO
            // client reads: it must fail immediately anyway.
            var big: [8 * 1024]u8 = undefined;
            @memset(&big, 'V');
            try daemonSendRaw(loop.daemon_fd, .SnapshotChunk, &big);
            for (0..8) |i| _ = try quic_test.sessionRound(&loop, &client, lbase + 200 + @as(i64, @intCast(i)));
            try testing.expect(sess.closedOrEnding());
            try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), sess.end_code.code());
            try testing.expect(!sess.snapshot_fin_sent);
            const cst = (try client.transport.connection().streamState(quic_session.snapshot_stream_id)) orelse return error.NoClientStream7;
            try testing.expect(cst.receive == .reset_received or cst.receive == .reset_read);
            continue;
        }

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        const sess = try z.session();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToInitSnapshot(&z, &dr, base);

        // Park a legal 8 KiB chunk with NO client reads.
        try daemonSendRaw(z.loop.daemon_fd, .SnapshotBegin, &.{1});
        var legal: [8 * 1024]u8 = undefined;
        @memset(&legal, 'P');
        try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, &legal);
        for (0..4) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
        try testing.expect(sess.pending_snapshot.items.len > 0);

        switch (kind) {
            .zero_len => try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, ""),
            .oversize => {
                var big: [33 * 1024]u8 = undefined;
                @memset(&big, 'V');
                try daemonSendRaw(z.loop.daemon_fd, .SnapshotChunk, &big);
            },
            else => unreachable,
        }
        // NO client reads anywhere: flow control cannot delay the
        // fail-closed handling.
        for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        try testing.expect(sess.closedOrEnding());
        try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), sess.end_code.code());
        try testing.expect(!sess.snapshot_fin_sent);
        const cst = (try z.client.transport.connection().streamState(quic_session.snapshot_stream_id)) orelse return error.NoClientStream7;
        try testing.expect(cst.receive == .reset_received or cst.receive == .reset_read);
    }
}

test "zmq1 q4: reads stop at an unacceptable frame header and resume losslessly" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1Dance(&z, &dr, base);

    // Occupied output storage: pending_output at its cap.
    var filler: [32 * 1024]u8 = undefined;
    @memset(&filler, 'F');
    try sess.pending_output.appendSlice(alloc, &filler);
    try sess.pending_output.appendSlice(alloc, &filler);
    try testing.expectEqual(quic_session.pending_output_cap, sess.pending_output.items.len);

    // ONLY an 8-byte Output header (declaring 1 KiB) reaches the
    // daemon socket — no payload.
    const only_hdr = ipc.Header{ .tag = .Output, .len = 1024 };
    _ = try lib_posix.write(z.loop.daemon_fd, std.mem.asBytes(&only_hdr));
    _ = try z.loop.gw.runOnce(0);
    // The same turn pumped a little of the stuffed backlog out (initial
    // credit): top pending_output back up to its cap so the declared
    // 1 KiB frame genuinely cannot be accepted.
    while (sess.pending_output.items.len < quic_session.pending_output_cap) {
        const room = quic_session.pending_output_cap - sess.pending_output.items.len;
        try sess.pending_output.appendSlice(alloc, filler[0..@min(room, filler.len)]);
    }

    // The header is buffered, the gate rejects the DECLARED frame, and
    // no further payload bytes are read into the buffer (reads stop at
    // the header; the eligibility flip below re-arms them only after
    // output credit returns).
    try testing.expect(!z.loop.gw.daemonReadEligible());
    {
        const rb = z.loop.gw.unix_read_buf;
        try testing.expectEqual(@sizeOf(ipc.Header), rb.buf.items.len - rb.head);
    }
    // (Writing arbitrary partial payload bytes as a further probe is
    // deliberately avoided: a real daemon never sends mid-frame
    // garbage, and the bounded reader correctly fails closed on it.)

    // Output credit returns (the client drains the backlog): the gate
    // opens, and a COMPLETE frame relays losslessly.
    var drained: usize = 0;
    var obuf: [16 * 1024]u8 = undefined;
    for (0..80) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
        while (try z.client.pollOutput(&obuf, null)) |n| drained += n;
        if (sess.pending_output.items.len == 0 and z.loop.gw.daemonReadEligible()) break;
    }
    try testing.expect(sess.pending_output.items.len == 0);
    try testing.expect(z.loop.gw.daemonReadEligible());
    // Complete the declared frame: its 1 KiB 'R' payload relays in
    // full after the 'F' backlog (stragglers may interleave in
    // flight, so the proof is the byte pattern, not a bare count).
    var rest: [1024]u8 = undefined;
    @memset(&rest, 'R');
    _ = try lib_posix.write(z.loop.daemon_fd, &rest);
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    for (0..80) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 400 + @as(i64, @intCast(i)));
        while (try z.client.pollOutput(&obuf, null)) |n| {
            try acc.appendSlice(alloc, obuf[0..n]);
        }
        if (acc.items.len >= 64 * 1024 + 1024) break;
    }
    // The backlog ('F') relayed completely and the payload ('R') sits
    // exactly at the tail.
    // The backlog drained during the credit-recovery loop; the newly
    // completed frame relays as exactly its 1 KiB 'R' payload.
    try testing.expectEqual(@as(usize, 1024), acc.items.len);
    try testing.expectEqual(@as(usize, 1), sess.counters.daemon_output_frames);
    for (acc.items) |b| {
        try testing.expectEqual(@as(u8, 'R'), b);
    }
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 q4: a coalesced header+payload write never over-reads an unacceptable frame" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1Dance(&z, &dr, base);

    // 1. ACTIVE with a stuffed output backlog.
    var filler: [32 * 1024]u8 = undefined;
    @memset(&filler, 'F');
    try sess.pending_output.appendSlice(alloc, &filler);
    try sess.pending_output.appendSlice(alloc, &filler);
    try testing.expectEqual(quic_session.pending_output_cap, sess.pending_output.items.len);

    // 2. Exhaust the server's output-stream credit WITHOUT any client
    // output read (sessionRound never polls output): rounds pump the
    // backlog only as the frozen window allows, until the stream state
    // itself proves send_max_data == send_offset. The backlog may be
    // fully OR partially drained at that point — the exhaustion, not
    // the backlog level, is what this step pins. Whatever drained is
    // re-added in step 3 and must all reach the client eventually.
    var f_after_exhaust: usize = 0;
    {
        var exhausted = false;
        for (0..100) |i| {
            _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
            const st = (try sess.transport.connection().streamState(quic_session.output_stream_id)) orelse
                return error.NoStream3State;
            const max = st.send_max_data orelse return error.NoSendMaxData;
            const off = st.send_offset orelse return error.NoSendOffset;
            if (max == off) {
                exhausted = true;
                break;
            }
        }
        try testing.expect(exhausted);
        f_after_exhaust = sess.pending_output.items.len;
    }

    // 3. Refill the backlog to capacity; with credit exhausted another
    // round must not drain a single byte.
    while (sess.pending_output.items.len < quic_session.pending_output_cap) {
        const room = quic_session.pending_output_cap - sess.pending_output.items.len;
        try sess.pending_output.appendSlice(alloc, filler[0..@min(room, filler.len)]);
    }
    _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300);
    try testing.expectEqual(quic_session.pending_output_cap, sess.pending_output.items.len);

    // 4. ONE contiguous write: the Output header declaring 1024 bytes
    // plus its entire payload in a single syscall — the coalesced
    // arrival the separate-write proof cannot exercise.
    const hdr = ipc.Header{ .tag = .Output, .len = 1024 };
    var coalesced: [@sizeOf(ipc.Header) + 1024]u8 = undefined;
    @memcpy(coalesced[0..@sizeOf(ipc.Header)], std.mem.asBytes(&hdr));
    @memset(coalesced[@sizeOf(ipc.Header)..], 'C');
    _ = try lib_posix.write(z.loop.daemon_fd, &coalesced);

    // 5. One gateway turn. An over-reading gate buffers all 1032 bytes
    // here; the capped read must buffer EXACTLY the 8-byte header,
    // keep the gate closed, count nothing, and stay nonterminal.
    _ = try z.loop.gw.runOnce(0);
    try testing.expect(!z.loop.gw.daemonReadEligible());
    {
        const rb = z.loop.gw.unix_read_buf;
        try testing.expectEqual(@sizeOf(ipc.Header), rb.buf.items.len - rb.head);
    }
    try testing.expectEqual(@as(usize, 0), sess.counters.daemon_output_frames);
    try testing.expect(!sess.closedOrEnding());

    // 6. Restore credit by draining the client; NO second daemon
    // write. Every 'F' byte — those the exhaust rounds drained plus
    // the full refilled backlog — and then exactly 1024 'C' bytes
    // arrive, in order; the frame counter increments exactly once.
    const total_f: usize = 64 * 1024 + (64 * 1024 - f_after_exhaust);
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    var obuf: [16 * 1024]u8 = undefined;
    for (0..160) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 400 + @as(i64, @intCast(i)));
        while (try z.client.pollOutput(&obuf, null)) |n| {
            try acc.appendSlice(alloc, obuf[0..n]);
        }
        if (acc.items.len >= total_f + 1024) break;
    }
    try testing.expectEqual(total_f + 1024, acc.items.len);
    try testing.expectEqual(@as(usize, 1), sess.counters.daemon_output_frames);
    try testing.expectEqual(@as(usize, 0), sess.pending_output.items.len);
    for (acc.items[0..total_f]) |b| try testing.expectEqual(@as(u8, 'F'), b);
    for (acc.items[total_f..]) |b| try testing.expectEqual(@as(u8, 'C'), b);
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 session: HELLO mismatches reject with the frozen codes and never initialize the daemon" {
    const alloc = testing.allocator;
    const BadHelloKind = enum { version, capability, fingerprint };
    const cases = [_]struct { kind: BadHelloKind, code: u32 }{
        .{ .kind = .version, .code = quic_wire.ErrCode.version_mismatch.code() },
        .{ .kind = .capability, .code = quic_wire.ErrCode.capability_mismatch.code() },
        .{ .kind = .fingerprint, .code = quic_wire.ErrCode.fingerprint_mismatch.code() },
    };
    for (cases) |c| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        try quic_test.driveHandshake(&loop);
        // Attach the gateway-owned session.
        _ = try loop.gw.runOnce(0);
        const sess = if (loop.gw.session) |*x| x else return error.NoSession;
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
        defer client.deinit();

        // Craft the BAD HELLO as the client's first and only frame —
        // a good HELLO must never precede it.
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);
        var hello = quic_wire.Hello.serverV1(quic_wire.mode_attach);
        switch (c.kind) {
            .version => hello.version_major = 2,
            .capability => hello.required_capabilities = 0x1E,
            .fingerprint => hello.snapshot_abi_id[0] ^= 0xFF,
        }
        var payload: [quic_wire.hello_payload_len]u8 = undefined;
        hello.encode(&payload);
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .hello, payload.len, 0);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &hdr, false);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &payload, false);

        const base: i64 = lib_posix.nowNs();
        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            if (try quic_test.sessionRound(&loop, &client, base + @as(i64, @intCast(i)))) |e| {
                err_ev = e;
                break;
            }
            err_ev = try client.pollControl();
            if (err_ev != null) break;
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(c.code, e.code),
            else => return error.TestUnexpectedResult,
        }
        // Authorization precedes session data: no `.Init` was ever
        // written to the daemon socket.
        try testing.expect((try dr.next(loop.daemon_fd)) == null);
        try testing.expect(sess.closedOrEnding());
    }
}

test "zmq1 session: SNAPSHOT_REQUEST is answered nonterminally and the relay continues" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    try zmq1Dance(&z, &dr, base);

    // Two SNAPSHOT_REQUESTs → two ERROR(unimplemented) responses, and
    // the session stays active.
    var errors_seen: usize = 0;
    for (0..2) |_| {
        try z.client.sendSnapshotRequest();
        for (0..8) |i| {
            if (try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)))) |e| {
                switch (e) {
                    .err => |er| {
                        try testing.expectEqual(quic_wire.ErrCode.unimplemented.code(), er.code);
                        errors_seen += 1;
                    },
                    else => {},
                }
            }
            while (try z.client.pollControl()) |e| {
                switch (e) {
                    .err => |er| {
                        try testing.expectEqual(quic_wire.ErrCode.unimplemented.code(), er.code);
                        errors_seen += 1;
                    },
                    else => {},
                }
            }
        }
    }
    try testing.expectEqual(@as(usize, 2), errors_seen);
    try testing.expect(!sess.closedOrEnding());

    // The relay still serves input after the nonterminal responses.
    try z.client.sendInput("still-alive");
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInputAfterError;
    try testing.expectEqual(ipc.Tag.Input, f.tag);
    try testing.expectEqualStrings("still-alive", f.payload);
}

test "zmq1 session: network-reordered input is parked, then flows strictly after .Init" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    var ev: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try z.client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);

    // Correct API order: RESIZE first, then input. The NETWORK
    // delivery is then reordered — the resize datagram is withheld
    // while the input datagram reaches the gateway first.
    try z.client.sendResize(30, 90, 0, 0);
    try z.client.sendInput("early-input");

    const held = (try z.loop.client.pollOutbound(base + 100)) orelse return error.NoResizeDatagram;
    defer alloc.free(held);
    var sent_input = false;
    for (0..4) |_| {
        const dg = (try z.loop.client.pollOutbound(base + 100)) orelse break;
        defer alloc.free(dg);
        try z.loop.client_sock.sendTo(dg, z.loop.gw_addr);
        sent_input = true;
    }
    try testing.expect(sent_input);
    _ = try z.loop.gw.runOnce(0);

    // The input arrived with no `.Init` yet: PARKED — nothing
    // rejected, nothing consumed, no credit granted.
    try testing.expect(sess.phase == .awaiting_resize);
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
    {
        const st = (try sess.transport.connection().streamState(quic_session.input_stream_id)) orelse return error.NoStreamState;
        try testing.expect((st.receive_buffered orelse 0) > (st.receive_read_offset orelse 0));
    }

    // Deliver the withheld resize: `.InitSnapshot` queues first, then
    // the parked input flows — strictly after it.
    try z.loop.client_sock.sendTo(held, z.loop.gw_addr);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    {
        const f1 = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
        try testing.expectEqual(ipc.Tag.InitSnapshot, f1.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f1.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 30), rz.rows);
        const f2 = (try dr.next(z.loop.daemon_fd)) orelse return error.NoParkedInput;
        try testing.expectEqual(ipc.Tag.Input, f2.tag);
        try testing.expectEqualStrings("early-input", f2.payload);
    }
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 session: a second control stream is rejected by the id scan" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    const base: i64 = lib_posix.nowNs();

    var ev: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try z.client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);

    // A second bidi stream (id 4) carrying a control preface.
    const s = try z.client.transport.connection().openStream();
    try testing.expectEqual(@as(u64, 4), s);
    var pre: [8]u8 = undefined;
    quic_wire.writePreface(&pre, .control);
    try z.client.transport.connection().sendOnStream(s, &pre, false);

    var err_ev: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)))) |e| {
            err_ev = e;
            break;
        }
        err_ev = try z.client.pollControl();
        if (err_ev != null) break;
    }
    try testing.expect(err_ev != null);
    switch (err_ev.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.stream_cardinality.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(sess.closedOrEnding());
}

test "zmq1 session: stream-2 data with no control stream closes immediately without a control write" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);
    // Attach the gateway-owned session.
    _ = try loop.gw.runOnce(0);
    const sess = if (loop.gw.session) |*x| x else return error.NoSession;
    const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;

    // The client never opens stream 0; input data arrives first. This
    // is the no-control-stream fatal arm: an immediate application
    // close — no sendOnStream(0) is ever attempted.
    const s = try loop.client.connection().openUniStream();
    try testing.expectEqual(@as(u64, 2), s);
    var pre: [8]u8 = undefined;
    quic_wire.writePreface(&pre, .input);
    try loop.client.connection().sendOnStream(s, &pre, false);
    try loop.client.connection().sendOnStream(s, "rogue", false);

    const base: i64 = lib_posix.nowNs();
    try loop.clientPump(base);
    _ = try loop.gw.runOnce(0);

    try testing.expect(sess.closed);
    var dr2 = try quic_test.DaemonReader.init(alloc);
    defer dr2.deinit();
    try testing.expect((try dr2.next(loop.daemon_fd)) == null);
    // No control send side was created on the server.
    const st = try t.connection().streamState(quic_session.control_stream_id);
    try testing.expect(st == null);
}

test "zmq1 session: daemon EOF sends SESSION_END and settles into a code-9 close" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    try zmq1Dance(&z, &dr, base);

    // Pending output plus a REAL daemon close in the same beat: the
    // wired loop reads the buffered `.Output` frame, then EOF, then
    // runs the SESSION_END terminal sequence.
    try ipc.send(z.loop.daemon_fd, .Output, "last-words");
    lib_posix.close(z.loop.daemon_fd);
    z.loop.daemon_fd = -1;

    var end_seen = false;
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    // The real client drains output every turn — before the server's
    // settle-close can make buffered bytes unreadable.
    for (0..12) |i| {
        if (try quic_test.sessionRoundWith(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)), &acc)) |e| {
            if (e == .session_end) end_seen = true;
        }
        while (try z.client.pollControl()) |e| {
            if (e == .session_end) end_seen = true;
        }
        if (sess.closed and end_seen) break;
    }
    try testing.expect(end_seen);
    try testing.expect(sess.closed);
    // The last output bytes reached the client before the end.
    try testing.expect(std.mem.endsWith(u8, acc.items, "last-words"));
}

test "zmq1 relay: DETACH flushes to the daemon and closes cleanly with code 0" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    try zmq1Dance(&z, &dr, base);

    try z.client.sendDetach();
    for (0..12) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));

    // The daemon received the `.Detach` (flushed before the close), and
    // the session settled into a clean code-0 close.
    const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoDetach;
    try testing.expectEqual(ipc.Tag.Detach, f.tag);
    try testing.expect(sess.closed);
    try testing.expectEqual(quic_wire.ErrCode.none.code(), sess.end_code.code());
}

test "zmq1 relay: daemon .Resize is answered with .Resize, never a second .Init" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    var ev: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try z.client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);
    try z.client.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    const init_frame = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try testing.expectEqual(ipc.Tag.InitSnapshot, init_frame.tag);

    // The daemon asks for the client's size (leadership dance). The
    // gateway replies `.Resize` with the LAST CLIENT size — a fresh
    // `.Init` would re-trigger the terminal replay.
    var daemon_size: ipc.Resize = .{ .rows = 10, .cols = 10 };
    try ipc.send(z.loop.daemon_fd, .Resize, std.mem.asBytes(&daemon_size));
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoResizeReply;
    try testing.expectEqual(ipc.Tag.Resize, f.tag);
    const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
    try testing.expectEqual(@as(u16, 24), rz.rows);
    try testing.expectEqual(@as(u16, 80), rz.cols);
    // Exactly ONE `.Init` for the whole session.
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 relay: oversized daemon frame fails closed; a normal frame relays first" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    try zmq1Dance(&z, &dr, base);

    // A normal 4 KiB PTY frame relays fine (the client drains output so
    // the daemon read is not backpressured).
    var pty: [4096]u8 = undefined;
    @memset(&pty, 'p');
    try ipc.send(z.loop.daemon_fd, .Output, &pty);
    var pty_acc: std.ArrayList(u8) = .empty;
    defer pty_acc.deinit(alloc);
    for (0..8) |i| _ = try quic_test.sessionRoundWith(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)), &pty_acc);
    try testing.expectEqual(@as(usize, 4096), pty_acc.items.len);

    // An oversized DECLARED frame — the legacy whole-replay shape — is
    // rejected before payload accumulation and fails the session closed.
    const big = ipc.Header{ .tag = .Output, .len = 10 * 1024 * 1024 };
    const big_bytes = std.mem.toBytes(big);
    _ = try lib_posix.write(z.loop.daemon_fd, &big_bytes);
    var err_ev: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)))) |e| {
            err_ev = e;
            break;
        }
        err_ev = try z.client.pollControl();
        if (err_ev != null) break;
    }
    try testing.expect(err_ev != null);
    switch (err_ev.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(z.loop.gw.daemon_oversized_frames == 1);
    try testing.expect(sess.closedOrEnding());
}

test "zmq1 relay: terminal deadline closes with no fd events (composed timeout)" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    const base: i64 = lib_posix.nowNs();

    var ev: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try z.client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);

    // Terminal state entered, then NO fd is ever ready and the final
    // frame is never ACKed: the one-second composed deadline closes.
    try sess.onDaemonEof(base + 100);
    try testing.expect(z.loop.gw.computePollTimeoutMs() <= 1000);
    const inert = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    _ = try z.loop.gw.processReadyAndDue(base + 100 + quic_session.settle_deadline_ns + 1, inert);
    try testing.expect(sess.closed);
}

test "zmq1 relay: second-client Initial is discarded and the session continues" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    try zmq1Dance(&z, &dr, base);
    const discarded_before = z.loop.gw.quic.counters.datagrams_discarded +
        z.loop.gw.quic.registry.get(1).?.transport.counters.datagrams_discarded;

    // A second client — same PSK, fresh SCID — fires its first Initial
    // at the established gateway: discarded, session unaffected.
    const second = try quic_transport.Transport.createClient(alloc, .{
        .psk = &psk,
        .scid = .{ 0x31, 0x32, 0x33, 0x34 },
        .original_dcid = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 },
    });
    defer second.destroy();
    try second.driveCrypto(.initial, base + 200);
    if (try second.pollOutbound(base + 200)) |dg| {
        defer alloc.free(dg);
        try z.loop.client_sock.sendTo(dg, z.loop.gw_addr);
    }
    _ = try z.loop.gw.runOnce(0);
    // The unknown-CID Initial is discarded at the transport's route
    // layer; the gateway-level counter may also advance.
    const transport_discards = z.loop.gw.quic.registry.get(1).?.transport.counters.datagrams_discarded;
    try testing.expect(transport_discards + z.loop.gw.quic.counters.datagrams_discarded > discarded_before);
    try testing.expect(!sess.closedOrEnding());

    // The established relay still serves input.
    try z.client.sendInput("still-relaying");
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInputAfterSecondClient;
    try testing.expectEqual(ipc.Tag.Input, f.tag);
    try testing.expectEqualStrings("still-relaying", f.payload);
}

test "zmq1 relay: client reset of the input stream ends input without an error" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    try zmq1Dance(&z, &dr, base);

    // RESET_STREAM(input): the gateway observes the reset, stops the
    // input relay, and the session continues (no protocol error).
    try z.client.sendInput("before-reset");
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
    _ = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInputBeforeReset;
    try z.client.transport.connection().resetStream(quic_session.input_stream_id, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    try testing.expect(sess.input_done);
    try testing.expect(!sess.closedOrEnding());
}

// ─── Client driver tests: the socket-owning Q5/Q6 client ───────────

fn driverRound(loop: *quic_test.Loop, driver: *quic_client.Client, now: i64) !?quic_client.ControlEvent {
    const ev = try driver.pump(now);
    _ = try loop.gw.runOnce(0);
    return ev;
}

/// Driver-side Q4 installation after the daemon saw `.InitSnapshot`:
/// one EMPTY daemon transaction, the stream-7 header and FIN OBSERVED
/// through the driver's own transport, then the crafted
/// SNAPSHOT_INSTALLED. The gateway session reaches active.
fn driverInstall(loop: *quic_test.Loop, driver: *quic_client.Client) !void {
    try quic_test.daemonSendEmptySnapshot(loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try driverRound(loop, driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(driver.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try quic_test.sendSnapshotInstalledOn(driver.transport);
    for (0..8) |i| _ = try driverRound(loop, driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
}

test "client driver: IPv4 connect, full round trip, peer close visible" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
    defer driver.deinit();

    // Handshake + HELLO_ACK through the driver's own pump.
    var ack: ?quic_client.ControlEvent = null;
    for (0..80) |i| {
        ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (ack != null) break;
    }
    try testing.expect(ack != null);
    try testing.expect(ack.? == .hello_ack);
    try testing.expect(driver.handshakeConfirmed());

    // RESIZE → .InitSnapshot → empty transaction observed on stream 7
    // with FIN → SNAPSHOT_INSTALLED; then input and output flow.
    try driver.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    const init_frame = (try dr.next(loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try testing.expectEqual(ipc.Tag.InitSnapshot, init_frame.tag);
    try quic_test.daemonSendEmptySnapshot(loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(driver.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try quic_test.sendSnapshotInstalledOn(driver.transport);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));

    try driver.sendInput("driver-input");
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    {
        const f = (try dr.next(loop.daemon_fd)) orelse return error.NoDriverInput;
        try testing.expectEqualStrings("driver-input", f.payload);
    }

    try ipc.send(loop.daemon_fd, .Output, "driver-output");
    var got: []const u8 = "";
    for (0..8) |i| {
        _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        var obuf: [64]u8 = undefined;
        if (try driver.pollOutput(&obuf)) |n| {
            got = obuf[0..n];
            break;
        }
    }
    try testing.expectEqualStrings("driver-output", got);

    // Daemon EOF: the SESSION_END terminal is surfaced by pump across
    // the settle-close race, and the APPLICATION close (code 9) is
    // visible distinctly from a transport close.
    lib_posix.close(loop.daemon_fd);
    loop.daemon_fd = -1;
    var end_seen = false;
    for (0..16) |i| {
        if (try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)))) |e| {
            if (e == .session_end) end_seen = true;
        }
        if (end_seen) break;
    }
    try testing.expect(end_seen);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    const pc = driver.peerClose();
    try testing.expect(pc != null);
    try testing.expect(pc.?.kind == .application);
    try testing.expectEqual(quic_wire.ErrCode.session_ended.code(), pc.?.code);
}

test "client driver: native IPv6 socket" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, true);
    defer loop.deinit();

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
    defer driver.deinit();
    try testing.expect(driver.sock.bound_port != 0);

    var ack: ?quic_client.ControlEvent = null;
    for (0..64) |i| {
        ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (ack != null) break;
    }
    try testing.expect(ack != null);
    try testing.expect(ack.? == .hello_ack);
}

test "client driver: handshake timeout enforced in pump, not just the deadline" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    // No gateway at all: the HELLO goes nowhere.
    var gw_sock = try udp.UdpSocket.bind(60400, 60500);
    defer gw_sock.close();
    const gw_addr = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, gw_sock.bound_port);

    const anchor: i64 = 1_000_000;
    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, gw_addr, anchor);
    defer driver.deinit();

    // Before expiry: no event.
    try testing.expect((try driver.pump(anchor + 100)) == null);
    // At expiry: the failure event is produced — the loop can never
    // busy-spin on a passed deadline.
    const ev = try driver.pump(anchor + quic_client.handshake_deadline_ns + 1);
    try testing.expect(ev != null);
    switch (ev.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.session_ended.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(driver.session.ended());
}

test "client driver: per-pump inbound bound" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var gw_sock = try udp.UdpSocket.bind(60400, 60500);
    defer gw_sock.close();
    const gw_addr = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, gw_sock.bound_port);

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, gw_addr, 1_000_000);
    defer driver.deinit();

    // Junk-flood the client's socket beyond the per-pump bound: one
    // pump processes at most 64 inbound datagrams.
    var flooder = try udp.UdpSocket.bind(60600, 60700);
    defer flooder.close();
    var junk: [64]u8 = undefined;
    @memset(&junk, 0);
    junk[0] = 0x40;
    const junk_addr = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, driver.sock.bound_port);
    for (0..80) |_| try flooder.sendTo(&junk, junk_addr);

    _ = try driver.pump(1_000_100);
    // At least 80 − 64 datagrams remain unconsumed.
    var left: usize = 0;
    var probe: [64]u8 = undefined;
    while (true) {
        _ = driver.sock.recvFrom(&probe) catch break;
        left += 1;
    }
    try testing.expect(left >= 16);
}

// ─── r7 correction proofs: session/relay ───────────────────────────

fn countUnimplemented(e: quic_client.ControlEvent) usize {
    return switch (e) {
        .err => |er| if (er.code == quic_wire.ErrCode.unimplemented.code()) 1 else 0,
        else => 0,
    };
}

/// Drives a session to the active phase and consumes the `.Init`.
fn zmq1ToActive(z: anytype, dr: *quic_test.DaemonReader, base: i64) !void {
    return zmq1Dance(z, dr, base);
}

test "zmq1 r7: control responses survive exhausted credit, computed request count" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // COMPUTED count: each response is header 8 + ERROR payload
    // (4 + "replacement snapshots are Q5".len = 32) = 40 B; the
    // preface (8) already left. Requests that exhaust the 2 KiB
    // control credit, plus slack.
    const response_len = quic_wire.control_header_len + 4 + "replacement snapshots are Q5".len;
    const requests = quic_transport.stream_credit / response_len + 8;

    // The client does NOT read control (raw drain) so responses pile
    // up unread: the server's control credit exhausts, ONE response
    // parks whole, and parsing stops with the rest held in the stash.
    for (0..requests) |_| try z.client.sendSnapshotRequest();
    for (0..10) |i| {
        try z.loop.clientPump(base + 200 + @as(i64, @intCast(i)));
        _ = try z.loop.gw.runOnce(0);
        try z.loop.clientDrain(base + 200 + @as(i64, @intCast(i)));
    }
    try testing.expect(sess.pending_control.items.len != 0);
    try testing.expect(sess.control_stash.items.len != 0);

    // Recovery: the client drains and ACKs — EVERY response arrives,
    // none dropped, none duplicated, framing intact.
    var seen: usize = 0;
    for (0..32) |i| {
        const now = base + 300 + @as(i64, @intCast(i));
        try z.loop.clientPump(now);
        _ = try z.loop.gw.runOnce(0);
        try z.loop.clientDrainFor(z.loop.client, now);
        while (try z.client.pollControl()) |e| {
            seen += countUnimplemented(e);
        }
        if (seen == requests) break;
    }
    try testing.expectEqual(requests, seen);
    try testing.expect(!sess.closedOrEnding());
}

test "zmq1 r7: terminal replacement of a parked response keeps framing whole" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    const response_len = quic_wire.control_header_len + 4 + "replacement snapshots are Q5".len;
    const requests = quic_transport.stream_credit / response_len + 8;
    for (0..requests) |_| try z.client.sendSnapshotRequest();
    for (0..10) |i| {
        try z.loop.clientPump(base + 200 + @as(i64, @intCast(i)));
        _ = try z.loop.gw.runOnce(0);
        try z.loop.clientDrain(base + 200 + @as(i64, @intCast(i)));
    }
    try testing.expect(sess.pending_control.items.len != 0);

    // A terminal frame REPLACES the parked (never sent) response: the
    // unsent preface is preserved and the client's control stream
    // decodes cleanly — no protocol violation surfaces client-side.
    try z.client.sendDetach();
    var malformed = false;
    var detach_seen = false;
    for (0..24) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
        while (try z.client.pollControl()) |e| {
            switch (e) {
                .err => |er| {
                    if (er.code == quic_wire.ErrCode.protocol_violation.code()) malformed = true;
                },
                else => {},
            }
        }
        if (sess.closed) detach_seen = true;
        if (detach_seen and z.client.connectionClosed()) break;
    }
    try testing.expect(!malformed);
    try testing.expect(sess.closed);
}

test "zmq1 r7: output-credit backpressure by credit math, exact resumption" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // 3 KiB of daemon output against the 2 KiB (+16 header) window,
    // with the client reading NOTHING: the gateway sends exactly the
    // window and retains the tail in the bounded pending buffer. All
    // three frames fit the 64 KiB buffer, so the frame-aware read
    // gate stays ELIGIBLE — output backpressure never blocks the
    // daemon fd (the Q4 anti-starvation property).
    var chunk: [1024]u8 = undefined;
    @memset(&chunk, 'o');
    for (0..3) |_| try ipc.send(z.loop.daemon_fd, .Output, &chunk);
    for (0..8) |i| {
        try z.loop.clientPump(base + 200 + @as(i64, @intCast(i)));
        _ = try z.loop.gw.runOnce(0);
        try z.loop.clientDrain(base + 200 + @as(i64, @intCast(i)));
    }
    try testing.expect(z.loop.gw.daemonReadEligible());
    try testing.expectEqual(3 * 1024 + quic_wire.output_header_len - quic_transport.stream_credit, sess.pending_output.items.len);
    const sent_at_window = sess.counters.output_bytes;

    // The client drains: credit returns, the tail leaves, and the
    // total is exact.
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    for (0..12) |i| {
        _ = try quic_test.sessionRoundWith(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)), &acc);
        if (sess.pending_output.items.len == 0) break;
    }
    try testing.expectEqual(@as(usize, 3 * 1024 + 16), sess.counters.output_bytes);
    try testing.expect(sent_at_window <= quic_transport.stream_credit + 16);
    try testing.expectEqual(@as(usize, 3 * 1024), acc.items.len);
    try testing.expect(sess.pending_output.items.len == 0);
    try testing.expect(z.loop.gw.daemonReadEligible());
}

test "zmq1 r7: zero-capacity input backpressure with POLL.OUT recovery" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // Fill the daemon-bound buffer to its cap (the daemon "hasn't
    // read" — nothing flushes because POLL.OUT only fires through a
    // gateway turn we control with inert fds).
    var filler: [4096]u8 = undefined;
    @memset(&filler, 'f');
    while (z.loop.gw.unix_out.list.items.len + 4104 <= quic_session.unix_write_cap) {
        try z.loop.gw.unix_out.append(.Input, &filler);
    }
    try testing.expect(!z.loop.gw.unix_out.empty());

    // Input arrives but is NOT consumed beyond the preface: the
    // stream-2 read offset stays frozen and the body's credit is
    // withheld — no loss, no drop.
    // Synthetic fds: the UDP arm delivers the datagram, the daemon
    // arms stay inert so nothing flushes and the buffer stays full.
    const deliver_fds = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = lib_posix.POLL.IN },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    try z.client.sendInput("blocked-input");
    var before: u64 = 0;
    for (0..6) |i| {
        const now = base + 200 + @as(i64, @intCast(i));
        try z.loop.clientPump(now);
        _ = try z.loop.gw.processReadyAndDue(now, deliver_fds);
        try z.loop.clientDrain(now);
        const st = (try sess.transport.connection().streamState(quic_session.input_stream_id)) orelse return error.NoStreamState;
        before = st.receive_read_offset orelse 0;
    }
    try testing.expect(before == quic_wire.preface_len);
    for (0..4) |i| {
        const now = base + 260 + @as(i64, @intCast(i));
        try z.loop.clientPump(now);
        _ = try z.loop.gw.processReadyAndDue(now, deliver_fds);
        try z.loop.clientDrain(now);
        const st = (try sess.transport.connection().streamState(quic_session.input_stream_id)) orelse return error.NoStreamState;
        try testing.expectEqual(before, st.receive_read_offset orelse 0);
    }

    // POLL.OUT flushes to the daemon; capacity returns; the withheld
    // input flows — strictly after the filler frames.
    var saw_blocked_early = false;
    const out_revents = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = lib_posix.POLL.OUT },
    };
    var flushed = false;
    for (0..40) |_| {
        _ = try z.loop.gw.processReadyAndDue(base + 300, out_revents);
        while (try dr.next(z.loop.daemon_fd)) |f| {
            if (f.tag == .Input and std.mem.eql(u8, f.payload, "blocked-input")) saw_blocked_early = true;
        }
        if (z.loop.gw.unix_out.empty()) {
            flushed = true;
            break;
        }
    }
    try testing.expect(flushed);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 400 + @as(i64, @intCast(i)));
    var saw_blocked = false;
    while (try dr.next(z.loop.daemon_fd)) |f| {
        if (f.tag == .Input and std.mem.eql(u8, f.payload, "blocked-input")) saw_blocked = true;
    }
    try testing.expect(saw_blocked or saw_blocked_early);
}

test "zmq1 r7: withheld-HELLO_ACK output parking (positive)" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();

    // Deliver everything with the RAW drain: the HELLO_ACK and the
    // output header sit unread while the session is unauthorized.
    for (0..10) |i| {
        try z.loop.clientPump(base + @as(i64, @intCast(i)));
        _ = try z.loop.gw.runOnce(0);
        try z.loop.clientDrain(base + @as(i64, @intCast(i)));
    }

    // Output polled BEFORE control: the parking gate refuses without
    // consuming — the bytes stay in QUIC, credit withheld.
    var obuf: [64]u8 = undefined;
    var epoch: u64 = 0;
    try testing.expect((try z.client.pollOutput(&obuf, &epoch)) == null);
    try testing.expect(z.client.output_hdr.remaining() > 0);
    {
        const st3 = (try z.client.transport.connection().streamState(quic_client.output_stream_id)) orelse return error.NoOutputStream;
        try testing.expectEqual(@as(u64, 0), st3.receive_read_offset orelse 0);
    }

    // HELLO_ACK validates → the parked output surfaces in order.
    const ev = try z.client.pollControl();
    try testing.expect(ev != null and ev.? == .hello_ack);
    _ = try z.client.pollOutput(&obuf, &epoch);
    try testing.expectEqual(@as(u64, 1), epoch);
}

test "zmq1 r7: pre-HELLO input violation with stream 0 present takes the ERROR+FIN arm" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);
    _ = try loop.gw.runOnce(0);
    const sess = if (loop.gw.session) |*x| x else return error.NoSession;
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    // A control preface exists on stream 0 (the framed arm), AND
    // input data arrives in the same flight — before HELLO.
    const cconn = loop.client.connection();
    _ = try cconn.openStream();
    var pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&pre, .control);
    _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);
    const s2 = try cconn.openUniStream();
    try testing.expectEqual(@as(u64, 2), s2);
    var ipre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&ipre, .input);
    _ = try cconn.sendOnStream(s2, &ipre, false);
    _ = try cconn.sendOnStream(s2, "early", false);

    const base: i64 = lib_posix.nowNs();
    try loop.clientPump(base);
    _ = try loop.gw.runOnce(0);

    // The framed arm: an ERROR(protocol_violation) with FIN reaches
    // the client (not a bare close), and no `.Init` was ever written.
    try testing.expect(sess.closedOrEnding());
    try testing.expect((try dr.next(loop.daemon_fd)) == null);
    var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
    defer client.deinit();
    var err_seen = false;
    for (0..10) |i| {
        try loop.clientPump(base + 100 + @as(i64, @intCast(i)));
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(base + 100 + @as(i64, @intCast(i)));
        while (try client.pollControl()) |e| {
            switch (e) {
                .err => |er| {
                    try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), er.code);
                    err_seen = true;
                },
                else => {},
            }
        }
        if (err_seen) break;
    }
    try testing.expect(err_seen);
}

test "zmq1 r7: stopSending(output) is observed and ends the session cleanly" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // The client stops the output stream; the gateway observes it on
    // the next send attempt (daemon output must exist to attempt one)
    // and ends the session with session_ended.
    try ipc.send(z.loop.daemon_fd, .Output, "tail");
    try z.client.transport.connection().stopSending(quic_session.output_stream_id, quic_wire.ErrCode.session_ended.code());
    var end_seen = false;
    for (0..16) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)))) |e| {
            if (e == .session_end) end_seen = true;
        }
        while (try z.client.pollControl()) |e| {
            if (e == .session_end) end_seen = true;
        }
        if (end_seen) break;
    }
    try testing.expect(end_seen);
    // The stopped output FIN counts as done; the control settle (or
    // the 1 s bound, driven here) completes the close.
    const inert = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    for (0..4) |_| {
        if (sess.closed) break;
        _ = try z.loop.gw.processReadyAndDue(base + 10 * quic_session.settle_deadline_ns, inert);
    }
    try testing.expect(sess.closed);
}

test "zmq1 r7: coalesced daemon frames stop after .Switch enters terminal" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // .Switch and .Resize coalesce in one batch: the terminal .Switch
    // ends processing — the later .Resize gets NO reply.
    try ipc.send(z.loop.daemon_fd, .Switch, "");
    var daemon_size: ipc.Resize = .{ .rows = 10, .cols = 10 };
    try ipc.send(z.loop.daemon_fd, .Resize, std.mem.asBytes(&daemon_size));
    const now = lib_posix.nowNs();
    try z.loop.clientPump(now);
    _ = try z.loop.gw.runOnce(0);
    try z.loop.clientDrain(now);

    try testing.expect(sess.closedOrEnding());
    // No `.Resize` reply was written after the terminal frame.
    var switch_replies: usize = 0;
    while (try dr.next(z.loop.daemon_fd)) |f| {
        if (f.tag == .Resize) switch_replies += 1;
    }
    try testing.expectEqual(@as(usize, 0), switch_replies);
}

test "zmq1 r7: a permanent daemon write error fails closed" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // Pending daemon-bound writes + a dead daemon socket: the flush's
    // permanent error must stop the gateway — POLL.OUT can never arm
    // again in a busy loop.
    var filler: [512]u8 = undefined;
    @memset(&filler, 'w');
    try z.loop.gw.unix_out.append(.Input, &filler);
    lib_posix.close(z.loop.daemon_fd);
    z.loop.daemon_fd = -1;

    const out_revents = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = lib_posix.POLL.OUT },
    };
    for (0..3) |_| {
        _ = try z.loop.gw.processReadyAndDue(base + 200, out_revents);
    }
    try testing.expect(!z.loop.gw.running);
}

test "zmq1 r7: deterministic drop and PTO recovery of lost daemon output" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // The datagram carrying daemon output is READ OFF THE WIRE AND
    // DISCARDED (a deterministic drop) — a mid-session loss with no
    // settle deadline racing the recovery.
    try ipc.send(z.loop.daemon_fd, .Output, "lost-then-recovered");
    try z.loop.clientPump(base + 200);
    _ = try z.loop.gw.runOnce(0);
    {
        var drop_buf: [quic_transport.max_udp_payload]u8 = undefined;
        var dropped: usize = 0;
        while (true) {
            _ = z.loop.client_sock.recvFrom(&drop_buf) catch break;
            dropped += 1;
        }
        try testing.expect(dropped > 0);
    }

    // PTO retransmission under synthetic time recovers the frame; the
    // client's ACKs flow back through clientPump.
    var acc: std.ArrayList(u8) = .empty;
    defer acc.deinit(alloc);
    const inert = [3]lib_posix.pollfd{
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
        .{ .fd = 0, .events = 0, .revents = 0 },
    };
    var step: usize = 0;
    while (step < 60) : (step += 1) {
        const now = base + 300 + @as(i64, @intCast(step)) * @divTrunc(std.time.ns_per_s, 4);
        _ = try z.loop.gw.processReadyAndDue(now, inert);
        try z.loop.clientPump(now);
        try z.loop.clientDrain(now);
        var ob: [256]u8 = undefined;
        while (try z.client.pollOutput(&ob, null)) |n| {
            try acc.appendSlice(alloc, ob[0..n]);
        }
        if (std.mem.endsWith(u8, acc.items, "lost-then-recovered")) break;
    }
    try testing.expectEqualStrings("lost-then-recovered", acc.items);
}

test "zmq1 r7: duplicated and reordered client datagrams deliver exactly once" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // Send input; drain EVERY pending client datagram to the wire and
    // duplicate the last (which carries the input): duplication plus
    // reordering must still deliver the payload exactly once.
    try z.client.sendInput("dup-once");
    var last: ?[]u8 = null;
    defer if (last) |dg| alloc.free(dg);
    for (0..8) |_| {
        const dg = (try z.loop.client.pollOutbound(base + 200)) orelse break;
        try z.loop.client_sock.sendTo(dg, z.loop.gw_addr);
        if (last) |prev| alloc.free(prev);
        last = dg;
    }
    try testing.expect(last != null);
    try z.loop.client_sock.sendTo(last.?, z.loop.gw_addr);
    try z.loop.client_sock.sendTo(last.?, z.loop.gw_addr);

    // One turn receives and relays; a second flushes the daemon write.
    _ = try z.loop.gw.runOnce(0);
    _ = try z.loop.gw.runOnce(0);
    try z.loop.clientDrain(base + 200);

    var copies: usize = 0;
    while (try dr.next(z.loop.daemon_fd)) |f| {
        if (f.tag == .Input and std.mem.eql(u8, f.payload, "dup-once")) copies += 1;
    }
    try testing.expectEqual(@as(usize, 1), copies);
}

test "zmq1 r7: replayed FIRST Initial is discarded with the session intact" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();

    // Hand-roll the first flight so the exact first Initial bytes are
    // captured before the exchange proceeds.
    const t0: i64 = lib_posix.nowNs();
    try loop.client.driveCrypto(.initial, t0);
    const first = (try loop.client.pollOutbound(t0)) orelse return error.NoFirstInitial;
    defer alloc.free(first);
    try loop.client_sock.sendTo(first, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    try loop.clientDrain(t0);
    try quic_test.driveHandshake(&loop);
    _ = try loop.gw.runOnce(0);
    const sess = if (loop.gw.session) |*x| x else return error.NoSession;
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    var client = try quic_client.ClientSession.init(alloc, loop.client);
    defer client.deinit();
    var ev: ?quic_client.ControlEvent = null;
    for (0..16) |i| {
        if (try quic_test.sessionRound(&loop, &client, t0 + 100 + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);
    try client.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try quic_test.sessionRound(&loop, &client, t0 + 200 + @as(i64, @intCast(i)));
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInit;

    // Replay the captured FIRST Initial: discarded at the committed
    // slot, the established session is untouched.
    const discarded_before = loop.gw.quic.counters.datagrams_discarded +
        loop.gw.quic.registry.get(1).?.transport.counters.datagrams_discarded;
    try loop.client_sock.sendTo(first, loop.gw_addr);
    _ = try loop.gw.runOnce(0);
    const discarded_after = loop.gw.quic.counters.datagrams_discarded +
        loop.gw.quic.registry.get(1).?.transport.counters.datagrams_discarded;
    try testing.expect(discarded_after > discarded_before);
    try testing.expect(!sess.closedOrEnding());

    // The relay still serves input afterwards.
    try client.sendInput("post-replay");
    for (0..8) |i| _ = try quic_test.sessionRound(&loop, &client, t0 + 300 + @as(i64, @intCast(i)));
    const f = (try dr.next(loop.daemon_fd)) orelse return error.NoPostReplayInput;
    try testing.expectEqualStrings("post-replay", f.payload);
}

test "zmq1 r7: HELLO mode 2 is unimplemented and mode 3 is a protocol violation" {
    const alloc = testing.allocator;
    const cases = [_]struct { mode: u8, code: u32 }{
        .{ .mode = 2, .code = quic_wire.ErrCode.unimplemented.code() },
        .{ .mode = 3, .code = quic_wire.ErrCode.protocol_violation.code() },
    };
    for (cases) |c| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        try quic_test.driveHandshake(&loop);
        _ = try loop.gw.runOnce(0);

        var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
        defer client.deinit();
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);
        var hello = quic_wire.Hello.serverV1(c.mode);
        var payload: [quic_wire.hello_payload_len]u8 = undefined;
        hello.encode(&payload);
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .hello, payload.len, 0);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &hdr, false);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &payload, false);

        const base: i64 = lib_posix.nowNs();
        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            if (try quic_test.sessionRound(&loop, &client, base + @as(i64, @intCast(i)))) |e| {
                err_ev = e;
                break;
            }
            err_ev = try client.pollControl();
            if (err_ev != null) break;
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(c.code, e.code),
            else => return error.TestUnexpectedResult,
        }
    }
}

test "zmq1 r7: unexpected uni stream 6 and a wrong-role preface are rejected" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const sess = try z.session();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // A SECOND uni stream (id 6) with an input preface: rejected by
    // the id scan as stream_cardinality. (Stream 2 opens first.)
    try z.client.sendInput("first-stream");
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
    const cconn = z.client.transport.connection();
    const s6 = try cconn.openUniStream();
    try testing.expectEqual(@as(u64, 6), s6);
    var pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&pre, .input);
    _ = try cconn.sendOnStream(s6, &pre, false);

    var err_ev: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)))) |e| {
            err_ev = e;
            break;
        }
        err_ev = try z.client.pollControl();
        if (err_ev != null) break;
    }
    try testing.expect(err_ev != null);
    switch (err_ev.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.stream_cardinality.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(sess.closedOrEnding());
}

test "zmq1 r7: split header first, tail and body together next delivery" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    // HELLO first (manual, silent client), then the SPLIT RESIZE.
    var client = try quic_client.ClientSession.initSilent(alloc, z.loop.client);
    defer client.deinit();
    var ev: ?quic_client.ControlEvent = null;
    for (0..16) |i| {
        _ = try z.loop.clientPump(base + @as(i64, @intCast(i)));
        _ = try z.loop.gw.runOnce(0);
        try z.loop.clientDrain(base + @as(i64, @intCast(i)));
        ev = try client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);

    // Delivery 1: the first FOUR bytes of the RESIZE header.
    // Delivery 2: the header tail PLUS a complete SNAPSHOT_REQUEST —
    // the exact regression shape.
    const cconn = z.loop.client.connection();
    var frame: [quic_wire.control_header_len + 8]u8 = undefined;
    quic_wire.writeControlHeader(frame[0..8], .resize, 8, 0);
    quic_wire.writeResizePayload(frame[8..16], 31, 91, 0, 0);
    _ = try cconn.sendOnStream(quic_client.control_stream_id, frame[0..4], false);
    const now1: i64 = lib_posix.nowNs();
    try z.loop.clientPump(now1);
    _ = try z.loop.gw.runOnce(0);
    try z.loop.clientDrain(now1);

    var snap_hdr: [quic_wire.control_header_len]u8 = undefined;
    quic_wire.writeControlHeader(&snap_hdr, .snapshot_request, 0, 0);
    var tail_and_next: [4 + 8 + quic_wire.control_header_len]u8 = undefined;
    @memcpy(tail_and_next[0..4], frame[4..8]);
    @memcpy(tail_and_next[4..12], frame[8..16]);
    @memcpy(tail_and_next[12..], &snap_hdr);
    _ = try cconn.sendOnStream(quic_client.control_stream_id, &tail_and_next, false);
    var errs_from_rounds: usize = 0;
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &client, now1 + 100 + @as(i64, @intCast(i)))) |e| {
            if (e == .err) errs_from_rounds += 1;
        }
    }

    // The split RESIZE completed (.InitSnapshot with 31x91) and the
    // coalesced SNAPSHOT_REQUEST was answered — both frames from one
    // delivery. Under Q4 that request arrives mid-installation, so the
    // answer is a terminal protocol_violation ERROR rather than the
    // nonterminal Q5 deferral.
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoSplitInit;
        try testing.expectEqual(ipc.Tag.InitSnapshot, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 31), rz.rows);
        try testing.expectEqual(@as(u16, 91), rz.cols);
    }
    var errs: usize = errs_from_rounds;
    while (try client.pollControl()) |e| {
        if (e == .err) errs += 1;
    }
    try testing.expect(errs >= 1);
}

test "zmq1 r7: allocation failure cannot lose consumed input" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    // Every allocation after setup FAILS: the input→UnixWriteBuf path
    // must still relay — its capacity is reserved at init.
    var fail_alloc = std.testing.FailingAllocator.init(alloc, .{ .fail_index = std.math.maxInt(usize) });
    var loop = try quic_test.Loop.init(fail_alloc.allocator(), &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);
    _ = try loop.gw.runOnce(0);
    fail_alloc.fail_index = 0;

    var client = try quic_client.ClientSession.init(alloc, loop.client);
    defer client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    var ev: ?quic_client.ControlEvent = null;
    for (0..16) |i| {
        _ = try loop.clientPump(base + @as(i64, @intCast(i)));
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(base + @as(i64, @intCast(i)));
        ev = try client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);
    try client.sendResize(24, 80, 0, 0);
    for (0..8) |i| {
        const now = base + 100 + @as(i64, @intCast(i));
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(now);
    }
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInit;

    try client.sendInput("no-alloc-loss");
    for (0..8) |i| {
        const now = base + 200 + @as(i64, @intCast(i));
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(now);
    }
    const f = (try dr.next(loop.daemon_fd)) orelse return error.NoInput;
    try testing.expectEqualStrings("no-alloc-loss", f.payload);
}

test "zmq1 r7: server rejects non-empty DETACH and SNAPSHOT_REQUEST payloads" {
    const alloc = testing.allocator;
    const cases = [_]quic_wire.ControlType{ .detach, .snapshot_request };
    for (cases) |case| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToActive(&z, &dr, base);

        // A crafted frame with a NON-EMPTY payload where empty is
        // frozen: protocol_violation.
        const cconn = z.client.transport.connection();
        var frame: [quic_wire.control_header_len + 4]u8 = undefined;
        quic_wire.writeControlHeader(frame[0..8], case, 4, 0);
        @memset(frame[8..12], 'x');
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &frame, false);

        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            if (try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)))) |e| {
                err_ev = e;
                break;
            }
            err_ev = try z.client.pollControl();
            if (err_ev != null) break;
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code),
            else => return error.TestUnexpectedResult,
        }
    }
}

// ─── r7 correction proofs: client validation of crafted server frames ──

/// Writes one crafted server→client control frame on the gateway's
/// side of stream 0 (bypassing the session's own egress).
fn craftServerControl(loop: *quic_test.Loop, frames: []const []const u8) !void {
    const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
    for (frames) |f| {
        try t.connection().sendOnStream(quic_client.control_stream_id, f, false);
    }
}

fn serverControlRound(loop: *quic_test.Loop, client: *quic_client.ClientSession, base: i64, i: usize) !?quic_client.ControlEvent {
    const now = base + @as(i64, @intCast(i));
    try loop.clientPump(now);
    _ = try loop.gw.runOnce(0);
    try loop.clientDrain(now);
    return client.pollControl();
}

test "zmq1 r7: client HELLO_ACK matrix — version, capability, fingerprint, mode, limits" {
    const alloc = testing.allocator;
    const Kind = enum { version, capability, fingerprint, mode, limits };
    const cases = [_]struct { kind: Kind, code: u32 }{
        .{ .kind = .version, .code = quic_wire.ErrCode.version_mismatch.code() },
        .{ .kind = .capability, .code = quic_wire.ErrCode.capability_mismatch.code() },
        .{ .kind = .fingerprint, .code = quic_wire.ErrCode.fingerprint_mismatch.code() },
        .{ .kind = .mode, .code = quic_wire.ErrCode.protocol_violation.code() },
        .{ .kind = .limits, .code = quic_wire.ErrCode.protocol_violation.code() },
    };
    for (cases) |c| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        try quic_test.driveHandshake(&loop);

        // The client's HELLO is silent-crafted; the server's ACK is
        // CRAFTED with one bad field.
        var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
        defer client.deinit();
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        // ONLY the preface reaches the gateway: the stream's server
        // send side comes into existence while the gateway session
        // stays in awaiting_hello (no HELLO_ACK of its own to fight
        // the crafted frames).
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);

        var ack = quic_wire.Hello.serverV1(quic_wire.mode_attach);
        switch (c.kind) {
            .version => ack.version_major = 2,
            .capability => ack.required_capabilities = 0x1E,
            .fingerprint => ack.snapshot_abi_id[0] ^= 0xFF,
            .mode => ack.mode = 9,
            .limits => ack.snapshot_limit = quic_wire.snapshot_limit_v1 + 1,
        }
        var ack_payload: [quic_wire.hello_payload_len]u8 = undefined;
        ack.encode(&ack_payload);
        var ack_hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&ack_hdr, .hello_ack, ack_payload.len, 0);
        var ack_pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&ack_pre, .control);
        const base: i64 = lib_posix.nowNs();
        // The client's HELLO must REACH the gateway before the server
        // can write stream 0 (the send side comes into existence with
        // the client's first stream bytes).
        try loop.clientPump(base);
        _ = try loop.gw.runOnce(0);
        try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload });
        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            err_ev = try serverControlRound(&loop, &client, base, i);
            if (err_ev != null) break;
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(c.code, e.code),
            else => return error.TestUnexpectedResult,
        }
        try testing.expect(client.ended());
    }
}

test "zmq1 r7: client rejects duplicate HELLO_ACK, oversized ERROR reason, illegal server frame" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
    defer client.deinit();
    const cconn = client.transport.connection();
    _ = try cconn.openStream();
    // Preface only (see the HELLO_ACK matrix test for why).
    var pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&pre, .control);
    _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);

    // A VALID ack, then a DUPLICATE.
    var ack = quic_wire.Hello.serverV1(quic_wire.mode_attach);
    var ack_payload: [quic_wire.hello_payload_len]u8 = undefined;
    ack.encode(&ack_payload);
    var ack_hdr: [quic_wire.control_header_len]u8 = undefined;
    quic_wire.writeControlHeader(&ack_hdr, .hello_ack, ack_payload.len, 0);
    var ack_pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&ack_pre, .control);
    const base: i64 = lib_posix.nowNs();
    try loop.clientPump(base);
    _ = try loop.gw.runOnce(0);
    try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload, &ack_hdr, &ack_payload });

    var got_ack = false;
    var err_ev: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try serverControlRound(&loop, &client, base, i)) |e| {
            if (e == .hello_ack and !got_ack) {
                got_ack = true;
                continue;
            }
            err_ev = e;
            break;
        }
    }
    try testing.expect(got_ack);
    try testing.expect(err_ev != null);
    switch (err_ev.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
}

test "zmq1 r8: protocol-state transition matrix — legal and illegal operations per state" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();

    // ── awaiting_ack: every send API is rejected; output is parked ──
    try testing.expectEqual(quic_client.StateTag.awaiting_ack, z.client.stateTag());
    try testing.expectError(error.NotActive, z.client.sendResize(24, 80, 0, 0));
    try testing.expectError(error.NotActive, z.client.sendInput("x"));
    try testing.expectError(error.NotActive, z.client.sendDetach());
    try testing.expectError(error.NotActive, z.client.sendSnapshotRequest());
    var obuf: [64]u8 = undefined;
    var epoch: u64 = 0;
    try testing.expect((try z.client.pollOutput(&obuf, &epoch)) == null);
    try testing.expectEqual(quic_client.StateTag.awaiting_ack, z.client.stateTag());

    // ── valid HELLO_ACK → awaiting_first_resize ──
    try zmq1ToActive0(&z);
    try testing.expectEqual(quic_client.StateTag.awaiting_first_resize, z.client.stateTag());
    // Input and every non-first control frame stay rejected; the
    // first RESIZE alone advances.
    try testing.expectError(error.NotActive, z.client.sendInput("x"));
    try testing.expectError(error.NotActive, z.client.sendDetach());
    try testing.expectError(error.NotActive, z.client.sendSnapshotRequest());
    // Output is authorized now: the header consumed, epoch reported.
    try testing.expect((try z.client.pollOutput(&obuf, &epoch)) == null);
    try testing.expectEqual(@as(u64, 1), epoch);

    // ── first RESIZE accepted → (client FSM) active; the GATEWAY now
    //    runs the Q4 installation before it reaches its own active ──
    try z.client.sendResize(24, 80, 0, 0);
    try testing.expectEqual(quic_client.StateTag.active, z.client.stateTag());
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    _ = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try quic_test.daemonSendEmptySnapshot(z.loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    const gw = try z.session();
    for (0..8) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 180 + @as(i64, @intCast(i)));
        if (gw.phase == .active) break;
    }
    try testing.expect(gw.phase == .active);
    try testing.expectEqual(quic_client.StateTag.active, z.client.stateTag());
    // Ordinary frames stay legal in active; an ordinary RESIZE does
    // not re-trigger anything.
    try z.client.sendResize(30, 90, 0, 0);
    try z.client.sendSnapshotRequest();
    try z.client.sendInput("matrix-input");
    try testing.expectEqual(quic_client.StateTag.active, z.client.stateTag());
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));

    // ── terminal SESSION_END (daemon EOF) → draining: no new sends,
    //    output stays readable ──
    // Consume every relayed frame first: an unread daemon socket
    // would make the terminal flush fail closed (internal_error)
    // instead of settling with SESSION_END.
    while (try dr.next(z.loop.daemon_fd)) |_| {}
    lib_posix.close(z.loop.daemon_fd);
    z.loop.daemon_fd = -1;
    var end_seen = false;
    for (0..16) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)))) |e| {
            if (e == .session_end) end_seen = true;
        }
        if (end_seen) break;
    }
    try testing.expect(end_seen);
    try testing.expectEqual(quic_client.StateTag.draining, z.client.stateTag());
    try testing.expectError(error.NotActive, z.client.sendResize(24, 80, 0, 0));
    try testing.expectError(error.NotActive, z.client.sendInput("x"));
    try testing.expectError(error.NotActive, z.client.sendDetach());
    try testing.expectError(error.NotActive, z.client.sendSnapshotRequest());
    // Draining keeps the output side readable (null, not an error —
    // the terminal control frame never strands output).
    try testing.expect((try z.client.pollOutput(&obuf, null)) == null);
    try testing.expectEqual(quic_client.StateTag.draining, z.client.stateTag());
}

/// The hello_ack-only prefix of zmq1ToActive (the matrix test drives
/// the first RESIZE itself to observe the transition).
fn zmq1ToActive0(z: anytype) !void {
    var ev: ?quic_client.ControlEvent = null;
    const base: i64 = lib_posix.nowNs();
    for (0..8) |i| {
        if (try quic_test.sessionRound(&z.loop, &z.client, base + @as(i64, @intCast(i)))) |e| {
            ev = e;
            break;
        }
        ev = try z.client.pollControl();
        if (ev != null) break;
    }
    try testing.expect(ev != null and ev.? == .hello_ack);
}

test "zmq1 r8: failed state — one failure, no resurrection, sends rejected" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
    defer client.deinit();
    const cconn = client.transport.connection();
    _ = try cconn.openStream();
    var pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&pre, .control);
    _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);

    var ack = quic_wire.Hello.serverV1(quic_wire.mode_attach);
    var ack_payload: [quic_wire.hello_payload_len]u8 = undefined;
    ack.encode(&ack_payload);
    var ack_hdr: [quic_wire.control_header_len]u8 = undefined;
    quic_wire.writeControlHeader(&ack_hdr, .hello_ack, ack_payload.len, 0);
    var ack_pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&ack_pre, .control);
    // An ILLEGAL server RESIZE follows the valid ack: the session
    // fails exactly once and stays failed.
    var bad_hdr: [quic_wire.control_header_len]u8 = undefined;
    quic_wire.writeControlHeader(&bad_hdr, .resize, 8, 0);
    var bad_payload: [8]u8 = undefined;
    quic_wire.writeResizePayload(&bad_payload, 1, 2, 3, 4);
    const base: i64 = lib_posix.nowNs();
    try loop.clientPump(base);
    _ = try loop.gw.runOnce(0);
    try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload, &bad_hdr, &bad_payload });

    var got_ack = false;
    var err_ev: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try serverControlRound(&loop, &client, base, i)) |e| {
            if (e == .hello_ack and !got_ack) {
                got_ack = true;
                continue;
            }
            err_ev = e;
            break;
        }
    }
    try testing.expect(got_ack);
    try testing.expect(err_ev != null);
    switch (err_ev.?) {
        .err => |e| {
            try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code);
            try testing.expect(e.terminal);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(quic_client.StateTag.failed, client.stateTag());
    try testing.expect(client.ended());

    // Every send API is rejected; the failure event never repeats;
    // retries never resurrect the session.
    try testing.expectError(error.NotActive, client.sendResize(24, 80, 0, 0));
    try testing.expectError(error.NotActive, client.sendInput("x"));
    try testing.expectError(error.NotActive, client.sendDetach());
    try testing.expectError(error.NotActive, client.sendSnapshotRequest());
    try client.retryPendingSends();
    try testing.expect((try client.pollControl()) == null);
    try testing.expectEqual(quic_client.StateTag.failed, client.stateTag());
}

test "client driver r8: deadline composition frozen by driver state" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    const anchor: i64 = 1_000_000;

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, anchor);
    defer driver.deinit();

    // handshaking: the anchor composes with (is never later than) the
    // transport deadline, and never sits in the past.
    const td = driver.transport.nextDeadlineNanos();
    const d0 = driver.nextDeadline(anchor + 100).?;
    try testing.expect(d0 > anchor + 100);
    if (td) |t| try testing.expect(d0 <= @max(t, anchor + 101));
    // A passed anchor clamps to now+1 — never zero, never in the past.
    try testing.expectEqual(@as(i64, anchor + quic_client.handshake_deadline_ns + 6), driver.nextDeadline(anchor + quic_client.handshake_deadline_ns + 5).?);

    // Terminal states return null — an expired anchor can never
    // busy-loop the poll timeout.
    driver.dstate = .terminal_delivered;
    try testing.expect(driver.nextDeadline(anchor + 10_000_000) == null);
    driver.dstate = .closed;
    try testing.expect(driver.nextDeadline(anchor + 10_000_000) == null);
    driver.dstate = .{ .event_ready = .{ .kind = .session_end, .code = 0 } };
    try testing.expect(driver.nextDeadline(anchor + 10_000_000) == null);

    // running: the transport deadline alone.
    driver.dstate = .running;
    if (td) |t| {
        try testing.expectEqual(@as(i64, @max(t, anchor + 101)), driver.nextDeadline(anchor + 100).?);
    } else {
        try testing.expect(driver.nextDeadline(anchor + 100) == null);
    }
    // draining: the transport deadline alone.
    driver.dstate = .{ .draining = .{ .kind = .session_end, .code = 0 } };
    if (td) |t| {
        try testing.expectEqual(@as(i64, @max(t, anchor + 101)), driver.nextDeadline(anchor + 100).?);
    } else {
        try testing.expect(driver.nextDeadline(anchor + 100) == null);
    }
}

test "client driver r8: terminal deferral holds output, releases after both FINs" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
    defer driver.deinit();

    var ack: ?quic_client.ControlEvent = null;
    for (0..80) |i| {
        ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (ack != null) break;
    }
    try testing.expect(ack != null and ack.? == .hello_ack);
    try driver.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try driverInstall(&loop, &driver);

    // Daemon output, THEN EOF: the SESSION_END terminal is deferred
    // until "deferred" is fully accumulated — output bytes surface
    // through the queue BEFORE (or with) the event, never after it.
    try ipc.send(loop.daemon_fd, .Output, "deferred-output");
    lib_posix.close(loop.daemon_fd);
    loop.daemon_fd = -1;

    var got_bytes: []const u8 = "";
    var end_seen = false;
    for (0..24) |i| {
        if (try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)))) |e| {
            if (e == .session_end) end_seen = true;
        }
        var obuf: [64]u8 = undefined;
        if (try driver.pollOutput(&obuf)) |n| {
            if (got_bytes.len == 0) got_bytes = try alloc.dupe(u8, obuf[0..n]);
        }
        if (end_seen and got_bytes.len > 0) break;
    }
    try testing.expect(end_seen);
    try testing.expectEqualStrings("deferred-output", got_bytes);
    try testing.expect(driver.driverState() == .terminal_delivered or driver.driverState() == .closed);
    // Once terminal-delivered, the event never repeats.
    try testing.expect((try driver.pump(lib_posix.nowNs())) == null);
    alloc.free(got_bytes);
}

test "zmq1 r8: wrong-role prefaces on the control stream reject with unknown_role" {
    const alloc = testing.allocator;
    for ([_]quic_wire.Role{ .input, .output, .snapshot, .command }) |role| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        try quic_test.driveHandshake(&loop);

        var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
        defer client.deinit();
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        // Preface only, so the server's stream-0 send side exists.
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);
        // The WRONG server preface for stream 0.
        var bad_pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&bad_pre, role);
        const base: i64 = lib_posix.nowNs();
        try loop.clientPump(base);
        _ = try loop.gw.runOnce(0);
        try craftServerControl(&loop, &.{&bad_pre});

        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            err_ev = try serverControlRound(&loop, &client, base, i);
            if (err_ev != null) break;
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| {
                try testing.expectEqual(quic_wire.ErrCode.unknown_role.code(), e.code);
                try testing.expect(e.terminal);
            },
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(quic_client.StateTag.failed, client.stateTag());
    }
}

test "zmq1 r8: FINAL ERROR after authorization drains; delayed FIN keeps draining" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
    defer client.deinit();
    const cconn = client.transport.connection();
    _ = try cconn.openStream();
    var pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&pre, .control);
    _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);

    var ack = quic_wire.Hello.serverV1(quic_wire.mode_attach);
    var ack_payload: [quic_wire.hello_payload_len]u8 = undefined;
    ack.encode(&ack_payload);
    var ack_hdr: [quic_wire.control_header_len]u8 = undefined;
    quic_wire.writeControlHeader(&ack_hdr, .hello_ack, ack_payload.len, 0);
    var ack_pre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&ack_pre, .control);
    // A FINAL ERROR (flags 0x01) with its FIN following separately.
    var err_hdr: [quic_wire.control_header_len]u8 = undefined;
    quic_wire.writeControlHeader(&err_hdr, .err, 8, quic_wire.control_flag_final);
    var err_payload: [8]u8 = undefined;
    _ = quic_wire.writeErrorPayload(&err_payload, .internal_error, "boom") catch unreachable;
    const base: i64 = lib_posix.nowNs();
    try loop.clientPump(base);
    _ = try loop.gw.runOnce(0);
    try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload, &err_hdr, &err_payload });

    var got_ack = false;
    var term: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try serverControlRound(&loop, &client, base, i)) |e| {
            if (e == .hello_ack and !got_ack) {
                got_ack = true;
                continue;
            }
            term = e;
            break;
        }
    }
    try testing.expect(got_ack);
    try testing.expect(term != null);
    switch (term.?) {
        .err => |e| {
            try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), e.code);
            try testing.expect(e.terminal);
            try testing.expectEqualStrings("boom", e.reason);
        },
        else => return error.TestUnexpectedResult,
    }
    // The FINAL marker recorded the drain WITHOUT the FIN: the session
    // is draining, waiting for the clean control FIN.
    try testing.expectEqual(quic_client.StateTag.draining, client.stateTag());
    try testing.expect(!client.controlFinished());

    // The FIN arrives in a later delivery: control finishes cleanly.
    const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
    try t.connection().sendOnStream(quic_client.control_stream_id, &.{}, true);
    for (0..8) |i| {
        _ = try serverControlRound(&loop, &client, base + 100, i);
        if (client.controlFinished()) break;
    }
    try testing.expect(client.controlFinished());
    try testing.expectEqual(quic_client.StateTag.draining, client.stateTag());
}

test "zmq1 r8: truncated control frame FIN and post-terminal frames are violations" {
    const alloc = testing.allocator;
    const Kind = enum { truncated_frame, post_terminal, control_reset };
    for ([_]Kind{ .truncated_frame, .post_terminal, .control_reset }) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        try quic_test.driveHandshake(&loop);

        var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
        defer client.deinit();
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);

        var ack = quic_wire.Hello.serverV1(quic_wire.mode_attach);
        var ack_payload: [quic_wire.hello_payload_len]u8 = undefined;
        ack.encode(&ack_payload);
        var ack_hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&ack_hdr, .hello_ack, ack_payload.len, 0);
        var ack_pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&ack_pre, .control);
        const base: i64 = lib_posix.nowNs();
        try loop.clientPump(base);
        _ = try loop.gw.runOnce(0);
        const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;

        var err_ev: ?quic_client.ControlEvent = null;
        switch (kind) {
            .truncated_frame => {
                // A frame header declaring 8 payload bytes, then only
                // 4 — and the FIN.
                var hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&hdr, .session_end, 8, 0);
                try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload, &hdr, "abcd" });
                try t.connection().sendOnStream(quic_client.control_stream_id, &.{}, true);
                var got_ack = false;
                for (0..10) |i| {
                    if (try serverControlRound(&loop, &client, base, i)) |e| {
                        if (e == .hello_ack and !got_ack) {
                            got_ack = true;
                            continue;
                        }
                        err_ev = e;
                        break;
                    }
                }
                try testing.expect(got_ack);
            },
            .post_terminal => {
                // SESSION_END (terminal), then ANOTHER frame after it.
                var end_hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&end_hdr, .session_end, 0, 0);
                var extra_hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&extra_hdr, .session_end, 0, 0);
                try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload, &end_hdr, &extra_hdr });
                var got_ack = false;
                var saw_terminal = false;
                for (0..10) |i| {
                    if (try serverControlRound(&loop, &client, base, i)) |e| {
                        if (e == .hello_ack and !got_ack) {
                            got_ack = true;
                            continue;
                        }
                        if (e == .session_end and !saw_terminal) {
                            saw_terminal = true;
                            continue;
                        }
                        err_ev = e;
                        break;
                    }
                }
                try testing.expect(got_ack);
                try testing.expect(saw_terminal);
            },
            .control_reset => {
                // A partial frame header, then the stream is RESET
                // mid-frame.
                var hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&hdr, .session_end, 8, 0);
                try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload, &hdr, "abcd" });
                var got_ack2 = false;
                for (0..10) |i| {
                    if (i == 4) {
                        try t.connection().resetStream(quic_client.control_stream_id, 0);
                    }
                    if (try serverControlRound(&loop, &client, base, i)) |e| {
                        if (e == .hello_ack and !got_ack2) {
                            got_ack2 = true;
                            continue;
                        }
                        err_ev = e;
                        break;
                    }
                }
                try testing.expect(got_ack2);
            },
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code),
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(quic_client.StateTag.failed, client.stateTag());
    }
}

test "zmq1 r8: truncated output header FIN and output reset are violations" {
    const alloc = testing.allocator;
    const Kind = enum { truncated_header, reset };
    for ([_]Kind{ .truncated_header, .reset }) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        try quic_test.driveHandshake(&loop);

        var client = try quic_client.ClientSession.initSilent(alloc, loop.client);
        defer client.deinit();
        const cconn = client.transport.connection();
        _ = try cconn.openStream();
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &pre, false);

        var ack = quic_wire.Hello.serverV1(quic_wire.mode_attach);
        var ack_payload: [quic_wire.hello_payload_len]u8 = undefined;
        ack.encode(&ack_payload);
        var ack_hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&ack_hdr, .hello_ack, ack_payload.len, 0);
        var ack_pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&ack_pre, .control);
        const base: i64 = lib_posix.nowNs();
        try loop.clientPump(base);
        _ = try loop.gw.runOnce(0);
        try craftServerControl(&loop, &.{ &ack_pre, &ack_hdr, &ack_payload });
        // A crafted OUTPUT stream: the server's first uni stream.
        const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
        const oid = try t.connection().openUniStream();
        try testing.expectEqual(quic_client.output_stream_id, oid);
        var ohdr: [quic_wire.output_header_len]u8 = undefined;
        quic_wire.writeOutputHeader(&ohdr, 1);
        switch (kind) {
            .truncated_header => {
                // Only 9 of the 16 header bytes, then the FIN.
                try t.connection().sendOnStream(oid, ohdr[0..9], false);
                try t.connection().sendOnStream(oid, &.{}, true);
            },
            .reset => {
                try t.connection().sendOnStream(oid, ohdr[0..16], false);
                try t.connection().resetStream(oid, 0);
            },
        }

        var got_ack = false;
        var err_ev: ?quic_client.ControlEvent = null;
        for (0..12) |i| {
            if (try serverControlRound(&loop, &client, base, i)) |e| {
                if (e == .hello_ack and !got_ack) {
                    got_ack = true;
                    // The authorized output side now reads the header.
                    var obuf: [64]u8 = undefined;
                    var epoch: u64 = 0;
                    if (kind == .reset) _ = try client.pollOutput(&obuf, &epoch);
                    continue;
                }
                err_ev = e;
                break;
            }
            // pollOutput takes the failure path on its own schedule.
            var obuf: [64]u8 = undefined;
            if (err_ev == null) {
                _ = try client.pollOutput(&obuf, null);
                if (client.stateTag() == .failed) break;
            }
        }
        try testing.expect(got_ack);
        try testing.expectEqual(quic_client.StateTag.failed, client.stateTag());
        if (err_ev) |e| {
            try testing.expect(e == .err);
            try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.err.code);
        } else {
            const late = try client.pollControl();
            try testing.expect(late != null and late.? == .err);
            try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), late.?.err.code);
        }
    }
}

test "zmq1 r8: output header splits 9+7+body; input preface splits 5+(3+body)" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // The CLIENT's input preface arrives 5 + (3 + body): the gateway
    // session parks the partial preface and resumes exactly once.
    const cconn = z.client.transport.connection();
    const iid = try cconn.openUniStream();
    try testing.expectEqual(quic_client.input_stream_id, iid);
    var ipre: [quic_wire.preface_len]u8 = undefined;
    quic_wire.writePreface(&ipre, .input);
    _ = try cconn.sendOnStream(quic_client.input_stream_id, ipre[0..5], false);
    for (0..6) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    _ = try cconn.sendOnStream(quic_client.input_stream_id, ipre[5..], false);
    _ = try cconn.sendOnStream(quic_client.input_stream_id, "split-body", false);
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoSplitInput;
    try testing.expectEqual(ipc.Tag.Input, f.tag);
    try testing.expectEqualStrings("split-body", f.payload);
    // Exactly one .Input frame — no duplicated or partial preface body.
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
}

test "zmq1 r8: SNAPSHOT_INSTALLED with or without payload is a Q3 violation" {
    const alloc = testing.allocator;
    const Kind = enum { empty, payload };
    for ([_]Kind{ .empty, .payload }) |kind| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToActive(&z, &dr, base);

        const cconn = z.client.transport.connection();
        const iid = try cconn.openUniStream();
        try testing.expectEqual(quic_client.input_stream_id, iid);
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .snapshot_installed, if (kind == .payload) 4 else 0, 0);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &hdr, false);
        if (kind == .payload) _ = try cconn.sendOnStream(quic_client.control_stream_id, "abcd", false);

        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            if (try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)))) |e| {
                err_ev = e;
                break;
            }
            err_ev = try z.client.pollControl();
            if (err_ev != null) break;
        }
        // The server's terminal is a FINAL ERROR: the client surfaces
        // the violation event and the session ends.
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code),
            else => return error.TestUnexpectedResult,
        }
        try testing.expect((try z.session()).closedOrEnding());
    }
}

test "client driver r8: transport-level close surfaces distinctly from application close" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
    defer driver.deinit();

    var ack: ?quic_client.ControlEvent = null;
    for (0..80) |i| {
        ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (ack != null) break;
    }
    try testing.expect(ack != null and ack.? == .hello_ack);
    try driver.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try driverInstall(&loop, &driver);

    // A TRANSPORT-level CONNECTION_CLOSE (not the adapter's
    // application shutdown): the client reports kind == .transport
    // with the wire code, distinct from the application close.
    const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
    try t.connection().closeConnection(0x0B, 0x03, "transport-level");
    for (0..16) |i| {
        _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (driver.peerClose() != null) break;
    }
    const pc = driver.peerClose();
    try testing.expect(pc != null);
    try testing.expect(pc.?.kind == .transport);
    try testing.expectEqual(@as(u64, 0x0B), pc.?.code);
}

test "zmq1 r8: blocked-write contract under controlled peer transport parameters" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    // Drive to authorized (HELLO_ACK) WITHOUT the first RESIZE.
    try zmq1ToActive0(&z);
    try testing.expectEqual(quic_client.StateTag.awaiting_first_resize, z.client.stateTag());

    const conn = z.client.transport.connection();
    // TEST-ONLY fault injection (public peer transport-parameter API):
    // zero the peer-granted stream credit so the next control send and
    // the input preface block. The peer's negotiated identity fields
    // are preserved so the re-application validates.
    var low = quicz.transport_parameters.TransportParameters{};
    low.initial_source_connection_id = conn.peerInitialSourceConnectionId();
    low.original_destination_connection_id = conn.originalDestinationConnectionId();
    low.retry_source_connection_id = conn.retrySourceConnectionId();
    low.initial_max_data = 64; // exactly the HELLO already consumed
    low.initial_max_stream_data_bidi_remote = 64; // stream 0 consumed
    low.initial_max_stream_data_uni = 0;
    low.initial_max_streams_bidi = 100;
    low.initial_max_streams_uni = 100;
    try conn.applyPeerTransportParameters(low);

    // A blocked first RESIZE parks the WHOLE encoded copy and the
    // call SUCCEEDS (ownership transferred); the state has not
    // advanced.
    try z.client.sendResize(24, 80, 0, 0);
    try testing.expectEqual(quic_client.StateTag.awaiting_first_resize, z.client.stateTag());
    // A second write while one is parked is ControlWritePending.
    try testing.expectError(error.ControlWritePending, z.client.sendResize(25, 81, 0, 0));

    // Restore generous credit (limits only grow).
    var high = quicz.transport_parameters.TransportParameters{};
    high.initial_source_connection_id = conn.peerInitialSourceConnectionId();
    high.original_destination_connection_id = conn.originalDestinationConnectionId();
    high.retry_source_connection_id = conn.retrySourceConnectionId();
    high.initial_max_data = 1024 * 1024;
    high.initial_max_stream_data_bidi_remote = 64 * 1024;
    high.initial_max_stream_data_bidi_local = 64 * 1024;
    high.initial_max_stream_data_uni = 64 * 1024;
    high.initial_max_streams_bidi = 100;
    high.initial_max_streams_uni = 100;
    try conn.applyPeerTransportParameters(high);

    // The parked first RESIZE retries whole: exactly one activation,
    // exactly one .InitSnapshot. (The session-level harness has no
    // driver pump, so retries are explicit.)
    for (0..8) |i| {
        try z.client.retryPendingSends();
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    }
    try testing.expectEqual(quic_client.StateTag.active, z.client.stateTag());
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
        try testing.expectEqual(ipc.Tag.InitSnapshot, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 24), rz.rows);
    }

    // Second injection, ACTIVE session: the input PREFACE alone
    // blocks — the body stays caller-owned and unsent.
    var low2 = quicz.transport_parameters.TransportParameters{};
    low2.initial_source_connection_id = conn.peerInitialSourceConnectionId();
    low2.original_destination_connection_id = conn.originalDestinationConnectionId();
    low2.retry_source_connection_id = conn.retrySourceConnectionId();
    low2.initial_max_data = 1024 * 1024;
    low2.initial_max_stream_data_bidi_remote = 64 * 1024;
    low2.initial_max_stream_data_uni = 0;
    low2.initial_max_streams_bidi = 100;
    low2.initial_max_streams_uni = 100;
    try conn.applyPeerTransportParameters(low2);
    try testing.expectError(error.WouldBlock, z.client.sendInput("blocked-body"));
    // A retry while the preface is staged stays WouldBlock.
    try testing.expectError(error.WouldBlock, z.client.sendInput("blocked-body"));
    // Restore: the staged preface retries on the SAME stream; the
    // body follows exactly once.
    try conn.applyPeerTransportParameters(high);
    for (0..8) |i| {
        try z.client.retryPendingSends();
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    }
    try z.client.sendInput("blocked-body");
    for (0..8) |i| {
        try z.client.retryPendingSends();
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    }
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoBlockedBody;
        try testing.expectEqual(ipc.Tag.Input, f.tag);
        try testing.expectEqualStrings("blocked-body", f.payload);
    }
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
}

test "client driver r8: permanent receive failure latches with ONE internal_error event" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    // No gateway: the handshake never completes.
    var gw_sock = try udp.UdpSocket.bind(60600, 60700);
    defer gw_sock.close();
    const gw_addr = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, gw_sock.bound_port);

    const anchor: i64 = 2_000_000;
    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, gw_addr, anchor);
    // Kill the socket: every receive now fails permanently.
    lib_posix.close(driver.sock.getFd());
    driver.sock.fd = -1;

    const ev = try driver.pump(anchor + 10);
    try testing.expect(ev != null);
    switch (ev.?) {
        .err => |e| {
            try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), e.code);
            try testing.expect(e.terminal);
        },
        else => return error.TestUnexpectedResult,
    }
    // Latched: later pumps attempt no I/O and never repeat the event.
    try testing.expect((try driver.pump(anchor + 20)) == null);
    try testing.expect((try driver.pump(anchor + 30)) == null);
    // Swap in a live fd so deinit's close never double-closes the
    // dead one (0.16's Threaded close panics on EBADF).
    const dummy = try udp.UdpSocket.bindEphemeral(lib_posix.AF.INET);
    driver.sock.fd = dummy.fd;
    driver.deinit();
}

test "client driver r8: bounded output queue suspends reception and resumes losslessly" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
    defer driver.deinit();
    var ack: ?quic_client.ControlEvent = null;
    for (0..80) |i| {
        ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (ack != null) break;
    }
    try testing.expect(ack != null and ack.? == .hello_ack);
    try driver.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try driverInstall(&loop, &driver);

    // Flood > 64 KiB of daemon output while the caller does NOT
    // drain: the bounded queue fills, reception suspends, and the
    // remaining datagrams stay queued — never dropped. A full daemon
    // socket (the whole pipeline is bounded end to end) simply waits
    // for pump rounds — that IS the backpressure under test.
    const frames: usize = 96; // 96 × 1 KiB = 96 KiB > the 64 KiB bound
    var payload: [1024]u8 = undefined;
    var seq: usize = 0;
    var stuck: usize = 0;
    while (seq < frames) {
        @memset(&payload, @intCast('A' + (seq % 26)));
        payload[0] = @intCast(seq % 26);
        payload[1] = @intCast((seq / 26) % 26);
        ipc.send(loop.daemon_fd, .Output, &payload) catch |e| switch (e) {
            error.WouldBlock => {
                stuck += 1;
                try testing.expect(stuck < 500);
                _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(stuck)));
                continue;
            },
            else => return e,
        };
        seq += 1;
        if (seq % 16 == 15) {
            for (0..2) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        }
    }

    // Drain everything; the byte count must be exactly frames × 1024
    // with every sequence marker seen exactly once, in order.
    var got_total: usize = 0;
    var expect_seq: usize = 0;
    var obuf: [4096]u8 = undefined;
    var rounds: usize = 0;
    while (got_total < frames * 1024 and rounds < 400) : (rounds += 1) {
        _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(rounds)));
        while (try driver.pollOutput(&obuf)) |n| {
            var off: usize = 0;
            while (off < n) : (off += 1024) {
                const marker = @as(usize, obuf[off]) + 26 * @as(usize, obuf[off + 1]);
                try testing.expectEqual(expect_seq, marker);
                expect_seq += 1;
                got_total += 1024;
            }
        }
    }
    try testing.expectEqual(frames * 1024, got_total);
}

test "r8: partially-failed construction leaks nothing (ClientSession, QuicSession, Client.connect)" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    // ClientSession.init: the transport (and its allocations) stay
    // outside the failing allocator so only the session's own
    // allocation points are exercised.
    {
        const transport = try quic_transport.Transport.createClient(alloc, .{
            .psk = &psk,
            .scid = .{ 1, 2, 3, 4 },
            .original_dcid = .{ 9, 9, 9, 9, 9, 9, 9, 9 },
        });
        defer transport.destroy();
        var fail_index: usize = 0;
        while (fail_index < 16) : (fail_index += 1) {
            var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
            if (quic_client.ClientSession.init(failing.allocator(), transport)) |s| {
                var sess = s;
                sess.deinit();
                break;
            } else |e| try testing.expect(error.OutOfMemory == e);
        }
    }

    // QuicSession.init: three preallocated buffers → three failure
    // points, each cleaned by errdefer.
    {
        const transport = try quic_transport.Transport.createClient(alloc, .{
            .psk = &psk,
            .scid = .{ 5, 6, 7, 8 },
            .original_dcid = .{ 8, 8, 8, 8, 8, 8, 8, 8 },
        });
        defer transport.destroy();
        var fail_index: usize = 0;
        while (fail_index < 16) : (fail_index += 1) {
            var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
            if (quic_session.QuicSession.init(failing.allocator(), transport)) |s| {
                var sess = s;
                sess.deinit();
                break;
            } else |e| try testing.expect(error.OutOfMemory == e);
        }
    }

    // Client.connect: socket + transport + session + parked capacity,
    // every partial construction fully unwound.
    {
        var gw_sock = try udp.UdpSocket.bind(60700, 60800);
        defer gw_sock.close();
        const gw_addr = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, gw_sock.bound_port);
        var fail_index: usize = 0;
        while (fail_index < 24) : (fail_index += 1) {
            var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
            if (quic_client.Client.connect(failing.allocator(), testing.io, &psk, gw_addr, 1_000_000)) |c| {
                var driver = c;
                driver.deinit();
                break;
            } else |e| try testing.expect(error.OutOfMemory == e);
        }
    }
}

test "r8: gateway observes the ACTUAL source path and keeps the registered route" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive(&z, &dr, base);

    // The original route's integrity is proven BEFORE the alt
    // experiment: stream reassembly would legitimately stall behind
    // an unvalidated-path frame, so relay one input normally first.
    try z.client.sendInput("original-path-still-works");
    for (0..8) |i| {
        try z.client.retryPendingSends();
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 500 + @as(i64, @intCast(i)));
    }
    var saw_orig = false;
    while (try dr.next(z.loop.daemon_fd)) |f| {
        if (f.tag == .Input and std.mem.eql(u8, f.payload, "original-path-still-works")) saw_orig = true;
    }
    try testing.expect(saw_orig);

    // Take one REAL authenticated client datagram and send it from an
    // ALTERNATE UDP source: the gateway feeds the kernel-reported
    // tuple to quicz, which answers with path validation addressed to
    // the alternate path — the registered route is never silently
    // rewritten.
    var alt = try udp.UdpSocket.bindEphemeral(lib_posix.AF.INET);
    defer alt.close();
    try z.client.sendInput("from-alt-path");
    var sent_alt = false;
    for (0..8) |i| {
        const now = base + 600 + @as(i64, @intCast(i));
        const dg = (try z.loop.client.pollOutbound(now)) orelse continue;
        defer alloc.free(dg);
        try alt.sendTo(dg, z.loop.gw_addr);
        sent_alt = true;
        _ = try z.loop.gw.runOnce(0);
        // The alternate socket receives the path-validation response.
        var rbuf: [quic_transport.max_udp_payload]u8 = undefined;
        const r = alt.recvFrom(&rbuf) catch break;
        try testing.expect(r.len > 0);
        break;
    }
    try testing.expect(sent_alt);

    // The session survived the unvalidated-path packet: no terminal,
    // no close — the route was not corrupted by the alternate source.
    const sess = try z.session();
    try testing.expect(!sess.closedOrEnding());
}

test "client driver r8: exact-capacity output with FIN releases the terminal without draining" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk, false);
    defer loop.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();

    var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
    defer driver.deinit();
    var ack: ?quic_client.ControlEvent = null;
    for (0..80) |i| {
        ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        if (ack != null) break;
    }
    try testing.expect(ack != null and ack.? == .hello_ack);
    try driver.sendResize(24, 80, 0, 0);
    for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
    _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInitSnapshot;
    try driverInstall(&loop, &driver);

    // Exactly 64 KiB of output, then EOF: the queue fills to its bound
    // at the same moment the FIN is consumed — a FULL queue does not
    // hold the terminal once the output side is settled.
    var payload: [1024]u8 = undefined;
    @memset(&payload, 'E');
    var stuck: usize = 0;
    var seq: usize = 0;
    while (seq < 64) {
        ipc.send(loop.daemon_fd, .Output, &payload) catch |e| switch (e) {
            error.WouldBlock => {
                stuck += 1;
                try testing.expect(stuck < 500);
                _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(stuck)));
                continue;
            },
            else => return e,
        };
        seq += 1;
        if (seq % 16 == 15) {
            for (0..2) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        }
    }
    while (try dr.next(loop.daemon_fd)) |_| {}
    lib_posix.close(loop.daemon_fd);
    loop.daemon_fd = -1;

    var end_seen = false;
    for (0..200) |i| {
        if (try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)))) |e| {
            if (e == .session_end) end_seen = true;
        }
        if (end_seen) break;
    }
    try testing.expect(end_seen);

    // The caller drains the full bound afterwards, losslessly.
    var got: usize = 0;
    var obuf: [4096]u8 = undefined;
    var rounds: usize = 0;
    while (got < 64 * 1024 and rounds < 100) : (rounds += 1) {
        while (try driver.pollOutput(&obuf)) |n| got += n;
    }
    try testing.expectEqual(@as(usize, 64 * 1024), got);
}

test "zmq1 r8.5: DETACH matrix — typed .detaching, writes rejected, preface rejection, clean completion" {
    const alloc = testing.allocator;
    {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var z = try zmq1Setup(alloc, &psk);
        defer z.loop.deinit();
        defer z.client.deinit();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();
        const base: i64 = lib_posix.nowNs();
        try zmq1ToActive(&z, &dr, base);

        // A staged input preface REJECTS the DETACH: WouldBlock, no
        // queue, no transition (option-1 semantics).
        {
            const conn = z.client.transport.connection();
            var low2 = quicz.transport_parameters.TransportParameters{};
            low2.initial_source_connection_id = conn.peerInitialSourceConnectionId();
            low2.original_destination_connection_id = conn.originalDestinationConnectionId();
            low2.retry_source_connection_id = conn.retrySourceConnectionId();
            low2.initial_max_data = 1024 * 1024;
            low2.initial_max_stream_data_bidi_remote = 64 * 1024;
            low2.initial_max_stream_data_bidi_local = 64 * 1024;
            low2.initial_max_stream_data_uni = 0;
            low2.initial_max_streams_bidi = 100;
            low2.initial_max_streams_uni = 100;
            try conn.applyPeerTransportParameters(low2);
            try testing.expectError(error.WouldBlock, z.client.sendInput("pending-preface"));
            try testing.expectError(error.WouldBlock, z.client.sendDetach());
            try testing.expectEqual(quic_client.StateTag.active, z.client.stateTag());
            // Flush the preface (the session-level harness retries
            // explicitly), restore, and the DETACH now proceeds.
            var high = quicz.transport_parameters.TransportParameters{};
            high.initial_source_connection_id = conn.peerInitialSourceConnectionId();
            high.original_destination_connection_id = conn.originalDestinationConnectionId();
            high.retry_source_connection_id = conn.retrySourceConnectionId();
            high.initial_max_data = 1024 * 1024;
            high.initial_max_stream_data_bidi_remote = 64 * 1024;
            high.initial_max_stream_data_bidi_local = 64 * 1024;
            high.initial_max_stream_data_uni = 64 * 1024;
            high.initial_max_streams_bidi = 100;
            high.initial_max_streams_uni = 100;
            try conn.applyPeerTransportParameters(high);
            for (0..4) |i| {
                try z.client.retryPendingSends();
                _ = try quic_test.sessionRound(&z.loop, &z.client, base + 50 + @as(i64, @intCast(i)));
            }
            while (try dr.next(z.loop.daemon_fd)) |_| {}
        }

        // The preface flushed: the DETACH now proceeds — sent whole,
        // the typed .detaching state, every application write rejected.
        try z.client.sendDetach();
        try testing.expectEqual(quic_client.StateTag.detaching, z.client.stateTag());
        try testing.expectError(error.NotActive, z.client.sendResize(1, 2, 0, 0));
        try testing.expectError(error.NotActive, z.client.sendInput("x"));
        try testing.expectError(error.NotActive, z.client.sendDetach());
        try testing.expectError(error.NotActive, z.client.sendSnapshotRequest());

        // The flushed DETACH completes cleanly: exactly one .Detach at
        // the daemon (the retry never duplicated bytes), code-0 close.
        for (0..12) |i| {
            try z.client.retryPendingSends();
            _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
        }
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoDetach;
        try testing.expectEqual(ipc.Tag.Detach, f.tag);
        var extra = false;
        while (try dr.next(z.loop.daemon_fd)) |f2| {
            if (f2.tag == ipc.Tag.Detach) extra = true;
        }
        try testing.expect(!extra);
        const sess = try z.session();
        try testing.expect(sess.closed);
        try testing.expectEqual(quic_wire.ErrCode.none.code(), sess.end_code.code());
    }
}

test "zmq1 r8.6 fixture A: DETACH parks under genuine flow control, retries once, completes cleanly" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    var dr = try quic_test.DaemonReader.init(alloc);
    defer dr.deinit();
    const base: i64 = lib_posix.nowNs();
    // Authorize at control offset 64 (preface + HELLO consumed).
    try zmq1ToActive0(&z);
    try testing.expectEqual(quic_client.StateTag.awaiting_first_resize, z.client.stateTag());

    // The Q4 installation completes under NORMAL credit first (a
    // DETACH mid-installation would be a protocol violation, and the
    // many installation rounds would consume any pre-set window).
    const conn = z.client.transport.connection();
    try z.client.sendResize(24, 80, 0, 0);
    try testing.expectEqual(quic_client.StateTag.active, z.client.stateTag());
    for (0..8) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 100 + @as(i64, @intCast(i)));
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoInitSnapshot;
        try testing.expectEqual(ipc.Tag.InitSnapshot, f.tag);
    }
    try quic_test.daemonSendEmptySnapshot(z.loop.daemon_fd);
    var observed: ?quic_wire.SnapshotHeader = null;
    var snap_rx: quic_test.ClientSnapshotRx = .{};
    for (0..16) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 150 + @as(i64, @intCast(i)));
        observed = try quic_test.clientObserveSnapshot(z.client.transport, testing.allocator, &snap_rx, null);
        if (observed != null) break;
    }
    try testing.expect(observed != null);
    try quic_test.sendSnapshotInstalledOn(z.client.transport);
    const gw = try z.session();
    for (0..8) |i| {
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 180 + @as(i64, @intCast(i)));
        if (gw.phase == .active) break;
    }
    try testing.expect(gw.phase == .active);

    // NOW clamp the peer's control credit to exactly the current
    // offset (HELLO 64 + RESIZE 16 + INSTALLED 8 = 88): the 8-byte
    // DETACH that follows parks NATURALLY through FlowControlBlocked
    // → beginDetach, and stays parked across rounds until an explicit
    // retry.
    var cap_now = quicz.transport_parameters.TransportParameters{};
    cap_now.initial_source_connection_id = conn.peerInitialSourceConnectionId();
    cap_now.original_destination_connection_id = conn.originalDestinationConnectionId();
    cap_now.retry_source_connection_id = conn.retrySourceConnectionId();
    cap_now.initial_max_data = 88;
    cap_now.initial_max_stream_data_bidi_remote = 88;
    cap_now.initial_max_stream_data_bidi_local = 64 * 1024;
    cap_now.initial_max_stream_data_uni = 64 * 1024;
    cap_now.initial_max_streams_bidi = 100;
    cap_now.initial_max_streams_uni = 100;
    try conn.applyPeerTransportParameters(cap_now);
    try z.client.sendDetach();
    try testing.expectEqual(quic_client.StateTag.detaching, z.client.stateTag());

    // One round under the exhausted credit — WITHOUT retryPendingSends,
    // so the parked DETACH cannot flush: nothing new reaches the daemon.
    for (0..6) |i| _ = try quic_test.sessionRound(&z.loop, &z.client, base + 200 + @as(i64, @intCast(i)));
    try testing.expect((try dr.next(z.loop.daemon_fd)) == null);
    try testing.expectEqual(quic_client.StateTag.detaching, z.client.stateTag());

    // Restore credit and retry EXPLICITLY: exactly one .Detach, then
    // the clean code-0 completion.
    var high = quicz.transport_parameters.TransportParameters{};
    high.initial_source_connection_id = conn.peerInitialSourceConnectionId();
    high.original_destination_connection_id = conn.originalDestinationConnectionId();
    high.retry_source_connection_id = conn.retrySourceConnectionId();
    high.initial_max_data = 1024 * 1024;
    high.initial_max_stream_data_bidi_remote = 64 * 1024;
    high.initial_max_stream_data_bidi_local = 64 * 1024;
    high.initial_max_stream_data_uni = 64 * 1024;
    high.initial_max_streams_bidi = 100;
    high.initial_max_streams_uni = 100;
    try conn.applyPeerTransportParameters(high);
    for (0..12) |i| {
        try z.client.retryPendingSends();
        _ = try quic_test.sessionRound(&z.loop, &z.client, base + 300 + @as(i64, @intCast(i)));
    }
    {
        const f = (try dr.next(z.loop.daemon_fd)) orelse return error.NoDetach;
        try testing.expectEqual(ipc.Tag.Detach, f.tag);
    }
    var extra = false;
    while (try dr.next(z.loop.daemon_fd)) |f2| {
        if (f2.tag == ipc.Tag.Detach) extra = true;
    }
    try testing.expect(!extra);
    const sess = try z.session();
    try testing.expect(sess.closed);
    try testing.expectEqual(quic_wire.ErrCode.none.code(), sess.end_code.code());
}

test "zmq1 r8.6 fixture B: parked DETACH plus server FIN before flush is a protocol violation" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();
    try zmq1ToActive0(&z);

    const conn = z.client.transport.connection();
    var cap80 = quicz.transport_parameters.TransportParameters{};
    cap80.initial_source_connection_id = conn.peerInitialSourceConnectionId();
    cap80.original_destination_connection_id = conn.originalDestinationConnectionId();
    cap80.retry_source_connection_id = conn.retrySourceConnectionId();
    cap80.initial_max_data = 80;
    cap80.initial_max_stream_data_bidi_remote = 80;
    cap80.initial_max_stream_data_bidi_local = 64 * 1024;
    cap80.initial_max_stream_data_uni = 64 * 1024;
    cap80.initial_max_streams_bidi = 100;
    cap80.initial_max_streams_uni = 100;
    try conn.applyPeerTransportParameters(cap80);
    try z.client.sendResize(24, 80, 0, 0);
    try z.client.sendDetach();
    try testing.expectEqual(quic_client.StateTag.detaching, z.client.stateTag());

    // The DETACH stays parked (no retry): a server control FIN before
    // the frame reached quicz is a protocol violation.
    const t = z.loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
    try t.connection().sendOnStream(quic_client.control_stream_id, &.{}, true);
    var viol: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        if (try serverControlRound(&z.loop, &z.client, base, i)) |e| {
            viol = e;
            break;
        }
    }
    try testing.expect(viol != null);
    switch (viol.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(quic_client.StateTag.failed, z.client.stateTag());
}

test "client driver r8.6: terminal coherence — drain failure, post-failure socket, clean-drain socket" {
    const alloc = testing.allocator;
    // POLL.IN on the driver's socket, zero timeout — the fixture's
    // readability oracle (never used to discard anything).
    const sockReadable = struct {
        fn check(driver: *quic_client.Client) bool {
            var pfd = [_]lib_posix.pollfd{.{ .fd = driver.sock.fd, .events = lib_posix.POLL.IN, .revents = 0 }};
            const n = lib_posix.poll(&pfd, 0) catch return false;
            return n == 1 and (pfd[0].revents & lib_posix.POLL.IN) != 0;
        }
    }.check;
    const Phase = enum { drain_failure, combined_failure_socket, post_failure_socket, clean_drain_socket };
    for ([_]Phase{ .drain_failure, .combined_failure_socket, .post_failure_socket, .clean_drain_socket }) |phase| {
        var bootstrap: [32]u8 = undefined;
        var psk: [32]u8 = undefined;
        try testing.io.randomSecure(&bootstrap);
        quic_transport.derivePsk(&psk, &bootstrap);
        defer std.crypto.secureZero(u8, &bootstrap);
        defer std.crypto.secureZero(u8, &psk);

        var loop = try quic_test.Loop.init(alloc, &psk, false);
        defer loop.deinit();
        var dr = try quic_test.DaemonReader.init(alloc);
        defer dr.deinit();

        var driver = try quic_client.Client.connect(alloc, testing.io, &psk, loop.gw_addr, lib_posix.nowNs());
        defer driver.deinit();
        var ack: ?quic_client.ControlEvent = null;
        for (0..80) |i| {
            ack = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
            if (ack != null) break;
        }
        try testing.expect(ack != null and ack.? == .hello_ack);
        try driver.sendResize(24, 80, 0, 0);
        for (0..8) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        _ = (try dr.next(loop.daemon_fd)) orelse return error.NoInit;

        // A crafted terminal SESSION_END defers cleanly.
        const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
        var end_hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&end_hdr, .session_end, 0, 0);
        // No FIN on the crafted terminal: the server's send side must
        // stay open for the follow-up crafted frames.
        try t.connection().sendOnStream(quic_client.control_stream_id, &end_hdr, false);
        for (0..4) |i| _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
        try testing.expect(driver.session.stateTag() == .draining);

        switch (phase) {
            .drain_failure => {
                // A protocol failure DURING the drain replaces the
                // deferred terminal and surfaces its OWN code and
                // reason exactly once through the driver.
                var bad_hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&bad_hdr, .resize, 8, 0);
                var bad_payload: [8]u8 = undefined;
                quic_wire.writeResizePayload(&bad_payload, 1, 2, 3, 4);
                try t.connection().sendOnStream(quic_client.control_stream_id, &bad_hdr, false);
                try t.connection().sendOnStream(quic_client.control_stream_id, &bad_payload, false);
                var ev: ?quic_client.ControlEvent = null;
                for (0..8) |i| {
                    if (try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)))) |e| {
                        ev = e;
                        break;
                    }
                }
                try testing.expect(ev != null);
                switch (ev.?) {
                    .err => |e| {
                        try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code);
                        try testing.expectEqualStrings("frame after terminal marker", e.reason);
                    },
                    else => return error.TestUnexpectedResult,
                }
                try testing.expect((try driver.pump(lib_posix.nowNs())) == null);
            },
            .combined_failure_socket => {
                // Same-pump combination: the protocol failure is
                // deferred (deferTerminal consumed its event into
                // .draining), then the NEXT receive fails inside the
                // SAME pump. The deferred FINAL ERROR must be
                // promoted unchanged — not replaced by the
                // missing-event invariant.
                //
                // Quiesce stale traffic through normal pumps until
                // the socket is provably empty (authenticated
                // datagrams are never raw-discarded), and verify
                // quiet BEFORE queuing the crafted frame.
                var quiet = false;
                for (0..16) |i| {
                    _ = try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)));
                    quiet = !sockReadable(&driver);
                    if (quiet) break;
                }
                try testing.expect(quiet);
                // One combined 16-byte illegal RESIZE, one stream
                // write.
                var bad: [quic_wire.control_header_len + 8]u8 = undefined;
                quic_wire.writeControlHeader(bad[0..quic_wire.control_header_len], .resize, 8, 0);
                quic_wire.writeResizePayload(bad[quic_wire.control_header_len..], 1, 2, 3, 4);
                try t.connection().sendOnStream(quic_client.control_stream_id, &bad, false);
                // Gateway egress only — the client is NOT pumped —
                // until its socket is observably readable.
                var readable = false;
                for (0..16) |_| {
                    _ = try loop.gw.runOnce(0);
                    readable = sockReadable(&driver);
                    if (readable) break;
                }
                try testing.expect(readable);
                driver.recv_fail_n = 2;
                const ev = try driver.pump(lib_posix.nowNs());
                try testing.expect(ev != null);
                switch (ev.?) {
                    .err => |e| {
                        try testing.expectEqual(quic_wire.ErrCode.protocol_violation.code(), e.code);
                        try testing.expectEqualStrings("frame after terminal marker", e.reason);
                    },
                    else => return error.TestUnexpectedResult,
                }
                try testing.expect(driver.io_failed);
                try testing.expect((try driver.pump(lib_posix.nowNs())) == null);
            },
            .post_failure_socket => {
                // The protocol failure is delivered first; a LATER
                // socket failure creates no second event.
                var bad_hdr: [quic_wire.control_header_len]u8 = undefined;
                quic_wire.writeControlHeader(&bad_hdr, .resize, 8, 0);
                var bad_payload: [8]u8 = undefined;
                quic_wire.writeResizePayload(&bad_payload, 1, 2, 3, 4);
                try t.connection().sendOnStream(quic_client.control_stream_id, &bad_hdr, false);
                try t.connection().sendOnStream(quic_client.control_stream_id, &bad_payload, false);
                var ev: ?quic_client.ControlEvent = null;
                for (0..8) |i| {
                    if (try driverRound(&loop, &driver, lib_posix.nowNs() + @as(i64, @intCast(i)))) |e| {
                        ev = e;
                        break;
                    }
                }
                try testing.expect(ev != null);
                try testing.expect(ev.? == .err);
                driver.recv_fail_n = 1;
                try testing.expect((try driver.pump(lib_posix.nowNs())) == null);
                try testing.expect(driver.io_failed);
            },
            .clean_drain_socket => {
                // A socket failure while draining a CLEAN SESSION_END:
                // output completeness is no longer provable →
                // internal_error.
                driver.recv_fail_n = 1;
                const ev = try driver.pump(lib_posix.nowNs());
                try testing.expect(ev != null);
                switch (ev.?) {
                    .err => |e| {
                        try testing.expectEqual(quic_wire.ErrCode.internal_error.code(), e.code);
                        try testing.expectEqualStrings("socket receive failed", e.reason);
                    },
                    else => return error.TestUnexpectedResult,
                }
                try testing.expect((try driver.pump(lib_posix.nowNs())) == null);
            },
        }
    }
}
