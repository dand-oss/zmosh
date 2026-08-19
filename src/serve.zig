//! `zmx serve` — the ephemeral QUIC gateway.
//!
//! One poll() loop bridges the daemon's Unix socket to the client's
//! QUIC connection. QUIC is this branch's active transport; the custom
//! UDP transport files stay untouched until the reviewed removal
//! checkpoint. No daemon IPC bytes are relayed yet: Q3 owns the frozen
//! stream preface and roles, so daemon output is drained and discarded
//! (bounded) while the gateway stays alive for connection lifecycle
//! and teardown.
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
        var unix_read_buf = try ipc.SocketBuffer.init(alloc);
        errdefer unix_read_buf.deinit();
        var quic = try quic_gateway.QuicGateway.init(alloc, io, psk, token_secret, local, 0);
        // Deinit in place: a copy would wipe only the copy's PSK.
        errdefer quic.deinit();
        return .{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .quic = quic,
            .unix_read_buf = unix_read_buf,
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
        poll_fds[2] = .{ .fd = self.unix_fd, .events = lib_posix.POLL.IN, .revents = 0 };
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
        if (poll_fds[2].revents & (lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR) != 0) {
            try self.drainDaemon(now, &budget);
            if (!self.running) return false;
        }
        const alive = try self.quic.serviceDue(&self.udp_sock, now, &budget);
        if (!alive) self.running = false;
        return alive;
    }

    /// The single composed timeout: the earliest QUIC deadline (recovery/
    /// idle/close, slot expiry, the absolute handshake deadline, the
    /// one-second keepalive) as milliseconds remaining, bounded above
    /// by one second so staleness cannot accumulate.
    fn computePollTimeoutMs(self: *const Gateway) i32 {
        const deadline = self.quic.nextDeadline() orelse return 1000;
        const now: i64 = lib_posix.nowNs();
        const remaining_ns = deadline - now;
        if (remaining_ns <= 0) return 0;
        const ms = @divFloor(remaining_ns, std.time.ns_per_ms);
        return @intCast(@min(ms, 1000));
    }

    /// Drain-and-discard the daemon socket (no relay in Q2), bounded
    /// per turn. Daemon closure queues the QUIC CONNECTION_CLOSE and
    /// attempts it through the reserved slot before exiting.
    fn drainDaemon(self: *Gateway, now: i64, budget: *quic_gateway.TurnBudget) !void {
        var discarded: usize = 0;
        while (discarded < max_daemon_discard_per_turn) {
            const n = self.unix_read_buf.read(self.unix_fd) catch |err| switch (err) {
                error.WouldBlock => return,
                else => {
                    log.warn("unix read error: {s}", .{@errorName(err)});
                    self.running = false;
                    return;
                },
            };
            if (n == 0) {
                log.info("daemon closed connection", .{});
                self.quic.closeForDaemonExit(&self.udp_sock, now, budget) catch |err| {
                    log.warn("daemon-close drain failed: {s}", .{@errorName(err)});
                };
                return;
            }
            discarded += n;
            while (self.unix_read_buf.next()) |_| {}
        }
    }

    pub fn deinit(self: *Gateway) void {
        lib_posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
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
            // A pipe stands in for the daemon socket: the drain-discard
            // and close-detection behavior under test is identical.
            const fds = try lib_posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
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

    fn peekUnixFrame(unix_out: *quic_session.UnixWriteBuf) ?UnixFrame {
        const bytes = unix_out.bytes();
        const total = ipc.expectedLength(bytes) orelse return null;
        if (bytes.len < total) return null;
        const hdr = std.mem.bytesToValue(ipc.Header, bytes[0..@sizeOf(ipc.Header)]);
        return .{ .tag = hdr.tag, .payload = bytes[@sizeOf(ipc.Header)..total], .total = total };
    }

    /// One full exchange round at a synthetic timestamp: pump client
    /// egress, run a gateway turn, feed the client, run the session
    /// pump (which queues stream egress), and flush both directions.
    /// The client PING after the session pump is the deterministic
    /// inbound trigger for the gateway's egress drain (the relay
    /// checkpoint wires a post-session drain into the production turn).
    fn sessionRound(
        loop: *Loop,
        sess: *quic_session.QuicSession,
        unix_out: *quic_session.UnixWriteBuf,
        now: i64,
    ) !void {
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(now);
        try sess.processTurn(now, unix_out);
        // The trigger PING is best-effort: after the session closes the
        // connection it is refused — the drain already happened.
        loop.client.connection().sendPing() catch {};
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(now);
        try loop.clientPump(now);
        _ = try loop.gw.runOnce(0);
        try loop.clientDrain(now);
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

test "gateway loop: established transport is exposed; stream dispatch belongs to the session" {
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

    // The borrowed established transport is the session's seam. Stream
    // data arriving before a session is attached is simply NOT consumed
    // by the gateway itself: enforcement moved to quic_session.zig
    // (wired by the relay checkpoint), which rejects it terminally.
    const t = loop.gw.quic.establishedTransport();
    try testing.expect(t != null);
    const s = try loop.client.connection().openStream();
    try loop.client.connection().sendOnStream(s, "pre-session", false);
    const now: i64 = lib_posix.nowNs();
    try loop.clientPump(now);
    _ = try loop.gw.runOnce(0);
    try loop.clientDrain(now);

    try testing.expect(loop.gw.quic.state == .established);
    try testing.expect(loop.gw.running);
    // Unconsumed: quicz still buffers the bytes (no credit granted).
    const st = (try t.?.connection().streamState(s)) orelse return error.NoStreamState;
    try testing.expect((st.receive_buffered orelse 0) > (st.receive_read_offset orelse 0));
    // The daemon pipe received nothing.
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
    sess: quic_session.QuicSession,
    unix_out: quic_session.UnixWriteBuf,
    client: quic_client.ClientSession,
} {
    var loop = try quic_test.Loop.init(alloc, psk, false);
    errdefer loop.deinit();
    try quic_test.driveHandshake(&loop);
    const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
    var sess = quic_session.QuicSession.init(alloc, t);
    errdefer sess.deinit();
    var unix_out = quic_session.UnixWriteBuf.init(alloc);
    errdefer unix_out.deinit();
    const client = try quic_client.ClientSession.init(alloc, loop.client);
    return .{ .loop = loop, .sess = sess, .unix_out = unix_out, .client = client };
}

test "zmq1 session: HELLO → ACK → RESIZE/.Init → input relay → output epoch 1" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.sess.deinit();
    defer z.unix_out.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();

    // HELLO flows; the client validates HELLO_ACK.
    var ack: ?quic_client.ControlEvent = null;
    for (0..8) |i| {
        try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + @as(i64, @intCast(i)));
        ack = try z.client.pollControl();
        if (ack != null) break;
    }
    try testing.expect(ack != null);
    try testing.expect(ack.? == .hello_ack);
    try testing.expect(z.sess.phase == .awaiting_resize);

    // The output stream opened with its header (epoch 1); the client
    // does NOT expose it until HELLO_ACK validated — which it now has.
    var epoch: u64 = 0;
    var obuf: [64]u8 = undefined;
    const on0 = try z.client.pollOutput(&obuf, &epoch);
    try testing.expect(on0 == null); // header consumed, no body yet
    try testing.expectEqual(@as(u64, 1), epoch);

    // First RESIZE → daemon `.Init` with the BE-decoded size.
    try z.client.sendResize(37, 101, 0, 0);
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 100 + @as(i64, @intCast(i)));
    {
        const f = quic_test.peekUnixFrame(&z.unix_out) orelse return error.NoInit;
        try testing.expectEqual(ipc.Tag.Init, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 37), rz.rows);
        try testing.expectEqual(@as(u16, 101), rz.cols);
        z.unix_out.consume(f.total);
    }
    try testing.expect(z.sess.phase == .active);

    // Input bytes → daemon `.Input` frames.
    try z.client.sendInput("hello-zmq1");
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 200 + @as(i64, @intCast(i)));
    {
        const f = quic_test.peekUnixFrame(&z.unix_out) orelse return error.NoInput;
        try testing.expectEqual(ipc.Tag.Input, f.tag);
        try testing.expectEqualStrings("hello-zmq1", f.payload);
        z.unix_out.consume(f.total);
    }

    // Daemon output relays on the epoch-1 output stream.
    try z.sess.offerDaemonOutput("relay-me");
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 300 + @as(i64, @intCast(i)));
    var got: []const u8 = "";
    for (0..4) |_| {
        const n = (try z.client.pollOutput(&obuf, null)) orelse continue;
        got = obuf[0..n];
        break;
    }
    try testing.expectEqualStrings("relay-me", got);

    // A second RESIZE forwards as `.Resize` — never a second `.Init`.
    try z.client.sendResize(40, 120, 0, 0);
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 400 + @as(i64, @intCast(i)));
    {
        const f = quic_test.peekUnixFrame(&z.unix_out) orelse return error.NoSecondResize;
        try testing.expectEqual(ipc.Tag.Resize, f.tag);
        const rz = std.mem.bytesToValue(ipc.Resize, f.payload[0..@sizeOf(ipc.Resize)]);
        try testing.expectEqual(@as(u16, 40), rz.rows);
        z.unix_out.consume(f.total);
    }
    try testing.expect(!z.sess.closedOrEnding());
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
        const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
        var sess = quic_session.QuicSession.init(alloc, t);
        defer sess.deinit();
        var unix_out = quic_session.UnixWriteBuf.init(alloc);
        defer unix_out.deinit();
        var client = quic_client.ClientSession.initSilent(alloc, loop.client);
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
        quic_wire.writeControlHeader(&hdr, .hello, payload.len);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &hdr, false);
        _ = try cconn.sendOnStream(quic_client.control_stream_id, &payload, false);

        const base: i64 = lib_posix.nowNs();
        var err_ev: ?quic_client.ControlEvent = null;
        for (0..10) |i| {
            try quic_test.sessionRound(&loop, &sess, &unix_out, base + @as(i64, @intCast(i)));
            err_ev = try client.pollControl();
            if (err_ev != null) break;
        }
        try testing.expect(err_ev != null);
        switch (err_ev.?) {
            .err => |e| try testing.expectEqual(c.code, e.code),
            else => return error.TestUnexpectedResult,
        }
        // Authorization precedes session data: no `.Init` was sent.
        try testing.expect(unix_out.empty());
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
    defer z.sess.deinit();
    defer z.unix_out.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();

    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + @as(i64, @intCast(i)));
    const ev = try z.client.pollControl();
    try testing.expect(ev != null and ev.? == .hello_ack);
    try z.client.sendResize(24, 80, 0, 0);
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 100 + @as(i64, @intCast(i)));
    if (quic_test.peekUnixFrame(&z.unix_out)) |f| z.unix_out.consume(f.total) else return error.NoInit;
    try testing.expect(z.sess.phase == .active);

    // Two SNAPSHOT_REQUESTs → two ERROR(unimplemented) responses, and
    // the session stays active.
    var errors_seen: usize = 0;
    for (0..2) |_| {
        try z.client.sendSnapshotRequest();
        for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 200 + @as(i64, @intCast(i)));
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
    try testing.expectEqual(@as(usize, 2), errors_seen);
    try testing.expect(!z.sess.closedOrEnding());

    // The relay still serves input after the nonterminal responses.
    try z.client.sendInput("still-alive");
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 300 + @as(i64, @intCast(i)));
    const f = quic_test.peekUnixFrame(&z.unix_out) orelse return error.NoInputAfterError;
    try testing.expectEqualStrings("still-alive", f.payload);
}

test "zmq1 session: input before RESIZE is parked, then flows strictly after .Init" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var z = try zmq1Setup(alloc, &psk);
    defer z.loop.deinit();
    defer z.sess.deinit();
    defer z.unix_out.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();

    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + @as(i64, @intCast(i)));
    const ev = try z.client.pollControl();
    try testing.expect(ev != null and ev.? == .hello_ack);

    // Input legitimately arrives BEFORE the RESIZE. The session parks
    // it: nothing rejected, nothing consumed, no credit granted.
    try z.client.sendInput("early-input");
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 100 + @as(i64, @intCast(i)));
    try testing.expect(z.sess.phase == .awaiting_resize);
    try testing.expect(z.unix_out.empty());
    {
        const st = (try z.sess.transport.connection().streamState(quic_session.input_stream_id)) orelse return error.NoStreamState;
        try testing.expect((st.receive_buffered orelse 0) > (st.receive_read_offset orelse 0));
    }

    // The first RESIZE maps to `.Init`; the parked input then flows —
    // strictly after it in the daemon-bound buffer.
    try z.client.sendResize(30, 90, 0, 0);
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 200 + @as(i64, @intCast(i)));
    {
        const f1 = quic_test.peekUnixFrame(&z.unix_out) orelse return error.NoInit;
        try testing.expectEqual(ipc.Tag.Init, f1.tag);
        z.unix_out.consume(f1.total);
        const f2 = quic_test.peekUnixFrame(&z.unix_out) orelse return error.NoParkedInput;
        try testing.expectEqual(ipc.Tag.Input, f2.tag);
        try testing.expectEqualStrings("early-input", f2.payload);
        z.unix_out.consume(f2.total);
    }
    try testing.expect(!z.sess.closedOrEnding());
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
    defer z.sess.deinit();
    defer z.unix_out.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();

    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + @as(i64, @intCast(i)));
    const ev = try z.client.pollControl();
    try testing.expect(ev != null and ev.? == .hello_ack);

    // A second bidi stream (id 4) carrying a control preface.
    const s = try z.client.transport.connection().openStream();
    try testing.expectEqual(@as(u64, 4), s);
    var pre: [8]u8 = undefined;
    quic_wire.writePreface(&pre, .control);
    try z.client.transport.connection().sendOnStream(s, &pre, false);

    var err_ev: ?quic_client.ControlEvent = null;
    for (0..10) |i| {
        try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 100 + @as(i64, @intCast(i)));
        err_ev = try z.client.pollControl();
        if (err_ev != null) break;
    }
    try testing.expect(err_ev != null);
    switch (err_ev.?) {
        .err => |e| try testing.expectEqual(quic_wire.ErrCode.stream_cardinality.code(), e.code),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(z.sess.closedOrEnding());
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
    const t = loop.gw.quic.establishedTransport() orelse return error.NotEstablished;
    var sess = quic_session.QuicSession.init(alloc, t);
    defer sess.deinit();
    var unix_out = quic_session.UnixWriteBuf.init(alloc);
    defer unix_out.deinit();

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
    try loop.clientDrain(base);
    try sess.processTurn(base, &unix_out);

    try testing.expect(sess.closed);
    try testing.expect(unix_out.empty());
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
    defer z.sess.deinit();
    defer z.unix_out.deinit();
    defer z.client.deinit();
    const base: i64 = lib_posix.nowNs();

    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + @as(i64, @intCast(i)));
    const ev = try z.client.pollControl();
    try testing.expect(ev != null and ev.? == .hello_ack);
    try z.client.sendResize(24, 80, 0, 0);
    for (0..8) |i| try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 100 + @as(i64, @intCast(i)));
    if (quic_test.peekUnixFrame(&z.unix_out)) |f| z.unix_out.consume(f.total);

    // Pending output drains and FINs before SESSION_END settles.
    try z.sess.offerDaemonOutput("last-words");
    try z.sess.onDaemonEof(base + 200);

    var end_seen = false;
    var obuf: [64]u8 = undefined;
    var got: []const u8 = "";
    // The real client drains output every turn — before the server's
    // settle-close can make buffered bytes unreadable.
    for (0..12) |i| {
        try quic_test.sessionRound(&z.loop, &z.sess, &z.unix_out, base + 200 + @as(i64, @intCast(i)));
        while (try z.client.pollControl()) |e| {
            if (e == .session_end) end_seen = true;
        }
        // Two passes per turn: the first may consume the output header
        // alone; the second drains body bytes (real clients poll both
        // streams every turn).
        _ = try z.client.pollOutput(&obuf, null);
        while (try z.client.pollOutput(&obuf, null)) |n| {
            got = obuf[0..n];
        }
        if (z.sess.closed and end_seen and got.len > 0) break;
    }
    try testing.expect(end_seen);
    try testing.expect(z.sess.closed);
    // The last output bytes reached the client before the end.
    try testing.expectEqualStrings("last-words", got);
}
