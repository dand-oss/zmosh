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

const Cfg = cfg_mod.Cfg;

const log = std.log.scoped(.serve);

/// Bounded `ZMX_ERROR` emission: numeric code, sanitized single line,
/// capped at this many bytes.
const max_error_line = 256;
/// The frozen pre-bootstrap failure code.
const gateway_init_failed = 1;
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

/// One sanitized single-line `ZMX_ERROR CODE MESSAGE`, capped at 256
/// bytes. Only printable ASCII survives sanitization.
fn emitInitError(message: []const u8) void {
    var buf: [max_error_line]u8 = undefined;
    var len = (std.fmt.bufPrint(buf[0..], "ZMX_ERROR {d} ", .{gateway_init_failed}) catch return).len;
    for (message) |c| {
        if (c < 0x20 or c > 0x7e) continue;
        if (len + 2 > buf.len) break;
        buf[len] = c;
        len += 1;
    }
    buf[len] = '\n';
    len += 1;
    _ = lib_posix.write(lib_posix.STDOUT_FILENO, buf[0..len]) catch return;
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
        const quic = try quic_gateway.QuicGateway.init(alloc, io, psk, token_secret, local, 0);
        errdefer {
            var q = quic;
            q.deinit();
        }
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
        // SIGTERM wakes poll() through the shared self-pipe.
        try signal.openSignalPipe();
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
    /// work, then due QUIC work. Tests drive this with synthetic
    /// timestamps and inert revents.
    pub fn processReadyAndDue(self: *Gateway, now: i64, poll_fds: [3]lib_posix.pollfd) !bool {
        if (poll_fds[1].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            log.info("SIGTERM received, shutting down gateway", .{});
            self.running = false;
            return false;
        }
        if (poll_fds[0].revents & lib_posix.POLL.IN != 0) {
            if (!try self.quic.receive(&self.udp_sock, now)) {
                self.running = false;
                return false;
            }
        }
        if (poll_fds[2].revents & (lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR) != 0) {
            try self.drainDaemon();
            if (!self.running) return false;
        }
        const alive = try self.quic.serviceDue(&self.udp_sock, now);
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
    /// per turn; daemon closure closes the QUIC connection and exits.
    fn drainDaemon(self: *Gateway) !void {
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
                self.running = false;
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
        var quic = self.quic;
        quic.deinit();
    }
};

/// Entry point for `zmx serve <session>`: every fallible step precedes
/// the bootstrap line; pre-success failures emit the bounded
/// `ZMX_ERROR`.
pub fn serveMain(alloc: std.mem.Allocator, io: std.Io, cfg: *const Cfg, session_name: []const u8) !void {
    const socket_path = try socket.getSocketPath(alloc, cfg.socket_dir, session_name);
    defer alloc.free(socket_path);

    const unix_fd = socket.sessionConnect(socket_path) catch |err| {
        log.err("failed to connect to daemon socket={s} err={s}", .{ socket_path, @errorName(err) });
        emitInitError(@errorName(err));
        return err;
    };
    errdefer lib_posix.close(unix_fd);
    const flags = try lib_posix.fcntl(unix_fd, lib_posix.F.GETFL, 0);
    _ = try lib_posix.fcntl(unix_fd, lib_posix.F.SETFL, flags | lib_posix.O_NONBLOCK);

    const range = portRangeFromEnv();
    var udp_sock = udp.UdpSocket.bind(range.start, range.end) catch |err| {
        emitInitError(@errorName(err));
        return err;
    };
    errdefer udp_sock.close();

    const key = crypto.generateKey(io) catch |err| {
        emitInitError(@errorName(err));
        return err;
    };
    var psk: [32]u8 = undefined;
    quic_transport.derivePsk(&psk, &key);
    var token_secret: [32]u8 = undefined;
    quic_gateway.deriveTokenSecret(&token_secret, &key);

    var gw = Gateway.init(alloc, io, unix_fd, udp_sock, &psk, &token_secret) catch |err| {
        emitInitError(@errorName(err));
        return err;
    };
    // The derived originals are dead: the gateway holds the sole
    // copies and wipes them in its deinit.
    std.crypto.secureZero(u8, &psk);
    std.crypto.secureZero(u8, &token_secret);
    defer gw.deinit();

    // Success: print, anchor the absolute handshake deadline at this
    // emission, close stdout so the SSH capture can finish.
    const encoded_key = crypto.keyToBase64(key);
    emitBootstrapLine(udp_sock.bound_port, &encoded_key) catch |err| {
        emitInitError(@errorName(err));
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
    const key = try crypto.generateKey(testing.io);
    const encoded = crypto.keyToBase64(key);
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

test "emitInitError bounds and sanitizes" {
    // A message with control characters and over-long input stays a
    // single sanitized line capped at 256 bytes.
    const long = [_]u8{0x41} ** 400 ++ [_]u8{ 0x01, 0x7f, 0x00 };
    var buf: [max_error_line]u8 = undefined;
    var len = (std.fmt.bufPrint(buf[0..], "ZMX_ERROR {d} ", .{gateway_init_failed}) catch return error.TestUnexpectedResult).len;
    for (long) |c| {
        if (c < 0x20 or c > 0x7e) continue;
        if (len + 2 > buf.len) break;
        buf[len] = c;
        len += 1;
    }
    const line = buf[0..len];
    try testing.expect(line.len < max_error_line);
    try testing.expect(std.mem.startsWith(u8, line, "ZMX_ERROR 1 "));
    for (line) |c| try testing.expect(c >= 0x20 and c <= 0x7e);
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

        fn init(alloc: std.mem.Allocator, psk: *const [32]u8) !Loop {
            // A pipe stands in for the daemon socket: the drain-discard
            // and close-detection behavior under test is identical.
            const fds = try lib_posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
            const gw_sock = try udp.UdpSocket.bind(60400, 60500);
            const client_sock = try udp.UdpSocket.bind(60600, 60700);
            var token_secret: [32]u8 = undefined;
            quic_gateway.deriveTokenSecret(&token_secret, psk);
            defer std.crypto.secureZero(u8, &token_secret);
            const gw = try Gateway.init(alloc, testing.io, fds[0], gw_sock, psk, &token_secret);
            const client = try Transport.createClient(alloc, .{
                .psk = psk,
                .scid = .{ 0x21, 0x22, 0x23, 0x24 },
                .original_dcid = .{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 },
            });
            errdefer client.destroy();
            try client.registerRoute(
                quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, client_sock.bound_port),
                quicz.endpoint.UdpAddress.init4(.{ 127, 0, 0, 1 }, gw_sock.bound_port),
            );
            try signal.openSignalPipe();
            var anchored = gw;
            anchored.quic.bootstrap_emitted_ns = lib_posix.nowNs();
            return .{
                .alloc = alloc,
                .gw = anchored,
                .daemon_fd = fds[1],
                .client_sock = client_sock,
                .client = client,
                .gw_addr = lib_posix.Address.initIp4(.{ 127, 0, 0, 1 }, gw_sock.bound_port),
                .gw_port = gw_sock.bound_port,
                .parked = .empty,
                .parked_ready = .empty,
            };
        }

        fn clientArrival(self: *const Loop) quicz.endpoint.UdpTuple {
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
            lib_posix.close(self.daemon_fd);
            var gw = self.gw;
            gw.deinit();
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
                    _ = try self.client.handleDatagram(self.clientArrival(), now, buf[0..r.len], &challenge);
                    continue;
                };
                if (info.packet_type == .handshake and !self.client.conn.hasHandshakeProtectionKeys()) {
                    try self.parked.append(self.alloc, try self.alloc.dupe(u8, buf[0..r.len]));
                    try self.parked_ready.append(self.alloc, true);
                    continue;
                }
                _ = try self.client.handleDatagram(self.clientArrival(), now, buf[0..r.len], &challenge);
            }
            try self.flushParked(now);
        }

        fn flushParked(self: *Loop, now: i64) !void {
            var i: usize = 0;
            while (i < self.parked.items.len) {
                if (!self.client.conn.hasHandshakeProtectionKeys()) {
                    i += 1;
                    continue;
                }
                _ = try self.client.handleDatagram(self.clientArrival(), now, self.parked.items[i], &challenge);
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
};

test "gateway loop: real-socket Retry transaction commits exactly once" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk);
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

test "gateway loop: pre-Q3 stream data closes the connection and exits" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    quic_transport.derivePsk(&psk, &bootstrap);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var loop = try quic_test.Loop.init(alloc, &psk);
    defer loop.deinit();
    try quic_test.driveHandshake(&loop);

    // The client sends application stream data before Q3 exists.
    const s = try loop.client.connection().openStream();
    try loop.client.connection().sendOnStream(s, "pre-q3", false);
    const now: i64 = lib_posix.nowNs();
    try loop.clientPump(now);
    _ = try loop.gw.runOnce(0);
    try loop.clientDrain(now);

    try testing.expect(loop.gw.quic.state == .closed);
    try testing.expect(!loop.gw.running);
    // The daemon socket received nothing.
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

    var loop = try quic_test.Loop.init(alloc, &psk);
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

    var loop = try quic_test.Loop.init(alloc, &psk);
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
