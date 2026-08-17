//! Q1 real-socket proofs: the certificate-free PSK handshake and 1-RTT
//! data over actual UDP sockets driven by poll() — IPv4, native IPv6,
//! and an IPv6 dual-stack server serving an IPv4-mapped client — with
//! emitted-datagram size checks against the configured 1200-byte cap.
//!
//! QUIC state uses the same sans-I/O lifecycles as the in-process
//! harness; here datagrams cross the kernel, so size assertions bind
//! real UDP payloads. Routing uses the fork's address-neutral endpoints
//! so native IPv6 paths work end to end.

const std = @import("std");
const testing = std.testing;
const quicz = @import("quicz");
const harness = @import("quic_harness.zig");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

const alpn_zmosh = harness.alpn_zmosh;
const psk_identity = harness.psk_identity;

/// Monotonic nanosecond clock for socket-driven calls.
fn clockNs(counter: *i64) i64 {
    counter.* += 1_000_000; // 1 ms per step
    return counter.*;
}

const SocketPair = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    now: i64 = 1_000,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *Connection,
    server: *Connection,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    client_path: quicz.endpoint.UdpTuple,
    server_path: quicz.endpoint.UdpTuple,
    secrets: protection.InitialSecrets,
    scratch: [16384]u8 = undefined,
    client_sock: std.Io.net.Socket,
    server_sock: std.Io.net.Socket,
    server_addr: std.Io.net.IpAddress,
    client_addr: std.Io.net.IpAddress,
    max_client_payload: usize = 0,
    max_server_payload: usize = 0,

    fn fdPoll(sock: std.Io.net.Socket) std.posix.pollfd {
        return .{ .fd = sock.handle, .events = std.posix.POLL.IN, .revents = 0 };
    }

    fn readable(sock: std.Io.net.Socket) bool {
        var fds = [1]std.posix.pollfd{fdPoll(sock)};
        const n = std.posix.poll(&fds, 0) catch return false;
        return n > 0;
    }

    fn sendToServer(self: *SocketPair, data: []const u8) !void {
        if (data.len > self.max_client_payload) self.max_client_payload = data.len;
        try self.client_sock.send(self.io, &self.server_addr, data);
    }

    fn sendToClient(self: *SocketPair, data: []const u8) !void {
        if (data.len > self.max_server_payload) self.max_server_payload = data.len;
        try self.server_sock.send(self.io, &self.client_addr, data);
    }

    /// Deliver every queued kernel datagram to its QUIC consumer.
    fn pump(self: *SocketPair) !void {
        var buf: [9000]u8 = undefined;
        while (SocketPair.readable(self.server_sock)) {
            const r = self.server_sock.receive(self.io, &buf) catch break;
            try self.deliverTo(r.data, true);
        }
        while (SocketPair.readable(self.client_sock)) {
            const r = self.client_sock.receive(self.io, &buf) catch break;
            try self.deliverTo(r.data, false);
        }
    }

    fn deliverTo(self: *SocketPair, data: []const u8, to_server: bool) !void {
        const lifecycle = if (to_server) self.server_lifecycle else self.client_lifecycle;
        const conn = if (to_server) self.server else self.client;
        const path = if (to_server) self.server_path else self.client_path;
        const handle = if (to_server) harness.server_handle else harness.client_handle;
        const now = clockNs(&self.now);

        const info = protection.peekProtectedLongPacketInfo(data) catch {
            _ = lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAddress(
                handle,
                conn,
                path,
                now,
                data,
            ) catch {};
            return;
        };
        switch (info.packet_type) {
            .initial => {
                _ = lifecycle.processRoutedProtectedInitialDatagramAddress(
                    handle,
                    conn,
                    path,
                    now,
                    &harness.original_dcid,
                    data,
                ) catch {};
            },
            .handshake => {
                _ = lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeysAddress(
                    handle,
                    conn,
                    path,
                    now,
                    data,
                ) catch {};
            },
            else => {},
        }
    }

    const PollKind = enum { long, handshake, short };

    fn pollOne(self: *SocketPair, client_side: bool, kind: PollKind) !?[]u8 {
        const lifecycle = if (client_side) self.client_lifecycle else self.server_lifecycle;
        const conn = if (client_side) self.client else self.server;
        const handle = if (client_side) harness.client_handle else harness.server_handle;
        const now = clockNs(&self.now);
        switch (kind) {
            .long => {
                if (conn.packetNumberSpaceDiscarded(.initial)) return null;
                return lifecycle.pollProtectedLongDatagram(
                    handle,
                    conn,
                    now,
                    if (client_side) &harness.original_dcid else &harness.client_scid,
                    if (client_side) &harness.client_scid else &harness.server_scid,
                    &[_]u8{},
                    .{ .initial = if (client_side) self.secrets.client else self.secrets.server },
                ) catch null;
            },
            .handshake => {
                if (!conn.hasHandshakeProtectionKeys() or conn.packetNumberSpaceDiscarded(.handshake)) return null;
                return lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
                    handle,
                    conn,
                    now,
                    if (client_side) &harness.server_scid else &harness.client_scid,
                    if (client_side) &harness.client_scid else &harness.server_scid,
                ) catch null;
            },
            .short => {
                if (!conn.hasOneRttProtectionKeys()) return null;
                return lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                    handle,
                    conn,
                    now,
                    if (client_side) &harness.server_scid else &harness.client_scid,
                ) catch null;
            },
        }
    }

    fn flushOutbound(self: *SocketPair, client_side: bool) !void {
        inline for (.{ PollKind.long, PollKind.handshake, PollKind.short }) |kind| {
            var guard: usize = 0;
            while (guard < 4) : (guard += 1) {
                const dg = (try self.pollOne(client_side, kind)) orelse break;
                defer self.alloc.free(dg);
                if (client_side) {
                    try self.sendToServer(dg);
                } else {
                    try self.sendToClient(dg);
                }
            }
        }
    }

    /// One poll()-style exchange round: outbound from both sides, pump
    /// the kernel queues, then outbound again for reactive traffic.
    fn exchange(self: *SocketPair) !void {
        try self.flushOutbound(true);
        try self.flushOutbound(false);
        try self.pump();
        try self.flushOutbound(true);
        try self.pump();
        try self.flushOutbound(false);
    }

    fn driveClientCrypto(self: *SocketPair, space: quicz.PacketNumberSpace) !void {
        if (self.client.packetNumberSpaceDiscarded(space)) return;
        _ = try self.client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            harness.client_handle,
            self.client,
            space,
            self.client_backend.cryptoBackend(),
            &self.scratch,
        );
    }

    fn driveServerCrypto(self: *SocketPair, space: quicz.PacketNumberSpace) !void {
        if (self.server.packetNumberSpaceDiscarded(space)) return;
        _ = try self.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            harness.server_handle,
            self.server,
            space,
            self.server_backend.cryptoBackend(),
            &self.scratch,
        );
    }

    /// Complete the PSK handshake over the real sockets, mirroring the
    /// in-process flight order.
    fn completeHandshake(self: *SocketPair) !void {
        try self.driveClientCrypto(.initial);
        try self.exchange();
        try self.driveServerCrypto(.initial);
        try self.exchange();
        try self.driveClientCrypto(.initial);
        try self.driveServerCrypto(.handshake);
        try self.exchange();
        try self.driveClientCrypto(.handshake);
        try self.exchange();
        try self.driveServerCrypto(.handshake);
        try self.exchange();
        if (!self.server.handshakeConfirmed()) return error.ServerNotConfirmed;
        try self.server.sendHandshakeDone();
        try self.exchange();
        if (!self.client.handshakeConfirmed()) return error.ClientNotConfirmed;
    }

    /// Send application data client->server over 1-RTT; returns what the
    /// server received.
    fn clientToServer(self: *SocketPair, stream_id: u64, bytes: []const u8, fin: bool) !?[]u8 {
        try self.client.sendOnStream(stream_id, bytes, fin);
        var rounds: usize = 0;
        while (rounds < 8) : (rounds += 1) {
            try self.exchange();
            var buf: [4096]u8 = undefined;
            if (try self.server.recvOnStream(stream_id, &buf)) |n| {
                return try self.alloc.dupe(u8, buf[0..n]);
            }
        }
        return null;
    }

    fn deinit(self: *SocketPair) void {
        const alloc = self.alloc;
        self.client.deinit();
        self.server.deinit();
        self.client_lifecycle.deinit();
        self.server_lifecycle.deinit();
        alloc.destroy(self.client_backend);
        alloc.destroy(self.server_backend);
        alloc.destroy(self.client);
        alloc.destroy(self.server);
        alloc.destroy(self.client_lifecycle);
        alloc.destroy(self.server_lifecycle);
        self.client_sock.close(self.io);
        self.server_sock.close(self.io);
        alloc.destroy(self);
    }
};

const Family = enum { ipv4, ipv6, dual_stack_v4_peer };

fn socketPairOver(alloc: std.mem.Allocator, io: std.Io, family: Family) !*SocketPair {
    const client_ip: std.Io.net.IpAddress = switch (family) {
        .ipv4, .dual_stack_v4_peer => .{ .ip4 = .loopback(0) },
        .ipv6 => .{ .ip6 = .loopback(0) },
    };
    // A dual-stack server binds :: (V6ONLY off by default on Linux) so an
    // IPv4 peer reaches it as a v4-mapped address; the pure-IPv6 server
    // binds ::1.
    const server_ip: std.Io.net.IpAddress = switch (family) {
        .ipv4 => .{ .ip4 = .loopback(0) },
        .ipv6 => .{ .ip6 = .loopback(0) },
        .dual_stack_v4_peer => .{ .ip6 = .{ .bytes = @splat(0), .port = 0 } },
    };

    const client_sock = try client_ip.bind(io, .{ .mode = .dgram, .protocol = .udp });
    const server_sock = try server_ip.bind(io, .{ .mode = .dgram, .protocol = .udp });
    const server_addr = server_sock.address;
    const client_addr = client_sock.address;
    // The client sends to the server's reachable form: the IPv4 mapping
    // of a dual-stack server, otherwise the bound address itself.
    const client_send_addr: std.Io.net.IpAddress = if (family == .dual_stack_v4_peer)
        .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = server_addr.ip6.port } }
    else
        server_addr;

    var bootstrap: [32]u8 = undefined;
    try io.randomSecure(&bootstrap);
    const psk = harness.derivePsk(bootstrap);

    const p = try alloc.create(SocketPair);
    errdefer alloc.destroy(p);
    p.* = .{
        .alloc = alloc,
        .io = io,
        .client_lifecycle = undefined,
        .server_lifecycle = undefined,
        .client = undefined,
        .server = undefined,
        .client_backend = undefined,
        .server_backend = undefined,
        .client_path = undefined,
        .server_path = undefined,
        .secrets = undefined,
        .client_sock = client_sock,
        .server_sock = server_sock,
        .server_addr = client_send_addr,
        .client_addr = client_addr,
    };

    p.client_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
    p.server_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
    p.client_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
    p.server_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);

    // Address-neutral paths: native IPv6 stays IPv6; IPv4 widens.
    const client_local: quicz.endpoint.UdpAddress = switch (client_addr) {
        .ip4 => |a| quicz.endpoint.UdpAddress.init4(a.bytes, a.port),
        .ip6 => |a| quicz.endpoint.UdpAddress.init6(a.bytes, a.port),
    };
    const server_local: quicz.endpoint.UdpAddress = switch (server_addr) {
        .ip4 => |a| quicz.endpoint.UdpAddress.init4(a.bytes, a.port),
        .ip6 => |a| quicz.endpoint.UdpAddress.init6(a.bytes, a.port),
    };
    // On the dual-stack server the kernel reports the IPv4 peer in
    // v4-mapped form (::ffff:a.b.c.d); the server-side route must use
    // exactly that view or every datagram looks like a path change.
    const server_view_of_client: quicz.endpoint.UdpAddress = blk: {
        if (family != .dual_stack_v4_peer) break :blk client_local;
        var mapped: [16]u8 = @splat(0);
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..16].* = client_addr.ip4.bytes;
        break :blk quicz.endpoint.UdpAddress.init6(mapped, client_addr.ip4.port);
    };
    p.client_path = .{ .local = client_local, .remote = server_local };
    p.server_path = .{ .local = server_local, .remote = server_view_of_client };

    // Route registration goes through the fork's neutral endpoints so
    // every family works identically.
    try p.client_lifecycle.router.registerConnectionIdAddress(
        harness.client_handle,
        &harness.client_scid,
        p.client_path,
        .{ .active_migration_disabled = true },
    );
    try p.server_lifecycle.router.registerConnectionIdAddress(
        harness.server_handle,
        &harness.original_dcid,
        p.server_path,
        .{ .active_migration_disabled = true },
    );
    try p.server_lifecycle.router.registerConnectionIdAddress(
        harness.server_handle,
        &harness.server_scid,
        p.server_path,
        .{ .active_migration_disabled = true },
    );

    const conn_cfg = quicz.Config{
        .initial_max_data = 8192,
        .initial_max_stream_data = 2048,
        .initial_max_streams_bidi = 8,
        .max_datagram_size = 1200,
    };
    p.client = try alloc.create(Connection);
    p.server = try alloc.create(Connection);
    p.client.* = try Connection.init(alloc, .client, conn_cfg);
    p.server.* = try Connection.init(alloc, .server, conn_cfg);
    try p.server.validatePeerAddress();
    try p.client.setLocalInitialSourceConnectionId(&harness.client_scid);
    try p.server.setLocalInitialSourceConnectionId(&harness.server_scid);

    p.client_backend = try alloc.create(Tls13Backend);
    p.client_backend.* = Tls13Backend.initClientWithPsk(.{
        .alpn = &alpn_zmosh,
        .server_name = "zmosh",
        .disable_session_resumption = true,
    }, psk);
    try p.client_backend.setClientPskIdentity(psk_identity);

    p.server_backend = try alloc.create(Tls13Backend);
    p.server_backend.* = Tls13Backend.initServerWithPsk(.{
        .alpn = &alpn_zmosh,
        .disable_session_resumption = true,
    }, psk);
    try p.server_backend.setServerPskIdentity(psk_identity);

    p.secrets = try protection.deriveInitialSecrets(.v1, &harness.original_dcid);
    return p;
}

fn assertSocketHandshakeAndEcho(
    alloc: std.mem.Allocator,
    io: std.Io,
    family: Family,
    label: []const u8,
) !void {
    var p = try socketPairOver(alloc, io, family);
    defer p.deinit();

    try p.completeHandshake();
    try testing.expect(p.server.handshakeConfirmed());
    try testing.expect(p.client.handshakeConfirmed());

    // QUIC Initial datagrams must be padded to at least 1200 bytes on a
    // real socket, and nothing exceeds the configured 1200-byte cap.
    try testing.expect(p.max_client_payload >= 1200);
    try testing.expect(p.max_client_payload <= 1200);
    try testing.expect(p.max_server_payload <= 1200);

    const s = try p.client.openStream();
    const got = try p.clientToServer(s, label, true);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings(label, got.?);
}

test "real sockets: IPv4 loopback PSK handshake, 1200-byte Initials, 1-RTT echo" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try assertSocketHandshakeAndEcho(alloc, io, .ipv4, "v4-socket-echo");
}

test "real sockets: native IPv6 loopback PSK handshake and 1-RTT echo" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try assertSocketHandshakeAndEcho(alloc, io, .ipv6, "v6-socket-echo");
}

test "real sockets: IPv6 dual-stack server serves an IPv4-mapped client" {
    const alloc = testing.allocator;
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // The server socket is IPv6 (dual-stack on Linux by default); the
    // client is IPv4, reaching it as a v4-mapped peer.
    try assertSocketHandshakeAndEcho(alloc, io, .dual_stack_v4_peer, "dual-stack-echo");
}
