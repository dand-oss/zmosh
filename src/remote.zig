const std = @import("std");
const lib_posix = @import("posix.zig");
const signal = @import("signal.zig");
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const builtin = @import("builtin");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_stdout_buf = 4 * 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const resync_cooldown_ns = 250 * std.time.ns_per_ms;

const c = switch (builtin.os.tag) {
    .macos => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    .freebsd => @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    else => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
};

const log = std.log.scoped(.remote);

pub const RemoteSession = struct {
    host: []const u8,
    port: u16,
    key: crypto.Key,
    /// SSH bootstrap child. Attach keeps it alive for the session and
    /// reaps it on exit; one-shot commands (stage 3) reap immediately.
    ssh: std.process.Child,
};

/// Terminate and reap the SSH bootstrap child. Child.kill blocks until the
/// child exits and reaps it (idempotent); wait() after kill would assert.
fn reapSsh(session: *RemoteSession, io: std.Io) void {
    session.ssh.kill(io);
}

/// Parse a ZMX_CONNECT line: "ZMX_CONNECT udp <port> <base64_key>\n"
pub fn parseConnectLine(line: []const u8) !struct { port: u16, key: crypto.Key } {
    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
    var it = std.mem.splitScalar(u8, trimmed, ' ');

    const prefix = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, prefix, "ZMX_CONNECT")) return error.InvalidConnectLine;

    const proto = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, proto, "udp")) return error.UnsupportedProtocol;

    const port_str = it.next() orelse return error.InvalidConnectLine;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

    const key_str = it.next() orelse return error.InvalidConnectLine;
    const key = crypto.keyFromBase64(key_str) catch return error.InvalidKey;

    return .{ .port = port, .key = key };
}

/// Bootstrap a remote session via SSH: ssh <host> zmosh serve <session>
/// Prepends common user bin dirs to PATH since SSH non-interactive sessions
/// often have a minimal PATH that excludes ~/.local/bin, ~/bin, etc.
fn appendShellQuoted(out: *std.ArrayList(u8), alloc: std.mem.Allocator, arg: []const u8) !void {
    try out.append(alloc, '\'');
    for (arg) |ch| {
        if (ch == '\'') try out.appendSlice(alloc, "'\\''") else try out.append(alloc, ch);
    }
    try out.append(alloc, '\'');
}

pub fn connectRemote(
    alloc: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    session: []const u8,
    command: ?[][]const u8,
) !RemoteSession {
    const term = lib_posix.getenv("TERM") orelse "xterm-256color";
    const colorterm = lib_posix.getenv("COLORTERM");
    var remote_cmd_buf: std.ArrayList(u8) = .empty;
    defer remote_cmd_buf.deinit(alloc);
    // Shell-quote TERM/COLORTERM: raw values with metacharacters must not
    // be able to alter the remote command line.
    try remote_cmd_buf.appendSlice(alloc, "TERM=");
    try appendShellQuoted(&remote_cmd_buf, alloc, term);
    try remote_cmd_buf.append(alloc, ' ');
    if (colorterm) |ct| {
        try remote_cmd_buf.appendSlice(alloc, "COLORTERM=");
        try appendShellQuoted(&remote_cmd_buf, alloc, ct);
        try remote_cmd_buf.append(alloc, ' ');
    }
    // --exact-session: `sesh` is already prefix-resolved locally; the remote
    // gateway must not apply ZMX_SESSION_PREFIX a second time.
    try remote_cmd_buf.appendSlice(alloc, "PATH=\"$PATH:/opt/homebrew/bin:$HOME/bin:$HOME/.local/bin\" zmosh serve --exact-session ");
    try appendShellQuoted(&remote_cmd_buf, alloc, session);
    if (command) |args| {
        for (args) |arg| {
            try remote_cmd_buf.append(alloc, ' ');
            try appendShellQuoted(&remote_cmd_buf, alloc, arg);
        }
    }
    const remote_cmd = try remote_cmd_buf.toOwnedSlice(alloc);
    defer alloc.free(remote_cmd);
    // ZMX_SSH overrides the SSH executable (tests use a local shim).
    const ssh_exe = lib_posix.getenv("ZMX_SSH") orelse "ssh";
    const argv = [_][]const u8{ ssh_exe, host, "--", remote_cmd };
    // stdin is .ignore so SSH can never steal the terminal's stdin.
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    }) catch |err| {
        log.err("failed to spawn SSH: {s}", .{@errorName(err)});
        return error.SshSpawnFailed;
    };
    errdefer child.kill(io);

    // Read the bootstrap line from SSH stdout with a bounded 10s wait.
    const stdout_fd = child.stdout.?.handle;
    var buf: [512]u8 = undefined;
    var total: usize = 0;

    outer: while (total < buf.len) {
        var poll_fds = [_]lib_posix.pollfd{.{ .fd = stdout_fd, .events = lib_posix.POLL.IN, .revents = 0 }};
        const ready = lib_posix.poll(&poll_fds, ssh_bootstrap_timeout_ms) catch break;
        if (ready == 0) {
            log.err("timed out waiting for the remote gateway to start", .{});
            return error.SshBootstrapTimeout;
        }
        const n = lib_posix.read(stdout_fd, buf[total..]) catch |err| {
            log.err("failed to read SSH stdout: {s}", .{@errorName(err)});
            return error.SshReadFailed;
        };
        if (n == 0) break;
        total += n;
        if (std.mem.indexOf(u8, buf[0..total], "\n") != null) break :outer;
    }

    if (total == 0) return error.SshNoOutput;

    const result = parseConnectLine(buf[0..total]) catch |err| {
        log.err("failed to parse connect line: {s}", .{@errorName(err)});
        return error.InvalidConnectLine;
    };

    // We have the connect info; close our end of the pipe. The child is
    // kept in RemoteSession and reaped by the attach/command caller.
    if (child.stdout) |f| f.close(io);
    child.stdout = null;

    return .{
        .host = host,
        .port = result.port,
        .key = result.key,
        .ssh = child,
    };
}

/// Bootstrap read deadline on the SSH stdout pipe.
const ssh_bootstrap_timeout_ms: i32 = 10_000;

fn getTerminalSize() ipc.Resize {
    var ws: c.struct_winsize = undefined;
    if (c.ioctl(lib_posix.STDOUT_FILENO, c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
        return .{ .rows = ws.ws_row, .cols = ws.ws_col, .xpixel = ws.ws_xpixel, .ypixel = ws.ws_ypixel };
    }
    return .{ .rows = 24, .cols = 80 };
}

/// Detects Kitty keyboard protocol escape sequence for Ctrl+\
fn isKittyCtrlBackslash(buf: []const u8) bool {
    return std.mem.indexOf(u8, buf, "\x1b[92;5u") != null or
        std.mem.indexOf(u8, buf, "\x1b[92;5:1u") != null;
}

fn sendHeartbeat(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_recv: *const transport.RecvState,
    last_ack_send_ns: *i64,
    ack_dirty: *bool,
    now: i64,
) !void {
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        "",
        &pkt_buf,
    );
    try peer.send(sock, pkt);
    last_ack_send_ns.* = now;
    ack_dirty.* = false;
}

fn sendReliablePayload(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    channel: transport.Channel,
    payload: []const u8,
    now: i64,
) !void {
    const packet = try reliable_send.buildAndTrack(
        channel,
        payload,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        now,
    );
    peer.send(sock, packet) catch |err| {
        if (err == error.NoPeerAddress or err == error.WouldBlock) return;
        return err;
    };
}

fn sendIpcReliable(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    tag: ipc.Tag,
    payload: []const u8,
    now: i64,
) !void {
    if (payload.len <= max_ipc_payload) {
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
        try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .reliable_ipc, ipc_bytes, now);
        return;
    }

    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
        try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .reliable_ipc, ipc_bytes, now);
        off = end;
    }
}

fn requestResync(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    last_resync_request_ns: *i64,
    now: i64,
) !void {
    if ((now - last_resync_request_ns.*) < resync_cooldown_ns) return;

    var ctrl_buf: [8]u8 = undefined;
    const payload = transport.buildControl(.resync_request, &ctrl_buf);
    try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .control, payload, now);
    last_resync_request_ns.* = now;
}

/// Resolve an SSH-config alias to a real hostname via `ssh -G HOST`.
/// Returns the input host unchanged on any failure (spawn error, parse
/// miss, or a ZMX_SSH test shim that doesn't implement -G) — the caller
/// falls back to connecting UDP to the supplied host string.
fn resolveSshHost(alloc: std.mem.Allocator, io: std.Io, host: []const u8) []const u8 {
    const ssh_exe = lib_posix.getenv("ZMX_SSH") orelse "ssh";
    const argv = [_][]const u8{ ssh_exe, "-G", host };
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    }) catch return host;
    defer child.kill(io);

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        var poll_fds = [_]lib_posix.pollfd{.{ .fd = child.stdout.?.handle, .events = lib_posix.POLL.IN, .revents = 0 }};
        const ready = lib_posix.poll(&poll_fds, ssh_bootstrap_timeout_ms) catch break;
        if (ready == 0) break;
        const n = lib_posix.read(child.stdout.?.handle, buf[total..]) catch break;
        if (n == 0) break;
        total += n;
    }

    // `ssh -G` emits `hostname <value>` among its config lines.
    var lines = std.mem.splitScalar(u8, buf[0..total], '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "hostname ")) {
            const resolved = std.mem.trim(u8, line["hostname ".len..], " \t\r");
            if (resolved.len > 0 and !std.mem.eql(u8, resolved, host)) {
                return alloc.dupe(u8, resolved) catch host;
            }
        }
    }
    return host;
}

/// Remote attach: connect to a remote zmx session via UDP.
pub fn remoteAttach(alloc: std.mem.Allocator, io: std.Io, session: RemoteSession) !void {
    var session_mut = session;
    defer reapSsh(&session_mut, io);

    // UDP goes to the resolved host, not the SSH alias: user@host forms and
    // ssh-config Host aliases would otherwise fail DNS after bootstrap.
    const udp_host = resolveSshHost(alloc, io, session.host);
    defer if (udp_host.ptr != session.host.ptr) alloc.free(udp_host);

    // Resolve host address (numeric IP or DNS via getaddrinfo)
    const addr = try lib_posix.resolveHost(udp_host, session.port);

    // Create UDP socket — bind ephemeral port (OS picks)
    const sock_fd = try lib_posix.socket(
        addr.any.family,
        lib_posix.SOCK.DGRAM | lib_posix.SOCK.NONBLOCK | lib_posix.SOCK.CLOEXEC,
        0,
    );
    var udp_sock = udp_mod.UdpSocket{ .fd = sock_fd, .bound_port = 0 };
    defer udp_sock.close();

    // Create peer
    var peer = udp_mod.Peer.init(session.key, .to_server);
    peer.addr = addr;

    var reliable_send = try transport.ReliableSend.init(alloc);
    defer reliable_send.deinit();
    var reliable_recv = transport.RecvState{};
    var output_recv = transport.OutputRecvState{};

    // Set terminal to raw mode
    var orig_termios: c.termios = undefined;
    _ = c.tcgetattr(lib_posix.STDIN_FILENO, &orig_termios);
    defer {
        _ = c.tcsetattr(lib_posix.STDIN_FILENO, c.TCSAFLUSH, &orig_termios);
        const restore_seq = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" ++
            "\x1b[?2004l\x1b[?1004l\x1b[?1049l" ++
            // Restore pre-attach Kitty keyboard protocol mode so Ctrl combos
            // return to legacy encoding in the user's outer shell.
            "\x1b[<u" ++
            "\x1b[?25h";
        _ = lib_posix.write(lib_posix.STDOUT_FILENO, restore_seq) catch {};
    }

    var raw_termios = orig_termios;
    c.cfmakeraw(&raw_termios);
    raw_termios.c_cc[c.VLNEXT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VQUIT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VMIN] = 1;
    raw_termios.c_cc[c.VTIME] = 0;
    _ = c.tcsetattr(lib_posix.STDIN_FILENO, c.TCSANOW, &raw_termios);

    // Clear screen before attaching. We do NOT use the alternate screen
    // (\x1b[?1049h) because it has no scrollback buffer.
    _ = try lib_posix.write(lib_posix.STDOUT_FILENO, "\x1b[2J\x1b[H");

    // SIGWINCH wakes poll() through the shared self-pipe.
    try signal.openSignalPipe();
    signal.installWakeHandler(@intFromEnum(lib_posix.SIG.WINCH));

    // Make stdin non-blocking
    const stdin_flags = try lib_posix.fcntl(lib_posix.STDIN_FILENO, lib_posix.F.GETFL, 0);
    _ = try lib_posix.fcntl(lib_posix.STDIN_FILENO, lib_posix.F.SETFL, stdin_flags | lib_posix.O_NONBLOCK);

    const config = udp_mod.Config{};
    var stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer stdout_buf.deinit(alloc);
    var was_disconnected = false;
    var session_ended = false;

    var last_ack_send_ns: i64 = lib_posix.nowNs();
    var ack_dirty = false;
    var last_resync_request_ns: i64 = 0;

    // Send Init message with terminal size (reliable)
    const size = getTerminalSize();
    var init_buf: [64]u8 = undefined;
    const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
    try sendReliablePayload(&peer, &udp_sock, &reliable_send, &reliable_recv, .reliable_ipc, init_ipc, last_ack_send_ns);

    while (true) {
        const now: i64 = lib_posix.nowNs();

        // Retransmit reliable packets based on adaptive RTO.
        var retransmits = try reliable_send.collectRetransmits(alloc, now, peer.rto_us());
        defer retransmits.deinit(alloc);
        for (retransmits.items) |pkt| {
            peer.send(&udp_sock, pkt) catch {};
        }

        // Ack heartbeat + keepalive heartbeat.
        if (ack_dirty and (now - last_ack_send_ns) >= ack_delay_ns) {
            sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
        } else if (peer.shouldSendHeartbeat(now, config)) {
            sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
        }

        // State check
        const state = peer.updateState(now, config);
        if (state == .dead) {
            _ = lib_posix.write(lib_posix.STDOUT_FILENO, "\r\nzmosh: connection lost permanently\r\n") catch {};
            return error.ConnectionLost;
        }
        if (state == .disconnected and !was_disconnected) {
            _ = lib_posix.write(lib_posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b[7mzmosh: connection lost — waiting to reconnect...\x1b[27m\x1b8") catch {};
            was_disconnected = true;
        } else if (state == .connected and was_disconnected) {
            _ = lib_posix.write(lib_posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b8") catch {};
            was_disconnected = false;
        }

        // Build poll fds: stdin, UDP socket, signal pipe, optional stdout.
        var poll_fds: [4]lib_posix.pollfd = undefined;
        var poll_count: usize = 3;
        poll_fds[0] = .{ .fd = lib_posix.STDIN_FILENO, .events = lib_posix.POLL.IN, .revents = 0 };
        poll_fds[1] = .{ .fd = udp_sock.getFd(), .events = lib_posix.POLL.IN, .revents = 0 };
        poll_fds[2] = .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = 0 };
        if (stdout_buf.items.len > 0) {
            poll_fds[3] = .{ .fd = lib_posix.STDOUT_FILENO, .events = lib_posix.POLL.OUT, .revents = 0 };
            poll_count = 4;
        }

        var poll_timeout: i64 = @min(@as(i64, config.heartbeat_interval_ms), 500);
        if (reliable_send.hasPending()) {
            const rto_ms = @divFloor(peer.rto_us(), 1000);
            poll_timeout = @min(poll_timeout, @max(@as(i64, 1), rto_ms));
        }
        if (ack_dirty) poll_timeout = @min(poll_timeout, @as(i64, 20));

        _ = try lib_posix.poll(poll_fds[0..poll_count], @intCast(poll_timeout));

        // SIGWINCH arrived via the self-pipe
        if (poll_fds[2].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            const new_size = getTerminalSize();
            try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Resize, std.mem.asBytes(&new_size), now);
        }

        // STDIN → reliable IPC over UDP
        if (poll_fds[0].revents & (lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR) != 0) {
            var input_raw: [4096]u8 = undefined;
            const n_opt: ?usize = lib_posix.read(lib_posix.STDIN_FILENO, &input_raw) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };
            if (n_opt) |n| {
                if (n > 0) {
                    if (input_raw[0] == 0x1C or isKittyCtrlBackslash(input_raw[0..n])) {
                        try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Detach, "", now);
                        return;
                    }
                    try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Input, input_raw[0..n], now);
                } else {
                    return; // EOF on stdin
                }
            }
        }

        // UDP recv → decode transport packets
        if (poll_fds[1].revents & lib_posix.POLL.IN != 0) {
            while (true) {
                var decrypt_buf: [9000]u8 = undefined;
                const recv_result = try peer.recv(&udp_sock, &decrypt_buf);
                const result = recv_result orelse break;

                const packet = transport.parsePacket(result.data) catch continue;
                reliable_send.ack(packet.ack, packet.ack_bits);

                switch (packet.channel) {
                    .heartbeat => {},
                    .control => {
                        ack_dirty = true;
                        if (reliable_recv.onReliable(packet.seq) != .accept) continue;
                    },
                    .reliable_ipc => {
                        ack_dirty = true;
                        if (reliable_recv.onReliable(packet.seq) != .accept) continue;

                        var offset: usize = 0;
                        while (offset < packet.payload.len) {
                            const remaining = packet.payload[offset..];
                            const msg_len = ipc.expectedLength(remaining) orelse break;
                            if (remaining.len < msg_len) break;

                            const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                            const payload = remaining[@sizeOf(ipc.Header)..msg_len];

                            if (hdr.tag == .Output and payload.len > 0) {
                                if (stdout_buf.items.len + payload.len > max_stdout_buf) {
                                    stdout_buf.clearRetainingCapacity();
                                    try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                                } else {
                                    try stdout_buf.appendSlice(alloc, payload);
                                }
                            } else if (hdr.tag == .SessionEnd) {
                                session_ended = true;
                            }

                            offset += msg_len;
                        }
                    },
                    .output => {
                        switch (output_recv.onPacket(packet.seq)) {
                            .accept => {
                                if (packet.payload.len == 0) continue;
                                if (stdout_buf.items.len + packet.payload.len > max_stdout_buf) {
                                    stdout_buf.clearRetainingCapacity();
                                    try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                                } else {
                                    try stdout_buf.appendSlice(alloc, packet.payload);
                                }
                            },
                            .gap => {
                                try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, now);
                            },
                            .duplicate, .stale => {},
                        }
                    },
                }
            }
        }

        // Flush stdout
        if (poll_count == 4 and poll_fds[3].revents & lib_posix.POLL.OUT != 0) {
            if (stdout_buf.items.len > 0) {
                const written = lib_posix.write(lib_posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    return err;
                };
                if (written > 0) {
                    try stdout_buf.replaceRange(alloc, 0, written, &[_]u8{});
                }
            }
        }

        if (session_ended) {
            if (stdout_buf.items.len > 0) {
                _ = lib_posix.write(lib_posix.STDOUT_FILENO, stdout_buf.items) catch {};
            }
            _ = lib_posix.write(lib_posix.STDOUT_FILENO, "\r\nzmosh: remote session ended\r\n") catch {};
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "appendShellQuoted escapes metacharacters" {
    const cases = [_]struct { in: []const u8, out: []const u8 }{
        .{ .in = "plain", .out = "'plain'" },
        .{ .in = "with space", .out = "'with space'" },
        .{ .in = "it's", .out = "'it'\\''s'" },
        .{ .in = "a;b", .out = "'a;b'" },
        .{ .in = "$HOME", .out = "'$HOME'" },
        .{ .in = "-leading-dash", .out = "'-leading-dash'" },
    };
    for (cases) |case| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(std.testing.allocator);
        try appendShellQuoted(&buf, std.testing.allocator, case.in);
        try std.testing.expectEqualStrings(case.out, buf.items);
    }
}

test "appendShellQuoted survives round-trip through a shell word" {
    // newline must stay inside the quotes, not break the command
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try appendShellQuoted(&buf, std.testing.allocator, "two\nlines");
    try std.testing.expectEqualStrings("'two\nlines'", buf.items);
}

test "parseConnectLine valid" {
    const result = try parseConnectLine("ZMX_CONNECT udp 60042 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    try std.testing.expect(result.port == 60042);
}

test "parseConnectLine invalid prefix" {
    try std.testing.expectError(error.InvalidConnectLine, parseConnectLine("INVALID udp 60042 key\n"));
}

test "parseConnectLine unsupported protocol" {
    try std.testing.expectError(error.UnsupportedProtocol, parseConnectLine("ZMX_CONNECT tcp 60042 key\n"));
}
