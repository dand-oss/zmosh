const std = @import("std");
const ghostty_vt = @import("ghostty-vt");
const ipc = @import("ipc.zig");
const log = @import("log.zig");
const util = @import("util.zig");
const cross = @import("cross.zig");
const socket = @import("socket.zig");
const label = @import("label.zig");
const lib_posix = @import("posix.zig");
const Cfg = @import("cfg.zig");
const signal = @import("signal.zig");
const assert = std.debug.assert;
const daemonize = @import("daemonize.zig");
const builtin = @import("builtin");

/// clientLoop sends ipc commands to its corresponding daemon.  It uses poll() as its non-blocking
/// mechanism. It will send stdin to the daemon and receive stdout from the daemon.
pub fn clientLoop(client_sock_fd: i32) !ClientResult {
    std.log.info("client loop fd={d}", .{client_sock_fd});
    const gpa: std.mem.Allocator = blk: {
        if (builtin.mode == .Debug) {
            const GPA = std.heap.DebugAllocator(.{});
            const Static = struct {
                var gpa: GPA = .{};
            };
            break :blk Static.gpa.allocator();
        }
        break :blk std.heap.c_allocator;
    };
    defer lib_posix.close(client_sock_fd);

    try signal.openSignalPipe();
    signal.installWakeHandler(@intFromEnum(lib_posix.SIG.WINCH));

    // Make socket non-blocking to avoid blocking on writes
    var sock_flags = try lib_posix.fcntl(client_sock_fd, lib_posix.F.GETFL, 0);
    sock_flags |= lib_posix.O_NONBLOCK;
    _ = try lib_posix.fcntl(client_sock_fd, lib_posix.F.SETFL, sock_flags);

    // Buffer for outgoing socket writes
    var sock_write_buf = try std.ArrayList(u8).initCapacity(gpa, 4096);
    defer sock_write_buf.deinit(gpa);

    // Send init message with terminal size (buffered)
    const size = ipc.getTerminalSize(lib_posix.STDOUT_FILENO);
    try ipc.appendMessage(gpa, &sock_write_buf, .Init, std.mem.asBytes(&size));

    var poll_fds = try std.ArrayList(lib_posix.pollfd).initCapacity(gpa, 4);
    defer poll_fds.deinit(gpa);

    var read_buf = try ipc.SocketBuffer.init(gpa);
    defer read_buf.deinit();

    var stdout_buf = try std.ArrayList(u8).initCapacity(gpa, 4096);
    defer stdout_buf.deinit(gpa);

    const stdin_fd = lib_posix.STDIN_FILENO;

    // Make stdin non-blocking. O_NONBLOCK is set on the open file description,
    // which is shared with the parent shell; restore on exit to avoid
    // corrupting the parent's stdin.
    const stdin_orig_flags = try lib_posix.fcntl(stdin_fd, lib_posix.F.GETFL, 0);
    _ = try lib_posix.fcntl(stdin_fd, lib_posix.F.SETFL, stdin_orig_flags | lib_posix.O_NONBLOCK);
    defer _ = lib_posix.fcntl(stdin_fd, lib_posix.F.SETFL, stdin_orig_flags) catch {};

    const detach_key_disabled = util.isDetachKeyDisabled();

    while (true) {
        poll_fds.clearRetainingCapacity();

        try poll_fds.append(gpa, .{
            .fd = stdin_fd,
            .events = lib_posix.POLL.IN,
            .revents = 0,
        });

        // Poll socket for read, and also for write if we have pending data
        var sock_events: i16 = lib_posix.POLL.IN;
        if (sock_write_buf.items.len > 0) {
            sock_events |= lib_posix.POLL.OUT;
        }
        try poll_fds.append(gpa, .{
            .fd = client_sock_fd,
            .events = sock_events,
            .revents = 0,
        });

        try poll_fds.append(gpa, .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = 0 });

        if (stdout_buf.items.len > 0) {
            try poll_fds.append(gpa, .{
                .fd = lib_posix.STDOUT_FILENO,
                .events = lib_posix.POLL.OUT,
                .revents = 0,
            });
        }

        _ = try lib_posix.poll(poll_fds.items, -1);

        if (poll_fds.items[2].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            const next_size = ipc.getTerminalSize(lib_posix.STDOUT_FILENO);
            try ipc.appendMessage(gpa, &sock_write_buf, .Resize, std.mem.asBytes(&next_size));
        }

        // Handle stdin -> socket (Input)
        const inp_flags = (lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL);
        if (poll_fds.items[0].revents & inp_flags != 0) {
            var buf: [4096]u8 = undefined;
            const n_opt: ?usize = lib_posix.read(stdin_fd, &buf) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };

            if (n_opt) |n| {
                if (n > 0) {
                    // Check for detach sequences (ctrl+\ as first byte or Kitty escape sequence)
                    if (!detach_key_disabled and util.isCtrlBackslash(buf[0..n])) {
                        std.log.info("detach key detected", .{});
                        try ipc.appendMessage(gpa, &sock_write_buf, .Detach, "");
                    } else {
                        try ipc.appendMessage(gpa, &sock_write_buf, .Input, buf[0..n]);
                    }
                } else {
                    std.log.info("eof stdin", .{});
                    // EOF on stdin
                    return ClientResult{ .kind = .detach, .session_name = null };
                }
            }
        }

        // Handle socket read (incoming Output messages from daemon)
        if (poll_fds.items[1].revents & lib_posix.POLL.IN != 0) {
            const n = read_buf.read(client_sock_fd) catch |err| {
                if (err == error.WouldBlock) continue;
                if (err == error.ConnectionResetByPeer or err == error.BrokenPipe) {
                    return ClientResult{ .kind = .detach, .session_name = null };
                }
                std.log.err("daemon read err={s}", .{@errorName(err)});
                return err;
            };
            if (n == 0) {
                std.log.info("server closed connection", .{});
                // Server closed connection
                return ClientResult{ .kind = .detach, .session_name = null };
            }

            while (read_buf.next()) |msg| {
                switch (msg.header.tag) {
                    .Output => {
                        if (msg.payload.len > 0) {
                            try stdout_buf.appendSlice(gpa, msg.payload);
                        }
                    },
                    .Resize => {
                        // daemon is asking for the client's window size usually in response
                        // to this client being set as leader.
                        const next_size = ipc.getTerminalSize(lib_posix.STDOUT_FILENO);
                        try ipc.appendMessage(
                            gpa,
                            &sock_write_buf,
                            .Resize,
                            std.mem.asBytes(&next_size),
                        );
                    },
                    .Switch => {
                        std.log.info("switch session", .{});
                        // Payload format: "session_name\ncwd" from the daemon
                        const newline_idx = std.mem.indexOfScalar(u8, msg.payload, '\n') orelse {
                            // No cwd provided (backward compat or old daemon)
                            return ClientResult{ .kind = .switch_session, .session_name = try gpa.dupe(u8, msg.payload) };
                        };
                        return ClientResult{
                            .kind = .switch_session,
                            .session_name = try gpa.dupe(u8, msg.payload[0..newline_idx]),
                            .cwd = if (newline_idx + 1 < msg.payload.len) try gpa.dupe(u8, msg.payload[newline_idx + 1 ..]) else null,
                        };
                    },
                    else => {},
                }
            }
        }

        // Handle socket write (flush buffered messages to daemon)
        if (poll_fds.items[1].revents & lib_posix.POLL.OUT != 0) {
            if (sock_write_buf.items.len > 0) {
                const n = lib_posix.write(client_sock_fd, sock_write_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    if (err == error.ConnectionResetByPeer or err == error.BrokenPipe) {
                        std.log.info("connection reset or broken pipe", .{});
                        return ClientResult{ .kind = .detach, .session_name = null };
                    }
                    return err;
                };
                if (n > 0) {
                    try sock_write_buf.replaceRange(gpa, 0, n, &[_]u8{});
                }
            }
        }

        if (stdout_buf.items.len > 0) {
            const n = lib_posix.write(lib_posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                if (err == error.WouldBlock) break :blk 0;
                return err;
            };
            if (n > 0) {
                try stdout_buf.replaceRange(gpa, 0, n, &[_]u8{});
            }
        }

        if (poll_fds.items[1].revents & (lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL) != 0) {
            std.log.info("poll hup|err|nval", .{});
            return ClientResult{ .kind = .detach, .session_name = null };
        }
    }
}

/// dameonLoop is what the daemon runs to send and receive ipc commands from its corresponding
/// clients.  It uses poll() as its non-blocking mechanism.
fn daemonLoop(daemon: *Daemon, gpa: std.mem.Allocator, io: std.Io, server_sock_fd: lib_posix.socket_t, pty_fd: i32) !void {
    std.log.info("daemon started session={s} pty_fd={d}", .{ daemon.session_name, pty_fd });

    try signal.openSignalPipe();
    signal.installWakeHandler(@intFromEnum(lib_posix.SIG.TERM));
    var poll_fds = try std.ArrayList(lib_posix.pollfd).initCapacity(gpa, 8);
    defer poll_fds.deinit(gpa);

    const init_size = ipc.getTerminalSize(pty_fd);
    var term = try ghostty_vt.Terminal.init(io, gpa, .{
        .cols = init_size.cols,
        .rows = init_size.rows,
        .max_scrollback_lines = daemon.cfg.max_scrollback_lines,
    });
    defer term.deinit(gpa);
    // One persistent continuation-tracking stream, created here — before
    // the loop can feed the first PTY byte — so a snapshot cut can export
    // the minimal unfinished VT/UTF-8 input (bounded by the tracker cap)
    // instead of reconstructing it from serialized output.
    var vt_stream = ghostty_vt.TerminalStream.init(.{
        .allocator = gpa,
        .handler = term.vtHandler(),
        .continuation_max_bytes = Daemon.snapshot_continuation_max,
    });
    defer vt_stream.deinit();

    // Carries the tail of the previous PTY read so the task-exit marker
    // search below can see across a read() boundary. Sized to comfortably
    // hold "ZMX_TASK_COMPLETED:" (19 bytes) plus a u8 exit code and CRLF.
    var marker_carry: [32]u8 = undefined;
    var marker_carry_len: usize = 0;

    daemon_loop: while (daemon.running) {
        poll_fds.clearRetainingCapacity();

        try poll_fds.append(gpa, .{
            .fd = server_sock_fd,
            .events = lib_posix.POLL.IN,
            .revents = 0,
        });

        var pty_events: i16 = lib_posix.POLL.IN;
        if (daemon.pty_write_buf.items.len > 0) {
            pty_events |= lib_posix.POLL.OUT;
        }
        try poll_fds.append(gpa, .{
            .fd = pty_fd,
            .events = pty_events,
            .revents = 0,
        });

        try poll_fds.append(gpa, .{ .fd = signal.sig_pipe[0], .events = lib_posix.POLL.IN, .revents = 0 });

        for (daemon.clients.items) |client| {
            var events: i16 = lib_posix.POLL.IN;
            if (client.has_pending_output) {
                events |= lib_posix.POLL.OUT;
            }
            try poll_fds.append(gpa, .{
                .fd = client.socket_fd,
                .events = events,
                .revents = 0,
            });
        }

        _ = try lib_posix.poll(poll_fds.items, -1);

        if (poll_fds.items[2].revents & lib_posix.POLL.IN != 0) {
            signal.drainSignalPipe();
            std.log.info(
                "SIGTERM received, shutting down gracefully session={s}",
                .{daemon.session_name},
            );
            break :daemon_loop;
        }

        if (poll_fds.items[0].revents & (lib_posix.POLL.ERR | lib_posix.POLL.HUP | lib_posix.POLL.NVAL) != 0) {
            std.log.err("server socket error revents={d}", .{poll_fds.items[0].revents});
            break :daemon_loop;
        } else if (poll_fds.items[0].revents & lib_posix.POLL.IN != 0) {
            const client_fd = try lib_posix.accept(
                server_sock_fd,
                null,
                null,
                lib_posix.SOCK.NONBLOCK | lib_posix.SOCK.CLOEXEC,
            );
            const client = try gpa.create(Client);
            client.* = Client{
                .alloc = gpa,
                .socket_fd = client_fd,
                .read_buf = try ipc.SocketBuffer.init(gpa),
                .write_buf = undefined,
            };
            // 64KB initial capacity lets ~15 broadcast cycles (N_TTY_BUF_SIZE reads
            // * header) accumulate before the first ArrayList growth. The write
            // buffer is userspace-only: it drains via POLLOUT to the client socket,
            // which has no corresponding kernel-imposed per-write limit.
            client.write_buf = try std.ArrayList(u8).initCapacity(client.alloc, 65536);
            try daemon.clients.append(gpa, client);
            std.log.info(
                "client connected fd={d} total={d}",
                .{ client_fd, daemon.clients.items.len },
            );
        }

        const inp_flags = lib_posix.POLL.IN | lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL;
        if (poll_fds.items[1].revents & inp_flags != 0) {
            // Read from PTY. Buffer is sized to N_TTY_BUF_SIZE (4096): the hard
            // kernel limit for the N_TTY line discipline. A larger buffer doesn't
            // help: each read() from a PTY master returns at most 4096 bytes
            // regardless of the userspace buffer size.
            var buf: [4096]u8 = undefined;
            const n_opt: ?usize = lib_posix.read(pty_fd, &buf) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                break :blk 0;
            };

            if (n_opt) |n| {
                if (n == 0) {
                    // EOF: Shell exited
                    std.log.info("shell exited pty_fd={d}", .{pty_fd});
                    // Let the rest of this poll iteration complete so client
                    // write buffers are flushed via the normal POLLOUT path.
                    // On the next iteration, daemon.running will be false.
                    daemon.running = false;
                } else {
                    // Feed PTY output to terminal emulator for state tracking
                    vt_stream.nextSlice(buf[0..n]);
                    daemon.setPwd(&term);
                    daemon.has_pty_output = true;

                    // When no real terminal client has attached yet, respond to
                    // terminal queries (e.g. DA1/DA2) on behalf of the terminal.
                    // This prevents fish from waiting 10s for unanswered queries.
                    // `has_terminal_client` is only set when a client sends .Init
                    // (a real zmx attach), not when a `zmx run` tail-only client
                    // connects.
                    if (!daemon.has_terminal_client and
                        daemon.pty_write_buf.items.len < Daemon.PTY_WRITE_BUF_MAX)
                    {
                        util.respondToDeviceAttributes(gpa, &daemon.pty_write_buf, buf[0..n]);
                    }

                    // In run mode, scan output for exit code marker. The marker
                    // can straddle two PTY reads (more likely under a throttled
                    // scheduler, e.g. containers), so prepend the tail carried
                    // over from the previous read before searching.
                    if (daemon.is_task_mode and daemon.task_exit_code == null) {
                        var scan_buf: [marker_carry.len + buf.len]u8 = undefined;
                        @memcpy(scan_buf[0..marker_carry_len], marker_carry[0..marker_carry_len]);
                        @memcpy(scan_buf[marker_carry_len..][0..n], buf[0..n]);
                        const scan_len = marker_carry_len + n;

                        if (try util.findTaskExitMarker(scan_buf[0..scan_len], daemon.task_id)) |exit_code| {
                            daemon.task_exit_code = exit_code;
                            daemon.task_ended_at = @intCast(std.Io.Timestamp.now(io, .real).toSeconds());

                            std.log.info("task completed exit_code={d}", .{exit_code});

                            // Notify connected clients
                            for (daemon.clients.items) |c| {
                                ipc.appendMessage(gpa, &c.write_buf, .TaskComplete, &[_]u8{exit_code}) catch {};
                                c.has_pending_output = true;
                            }
                        }

                        marker_carry_len = @min(marker_carry.len, scan_len);
                        @memcpy(
                            marker_carry[0..marker_carry_len],
                            scan_buf[scan_len - marker_carry_len .. scan_len],
                        );
                    }

                    // Broadcast data to all clients.
                    // Rewrite OSC 133;A to include redraw=0 so the outer terminal
                    // does not clear prompt lines on resize (issue #111).
                    const broadcast_data = util.rewritePromptRedraw(gpa, buf[0..n]) orelse buf[0..n];
                    defer if (broadcast_data.ptr != buf[0..n].ptr) gpa.free(broadcast_data);
                    for (daemon.clients.items) |client| {
                        ipc.appendMessage(gpa, &client.write_buf, .Output, broadcast_data) catch |err| {
                            std.log.warn(
                                "failed to buffer output for client err={s}",
                                .{@errorName(err)},
                            );
                            continue;
                        };
                        client.has_pending_output = true;
                    }
                }
            }
        }

        if (poll_fds.items[1].revents & lib_posix.POLL.OUT != 0) {
            while (daemon.pty_write_buf.items.len > 0) {
                const n = lib_posix.write(pty_fd, daemon.pty_write_buf.items) catch |err| {
                    if (err != error.WouldBlock) {
                        std.log.warn("pty write failed: {s}", .{@errorName(err)});
                        daemon.pty_write_buf.clearRetainingCapacity();
                    }
                    break;
                };
                if (n == 0) break;
                daemon.pty_write_buf.replaceRange(gpa, 0, n, &[_]u8{}) catch unreachable;
            }
        }

        var i: usize = daemon.clients.items.len;
        // Only iterate over clients that were present when poll_fds was constructed
        // poll_fds contains [server, pty, sig_pipe, client0, client1, ...]
        // So number of clients in poll_fds is poll_fds.items.len - 3
        const num_polled_clients = poll_fds.items.len - 3;
        if (i > num_polled_clients) {
            // If we have more clients than polled (i.e. we just accepted one), start from the
            // polled ones
            i = num_polled_clients;
        }

        clients_loop: while (i > 0) {
            i -= 1;
            const client = daemon.clients.items[i];
            const revents = poll_fds.items[i + 3].revents;

            if (revents & lib_posix.POLL.IN != 0) {
                const n = client.read_buf.read(client.socket_fd) catch |err| {
                    if (err == error.WouldBlock) continue;
                    std.log.debug(
                        "client read err={s} fd={d}",
                        .{ @errorName(err), client.socket_fd },
                    );
                    const last = daemon.closeClient(gpa, client, i, false);
                    if (last) break :daemon_loop;
                    continue;
                };

                if (n == 0) {
                    // Client closed connection
                    const last = daemon.closeClient(gpa, client, i, false);
                    if (last) break :daemon_loop;
                    continue;
                }

                while (client.read_buf.next()) |msg| {
                    switch (msg.header.tag) {
                        .Input => try daemon.handleInput(gpa, client, msg.payload),
                        .Send => daemon.handleSend(gpa, msg.payload),
                        .Output => try daemon.handleOutput(gpa, msg.payload, &term, &vt_stream),
                        .Init => try daemon.handleInit(gpa, client, pty_fd, &term, msg.payload),
                        // Snapshot-local failures never unwind the
                        // daemon loop. Only the (unreportable) error-
                        // capacity reservation closes a client, and it
                        // closes ONLY the requester — same shape as
                        // .Detach's close path.
                        .InitSnapshot => {
                            if (daemon.handleInitSnapshot(gpa, client, pty_fd, &term, &vt_stream, msg.payload)) {
                                _ = daemon.closeClient(gpa, client, i, false);
                                break :clients_loop;
                            }
                        },
                        .Switch => try daemon.handleSwitch(gpa, msg.payload),
                        .Resize => try daemon.handleResize(gpa, client, pty_fd, &term, msg.payload),
                        .Detach => {
                            daemon.handleDetach(gpa, client, i);
                            break :clients_loop;
                        },
                        .DetachAll => {
                            daemon.handleDetachAll(gpa);
                            break :clients_loop;
                        },
                        .Kill => {
                            break :daemon_loop;
                        },
                        .Info => try daemon.handleInfo(gpa, client, &term),
                        .LabelGet => try daemon.handleLabelGet(gpa, client),
                        .LabelSet => try daemon.handleLabelSet(gpa, client, msg.payload),
                        .LabelClear => try daemon.handleLabelClear(gpa, client),
                        .History => try daemon.handleHistory(gpa, client, &term, msg.payload),
                        .Run => try daemon.handleRun(gpa, io, client, msg.payload),
                        .Ack, .TaskComplete, .LabelData => {},
                        .Write => try daemon.handleWrite(gpa, client, msg.payload),
                        // Gateway-only tag: a client must never send it. Named
                        // explicitly because `_` only covers unnamed tags.
                        .SessionEnd => std.log.warn(
                            "ignoring SessionEnd tag from client",
                            .{},
                        ),
                        // Q4 daemon-to-client snapshot tags: same rule.
                        .SnapshotBegin, .SnapshotChunk, .SnapshotEnd, .SnapshotError => std.log.warn(
                            "ignoring snapshot tag from client tag={d}",
                            .{@intFromEnum(msg.header.tag)},
                        ),
                        _ => std.log.warn(
                            "ignoring unknown IPC tag={d}",
                            .{@intFromEnum(msg.header.tag)},
                        ),
                    }
                }
            }

            if (revents & lib_posix.POLL.OUT != 0) {
                // Flush pending output buffers
                const n = lib_posix.write(client.socket_fd, client.write_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    // Error on write, close client
                    const last = daemon.closeClient(gpa, client, i, false);
                    if (last) break :daemon_loop;
                    continue;
                };

                if (n > 0) {
                    client.write_buf.replaceRange(gpa, 0, n, &[_]u8{}) catch unreachable;
                }

                if (client.write_buf.items.len == 0) {
                    client.has_pending_output = false;
                }
            }

            if (revents & (lib_posix.POLL.HUP | lib_posix.POLL.ERR | lib_posix.POLL.NVAL) != 0) {
                const last = daemon.closeClient(gpa, client, i, false);
                if (last) break :daemon_loop;
            }
        }
    }
}

const ClientResult = struct {
    kind: enum {
        detach,
        switch_session,
    },
    session_name: ?[]const u8,
    cwd: ?[]const u8 = null,
};

/// Client represents each terminal that has connected to a session.
///
/// Multiple Clients can connect to a single session.
pub const Client = struct {
    alloc: std.mem.Allocator,
    socket_fd: i32,
    has_pending_output: bool = false,
    read_buf: ipc.SocketBuffer,
    write_buf: std.ArrayList(u8),

    pub fn deinit(self: *Client) void {
        lib_posix.close(self.socket_fd);
        self.read_buf.deinit();
        self.write_buf.deinit(self.alloc);
    }
};

/// The Q4 snapshot chunking writer: stages Ghostty encoder output in a
/// fixed 32 KiB buffer and frames each full staging area as one
/// `.SnapshotChunk` IPC message appended to the requesting client's
/// write queue. `total` counts Ghostty bytes only — never IPC framing —
/// and the 128 MiB ceiling is enforced BEFORE every queue growth.
///
/// The std.Io.Writer interface reports every failure as WriteFailed, so
/// the underlying cause (limit exceeded vs allocation failure) rides in
/// `cause` for the exporter's frozen-code mapping.
const SnapshotChunkWriter = struct {
    const chunk_len = ipc.snapshot_chunk_max;
    const EmitError = error{ LimitExceeded, OutOfMemory };

    alloc: std.mem.Allocator,
    /// The requesting client's IPC write queue.
    queue: *std.ArrayList(u8),
    staging: [chunk_len]u8 = undefined,
    writer: std.Io.Writer = undefined,
    /// Ghostty bytes handed to this writer so far.
    total: u64 = 0,
    max_total: usize,
    /// Set when drain/flush failed; distinguishes codes 4 and 5.
    cause: ?Cause = null,

    const Cause = enum { limit, out_of_memory, write };

    fn init(self: *SnapshotChunkWriter, alloc: std.mem.Allocator, queue: *std.ArrayList(u8), max_total: usize) void {
        self.* = .{ .alloc = alloc, .queue = queue, .max_total = max_total };
        self.writer = .{
            .buffer = self.staging[0..],
            .vtable = &.{ .drain = drain, .flush = flush },
        };
    }

    /// Appends one framed chunk. Payload bounds: 1..=32 KiB.
    fn emit(self: *SnapshotChunkWriter, bytes: []const u8) EmitError!void {
        std.debug.assert(bytes.len >= ipc.snapshot_chunk_min and bytes.len <= ipc.snapshot_chunk_max);
        if (self.total + bytes.len > self.max_total) return error.LimitExceeded;
        try ipc.appendMessage(self.alloc, self.queue, .SnapshotChunk, bytes);
        self.total += bytes.len;
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SnapshotChunkWriter = @alignCast(@fieldParentPtr("writer", w));
        return self.drainInner(w, data, splat) catch |e| {
            self.cause = switch (e) {
                error.LimitExceeded => .limit,
                error.OutOfMemory => .out_of_memory,
            };
            return error.WriteFailed;
        };
    }

    fn drainInner(
        self: *SnapshotChunkWriter,
        w: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) EmitError!usize {
        // Staged bytes go out first as one chunk.
        if (w.end > 0) {
            try self.emit(w.buffer[0..w.end]);
            w.end = 0;
        }
        // Then the incoming slices, chunk-aligned; the tail stays staged.
        var written: usize = 0;
        for (data[0 .. data.len - 1]) |bytes| written += try self.writeBytes(bytes);
        var rep: usize = 0;
        while (rep < splat) : (rep += 1) {
            written += try self.writeBytes(data[data.len - 1]);
        }
        return written;
    }

    fn writeBytes(self: *SnapshotChunkWriter, bytes: []const u8) EmitError!usize {
        var off: usize = 0;
        while (off < bytes.len) {
            const end = self.writer.end;
            const take = @min(bytes.len - off, chunk_len - end);
            @memcpy(self.staging[end..][0..take], bytes[off..][0..take]);
            self.writer.end += take;
            off += take;
            if (self.writer.end == chunk_len) {
                try self.emit(self.staging[0..chunk_len]);
                self.writer.end = 0;
            }
        }
        return bytes.len;
    }

    /// Flushes the final PARTIAL chunk (guarded so an explicit flush
    /// after a failure is a no-op).
    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *SnapshotChunkWriter = @alignCast(@fieldParentPtr("writer", w));
        if (w.end > 0) {
            self.emit(w.buffer[0..w.end]) catch |e| {
                self.cause = switch (e) {
                    error.LimitExceeded => .limit,
                    error.OutOfMemory => .out_of_memory,
                };
                return error.WriteFailed;
            };
            w.end = 0;
        }
    }
};

/// Daemon is responsible for managing a zmx session.
///
/// It holds all the state for a running session.  Instead of a single daemon for all sessions, we
/// create a daemon for every session.  This has some benefits. The ipc communication between
/// session clients and the daemon doesn't need to be tagged with the session name.  If a daemon
/// crashes for one session won't crash all the other sessions.
///
/// Conceptually it's also much simpler to reason about.
pub const Daemon = struct {
    cfg: *Cfg,
    session_name: []const u8,
    socket_path: []const u8,
    // === opt ===
    pty_write_buf: std.ArrayList(u8) = .empty,
    clients: std.ArrayList(*Client) = .empty,
    labels: std.StringHashMapUnmanaged([]u8) = .empty,
    // This control which client is the leader.  The leader controls terminal state and
    // cols/rows of session.
    leader_client_fd: ?i32 = null,
    running: bool = true,
    pid: i32 = undefined,
    command: ?[]const []const u8 = null,
    /// The session's working directory in OSC 7 form, `file://<host><path>`.
    /// Kept as a URI rather than a path so `zmx list` shows the host, which is
    /// what tells you a session is inside SSH. Points into `cwd_buf` once set,
    /// so a Daemon must not be copied by value after that.
    cwd: []const u8 = "",
    /// The same directory as a path that can be opened: percent-decoding
    /// applied, scheme and host stripped. Empty when the cwd is on another
    /// host, since then it names no directory here and nothing should chdir
    /// into it. Points into `cwd_path_buf`.
    cwd_path: []const u8 = "",
    cwd_buf: [std.fs.max_path_bytes]u8 = undefined,
    cwd_path_buf: [std.fs.max_path_bytes]u8 = undefined,
    has_pty_output: bool = false,
    has_had_client: bool = false,
    has_terminal_client: bool = false, // true only after a real attach (.Init received)
    created_at: u64, // unix timestamp (ns)
    is_task_mode: bool = false, // flag for when session is run as a task
    task_id: [4]u8 = undefined,
    task_exit_code: ?u8 = null, // null = running or n/a, set when task completes
    task_ended_at: ?u64 = null, // timestamp when task exited
    pty_fd: i32 = -1, // set by daemonLoop so handleRun can probe the foreground process
    shell: []const u8 = "/bin/sh",

    /// Create a Daemon. Caller is responsible for freeing all variables passed
    /// into the init fn.
    pub fn init(io: std.Io, cfg: *Cfg, sesh_name: []const u8, socket_path: []const u8) Daemon {
        return .{
            .cfg = cfg,
            .session_name = sesh_name,
            .socket_path = socket_path,
            .created_at = @intCast(std.Io.Timestamp.now(io, .real).toSeconds()),
        };
    }

    pub fn deinit(self: *Daemon, gpa: std.mem.Allocator) void {
        self.clients.deinit(gpa);
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            gpa.free(entry.value_ptr.*);
        }
        self.labels.deinit(gpa);
        self.pty_write_buf.deinit(gpa);
        gpa.free(self.socket_path);
    }

    pub fn shutdown(self: *Daemon, gpa: std.mem.Allocator) void {
        std.log.info("shutting down daemon session={s}", .{self.session_name});
        self.running = false;

        for (self.clients.items) |client| {
            client.deinit();
            gpa.destroy(client);
        }
        self.clients.clearRetainingCapacity();
    }

    pub fn closeClient(self: *Daemon, gpa: std.mem.Allocator, client: *Client, i: usize, shutdown_on_last: bool) bool {
        const fd = client.socket_fd;
        // leader is disconnected, remove ref and let another client claim leader on input
        if (self.leader_client_fd == client.socket_fd) {
            std.log.info(
                "unsetting leader session={s} fd={d}",
                .{ self.session_name, client.socket_fd },
            );
            self.leader_client_fd = null;
        }
        client.deinit();
        gpa.destroy(client);
        _ = self.clients.orderedRemove(i);
        std.log.info("client disconnected fd={d} remaining={d}", .{ fd, self.clients.items.len });
        if (shutdown_on_last and self.clients.items.len == 0) {
            self.shutdown(gpa);
            return true;
        }
        return false;
    }

    /// ensureSession will either create or re-use the daemon used for a session.
    /// It will spin up a unix socket, double-fork the process (so it survives
    /// the terminal dying), and automatically attach the client to the ipc unix
    /// socket.
    ///
    /// The return bool value indicates if the current process is the daemon
    /// or the client since they have different behaviors post-fork.
    ///
    /// E.g. If it's the client process then we need to connect to the unix socket
    /// and run the clientLoop.  If it's the daemon then we need to bail since
    /// the daemonLoop is created inside this fn and when it returns that means
    /// the daemon stopped and needs to exit.
    pub fn ensureSession(self: *Daemon, io: std.Io) !bool {
        const sesh_name = self.session_name;
        std.log.info("ensure session session={s}", .{sesh_name});
        var dir = try std.Io.Dir.openDirAbsolute(io, self.cfg.socket_dir, .{});
        defer dir.close(io);

        const exists = try socket.sessionExists(io, dir, sesh_name);
        // if daemon is gone then we flip this to true
        var should_create = !exists;

        if (exists) {
            if (ipc.connectSession(self.socket_path)) |fd| {
                lib_posix.close(fd);
                if (self.command != null) {
                    std.log.warn(
                        "session already exists, ignoring command session={s}",
                        .{sesh_name},
                    );
                }
            } else |err| switch (err) {
                // Daemon is definitively gone: safe to replace.
                error.ConnectionRefused => {
                    socket.cleanupStaleSocket(io, dir, sesh_name);
                    should_create = true;
                },
                // Connect failed for an unusual reason. The check is only to
                // decide create-vs-attach; the socket file exists, so proceed
                // to attach rather than fail or orphan.
                else => {
                    std.log.warn(
                        "connect failed ({s}), proceeding to attach session={s}",
                        .{ @errorName(err), sesh_name },
                    );
                },
            }
        }

        if (!should_create) {
            return false;
        }

        return self.run(io, dir, sesh_name);
    }

    fn run(self: *Daemon, io: std.Io, dir: std.Io.Dir, sesh_name: []const u8) !bool {
        std.log.info("creating session={s}", .{sesh_name});
        const server_sock_fd: lib_posix.socket_t = try socket.createSocket(self.socket_path);
        const log_fd = log.log_system.file.?.handle;

        var keep_fds_open = [_]i32{ server_sock_fd, dir.handle, log_fd };
        const cmd = try daemonize.createCmdZ(self.shell, self.is_task_mode, self.command);

        // `cwd_path` is the decoded path, and is empty when the cwd is on
        // another host: OSC 7 crosses SSH boundaries, so a session that ssh'd
        // elsewhere reports a directory that does not exist on this machine.
        std.log.info("checking pwd={s} path={s}", .{ self.cwd, self.cwd_path });
        if (self.cwd_path.len > 0) {
            const pwd_dir = std.Io.Dir.openDirAbsolute(io, self.cwd_path, .{}) catch |err| blk: {
                std.log.warn("failed to open dir={s} err={s}", .{ self.cwd_path, @errorName(err) });
                break :blk null;
            };
            if (pwd_dir) |pdir| {
                defer std.Io.Dir.close(pdir, io);
                std.log.info("set directory dir={s}", .{self.cwd_path});
                try std.process.setCurrentDir(io, pdir);
            }
        }

        const pty_info = daemonize.daemonize(
            sesh_name,
            cmd,
            &keep_fds_open,
        ) catch |err| {
            switch (err) {
                error.IsClientProc => {
                    // send a msg to the client that the session was created.
                    var w_buf: [2048]u8 = undefined;
                    var w = std.Io.File.stdout().writer(io, &w_buf);
                    try w.interface.print("session \"{s}\" created\n", .{sesh_name});
                    try w.interface.flush();
                    lib_posix.close(server_sock_fd);
                    return false;
                },
                else => {
                    lib_posix.close(server_sock_fd);
                    dir.deleteFile(io, self.session_name) catch {};
                    return err;
                },
            }
        };
        // =======
        // WARNING: cannot use upstream allocator or io after this point since
        // we forked the process and there's a risk of a mutex (e.g. thread-safe
        // allocator) being locked by a thread prior to fork which can cause a
        // deadlock.
        // =======

        self.pid = pty_info.pid;

        var threaded: std.Io.Threaded = .init_single_threaded;
        defer threaded.deinit();
        const new_io = threaded.io();

        { // re-initialize logs with the session name as the filename
            log.log_system.deinit();
            var log_buf: [4096]u8 = undefined;
            const session_log_name = try std.fmt.bufPrint(
                &log_buf,
                "{s}.log",
                .{sesh_name},
            );
            var fba_buf: [4096]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
            const session_log_path = try std.fs.path.join(
                fba.allocator(),
                &.{ self.cfg.log_dir, session_log_name },
            );
            const log_mode = std.Io.File.Permissions.fromMode(@intCast(self.cfg.log_mode));
            log.log_system.init(new_io, session_log_path, log_mode) catch {};
        }

        const gpa: std.mem.Allocator = blk: {
            if (builtin.mode == .Debug) {
                const GPA = std.heap.DebugAllocator(.{});
                const Static = struct {
                    var gpa: GPA = .{};
                };
                break :blk Static.gpa.allocator();
            }
            break :blk std.heap.c_allocator;
        };

        defer {
            // Close and unlink the listen socket BEFORE handleKill()'s
            // 500ms SIGHUP->SIGKILL grace sleep. Otherwise a `zmx run`
            // for the same name issued in that window will hang waiting
            // for a connect.
            lib_posix.close(server_sock_fd);
            std.log.info("deleting socket file session={s}", .{sesh_name});
            dir.deleteFile(new_io, sesh_name) catch |err| {
                std.log.warn("failed to delete socket file err={s}", .{@errorName(err)});
            };
            self.handleKill(gpa, new_io);
            self.deinit(gpa);
            lib_posix.close(pty_info.master_fd);
            _ = lib_posix.waitpid(self.pid, 0);
        }

        try daemonLoop(self, gpa, new_io, server_sock_fd, pty_info.master_fd);
        std.log.info("daemon loop shutdown", .{});
        return true;
    }

    fn setLeader(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        std.log.info("setting new leader client_fd={d}", .{client.socket_fd});
        self.leader_client_fd = client.socket_fd;
        // Send a resize message to the client so it can send us back their window size
        // so we can resize the pty and ghostty state.
        try ipc.appendMessage(gpa, &client.write_buf, .Resize, "");
        client.has_pending_output = true;
    }

    const PTY_WRITE_BUF_MAX = 256 * 1024;

    /// Q4 snapshot bounds: the persistent stream's retained unfinished
    /// VT/UTF-8 input and the complete-snapshot ceiling enforced before
    /// every queue growth.
    pub const snapshot_continuation_max: usize = 64 * 1024 * 1024;
    pub const snapshot_total_max: usize = 128 * 1024 * 1024;

    /// Queue bytes for the PTY's stdin. Flushed by daemonLoop on POLLOUT.
    /// Drops the payload if the buffer is over cap -- same failure mode as
    /// the old direct-write ptyWrite (drop on EAGAIN), just at a 64x higher
    /// threshold. Capping avoids OOM when the shell stops reading; dropping
    /// new (not old) bytes avoids tearing a partially-accepted sequence.
    /// Fallible, atomic enqueue for command paths that must know the
    /// bytes are queued: returns QueueFull or the allocator error instead
    /// of silently dropping, and leaves the queue untouched on failure.
    fn queuePtyInputChecked(self: *Daemon, gpa: std.mem.Allocator, data: []const u8) error{ QueueFull, OutOfMemory }!void {
        if (data.len == 0) return;
        if (self.pty_write_buf.items.len + data.len > PTY_WRITE_BUF_MAX) return error.QueueFull;
        try self.pty_write_buf.appendSlice(gpa, data);
    }

    fn queuePtyInput(self: *Daemon, gpa: std.mem.Allocator, data: []const u8) void {
        if (data.len == 0) return;
        if (self.pty_write_buf.items.len + data.len > PTY_WRITE_BUF_MAX) {
            std.log.warn(
                "pty input dropped {d} bytes (buffer full, shell not reading)",
                .{data.len},
            );
            return;
        }

        // NOTE: for local dev only
        // std.log.debug("buffering pty input data={x}", .{data});

        self.pty_write_buf.appendSlice(gpa, data) catch |err| {
            std.log.warn(
                "pty input dropped {d} bytes: {s}",
                .{ data.len, @errorName(err) },
            );
        };
    }

    pub fn handleInput(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        // NOTE: for local dev only
        // std.log.debug("buffering pty input data={x}", .{payload});

        // client is leader, send entire payload (ansi escape codes + text)
        if (self.leader_client_fd == client.socket_fd) {
            self.queuePtyInput(gpa, payload);
            return;
        }

        // check if leader needs to be updated by detecting any user input
        if (util.isUserInput(payload)) {
            try self.setLeader(gpa, client);
            self.queuePtyInput(gpa, payload);
        }
    }

    /// Queue input from `zmx send` without changing interactive client leadership.
    pub fn handleSend(self: *Daemon, gpa: std.mem.Allocator, payload: []const u8) void {
        self.queuePtyInput(gpa, payload);
    }

    pub fn handleSwitch(self: *Daemon, gpa: std.mem.Allocator, session_name: []const u8) !void {
        for (self.clients.items) |client| {
            if (self.leader_client_fd == client.socket_fd) {
                // Include the daemon's current cwd so the new session can start
                // in the right directory. A remote cwd is left out: it names no
                // directory here, so the new session is better off with the
                // attaching client's own cwd than with a path it cannot enter.
                if (self.cwd.len > 0 and self.cwd_path.len > 0) {
                    var payload = gpa.alloc(u8, session_name.len + 1 + self.cwd.len) catch return;
                    defer gpa.free(payload);
                    @memcpy(payload[0..session_name.len], session_name);
                    payload[session_name.len] = '\n';
                    @memcpy(payload[session_name.len + 1 ..], self.cwd);
                    ipc.appendMessage(gpa, &client.write_buf, .Switch, payload) catch |err| {
                        std.log.warn(
                            "failed to buffer terminal state for client err={s}",
                            .{@errorName(err)},
                        );
                    };
                } else {
                    ipc.appendMessage(gpa, &client.write_buf, .Switch, session_name) catch |err| {
                        std.log.warn(
                            "failed to buffer terminal state for client err={s}",
                            .{@errorName(err)},
                        );
                    };
                }
                client.has_pending_output = true;
                return;
            }
        }
        return error.NoLeaderFound;
    }

    pub fn handleInit(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        pty_fd: i32,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        if (payload.len != @sizeOf(ipc.Resize)) return;

        // Serialize terminal state BEFORE resize to capture correct cursor position.
        // Resizing triggers reflow which can move the cursor, and the shell's
        // SIGWINCH-triggered redraw will run after our snapshot is sent.
        // Only serialize on re-attach (has_had_client), not first attach, to avoid
        // interfering with shell initialization (DA1 queries, etc.)
        if (self.has_pty_output and self.has_had_client) {
            const cursor = &term.screens.active.cursor;
            std.log.debug(
                "cursor before serialize: x={d} y={d} pending_wrap={}",
                .{ cursor.x, cursor.y, cursor.pending_wrap },
            );
            if (util.serializeTerminalState(gpa, term)) |term_output| {
                std.log.debug("serialize terminal state", .{});
                // Rewrite OSC 133;A to include redraw=0 so the outer terminal
                // does not clear prompt lines on resize (issue #111).
                const restore_data = util.rewritePromptRedraw(gpa, term_output) orelse term_output;
                defer gpa.free(term_output);
                defer if (restore_data.ptr != term_output.ptr) gpa.free(restore_data);
                ipc.appendMessage(gpa, &client.write_buf, .Output, restore_data) catch |err| {
                    std.log.warn(
                        "failed to buffer terminal state for client err={s}",
                        .{@errorName(err)},
                    );
                };
                client.has_pending_output = true;
            }
        }

        // no leader is set so set one
        if (self.leader_client_fd == null) {
            try self.setLeader(gpa, client);
        }

        // only resize if leader
        if (self.leader_client_fd == client.socket_fd) {
            try self.applyLeaderResize(gpa, pty_fd, term, payload);

            // Mark that we've had a client init, so subsequent clients get terminal state
            self.has_had_client = true;
            self.has_terminal_client = true;
        }
    }

    /// Leader-only Ghostty + PTY resize shared by `.Init` and
    /// `.InitSnapshot` (Q4 factored the mechanics; both callers keep
    /// their own replay/leadership ordering). The fallible Ghostty
    /// resize runs BEFORE TIOCSWINSZ: on failure neither geometry has
    /// changed, so a contained resize failure can never leave the PTY
    /// and the terminal at different sizes. The ioctl itself stays
    /// best-effort with its result ignored, as it always was.
    fn applyLeaderResize(
        self: *Daemon,
        gpa: std.mem.Allocator,
        pty_fd: i32,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        _ = self;
        const resize = std.mem.bytesToValue(ipc.Resize, payload);
        // Disable prompt_redraw before resize. The daemon's internal terminal
        // would otherwise clear prompt lines expecting the shell to redraw them,
        // but the shell's redraw goes to the PTY (forwarded to clients), not to
        // this daemon terminal. The clearing corrupts the daemon's snapshot state.
        const saved_prompt_redraw = term.flags.shell_redraws_prompt;
        term.flags.shell_redraws_prompt = .false;
        defer term.flags.shell_redraws_prompt = saved_prompt_redraw;
        const opts = ghostty_vt.Terminal.Resize{
            .cols = resize.cols,
            .rows = resize.rows,
        };
        try term.resize(gpa, opts);
        var ws: cross.c.struct_winsize = .{
            .ws_row = resize.rows,
            .ws_col = resize.cols,
            .ws_xpixel = resize.xpixel,
            .ws_ypixel = resize.ypixel,
        };
        _ = cross.c.ioctl(pty_fd, cross.c.TIOCSWINSZ, &ws);
        std.log.debug("leader resize rows={d} cols={d}", .{ resize.rows, resize.cols });
    }

    /// Q4 attach-with-snapshot: establish leadership, apply the payload
    /// size to the PTY and the Ghostty terminal, then synchronously
    /// capture one transactional binary snapshot into the requesting
    /// client's IPC queue — after the resize and before the event loop
    /// reads the shell's next (SIGWINCH-triggered) output, so the cut is
    /// unambiguously post-resize.
    ///
    /// Snapshot-local failures NEVER unwind the daemon loop: every one
    /// is reported through the transactional SnapshotError rollback.
    /// The single exception is the initial error-capacity reservation,
    /// which cannot report itself — the return value `true` tells the
    /// dispatch to close ONLY this requester; the daemon and every
    /// other client keep serving.
    pub fn handleInitSnapshot(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        pty_fd: i32,
        term: *ghostty_vt.Terminal,
        vt_stream: *ghostty_vt.TerminalStream,
        payload: []const u8,
    ) bool {
        // Reserve room for the maximum SnapshotError BEFORE starting:
        // after this, the rollback error append can never allocate.
        client.write_buf.ensureTotalCapacity(
            gpa,
            client.write_buf.items.len +
                @sizeOf(ipc.Header) + 4 + ipc.snapshot_error_diag_max,
        ) catch |e| {
            std.log.warn(
                "snapshot reservation failed, closing requester err={s}",
                .{@errorName(e)},
            );
            return true;
        };
        const mark = client.write_buf.items.len;

        if (payload.len != @sizeOf(ipc.Resize)) {
            self.rollbackSnapshot(client, mark, ipc.snapshot_error_invalid_request, "bad InitSnapshot payload");
            return false;
        }
        // Dimensions are validated before leadership or any ioctl: a
        // zero row or column can never size a terminal.
        const resize = std.mem.bytesToValue(ipc.Resize, payload);
        if (resize.rows == 0 or resize.cols == 0) {
            self.rollbackSnapshot(client, mark, ipc.snapshot_error_invalid_request, "invalid InitSnapshot dimensions");
            return false;
        }

        // The size travels in this payload, so leadership is established
        // directly (no .Resize ask-back), then the resize applies. The
        // previous leader is preserved and restored if the resize fails:
        // a failed attach never steals the session. The resize failure
        // itself is snapshot-local: code 5 through the normal rollback,
        // never an unwind.
        const prev_leader = self.leader_client_fd;
        if (prev_leader != client.socket_fd) {
            std.log.info("setting snapshot leader client_fd={d}", .{client.socket_fd});
            self.leader_client_fd = client.socket_fd;
        }
        self.applyLeaderResize(gpa, pty_fd, term, payload) catch |e| {
            self.leader_client_fd = prev_leader;
            self.rollbackSnapshot(client, mark, ipc.snapshot_error_out_of_memory, @errorName(e));
            return false;
        };
        self.has_had_client = true;
        self.has_terminal_client = true;

        // Empty session: open and close the transaction with no encoder
        // invocation (PRESENT=0).
        if (!self.has_pty_output) {
            var endp: [8]u8 = undefined;
            ipc.writeSnapshotEndPayload(&endp, 0);
            ipc.appendMessage(gpa, &client.write_buf, .SnapshotBegin, &.{0}) catch |e| {
                self.rollbackSnapshot(client, mark, ipc.snapshot_error_out_of_memory, @errorName(e));
                return false;
            };
            ipc.appendMessage(gpa, &client.write_buf, .SnapshotEnd, &endp) catch |e| {
                self.rollbackSnapshot(client, mark, ipc.snapshot_error_out_of_memory, @errorName(e));
                return false;
            };
            client.has_pending_output = true;
            return false;
        }

        // Continuation: ground needs no bytes and skips the buffer;
        // otherwise export exactly once into a bounded buffer.
        var cont: ghostty_vt.snapshot.Continuation = .ground;
        var cont_writer: std.Io.Writer.Allocating = .init(gpa);
        defer cont_writer.deinit();
        if (!vt_stream.ground()) {
            vt_stream.writeContinuation(&cont_writer.writer) catch |e| {
                switch (e) {
                    error.ContinuationUnavailable => self.rollbackSnapshot(
                        client,
                        mark,
                        ipc.snapshot_error_continuation_unavailable,
                        "continuation unavailable",
                    ),
                    // The Allocating writer's only drain failure is growth
                    // failure, surfaced as WriteFailed.
                    error.WriteFailed => self.rollbackSnapshot(
                        client,
                        mark,
                        ipc.snapshot_error_out_of_memory,
                        "out of memory",
                    ),
                    // Tracking is always enabled for the daemon stream.
                    error.ContinuationDisabled => self.rollbackSnapshot(
                        client,
                        mark,
                        ipc.snapshot_error_encode_failed,
                        "continuation tracking disabled",
                    ),
                }
                return false;
            };
            const bytes = cont_writer.written();
            if (bytes.len > Daemon.snapshot_continuation_max) {
                self.rollbackSnapshot(
                    client,
                    mark,
                    ipc.snapshot_error_limit_exceeded,
                    "continuation exceeds the 64 MiB bound",
                );
                return false;
            }
            cont = .{ .bytes = bytes };
        }

        self.exportSnapshotTransaction(gpa, client, term, cont, Daemon.snapshot_total_max);
        return false;
    }

    /// Streams one complete encoded snapshot into the client's queue as
    /// a SnapshotBegin / SnapshotChunk... / SnapshotEnd transaction.
    /// Every failure rolls the queue back to its length on entry and
    /// appends exactly one SnapshotError. `max_total` is the caller's
    /// bound (the daemon's frozen 128 MiB; tests inject smaller bounds
    /// to exercise the limit path genuinely).
    fn exportSnapshotTransaction(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        term: *ghostty_vt.Terminal,
        cont: ghostty_vt.snapshot.Continuation,
        max_total: usize,
    ) void {
        const mark = client.write_buf.items.len;
        ipc.appendMessage(gpa, &client.write_buf, .SnapshotBegin, &.{1}) catch |e| {
            self.rollbackSnapshot(client, mark, ipc.snapshot_error_out_of_memory, @errorName(e));
            return;
        };
        var cw: SnapshotChunkWriter = undefined;
        cw.init(gpa, &client.write_buf, max_total);
        ghostty_vt.snapshot.encode(gpa, &cw.writer, term, .{
            .continuation = cont,
        }) catch |e| {
            self.rollbackSnapshot(client, mark, Daemon.snapshotFailureCode(e, cw.cause), Daemon.snapshotFailureDiag(e, cw.cause));
            return;
        };
        // Explicit final partial-chunk flush (skipped on failure — the
        // rollback already discarded the partial transaction).
        cw.writer.flush() catch |e| {
            const cause = cw.cause orelse SnapshotChunkWriter.Cause.write;
            self.rollbackSnapshot(client, mark, Daemon.snapshotFailureCode(e, cause), Daemon.snapshotFailureDiag(e, cause));
            return;
        };
        var endp: [8]u8 = undefined;
        ipc.writeSnapshotEndPayload(&endp, cw.total);
        ipc.appendMessage(gpa, &client.write_buf, .SnapshotEnd, &endp) catch |e| {
            self.rollbackSnapshot(client, mark, ipc.snapshot_error_out_of_memory, @errorName(e));
            return;
        };
        client.has_pending_output = true;
    }

    /// Transactional rollback: restore the queue to the length recorded
    /// immediately before SnapshotBegin and append exactly one
    /// SnapshotError. The error capacity was reserved up front, so this
    /// never allocates.
    fn rollbackSnapshot(
        self: *Daemon,
        client: *Client,
        mark: usize,
        code: u32,
        diag: []const u8,
    ) void {
        _ = self;
        client.write_buf.items.len = mark;
        var ebuf: [4 + ipc.snapshot_error_diag_max]u8 = undefined;
        // Constant, bounded inputs: the payload encode cannot fail.
        const n = ipc.writeSnapshotErrorPayload(&ebuf, code, diag) catch unreachable;
        // Allocation-free by construction: capacity >= mark + this frame
        // was reserved before the transaction started.
        ipc.appendMessage(client.alloc, &client.write_buf, .SnapshotError, ebuf[0..n]) catch |e| {
            // Capacity was reserved; any failure here is an invariant.
            std.log.err(
                "snapshot rollback could not append SnapshotError err={s}",
                .{@errorName(e)},
            );
            return;
        };
        client.has_pending_output = true;
    }

    /// Maps an encode-path failure to the frozen local code, preserving
    /// the chunk writer's cause (limit vs OOM) over the generic
    /// WriteFailed the Writer interface reports. The chunk writer always
    /// records its cause BEFORE returning WriteFailed, so a WriteFailed
    /// arriving without one can only originate in Ghostty's internal
    /// record scratch — an Allocating writer, whose only drain failure
    /// is allocation growth — and maps to out-of-memory as well.
    fn snapshotFailureCode(err: anyerror, cause: ?SnapshotChunkWriter.Cause) u32 {
        return switch (cause orelse .write) {
            .limit => ipc.snapshot_error_limit_exceeded,
            .out_of_memory => ipc.snapshot_error_out_of_memory,
            .write => switch (err) {
                error.OutOfMemory, error.WriteFailed => ipc.snapshot_error_out_of_memory,
                error.ContinuationUnavailable => ipc.snapshot_error_continuation_unavailable,
                else => ipc.snapshot_error_encode_failed,
            },
        };
    }

    fn snapshotFailureDiag(err: anyerror, cause: ?SnapshotChunkWriter.Cause) []const u8 {
        return switch (cause orelse .write) {
            .limit => "snapshot exceeds the 128 MiB limit",
            .out_of_memory => "out of memory",
            .write => switch (err) {
                error.OutOfMemory, error.WriteFailed => "out of memory",
                error.ContinuationUnavailable => "continuation unavailable",
                else => "snapshot encode failed",
            },
        };
    }

    pub fn handleResize(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        pty_fd: i32,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        if (payload.len != @sizeOf(ipc.Resize)) return;
        if (self.leader_client_fd == null) {
            try self.setLeader(gpa, client);
        }
        // only leader can resize
        if (self.leader_client_fd != client.socket_fd) return;

        const resize = std.mem.bytesToValue(ipc.Resize, payload);
        var ws: cross.c.struct_winsize = .{
            .ws_row = resize.rows,
            .ws_col = resize.cols,
            .ws_xpixel = resize.xpixel,
            .ws_ypixel = resize.ypixel,
        };
        _ = cross.c.ioctl(pty_fd, cross.c.TIOCSWINSZ, &ws);
        // Disable prompt_redraw before resize (same rationale as handleInit).
        const saved_prompt_redraw = term.flags.shell_redraws_prompt;
        term.flags.shell_redraws_prompt = .false;
        defer term.flags.shell_redraws_prompt = saved_prompt_redraw;
        const opts = ghostty_vt.Terminal.Resize{
            .cols = resize.cols,
            .rows = resize.rows,
        };
        try term.resize(gpa, opts);
        std.log.debug("resize rows={d} cols={d}", .{ resize.rows, resize.cols });
    }

    pub fn handleDetach(self: *Daemon, gpa: std.mem.Allocator, client: *Client, i: usize) void {
        std.log.info("client detach session={s} fd={d}", .{ self.session_name, client.socket_fd });
        _ = self.closeClient(gpa, client, i, false);
    }

    pub fn handleDetachAll(self: *Daemon, gpa: std.mem.Allocator) void {
        std.log.info("detach all clients={d}", .{self.clients.items.len});
        for (self.clients.items) |client_to_close| {
            client_to_close.deinit();
            gpa.destroy(client_to_close);
        }
        self.clients.clearRetainingCapacity();
    }

    pub fn handleKill(self: *Daemon, gpa: std.mem.Allocator, io: std.Io) void {
        std.log.info("kill received session={s}", .{self.session_name});
        self.shutdown(gpa);
        // gracefully shutdown shell processes, shells tend to ignore SIGTERM so we send SIGHUP
        // instead
        //   https://www.gnu.org/software/bash/manual/html_node/Signals.html
        // negative pid means kill process and children
        std.log.info("sending SIGHUP session={s} pid={d}", .{ self.session_name, self.pid });
        lib_posix.kill(-self.pid, lib_posix.SIG.HUP) catch |err| {
            std.log.warn("failed to send SIGHUP to pty child err={s}", .{@errorName(err)});
        };
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(500), .real) catch unreachable;
        lib_posix.kill(-self.pid, lib_posix.SIG.KILL) catch |err| {
            std.log.warn("failed to send SIGKILL to pty child err={s}", .{@errorName(err)});
        };
    }

    pub fn handleInfo(self: *Daemon, gpa: std.mem.Allocator, client: *Client, term: *ghostty_vt.Terminal) !void {
        self.setPwd(term);

        // zeroes() so asBytes() doesn't ship struct padding + unused cmd/cwd
        // tail bytes (daemon stack contents) to clients.
        var info = std.mem.zeroes(ipc.Info);
        info.clients_len = self.clients.items.len - 1;
        info.pid = self.pid;
        info.created_at = self.created_at;
        info.task_ended_at = self.task_ended_at orelse 0;
        info.task_exit_code = self.task_exit_code orelse 0;

        // Build command string from args, re-quoting args that contain
        // shell-special characters so the displayed command is copy-pasteable.
        const cur_cmd = self.command;
        if (cur_cmd) |args| {
            for (args, 0..) |arg, i| {
                const quoted = if (util.shellNeedsQuoting(arg))
                    util.shellQuote(gpa, arg) catch null
                else
                    null;
                defer if (quoted) |q| gpa.free(q);
                const src = quoted orelse arg;

                const need = src.len + @as(usize, if (i > 0) 1 else 0);
                if (info.cmd_len + need > ipc.MAX_CMD_LEN) {
                    const ellipsis = "...";
                    if (info.cmd_len + ellipsis.len <= ipc.MAX_CMD_LEN) {
                        @memcpy(info.cmd[info.cmd_len..][0..ellipsis.len], ellipsis);
                        info.cmd_len += ellipsis.len;
                    }
                    break;
                }

                if (i > 0) {
                    info.cmd[info.cmd_len] = ' ';
                    info.cmd_len += 1;
                }
                @memcpy(info.cmd[info.cmd_len..][0..src.len], src);
                info.cmd_len += @intCast(src.len);
            }
        }

        info.cwd_len = @intCast(@min(self.cwd.len, ipc.MAX_CWD_LEN));
        @memcpy(info.cwd[0..info.cwd_len], self.cwd[0..info.cwd_len]);

        try ipc.appendMessage(gpa, &client.write_buf, .Info, std.mem.asBytes(&info));
        client.has_pending_output = true;
    }

    pub fn handleHistory(
        self: *Daemon,
        gpa: std.mem.Allocator,
        client: *Client,
        term: *ghostty_vt.Terminal,
        payload: []const u8,
    ) !void {
        self.setPwd(term);
        const format: util.HistoryFormat = if (payload.len > 0)
            @enumFromInt(payload[0])
        else
            .plain;
        if (util.serializeTerminal(gpa, term, format)) |output| {
            defer gpa.free(output);
            try ipc.appendMessage(gpa, &client.write_buf, .History, output);
            client.has_pending_output = true;
        } else {
            try ipc.appendMessage(gpa, &client.write_buf, .History, "");
            client.has_pending_output = true;
        }
    }

    pub fn handleRun(self: *Daemon, gpa: std.mem.Allocator, io: std.Io, client: *Client, payload: []const u8) !void {
        // Reset task tracking so the new command's exit marker is detected.
        // Without this, a second `zmx run` on the same session is ignored
        // because task_exit_code is still set from the first run.
        self.task_exit_code = null;
        self.task_ended_at = null;
        self.is_task_mode = true;
        self.task_id = util.generateTaskId(io);

        if (payload.len == 0) return;

        const cmd = payload;

        // Chain the exit marker with `;` on the same line. `$?` captures the
        // exit code of the command (not the `;`). The sole exception is when
        // the command contains a heredoc (`<<`), the delimiter must be alone
        // on its line, so the marker goes on the next line instead.
        var buf: [1024]u8 = undefined;
        const marker = try util.getTaskExitMarker(&buf, self.task_id);
        var single_buf: [1024]u8 = undefined;
        const single_line_marker = try std.fmt.bufPrint(&single_buf, "; echo {s}$?\r", .{marker});
        var here_buf: [1024]u8 = undefined;
        const heredoc_marker = try std.fmt.bufPrint(&here_buf, "\r\necho {s}$?\r", .{marker});
        const uses_heredoc = std.mem.indexOf(u8, cmd, "<<") != null;

        if (cmd.len > 0 and cmd[cmd.len - 1] == '\r') {
            self.queuePtyInput(gpa, cmd[0 .. cmd.len - 1]);
        } else {
            self.queuePtyInput(gpa, cmd);
        }
        self.queuePtyInput(gpa, if (uses_heredoc) heredoc_marker else single_line_marker);

        try ipc.appendMessage(gpa, &client.write_buf, .Ack, "");
        client.has_pending_output = true;
        self.has_had_client = true;
        std.log.debug("run command len={d}", .{payload.len});
    }

    /// Store the session's working directory as a plain path.
    ///
    /// Accepts either an OSC 7 value (`file://<host><path>`, percent-encoded)
    /// or a path. Decoding here rather than at each use keeps `zmx list`
    /// printing a path and lets the chdir on session create find directories
    /// whose names needed escaping.
    ///
    /// The value is copied, so callers may pass a temporary.
    pub fn setCwd(self: *Daemon, value: []const u8) void {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        var host_buf: [std.posix.HOST_NAME_MAX]u8 = undefined;
        const hostname = std.posix.gethostname(&host_buf) catch "";
        const cwd = util.parseOsc7Cwd(&buf, value, hostname) orelse {
            std.log.warn("ignoring unusable cwd={s}", .{value});
            return;
        };

        // Store the URI form. A caller that handed us a plain path gets one
        // built here, so `cwd` has the same shape no matter the source. A value
        // that already was a URI is kept verbatim, so `list` shows what the
        // shell actually reported.
        self.cwd = if (std.fs.path.isAbsolute(value))
            util.toOsc7Cwd(&self.cwd_buf, value, hostname) orelse return
        else blk: {
            if (value.len > self.cwd_buf.len) return;
            @memcpy(self.cwd_buf[0..value.len], value);
            break :blk self.cwd_buf[0..value.len];
        };

        // Only keep an openable path when it names a directory on this host.
        if (cwd.is_local and cwd.path.len <= self.cwd_path_buf.len) {
            @memcpy(self.cwd_path_buf[0..cwd.path.len], cwd.path);
            self.cwd_path = self.cwd_path_buf[0..cwd.path.len];
        } else {
            self.cwd_path = "";
        }
        std.log.info("set cwd={s} path={s}", .{ self.cwd, self.cwd_path });
    }

    fn setPwd(self: *Daemon, term: *ghostty_vt.Terminal) void {
        const pwd = term.getPwd() orelse return;
        self.setCwd(pwd);
    }

    pub fn handleOutput(self: *Daemon, gpa: std.mem.Allocator, payload: []const u8, term: *ghostty_vt.Terminal, vt_stream: anytype) !void {
        vt_stream.nextSlice(payload);
        self.setPwd(term);
        self.has_pty_output = true;
        for (self.clients.items) |client| {
            try ipc.appendMessage(gpa, &client.write_buf, .Output, payload);
            client.has_pending_output = true;
        }
        if (self.clients.items.len > 0) {
            lib_posix.kill(self.pid, lib_posix.SIG.WINCH) catch |err| {
                std.log.warn("failed to send SIGWINCH err={s}", .{@errorName(err)});
            };
        }
    }

    pub fn handleWrite(self: *Daemon, gpa: std.mem.Allocator, client: *Client, payload: []const u8) !void {
        // Wire format: [u32 path len][path bytes][file content]
        if (payload.len < @sizeOf(u32)) return error.InvalidPayload;
        const path_len = std.mem.bytesToValue(u32, payload[0..@sizeOf(u32)]);
        if (payload.len < @sizeOf(u32) + path_len) return error.InvalidPayload;
        const file_path = payload[@sizeOf(u32)..][0..path_len];
        const file_content = payload[@sizeOf(u32) + path_len ..];

        // Ack convention (v1): empty payload = success; non-empty payload =
        // the write was rejected atomically and nothing was enqueued.
        // Shared semantic cap, identical for local and remote writes.
        if (file_content.len > ipc.max_write_len) {
            try ipc.appendMessage(gpa, &client.write_buf, .Ack, "input exceeds the 128 KiB write limit");
            client.has_pending_output = true;
            std.log.warn("write rejected over limit len={d}", .{file_content.len});
            return;
        }

        // Build the COMPLETE PTY input before enqueueing anything so the
        // write is atomic: either the whole encoded command fits the queue
        // or nothing is enqueued and the client is told why. The path is
        // shell-quoted — never interpolated raw into the shell command.
        const quoted_path = try util.shellQuote(gpa, file_path);
        defer gpa.free(quoted_path);

        var cmd_buf: std.ArrayList(u8) = .empty;
        defer cmd_buf.deinit(gpa);

        // 48000 is divisible by 3 (clean base64 boundaries) and encodes
        // to ~64KB, well under typical ARG_MAX.
        const chunk_size = 48000;
        var offset: usize = 0;
        var is_first = true;

        while (offset < file_content.len or is_first) {
            const end = @min(offset + chunk_size, file_content.len);
            const chunk = file_content[offset..end];

            const encoded_len = std.base64.standard.Encoder.calcSize(chunk.len);
            const encoded = try gpa.alloc(u8, encoded_len);
            defer gpa.free(encoded);
            _ = std.base64.standard.Encoder.encode(encoded, chunk);

            try cmd_buf.appendSlice(gpa, "printf '%s' '");
            try cmd_buf.appendSlice(gpa, encoded);
            try cmd_buf.appendSlice(gpa, if (is_first) "' | base64 -d > " else "' | base64 -d >> ");
            try cmd_buf.appendSlice(gpa, quoted_path);
            try cmd_buf.appendSlice(gpa, "\r");

            offset = end;
            is_first = false;
        }

        // Atomic enqueue: the finished command must fit alongside what is
        // already queued, or the write is rejected without touching the
        // queue — a partial command must never reach the PTY, and an
        // allocation failure mid-enqueue must never report success.
        self.queuePtyInputChecked(gpa, cmd_buf.items) catch |err| {
            const reason: []const u8 = switch (err) {
                error.QueueFull => "session busy; try again",
                error.OutOfMemory => "internal error; try again",
            };
            try ipc.appendMessage(gpa, &client.write_buf, .Ack, reason);
            client.has_pending_output = true;
            std.log.warn("write rejected err={s} queued={d} needed={d}", .{
                @errorName(err),
                self.pty_write_buf.items.len,
                cmd_buf.items.len,
            });
            return;
        };

        try ipc.appendMessage(gpa, &client.write_buf, .Ack, "");
        client.has_pending_output = true;
        self.has_had_client = true;
        // Privacy: sizes only — never paths, content, or keys.
        std.log.debug("write accepted len={d} encoded_len={d}", .{
            file_content.len,
            cmd_buf.items.len,
        });
    }

    fn handleLabelGet(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        const out = try label.labelsToU8(gpa, self.labels);
        defer gpa.free(out);
        try ipc.appendMessage(gpa, &client.write_buf, .LabelData, out);
        client.has_pending_output = true;
    }

    fn handleLabelSet(self: *Daemon, gpa: std.mem.Allocator, client: *Client, labels: []const u8) !void {
        // Privacy: log counts only — never label keys or values.
        std.log.info("handle label set payload_len={d}", .{labels.len});

        var kvs = label.LabelIterator.init(labels);
        while (kvs.next()) |kv| {
            if (kv.value.len == 0) {
                if (self.labels.fetchRemove(kv.key)) |existing| {
                    gpa.free(existing.key);
                    gpa.free(existing.value);
                }
                continue;
            }

            const owned_key = try gpa.dupe(u8, kv.key);
            errdefer gpa.free(owned_key);
            const owned_value = try gpa.dupe(u8, kv.value);
            errdefer gpa.free(owned_value);
            if (try self.labels.fetchPut(gpa, owned_key, owned_value)) |existing| {
                // fetchPut does NOT replace the key in the map, the old
                // key pointer stays. So free the new (unused) key and the
                // old value.
                gpa.free(owned_key);
                gpa.free(existing.value);
            }
        }

        try ipc.appendMessage(gpa, &client.write_buf, .Ack, "");
        client.has_pending_output = true;
    }

    fn handleLabelClear(self: *Daemon, gpa: std.mem.Allocator, client: *Client) !void {
        var it = self.labels.iterator();
        while (it.next()) |entry| {
            gpa.free(entry.key_ptr.*);
            gpa.free(entry.value_ptr.*);
        }
        self.labels.clearRetainingCapacity();
        try ipc.appendMessage(gpa, &client.write_buf, .Ack, "");
        client.has_pending_output = true;
    }
};

test "send queues PTY input without changing leader" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .clients = .empty,
        .leader_client_fd = 42,
        .session_name = "test",
        .socket_path = "",
        .running = true,
        .pid = 0,
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);

    daemon.handleSend(alloc, "hello");

    try std.testing.expectEqual(@as(?i32, 42), daemon.leader_client_fd);
    try std.testing.expectEqualStrings("hello", daemon.pty_write_buf.items);
}

// ---------------------------------------------------------------------------
// Write-path safety (Phase 4A)
// ---------------------------------------------------------------------------

fn writeWirePayload(alloc: std.mem.Allocator, path: []const u8, content: []const u8) ![]u8 {
    var buf = try std.ArrayList(u8).initCapacity(alloc, 4 + path.len + content.len);
    defer buf.deinit(alloc);
    const path_len: u32 = @intCast(path.len);
    try buf.appendSlice(alloc, std.mem.asBytes(&path_len));
    try buf.appendSlice(alloc, path);
    try buf.appendSlice(alloc, content);
    return buf.toOwnedSlice(alloc);
}

fn lastAckPayload(client: *const Client) ?[]const u8 {
    var head: usize = 0;
    var last: ?[]const u8 = null;
    while (ipc.expectedLength(client.write_buf.items[head..])) |total| {
        if (client.write_buf.items.len - head < total) break;
        const hdr = std.mem.bytesToValue(ipc.Header, client.write_buf.items[head..][0..@sizeOf(ipc.Header)]);
        const payload = client.write_buf.items[head..][@sizeOf(ipc.Header)..total];
        if (hdr.tag == .Ack) last = payload;
        head += total;
    }
    return last;
}

test "handleWrite rejects a full pty queue without touching it" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .clients = .empty,
        .session_name = "test",
        .socket_path = "",
        .running = true,
        .pid = 0,
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = -1,
        .read_buf = undefined,
        .write_buf = .empty,
    };
    defer client.write_buf.deinit(alloc);

    // Queue nearly full: only 10 bytes of headroom.
    try daemon.pty_write_buf.resize(alloc, Daemon.PTY_WRITE_BUF_MAX - 10);
    @memset(daemon.pty_write_buf.items, 'x');
    const queued_before = daemon.pty_write_buf.items.len;

    const payload = try writeWirePayload(alloc, "file.txt", "hello");
    defer alloc.free(payload);
    try daemon.handleWrite(alloc, &client, payload);

    // Rejection is atomic: the queue is byte-for-byte unchanged.
    try std.testing.expectEqual(queued_before, daemon.pty_write_buf.items.len);
    // And the client sees an Ack carrying the rejection reason.
    const ack = lastAckPayload(&client).?;
    try std.testing.expect(ack.len > 0);
}

test "handleWrite allocation failure never sends a success Ack" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .clients = .empty,
        .session_name = "test",
        .socket_path = "",
        .running = true,
        .pid = 0,
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);
    var client = Client{
        .alloc = alloc,
        .socket_fd = -1,
        .read_buf = undefined,
        .write_buf = .empty,
    };
    defer client.write_buf.deinit(alloc);

    const payload = try writeWirePayload(alloc, "file.txt", "hello");
    defer alloc.free(payload);

    // Fail the very first allocation inside handleWrite: the error must
    // propagate (no Ack of any kind), never an empty-payload success Ack.
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, daemon.handleWrite(failing.allocator(), &client, payload));
    try std.testing.expectEqual(@as(usize, 0), client.write_buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), daemon.pty_write_buf.items.len);
}

test "queuePtyInputChecked leaves the queue untouched on failure" {
    const alloc = std.testing.allocator;
    var daemon = Daemon{
        .cfg = undefined,
        .clients = .empty,
        .session_name = "test",
        .socket_path = "",
        .running = true,
        .pid = 0,
        .created_at = 0,
    };
    defer daemon.pty_write_buf.deinit(alloc);

    try daemon.pty_write_buf.appendSlice(alloc, "abc");
    // Over capacity: rejected, unchanged.
    try std.testing.expectError(error.QueueFull, daemon.queuePtyInputChecked(alloc, &([_]u8{'y'} ** (Daemon.PTY_WRITE_BUF_MAX + 1))));
    try std.testing.expectEqualStrings("abc", daemon.pty_write_buf.items);

    // Allocation failure mid-append: unchanged, error surfaced.
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    // Large enough to force growth beyond the existing capacity, so the
    // allocation actually happens (and fails) instead of fitting in place.
    const big = try alloc.alloc(u8, 4096);
    defer alloc.free(big);
    @memset(big, 'z');
    try std.testing.expectError(error.OutOfMemory, daemon.queuePtyInputChecked(failing.allocator(), big));
    try std.testing.expectEqualStrings("abc", daemon.pty_write_buf.items);
}

// ---------------------------------------------------------------------------
// Q4 snapshot export (Phase Q4)
// ---------------------------------------------------------------------------

const TestFrame = struct { tag: ipc.Tag, payload: []const u8 };

/// Walks complete IPC frames out of a client write queue; payloads point
/// into `buf` and stay valid while it does.
fn collectFrames(alloc: std.mem.Allocator, buf: []const u8) ![]TestFrame {
    var list: std.ArrayList(TestFrame) = .empty;
    errdefer list.deinit(alloc);
    var head: usize = 0;
    while (ipc.expectedLength(buf[head..])) |total| {
        if (buf.len - head < total) break;
        const hdr = std.mem.bytesToValue(ipc.Header, buf[head..][0..@sizeOf(ipc.Header)]);
        try list.append(alloc, .{
            .tag = hdr.tag,
            .payload = buf[head..][@sizeOf(ipc.Header)..total],
        });
        head += total;
    }
    return list.toOwnedSlice(alloc);
}

fn snapshotTestDaemon() Daemon {
    return .{
        .cfg = undefined,
        .clients = .empty,
        .session_name = "test",
        .socket_path = "",
        .running = true,
        .pid = 0,
        .created_at = 0,
    };
}

fn snapshotTestClient(alloc: std.mem.Allocator) Client {
    return .{
        .alloc = alloc,
        .socket_fd = -1,
        .read_buf = undefined,
        .write_buf = .empty,
    };
}

test "handleInitSnapshot empty session queues Begin(0) and End(0)" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = Daemon.snapshot_continuation_max,
    });
    defer vts.deinit();

    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 24, .cols = 80, .xpixel = 0, .ypixel = 0 });
    try std.testing.expectEqual(false, daemon.handleInitSnapshot(alloc, &client, -1, &term, &vts, payload));

    try std.testing.expect(daemon.leader_client_fd == client.socket_fd);
    try std.testing.expect(daemon.has_terminal_client);
    try std.testing.expect(client.has_pending_output);

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 2), frames.len);
    try std.testing.expectEqual(ipc.Tag.SnapshotBegin, frames[0].tag);
    try std.testing.expectEqualSlices(u8, &.{0}, frames[0].payload);
    try std.testing.expectEqual(ipc.Tag.SnapshotEnd, frames[1].tag);
    try std.testing.expectEqual(@as(u64, 0), ipc.parseSnapshotEndPayload(frames[1].payload[0..8]));
}

test "handleInitSnapshot populated transaction streams a decodable snapshot" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = Daemon.snapshot_continuation_max,
    });
    defer vts.deinit();

    // Populated screen, a title, scrollback, and an unfinished CSI so the
    // continuation path (non-ground export) is exercised too.
    var n: usize = 0;
    while (n < 60) : (n += 1) {
        vts.nextSlice("line of output text\r\n");
    }
    vts.nextSlice("\x1b]0;session title\x07");
    vts.nextSlice("\x1b[31");

    // Requested dimensions differ from the terminal's construction
    // (80x24): the capture must reflect the post-resize geometry.
    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 30, .cols = 100, .xpixel = 0, .ypixel = 0 });
    try std.testing.expectEqual(false, daemon.handleInitSnapshot(alloc, &client, -1, &term, &vts, payload));

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expect(frames.len >= 3);
    try std.testing.expectEqual(ipc.Tag.SnapshotBegin, frames[0].tag);
    try std.testing.expectEqualSlices(u8, &.{1}, frames[0].payload);
    try std.testing.expectEqual(ipc.Tag.SnapshotEnd, frames[frames.len - 1].tag);

    var spool: std.ArrayList(u8) = .empty;
    defer spool.deinit(alloc);
    for (frames[1 .. frames.len - 1]) |f| {
        try std.testing.expectEqual(ipc.Tag.SnapshotChunk, f.tag);
        try std.testing.expect(f.payload.len >= ipc.snapshot_chunk_min);
        try std.testing.expect(f.payload.len <= ipc.snapshot_chunk_max);
        try spool.appendSlice(alloc, f.payload);
    }
    const declared = ipc.parseSnapshotEndPayload(frames[frames.len - 1].payload[0..8]);
    try std.testing.expectEqual(spool.items.len, declared);

    // The concatenated chunks decode EXACTLY: one snapshot through FINISH
    // with zero trailing bytes, and the restored terminal serializes to
    // the same VT as the captured source.
    var reader: std.Io.Reader = .fixed(spool.items);
    var decoded = try ghostty_vt.snapshot.decodeExact(alloc, std.testing.io, &reader, .{
        .max_continuation_bytes = Daemon.snapshot_continuation_max,
    });
    defer decoded.deinit(alloc);
    var restored = decoded.toOwned();
    defer restored.deinit(alloc);

    // The snapshot carries the POST-RESIZE dimensions (30x100), not the
    // terminal's 80x24 construction.
    try std.testing.expectEqual(@as(@TypeOf(restored.rows), 30), restored.rows);
    try std.testing.expectEqual(@as(@TypeOf(restored.cols), 100), restored.cols);

    const want = util.serializeTerminalState(alloc, &term) orelse return error.TestUnexpectedNull;
    defer alloc.free(want);
    const got = util.serializeTerminalState(alloc, &restored) orelse return error.TestUnexpectedNull;
    defer alloc.free(got);
    try std.testing.expectEqualSlices(u8, want, got);
}

test "SnapshotChunkWriter exact 32 KiB boundaries and final partial flush" {
    const alloc = std.testing.allocator;
    var queue: std.ArrayList(u8) = .empty;
    defer queue.deinit(alloc);

    // Exactly chunk_len through one oversized write: one full chunk, and
    // the explicit flush has no partial tail to emit.
    {
        var cw: SnapshotChunkWriter = undefined;
        cw.init(alloc, &queue, 1 << 30);
        var data: [SnapshotChunkWriter.chunk_len]u8 = undefined;
        @memset(&data, 'a');
        try cw.writer.writeAll(&data);
        try cw.writer.flush();
        try std.testing.expectEqual(@as(u64, SnapshotChunkWriter.chunk_len), cw.total);
        const frames = try collectFrames(alloc, queue.items);
        defer alloc.free(frames);
        try std.testing.expectEqual(@as(usize, 1), frames.len);
        try std.testing.expectEqual(ipc.Tag.SnapshotChunk, frames[0].tag);
        try std.testing.expectEqual(SnapshotChunkWriter.chunk_len, frames[0].payload.len);
    }

    // chunk_len + 1: the full chunk, then the one-byte final partial.
    {
        queue.clearRetainingCapacity();
        var cw: SnapshotChunkWriter = undefined;
        cw.init(alloc, &queue, 1 << 30);
        var data: [SnapshotChunkWriter.chunk_len + 1]u8 = undefined;
        @memset(&data, 'b');
        try cw.writer.writeAll(&data);
        try cw.writer.flush();
        try std.testing.expectEqual(@as(u64, SnapshotChunkWriter.chunk_len + 1), cw.total);
        const frames = try collectFrames(alloc, queue.items);
        defer alloc.free(frames);
        try std.testing.expectEqual(@as(usize, 2), frames.len);
        try std.testing.expectEqual(SnapshotChunkWriter.chunk_len, frames[0].payload.len);
        try std.testing.expectEqual(@as(usize, 1), frames[1].payload.len);
    }

    // Small writes accumulate in the staging area until a boundary: no
    // chunk frames appear until the flush emits the residue.
    {
        queue.clearRetainingCapacity();
        var cw: SnapshotChunkWriter = undefined;
        cw.init(alloc, &queue, 1 << 30);
        var i: usize = 0;
        while (i < 100) : (i += 1) {
            try cw.writer.writeAll(&([_]u8{'c'} ** 300));
        }
        try std.testing.expectEqual(@as(usize, 0), queue.items.len);
        try cw.writer.flush();
        const frames = try collectFrames(alloc, queue.items);
        defer alloc.free(frames);
        var summed: usize = 0;
        for (frames) |f| {
            try std.testing.expectEqual(ipc.Tag.SnapshotChunk, f.tag);
            summed += f.payload.len;
        }
        try std.testing.expectEqual(@as(usize, 100 * 300), summed);
        try std.testing.expectEqual(@as(u64, 100 * 300), cw.total);
    }
}

test "SnapshotChunkWriter enforces the total before every growth" {
    const alloc = std.testing.allocator;
    var queue: std.ArrayList(u8) = .empty;
    defer queue.deinit(alloc);
    var cw: SnapshotChunkWriter = undefined;
    cw.init(alloc, &queue, 8);

    // Ten bytes stage silently (no growth yet), then the explicit flush
    // refuses to grow past the cap: nothing is queued, the cause rides.
    try cw.writer.writeAll("0123456789");
    try std.testing.expectEqual(@as(usize, 0), queue.items.len);
    try std.testing.expectError(error.WriteFailed, cw.writer.flush());
    try std.testing.expectEqual(@as(?SnapshotChunkWriter.Cause, .limit), cw.cause);
    try std.testing.expectEqual(@as(u64, 0), cw.total);
    try std.testing.expectEqual(@as(usize, 0), queue.items.len);
}

test "snapshot failure mapping preserves the writer cause" {
    const t = std.testing;
    // Cause wins over the generic WriteFailed the interface reports.
    try t.expectEqual(ipc.snapshot_error_limit_exceeded, Daemon.snapshotFailureCode(error.WriteFailed, .limit));
    try t.expectEqual(ipc.snapshot_error_out_of_memory, Daemon.snapshotFailureCode(error.WriteFailed, .out_of_memory));
    // Without a cause: OOM and continuation keep their codes. A bare
    // WriteFailed can only be Ghostty's internal scratch allocation
    // failing (the chunk writer always records its cause first); other
    // errors are genuine encode failures.
    try t.expectEqual(ipc.snapshot_error_out_of_memory, Daemon.snapshotFailureCode(error.OutOfMemory, null));
    try t.expectEqual(ipc.snapshot_error_out_of_memory, Daemon.snapshotFailureCode(error.WriteFailed, null));
    try t.expectEqual(ipc.snapshot_error_continuation_unavailable, Daemon.snapshotFailureCode(error.ContinuationUnavailable, null));
    try t.expectEqual(ipc.snapshot_error_encode_failed, Daemon.snapshotFailureCode(error.Overflow, null));
    try t.expectEqual(ipc.snapshot_error_encode_failed, Daemon.snapshotFailureCode(error.PayloadTooLarge, null));
}

test "handleInitSnapshot continuation unavailable rolls back to code 2" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    // Tiny cap: a 5-byte unfinished CSI breaks the tracker, so the cut
    // reports ContinuationUnavailable instead of exporting.
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = 4,
    });
    defer vts.deinit();
    vts.nextSlice("\x1b[312");

    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 24, .cols = 80, .xpixel = 0, .ypixel = 0 });
    try std.testing.expectEqual(false, daemon.handleInitSnapshot(alloc, &client, -1, &term, &vts, payload));

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(ipc.Tag.SnapshotError, frames[0].tag);
    const ew = try ipc.parseSnapshotErrorPayload(frames[0].payload);
    try std.testing.expectEqual(ipc.snapshot_error_continuation_unavailable, ew.code);
}

test "handleInitSnapshot preserves pre-existing queue content through rollback" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    try ipc.appendMessage(alloc, &client.write_buf, .Output, "pre-cut bytes");
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = 4,
    });
    defer vts.deinit();
    vts.nextSlice("\x1b[312");

    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 24, .cols = 80, .xpixel = 0, .ypixel = 0 });
    try std.testing.expectEqual(false, daemon.handleInitSnapshot(alloc, &client, -1, &term, &vts, payload));

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 2), frames.len);
    try std.testing.expectEqual(ipc.Tag.Output, frames[0].tag);
    try std.testing.expectEqualStrings("pre-cut bytes", frames[0].payload);
    try std.testing.expectEqual(ipc.Tag.SnapshotError, frames[1].tag);
    try std.testing.expectEqual(
        ipc.snapshot_error_continuation_unavailable,
        (try ipc.parseSnapshotErrorPayload(frames[1].payload)).code,
    );
}

test "handleInitSnapshot rolls back every allocation failure to one error" {
    const alloc = std.testing.allocator;
    var fail_index: usize = 0;
    while (fail_index <= 24) : (fail_index += 1) {
        var daemon = snapshotTestDaemon();
        daemon.has_pty_output = true;
        var client = snapshotTestClient(alloc);
        defer client.write_buf.deinit(alloc);
        var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
        defer term.deinit(alloc);
        var vts = ghostty_vt.TerminalStream.init(.{
            .allocator = alloc,
            .handler = term.vtHandler(),
            .continuation_max_bytes = Daemon.snapshot_continuation_max,
        });
        defer vts.deinit();
        vts.nextSlice("some output\r\nwith content\r\n");

        var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = fail_index });
        // Dimensions differ from the terminal's so the resize itself
        // allocates (reflow), not just the encoder.
        const payload = std.mem.asBytes(&ipc.Resize{ .rows = 30, .cols = 100, .xpixel = 0, .ypixel = 0 });
        // Nothing unwinds the daemon loop: the only failure mode is the
        // close-requester signal (the unreportable reservation), and it
        // leaves the queue untouched for the dispatch's close path.
        const close = daemon.handleInitSnapshot(failing.allocator(), &client, -1, &term, &vts, payload);
        if (close) {
            try std.testing.expectEqual(@as(usize, 0), fail_index);
            try std.testing.expectEqual(@as(usize, 0), client.write_buf.items.len);
            continue;
        }

        const frames = try collectFrames(alloc, client.write_buf.items);
        defer alloc.free(frames);
        var saw_error: ?ipc.Tag = null;
        for (frames) |f| {
            if (f.tag == .SnapshotError) {
                try std.testing.expect(saw_error == null); // exactly one
                saw_error = f.tag;
                const ew = try ipc.parseSnapshotErrorPayload(f.payload);
                // Every injected failure on this path is an allocation
                // failure: it must map to code 5, never generic 3.
                try std.testing.expectEqual(ipc.snapshot_error_out_of_memory, ew.code);
            } else {
                // No transaction frame may coexist with the error.
                try std.testing.expect(saw_error == null);
            }
        }
        // Either exactly one SnapshotError, or a complete transaction.
        if (saw_error != null) {
            try std.testing.expectEqual(@as(usize, 1), frames.len);
        } else {
            try std.testing.expectEqual(ipc.Tag.SnapshotBegin, frames[0].tag);
            try std.testing.expectEqual(ipc.Tag.SnapshotEnd, frames[frames.len - 1].tag);
        }
    }
}

test "handleInit first attach sets leader without replay or snapshot frames" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = term.vtStream();
    defer vts.deinit();

    // First attach (has_had_client false): no legacy replay is emitted.
    // setLeader still asks the client for its size (the empty .Resize
    // ask-back) — pre-existing .Init behavior, unchanged by Q4.
    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 24, .cols = 80, .xpixel = 0, .ypixel = 0 });
    try daemon.handleInit(alloc, &client, -1, &term, payload);

    try std.testing.expect(daemon.leader_client_fd == client.socket_fd);
    try std.testing.expect(daemon.has_terminal_client);
    try std.testing.expect(daemon.has_had_client);
    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(ipc.Tag.Resize, frames[0].tag);
    try std.testing.expectEqual(@as(usize, 0), frames[0].payload.len);
}

test "snapshot reservation failure closes only the requester; daemon and peers survive" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    defer daemon.clients.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = Daemon.snapshot_continuation_max,
    });
    defer vts.deinit();
    vts.nextSlice("shared session content\r\n");

    // Two connected clients, as daemonLoop's accept path creates them.
    // A carries a REAL fd: the dispatch's close path runs Client.deinit,
    // and closing -1 panics in this Zig version.
    const a = try alloc.create(Client);
    a.* = snapshotTestClient(alloc);
    a.socket_fd = lib_posix.open("/dev/null", .{ .ACCMODE = .RDWR }, 0) catch
        return error.TestUnexpectedError;
    a.read_buf = try ipc.SocketBuffer.init(alloc); // deinit runs via closeClient
    const b = try alloc.create(Client);
    b.* = snapshotTestClient(alloc);
    defer alloc.destroy(b);
    defer b.write_buf.deinit(alloc);
    try daemon.clients.append(alloc, a);
    try daemon.clients.append(alloc, b);

    // The dispatch site's exact handling of the close signal: the
    // reservation is the first allocation, so fail_index 0 reaches it.
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 30, .cols = 100, .xpixel = 0, .ypixel = 0 });
    const a_fd = a.socket_fd; // closeClient frees `a` below; read it now
    const close = daemon.handleInitSnapshot(failing.allocator(), a, -1, &term, &vts, payload);
    try std.testing.expect(close);
    try std.testing.expectEqual(@as(usize, 0), a.write_buf.items.len);
    _ = daemon.closeClient(alloc, a, 0, false);

    // The daemon lives, the peer is intact, and the peer can still run
    // its own successful snapshot transaction on the same terminal.
    // Nothing below may touch `a` — closeClient destroyed it.
    try std.testing.expect(daemon.running);
    try std.testing.expectEqual(@as(usize, 1), daemon.clients.items.len);
    try std.testing.expect(daemon.clients.items[0] == b);
    try std.testing.expect(daemon.leader_client_fd == null or daemon.leader_client_fd != a_fd);
    try std.testing.expectEqual(false, daemon.handleInitSnapshot(alloc, b, -1, &term, &vts, payload));
    const frames = try collectFrames(alloc, b.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expect(frames.len >= 2);
    try std.testing.expectEqual(ipc.Tag.SnapshotBegin, frames[0].tag);
    try std.testing.expectEqual(ipc.Tag.SnapshotEnd, frames[frames.len - 1].tag);

    daemon.clients.clearRetainingCapacity();
}

test "genuine transaction limit failure preserves the prefix and leaves no residue" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);

    try ipc.appendMessage(alloc, &client.write_buf, .Output, "prefix frame");
    // A 16-byte bound makes the FIRST chunk append exceed the limit
    // mid-transaction — a genuine encode that started and was bounded.
    daemon.exportSnapshotTransaction(alloc, &client, &term, .ground, 16);

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 2), frames.len);
    try std.testing.expectEqual(ipc.Tag.Output, frames[0].tag);
    try std.testing.expectEqualStrings("prefix frame", frames[0].payload);
    try std.testing.expectEqual(ipc.Tag.SnapshotError, frames[1].tag);
    const ew = try ipc.parseSnapshotErrorPayload(frames[1].payload);
    try std.testing.expectEqual(ipc.snapshot_error_limit_exceeded, ew.code);
}

test "genuine generic encode failure preserves the prefix and leaves no residue" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);

    try ipc.appendMessage(alloc, &client.write_buf, .Output, "prefix frame");
    // "ab" leaves the parser in ground: Ghostty's own continuation
    // validation rejects it inside encode, BEFORE the envelope — a
    // genuine non-allocation encode failure (code 3).
    daemon.exportSnapshotTransaction(alloc, &client, &term, .{ .bytes = "ab" }, Daemon.snapshot_total_max);

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 2), frames.len);
    try std.testing.expectEqual(ipc.Tag.Output, frames[0].tag);
    try std.testing.expectEqual(ipc.Tag.SnapshotError, frames[1].tag);
    const ew = try ipc.parseSnapshotErrorPayload(frames[1].payload);
    try std.testing.expectEqual(ipc.snapshot_error_encode_failed, ew.code);
}

test "handleInitSnapshot rejects zero dimensions before leadership" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = Daemon.snapshot_continuation_max,
    });
    defer vts.deinit();

    for ([_][2]u16{ .{ 0, 80 }, .{ 24, 0 }, .{ 0, 0 } }) |dims| {
        client.write_buf.clearRetainingCapacity();
        const payload = std.mem.asBytes(&ipc.Resize{ .rows = dims[0], .cols = dims[1], .xpixel = 0, .ypixel = 0 });
        try std.testing.expectEqual(false, daemon.handleInitSnapshot(alloc, &client, -1, &term, &vts, payload));
        const frames = try collectFrames(alloc, client.write_buf.items);
        defer alloc.free(frames);
        try std.testing.expectEqual(@as(usize, 1), frames.len);
        try std.testing.expectEqual(ipc.Tag.SnapshotError, frames[0].tag);
        const ew = try ipc.parseSnapshotErrorPayload(frames[0].payload);
        try std.testing.expectEqual(ipc.snapshot_error_invalid_request, ew.code);
    }
    // Leadership was never taken and the terminal kept its geometry.
    try std.testing.expect(daemon.leader_client_fd == null);
    try std.testing.expect(!daemon.has_terminal_client);
    try std.testing.expectEqual(@as(@TypeOf(term.cols), 80), term.cols);
    try std.testing.expectEqual(@as(@TypeOf(term.rows), 24), term.rows);
}

test "handleInitSnapshot resize failure is atomic across PTY, terminal, and leadership" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = Daemon.snapshot_continuation_max,
    });
    defer vts.deinit();

    // A real PTY sized 24x80, as daemonLoop's sessions are: the failure
    // must leave BOTH geometries untouched, which only a genuine pty fd
    // can prove.
    var pty_master: c_int = -1;
    var pty_slave: c_int = -1;
    const initial: cross.c.struct_winsize = .{
        .ws_row = 24,
        .ws_col = 80,
        .ws_xpixel = 0,
        .ws_ypixel = 0,
    };
    if (cross.c.openpty(&pty_master, &pty_slave, null, null, &initial) != 0) {
        return error.TestUnexpectedResult;
    }
    defer lib_posix.close(pty_master);
    defer lib_posix.close(pty_slave);

    // A prior leader owns the session; the failed attach must hand the
    // session back rather than keep stolen leadership.
    daemon.leader_client_fd = 4242;

    // cols 513 crosses the pinned Ghostty Tabstops' 512 prealloc
    // columns, so Terminal.resize allocates (the dynamic tabstop
    // segment) as its FIRST fallible step — before any terminal state
    // changes. Reservation is allocation 0, so fail_index 1 fails
    // inside the resize, deterministically.
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 1 });
    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 24, .cols = 513, .xpixel = 0, .ypixel = 0 });
    try std.testing.expectEqual(false, daemon.handleInitSnapshot(failing.allocator(), &client, pty_master, &term, &vts, payload));
    try std.testing.expect(failing.has_induced_failure);

    // Containment: exactly one SnapshotError(5), no Begin/Chunk/End
    // residue, no close signal (the expectEqual above), no unwind.
    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    try std.testing.expectEqual(@as(usize, 1), frames.len);
    try std.testing.expectEqual(ipc.Tag.SnapshotError, frames[0].tag);
    const ew = try ipc.parseSnapshotErrorPayload(frames[0].payload);
    try std.testing.expectEqual(ipc.snapshot_error_out_of_memory, ew.code);

    // Atomicity: the Ghostty terminal never left 24x80...
    try std.testing.expectEqual(@as(@TypeOf(term.cols), 80), term.cols);
    try std.testing.expectEqual(@as(@TypeOf(term.rows), 24), term.rows);
    // ...and because the fallible resize runs before TIOCSWINSZ, the
    // failed attempt never reached the PTY either.
    var now: cross.c.struct_winsize = undefined;
    if (cross.c.ioctl(pty_master, cross.c.TIOCGWINSZ, &now) != 0) {
        return error.TestUnexpectedResult;
    }
    try std.testing.expectEqual(@as(c_ushort, 24), now.ws_row);
    try std.testing.expectEqual(@as(c_ushort, 80), now.ws_col);

    // Leadership restored to the prior owner; the terminal-client flags
    // were never committed.
    try std.testing.expectEqual(@as(?i32, 4242), daemon.leader_client_fd);
    try std.testing.expect(!daemon.has_had_client);
    try std.testing.expect(!daemon.has_terminal_client);
}

test "handleInit reattach emits legacy replay before the resize ask-back" {
    const alloc = std.testing.allocator;
    var daemon = snapshotTestDaemon();
    daemon.has_pty_output = true;
    daemon.has_had_client = true; // reattach: the replay path is live
    var client = snapshotTestClient(alloc);
    defer client.write_buf.deinit(alloc);
    var term = try ghostty_vt.Terminal.init(std.testing.io, alloc, .{ .cols = 80, .rows = 24 });
    defer term.deinit(alloc);
    var vts = term.vtStream();
    defer vts.deinit();
    vts.nextSlice("legacy session content\r\nwith two lines\r\n");

    // The replay must serialize the PRE-resize state: capture it first.
    const want = util.serializeTerminalState(alloc, &term) orelse return error.TestUnexpectedNull;
    defer alloc.free(want);

    const payload = std.mem.asBytes(&ipc.Resize{ .rows = 30, .cols = 100, .xpixel = 0, .ypixel = 0 });
    try daemon.handleInit(alloc, &client, -1, &term, payload);

    const frames = try collectFrames(alloc, client.write_buf.items);
    defer alloc.free(frames);
    // Exactly the historical shape: replay Output first, then the
    // leader ask-back Resize — and nothing else.
    try std.testing.expectEqual(@as(usize, 2), frames.len);
    try std.testing.expectEqual(ipc.Tag.Output, frames[0].tag);
    try std.testing.expectEqualSlices(u8, want, frames[0].payload);
    try std.testing.expectEqual(ipc.Tag.Resize, frames[1].tag);
    try std.testing.expectEqual(@as(usize, 0), frames[1].payload.len);
    // The resize itself applied after the replay.
    try std.testing.expectEqual(@as(@TypeOf(term.cols), 100), term.cols);
    try std.testing.expectEqual(@as(@TypeOf(term.rows), 30), term.rows);
}
