const std = @import("std");
const cross = @import("cross.zig");
const socket = @import("socket.zig");
const lib_posix = @import("posix.zig");

/// Shared semantic cap for the write command, local and remote: the
/// complete encoded PTY input must fit the daemon's 256 KiB queue with
/// headroom, so file content is limited to 128 KiB. Raising it requires
/// streamed daemon-side flow control (out of scope for v1).
pub const max_write_len: usize = 128 * 1024;

pub const Tag = enum(u8) {
    Input = 0,
    Output = 1,
    Resize = 2,
    Detach = 3,
    DetachAll = 4,
    Kill = 5,
    Info = 6,
    Init = 7,
    History = 8,
    Run = 9,
    Ack = 10,
    Switch = 11,
    Write = 12,
    TaskComplete = 13,
    LabelGet = 14,
    LabelSet = 15,
    LabelClear = 16,
    LabelData = 17,
    Send = 18,
    /// Gateway-only: the UDP serve gateway sends this to its remote client
    /// when the daemon closes the connection (session ended).
    SessionEnd = 19,
    /// Q4 gateway attach: become the terminal client, apply the target
    /// Resize, and answer with one snapshot transaction. Exactly one
    /// existing 8-byte ipc.Resize payload.
    InitSnapshot = 20,
    /// Q4: opens the transaction; payload is one byte, 0 (absent) or
    /// 1 (Ghostty bytes follow in chunks).
    SnapshotBegin = 21,
    /// Q4: 1..=32 KiB of opaque Ghostty snapshot bytes.
    SnapshotChunk = 22,
    /// Q4: closes the transaction; payload is the u64 big-endian count
    /// of Ghostty bytes only (IPC framing excluded).
    SnapshotEnd = 23,
    /// Q4: replaces a failed transaction; payload is a u32 big-endian
    /// local error code plus a printable diagnostic <= 256 bytes.
    SnapshotError = 24,
    // Non-exhaustive: this enum comes off the wire via bytesToValue and
    // @enumFromInt, so out-of-range values are representable
    // rather than UB. Switches must handle `_` (unknown tag).
    _,
};

comptime {
    if (@typeInfo(Tag).@"enum".is_exhaustive) @compileError(
        "ipc.Tag must stay non-exhaustive -- old daemons rely on `_` to ignore unknown tags",
    );
}

pub const Header = packed struct {
    tag: Tag,
    len: u32,
};

pub const Resize = packed struct {
    rows: u16,
    cols: u16,
    xpixel: u16 = 0,
    ypixel: u16 = 0,
};

pub fn getTerminalSize(fd: i32) Resize {
    var ws: cross.c.struct_winsize = undefined;
    if (cross.c.ioctl(fd, cross.c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
        return .{ .rows = ws.ws_row, .cols = ws.ws_col, .xpixel = ws.ws_xpixel, .ypixel = ws.ws_ypixel };
    }
    inline for (.{ lib_posix.STDOUT_FILENO, lib_posix.STDIN_FILENO, lib_posix.STDERR_FILENO }) |fallback_fd| {
        if (fallback_fd != fd) {
            if (cross.c.ioctl(fallback_fd, cross.c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
                return .{ .rows = ws.ws_row, .cols = ws.ws_col, .xpixel = ws.ws_xpixel, .ypixel = ws.ws_ypixel };
            }
        }
    }
    if (lib_posix.open("/dev/tty", .{ .ACCMODE = .RDWR }, 0)) |tty_fd| {
        defer lib_posix.close(tty_fd);
        if (cross.c.ioctl(tty_fd, cross.c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
            return .{ .rows = ws.ws_row, .cols = ws.ws_col, .xpixel = ws.ws_xpixel, .ypixel = ws.ws_ypixel };
        }
    } else |_| {}
    return .{ .rows = 24, .cols = 120 };
}

pub const MAX_CMD_LEN = 256;
pub const MAX_CWD_LEN = 256;

/// Frozen wire shape. Do NOT add fields! New stats go in new `Tag` values
/// so old daemons (whose `_` arm ignores unknown tags) stay reachable.
/// Changing `@sizeOf(Info)` breaks `zmx list` against running daemons.
pub const Info = extern struct {
    clients_len: u64,
    pid: i32,
    cmd_len: u16,
    cwd_len: u16,
    cmd: [MAX_CMD_LEN]u8,
    cwd: [MAX_CWD_LEN]u8,
    created_at: u64,
    task_ended_at: u64,
    task_exit_code: u8,
};

pub fn expectedLength(data: []const u8) ?usize {
    if (data.len < @sizeOf(Header)) return null;
    const header = std.mem.bytesToValue(Header, data[0..@sizeOf(Header)]);
    // header.len comes off the wire; widen to usize before adding so a
    // near-u32-max value can't wrap (panic in safe mode, UB in release).
    return @as(usize, @sizeOf(Header)) + @as(usize, header.len);
}

pub fn send(fd: i32, tag: Tag, data: []const u8) !void {
    const header = Header{
        .tag = tag,
        .len = @intCast(data.len),
    };
    const header_bytes = std.mem.asBytes(&header);
    try writeAll(fd, header_bytes);
    if (data.len > 0) {
        try writeAll(fd, data);
    }
}

pub fn appendMessage(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    tag: Tag,
    data: []const u8,
) !void {
    const header = Header{
        .tag = tag,
        .len = @intCast(data.len),
    };
    // Guarantee capacity for header + payload in one check to avoid
    // intermediate realloc between the two appends on the hot path.
    try list.ensureTotalCapacity(gpa, list.items.len + @sizeOf(Header) + data.len);
    list.appendSliceAssumeCapacity(std.mem.asBytes(&header));
    if (data.len > 0) {
        list.appendSliceAssumeCapacity(data);
    }
}

fn writeAll(fd: i32, data: []const u8) !void {
    var index: usize = 0;
    while (index < data.len) {
        const n = try lib_posix.write(fd, data[index..]);
        if (n == 0) return error.DiskQuota;
        index += n;
    }
}

pub const Message = struct {
    tag: Tag,
    data: []u8,

    pub fn deinit(self: Message, alloc: std.mem.Allocator) void {
        if (self.data.len > 0) {
            alloc.free(self.data);
        }
    }
};

pub const SocketMsg = struct {
    header: Header,
    payload: []const u8,
};

pub const SocketBuffer = struct {
    buf: std.ArrayList(u8),
    alloc: std.mem.Allocator,
    head: usize,
    /// Zero (default) keeps the historic unbounded behavior. Non-zero
    /// bounds a single frame's TOTAL length (header + payload): an
    /// oversized DECLARED length is rejected as soon as its header is
    /// readable, before the payload accumulates.
    max_frame_len: usize = 0,

    pub fn init(alloc: std.mem.Allocator) !SocketBuffer {
        return .{
            .buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
            .alloc = alloc,
            .head = 0,
        };
    }

    /// Bounded construction for readers that must never grow past one
    /// legal frame (the QUIC gateway's daemon reader).
    pub fn initBounded(alloc: std.mem.Allocator, max_frame_len: usize) !SocketBuffer {
        var sb = try SocketBuffer.init(alloc);
        sb.max_frame_len = max_frame_len;
        return sb;
    }

    pub fn deinit(self: *SocketBuffer) void {
        self.buf.deinit(self.alloc);
    }

    /// Reads from fd into buffer.
    /// Returns number of bytes read.
    /// Propagates error.WouldBlock and other errors to caller.
    /// Returns 0 on EOF.
    /// Bounded buffers additionally return error.FrameTooLarge once the
    /// pending frame's declared length exceeds `max_frame_len` — the
    /// caller fails closed; the buffer state is then poisoned.
    pub fn read(self: *SocketBuffer, fd: i32) !usize {
        return self.readAtMost(fd, 4096);
    }

    /// `read` bounded to AT MOST `max_bytes` (1..4096): the reader
    /// never admits more per call than the caller has authorized, so
    /// a caller gating on a not-yet-inspectable header can cap the
    /// read to exactly that header's remaining bytes — a coalesced
    /// header+payload arrival cannot pull the payload in early.
    pub fn readAtMost(self: *SocketBuffer, fd: i32, max_bytes: usize) !usize {
        std.debug.assert(max_bytes >= 1 and max_bytes <= 4096);
        if (self.head > 0) {
            const remaining = self.buf.items.len - self.head;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.buf.items[0..remaining], self.buf.items[self.head..]);
                self.buf.items.len = remaining;
            } else {
                self.buf.clearRetainingCapacity();
            }
            self.head = 0;
        }

        var tmp: [4096]u8 = undefined;
        const n = try lib_posix.read(fd, tmp[0..max_bytes]);
        if (n > 0) {
            try self.buf.appendSlice(self.alloc, tmp[0..n]);
        }
        if (self.max_frame_len != 0 and self.buf.items.len >= @sizeOf(Header)) {
            // Walk every frame whose header is readable — not just the
            // first: a legal leading frame must not mask an oversized
            // pending one accumulating behind it.
            var pos: usize = 0;
            while (pos + @sizeOf(Header) <= self.buf.items.len) {
                const total = expectedLength(self.buf.items[pos..]).?;
                if (total > self.max_frame_len) return error.FrameTooLarge;
                pos += total;
            }
        }
        return n;
    }

    /// Returns the next complete message or `null` when none available.
    /// `buf` is advanced automatically; caller keeps the returned slices
    /// valid until the following `next()` (or `deinit`).
    pub fn next(self: *SocketBuffer) ?SocketMsg {
        const available = self.buf.items[self.head..];
        const total = expectedLength(available) orelse return null;
        if (available.len < total) return null;

        const hdr = std.mem.bytesToValue(Header, available[0..@sizeOf(Header)]);
        const pay = available[@sizeOf(Header)..total];

        self.head += total;
        return .{ .header = hdr, .payload = pay };
    }
};

const ConnectError = error{
    ConnectionRefused,
    Unexpected,
};

/// Connect-only liveness check. Callers that don't read `Info` should use
/// this (not `probeSession`) so they survive `Info` shape changes.
pub fn connectSession(socket_path: []const u8) ConnectError!i32 {
    return socket.sessionConnect(socket_path) catch |err| switch (err) {
        error.ConnectionRefused => return error.ConnectionRefused,
        else => return error.Unexpected,
    };
}

const SessionProbeError = error{
    Timeout,
    ConnectionRefused,
    Unexpected,
    InfoSizeMismatch,
};

const SessionProbeResult = struct {
    fd: i32,
    info: Info,
    labels: ?[]const u8,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *const SessionProbeResult) void {
        if (self.labels) |lbl| self.alloc.free(lbl);
        lib_posix.close(self.fd);
    }
};

pub fn probeSession(
    alloc: std.mem.Allocator,
    socket_path: []const u8,
) SessionProbeError!SessionProbeResult {
    const timeout_ms = 1000;
    const fd = try connectSession(socket_path);
    errdefer lib_posix.close(fd);

    send(fd, .Info, "") catch return error.Unexpected;
    send(fd, .LabelGet, "") catch {};

    var poll_fds = [_]lib_posix.pollfd{.{ .fd = fd, .events = lib_posix.POLL.IN, .revents = 0 }};
    const poll_result = lib_posix.poll(&poll_fds, timeout_ms) catch return error.Unexpected;
    if (poll_result == 0) {
        return error.Timeout;
    }

    var sb = SocketBuffer.init(alloc) catch return error.Unexpected;
    defer sb.deinit();

    const n = sb.read(fd) catch return error.Unexpected;
    if (n == 0) return error.Unexpected;

    var info_result: ?Info = null;
    var labels: ?[]const u8 = null;
    errdefer if (labels) |lbl| alloc.free(lbl);

    while (true) {
        if (sb.next()) |msg| {
            if (msg.header.tag == .Info) {
                if (msg.payload.len != @sizeOf(Info)) return error.InfoSizeMismatch;
                info_result = std.mem.bytesToValue(Info, msg.payload[0..@sizeOf(Info)]);
            }
            if (msg.header.tag == .LabelData) {
                labels = alloc.dupe(u8, msg.payload) catch null;
            }

            if (info_result != null and labels != null) break;
            continue;
        }

        // No complete message available, wait for more data
        const more = lib_posix.poll(&poll_fds, 50) catch break;
        if (more == 0) break;
        const n_read = sb.read(fd) catch break;
        if (n_read == 0) break;
    }

    if (info_result) |info| {
        return .{
            .fd = fd,
            .info = info,
            .labels = labels,
            .alloc = alloc,
        };
    }
    return error.Unexpected;
}

//  WIRE PROTOCOL FREEZE: read before "fixing" any test below.
//
//  Changing these constants does not fix the test; it breaks every
//  running daemon for every user until they `pkill -f zmx`.
//
//  Need a new field?   → add a new `Tag` value (next free integer).
//  Need to remove one? → don't. Reserve the integer, stop sending it.
test "Info wire size is frozen" {
    try std.testing.expectEqual(@as(usize, 552), @sizeOf(Info));
    // packed struct{u8,u32} backs to u40 → @sizeOf rounds to 8, not 5.
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(Header));
}

test "Tag wire values are frozen" {
    inline for (.{
        .{ Tag.Input, 0 },          .{ Tag.Output, 1 },         .{ Tag.Resize, 2 },
        .{ Tag.Detach, 3 },         .{ Tag.DetachAll, 4 },      .{ Tag.Kill, 5 },
        .{ Tag.Info, 6 },           .{ Tag.Init, 7 },           .{ Tag.History, 8 },
        .{ Tag.Run, 9 },            .{ Tag.Ack, 10 },           .{ Tag.Switch, 11 },
        .{ Tag.Write, 12 },         .{ Tag.TaskComplete, 13 },  .{ Tag.LabelGet, 14 },
        .{ Tag.LabelSet, 15 },      .{ Tag.LabelClear, 16 },    .{ Tag.LabelData, 17 },
        .{ Tag.Send, 18 },          .{ Tag.SessionEnd, 19 },    .{ Tag.InitSnapshot, 20 },
        .{ Tag.SnapshotBegin, 21 }, .{ Tag.SnapshotChunk, 22 }, .{ Tag.SnapshotEnd, 23 },
        .{ Tag.SnapshotError, 24 },
    }) |p| try std.testing.expectEqual(@as(u8, p[1]), @intFromEnum(p[0]));
}

test "snapshot IPC payload codecs golden and bounds" {
    // End: u64 big-endian Ghostty byte count.
    var end: [8]u8 = undefined;
    writeSnapshotEndPayload(&end, 0x0102030405060708);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &end);
    try std.testing.expectEqual(@as(u64, 0x0102030405060708), parseSnapshotEndPayload(&end));

    // Error: u32 big-endian code + printable diag <= 256.
    var buf: [4 + snapshot_error_diag_max]u8 = undefined;
    const n = try writeSnapshotErrorPayload(&buf, snapshot_error_limit_exceeded, "too big");
    try std.testing.expectEqual(@as(usize, 4 + "too big".len), n);
    const parsed = try parseSnapshotErrorPayload(buf[0..n]);
    try std.testing.expectEqual(snapshot_error_limit_exceeded, parsed.code);
    try std.testing.expectEqualStrings("too big", parsed.diag);

    // Exactly 256 fits in both directions, 257 does not.
    try std.testing.expectEqual(@as(usize, 260), try writeSnapshotErrorPayload(&buf, 1, "a" ** 256));
    try std.testing.expectError(error.DiagTooLong, writeSnapshotErrorPayload(&buf, 1, "a" ** 257));
    const n256 = try writeSnapshotErrorPayload(&buf, 1, "b" ** 256);
    const parsed_max = try parseSnapshotErrorPayload(buf[0..n256]);
    try std.testing.expectEqual(@as(usize, 256), parsed_max.diag.len);
    var tiny: [7]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, writeSnapshotErrorPayload(&tiny, 1, "toolong"));

    // Non-printable diag bytes are rejected on write AND on parse, at
    // both control-character edges (0x01 and 0x7F).
    try std.testing.expectError(error.NonPrintableDiag, writeSnapshotErrorPayload(&buf, 1, "a\x01b"));
    try std.testing.expectError(error.NonPrintableDiag, writeSnapshotErrorPayload(&buf, 1, "a\x7Fb"));
    var raw: [6]u8 = undefined;
    std.mem.writeInt(u32, raw[0..4], 2, .big);
    raw[4] = 0x01;
    raw[5] = 0x7F;
    try std.testing.expectError(error.NonPrintableDiag, parseSnapshotErrorPayload(&raw));
    try std.testing.expectError(error.TooShort, parseSnapshotErrorPayload(raw[0..2]));

    // A parse-side 257-byte printable diag is rejected at the bound.
    var long_raw: [4 + 257]u8 = undefined;
    std.mem.writeInt(u32, long_raw[0..4], 1, .big);
    @memset(long_raw[4..], 'c');
    try std.testing.expectError(error.DiagTooLong, parseSnapshotErrorPayload(&long_raw));

    // Known-code predicate covers exactly the five frozen codes.
    var code: u32 = 0;
    while (code <= 6) : (code += 1) {
        try std.testing.expectEqual(code >= 1 and code <= 5, snapshotErrorKnown(code));
    }

    // Chunk payload bounds are the documented constants.
    try std.testing.expectEqual(@as(usize, 32 * 1024), snapshot_chunk_max);
    try std.testing.expectEqual(@as(usize, 1), snapshot_chunk_min);
}

/// The Q3 gateway's per-frame cap: one header plus 64 KiB of payload.
/// A large legacy `.Init` VT replay exceeds this by design and fails
/// closed until Q4's chunked snapshots.
pub const gateway_frame_cap: usize = @sizeOf(Header) + 64 * 1024;

// ---------------------------------------------------------------------------
// Q4 snapshot IPC payload bounds and codecs (tags 20-24)
// ---------------------------------------------------------------------------

/// A SnapshotChunk payload is 1..=32 KiB of opaque Ghostty bytes.
pub const snapshot_chunk_min: usize = 1;
pub const snapshot_chunk_max: usize = 32 * 1024;
/// The longest printable SnapshotError diagnostic.
pub const snapshot_error_diag_max: usize = 256;

/// Frozen local (daemon -> gateway) snapshot error codes. Unknown codes
/// or malformed payloads fail the gateway session closed.
pub const snapshot_error_invalid_request: u32 = 1;
pub const snapshot_error_continuation_unavailable: u32 = 2;
pub const snapshot_error_encode_failed: u32 = 3;
pub const snapshot_error_limit_exceeded: u32 = 4;
pub const snapshot_error_out_of_memory: u32 = 5;

/// True when `code` is one of the five frozen local snapshot codes.
pub fn snapshotErrorKnown(code: u32) bool {
    return switch (code) {
        snapshot_error_invalid_request,
        snapshot_error_continuation_unavailable,
        snapshot_error_encode_failed,
        snapshot_error_limit_exceeded,
        snapshot_error_out_of_memory,
        => true,
        else => false,
    };
}

/// SnapshotEnd payload: u64 big-endian count of Ghostty bytes only.
pub fn writeSnapshotEndPayload(out: *[8]u8, ghostty_bytes: u64) void {
    std.mem.writeInt(u64, out, ghostty_bytes, .big);
}

pub fn parseSnapshotEndPayload(bytes: *const [8]u8) u64 {
    return std.mem.readInt(u64, bytes, .big);
}

/// SnapshotError payload: code u32 big-endian plus a printable
/// diagnostic (<= 256 bytes). Mirrors the ZMQ1 ERROR payload shape but
/// lives here so the daemon never imports the QUIC wire module. Both
/// directions enforce printability and the 256-byte bound.
pub fn writeSnapshotErrorPayload(
    out: []u8,
    code: u32,
    diag: []const u8,
) error{ DiagTooLong, NonPrintableDiag, BufferTooSmall }!usize {
    if (diag.len > snapshot_error_diag_max) return error.DiagTooLong;
    for (diag) |c| {
        if (c < 0x20 or c > 0x7E) return error.NonPrintableDiag;
    }
    if (out.len < 4 + diag.len) return error.BufferTooSmall;
    std.mem.writeInt(u32, out[0..4], code, .big);
    @memcpy(out[4 .. 4 + diag.len], diag);
    return 4 + diag.len;
}

pub const SnapshotErrorWire = struct { code: u32, diag: []const u8 };

pub const SnapshotErrorPayloadError = error{ TooShort, DiagTooLong, NonPrintableDiag };

pub fn parseSnapshotErrorPayload(bytes: []const u8) SnapshotErrorPayloadError!SnapshotErrorWire {
    if (bytes.len < 4) return error.TooShort;
    const diag = bytes[4..];
    if (diag.len > snapshot_error_diag_max) return error.DiagTooLong;
    for (diag) |c| {
        if (c < 0x20 or c > 0x7E) return error.NonPrintableDiag;
    }
    return .{ .code = std.mem.readInt(u32, bytes[0..4], .big), .diag = diag };
}

test "bounded SocketBuffer rejects an oversized declared length before payload accumulation" {
    const alloc = std.testing.allocator;
    // A nonblocking pipe stands in for the daemon socket, exactly as
    // the serve fixtures do.
    const fds = try lib_posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    defer lib_posix.close(fds[0]);
    defer lib_posix.close(fds[1]);

    var bounded = try SocketBuffer.initBounded(alloc, gateway_frame_cap);
    defer bounded.deinit();

    // A normal 4 KiB PTY-sized frame reads through fine (the reader
    // pulls 4 KiB per call; drain until WouldBlock, then consume).
    {
        var payload: [4096]u8 = undefined;
        @memset(&payload, 'x');
        try send(fds[1], .Output, &payload);
        while (true) {
            _ = bounded.read(fds[0]) catch break;
        }
        var seen: usize = 0;
        while (bounded.next()) |_| seen += 1;
        try std.testing.expectEqual(@as(usize, 1), seen);
    }

    // An oversized DECLARED length: rejection fires as soon as the
    // header is readable — only kilobytes accumulate, never the
    // declared payload.
    {
        const hdr = Header{ .tag = .Output, .len = 10 * 1024 * 1024 };
        const hdr_bytes = std.mem.toBytes(hdr);
        _ = try lib_posix.write(fds[1], &hdr_bytes);
        try std.testing.expectError(error.FrameTooLarge, bounded.read(fds[0]));
        try std.testing.expect(bounded.buf.items.len < 8192);
    }

    // A legal leading frame must not mask an oversized pending one.
    {
        var sb = try SocketBuffer.initBounded(alloc, @sizeOf(Header) + 8);
        defer sb.deinit();
        try send(fds[1], .Input, "12345678");
        const big = Header{ .tag = .Output, .len = 4096 };
        const big_bytes = std.mem.toBytes(big);
        _ = try lib_posix.write(fds[1], &big_bytes);
        var rejected = false;
        var attempts: usize = 0;
        while (attempts < 8) : (attempts += 1) {
            _ = sb.read(fds[0]) catch |e| {
                try std.testing.expectEqual(error.FrameTooLarge, e);
                rejected = true;
                break;
            };
        }
        try std.testing.expect(rejected);
    }
}

test "SocketBuffer.readAtMost admits only the authorized bytes of a coalesced frame" {
    const alloc = std.testing.allocator;
    const fds = try lib_posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    defer lib_posix.close(fds[0]);
    defer lib_posix.close(fds[1]);

    var sb = try SocketBuffer.initBounded(alloc, gateway_frame_cap);
    defer sb.deinit();

    // One contiguous header + 16-byte payload preloaded in the pipe —
    // the coalesced arrival shape.
    try send(fds[1], .Output, "0123456789abcdef");

    // Capped at the header: exactly its 8 bytes enter the buffer, the
    // payload stays in the pipe, and the frame is correctly incomplete.
    {
        const n = try sb.readAtMost(fds[0], @sizeOf(Header));
        try std.testing.expectEqual(@sizeOf(Header), n);
        try std.testing.expectEqual(@sizeOf(Header), sb.buf.items.len);
        try std.testing.expect(sb.next() == null);
    }
    // A one-byte cap stays binding mid-payload.
    {
        const n = try sb.readAtMost(fds[0], 1);
        try std.testing.expectEqual(@as(usize, 1), n);
        try std.testing.expectEqual(@sizeOf(Header) + 1, sb.buf.items.len);
    }
    // The remainder recovers exactly: the frame completes losslessly
    // through further capped reads.
    var msg: ?SocketMsg = null;
    while (true) {
        if (sb.next()) |m| {
            msg = m;
            break;
        }
        _ = sb.readAtMost(fds[0], 4096) catch |e| switch (e) {
            error.WouldBlock => return error.PayloadLost,
            else => return e,
        };
    }
    const m = msg.?;
    try std.testing.expectEqual(Tag.Output, m.header.tag);
    try std.testing.expectEqualStrings("0123456789abcdef", m.payload);
}

pub fn roundTripForTag(
    alloc: std.mem.Allocator,
    socket_path: []const u8,
    request_tag: Tag,
    payload: []const u8,
    expected_tag: Tag,
) SessionProbeError![]u8 {
    const timeout_ms = 1000;
    const fd = try connectSession(socket_path);
    defer lib_posix.close(fd);

    send(fd, request_tag, payload) catch return error.Unexpected;

    var poll_fds = [_]lib_posix.pollfd{.{ .fd = fd, .events = lib_posix.POLL.IN, .revents = 0 }};
    const poll_result = lib_posix.poll(&poll_fds, timeout_ms) catch return error.Unexpected;
    if (poll_result == 0) return error.Timeout;

    var sb = SocketBuffer.init(alloc) catch return error.Unexpected;
    defer sb.deinit();

    const n = sb.read(fd) catch return error.Unexpected;
    if (n == 0) return error.Unexpected;

    while (sb.next()) |msg| {
        if (msg.header.tag == expected_tag) {
            return alloc.dupe(u8, msg.payload) catch return error.Unexpected;
        }
    }
    return error.Unexpected;
}

test "zeroed Info has no stack garbage in wire bytes" {
    var info = std.mem.zeroes(Info);
    info.clients_len = 3;
    info.pid = 999;
    info.task_exit_code = 7;
    const bytes = std.mem.asBytes(&info);
    // Tail padding after task_exit_code must be zero (asBytes ships it).
    const last_field_end = @offsetOf(Info, "task_exit_code") + @sizeOf(u8);
    for (bytes[last_field_end..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
