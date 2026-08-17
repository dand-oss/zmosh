//! Remote one-shot command protocol: framing, validation, reassembly.
//!
//! A command rides the reliable UDP transport inside `Channel.command`
//! packets. Each packet carries one frame of the frozen envelope:
//!
//!   20-byte header
//!   0       version       u8, initially 1
//!   1       kind          request=1, response=2, cancel=3
//!   2       opcode        u8
//!   3       status        u8; zero in requests
//!   4       flags         FIRST=1, LAST=2, STREAM=4
//!   5..7    reserved      zero
//!   8..11   request_id    u32 big-endian
//!   12..15  total_len     u32 big-endian
//!   16..19  offset        u32 big-endian
//!   20..    payload
//!
//! Chunks must be `max_chunk_payload`-aligned: a chunk's offset is
//! `index * max_chunk_payload` and every chunk except the final one is
//! full-size. This keeps duplicate detection and completion cheap and
//! makes malformed input rejectable before any allocation.
//!
//! This module is pure framing — no sockets, no I/O, no logging of
//! command content, labels, or file data.

const std = @import("std");
const transport = @import("transport.zig");

pub const version: u8 = 1;
pub const header_len: usize = 20;

/// Largest command payload carried in a single transport packet.
pub const max_chunk_payload: usize = transport.max_payload_len - header_len;

/// Shared cap for local and remote `write` (and any request body):
/// 64 MiB, so parity and memory bounds stay identical.
pub const max_total_len: usize = 64 * 1024 * 1024;

/// In-flight command frames allowed at once. The transport ACK window
/// is 32 packets; staying at 16 leaves headroom for heartbeats, ACKs,
/// and retransmits so a lost early chunk remains recoverable.
pub const max_inflight_chunks: usize = 16;

pub const Kind = enum(u8) {
    request = 1,
    response = 2,
    cancel = 3,
};

pub const Opcode = enum(u8) {
    send = 1,
    print = 2,
    write = 3,
    label_get = 4,
    label_set = 5,
    label_clear = 6,
    tail = 7,
    kill = 8,
};

pub const Status = enum(u8) {
    ok = 0,
    invalid_request = 1,
    unsupported_version = 2,
    unsupported_opcode = 3,
    session_not_found = 4,
    session_unresponsive = 5,
    timeout = 6,
    too_large = 7,
    cancelled = 8,
    backpressure = 9,
    internal_error = 255,
};

pub const Flags = struct {
    pub const FIRST: u8 = 1;
    pub const LAST: u8 = 2;
    pub const STREAM: u8 = 4;
};

pub const Header = struct {
    version: u8,
    kind: Kind,
    opcode: Opcode,
    status: Status,
    flags: u8,
    request_id: u32,
    total_len: u32,
    offset: u32,
};

pub const ParseError = error{
    TooShort,
    UnsupportedVersion,
    InvalidKind,
    InvalidOpcode,
    InvalidStatus,
    InvalidStatusForKind,
    ReservedNotZero,
    InvalidFlags,
    InvalidGeometry,
};

/// Serialize a header (big-endian fields) into exactly 20 bytes.
pub fn writeHeader(dst: *[header_len]u8, h: Header) void {
    dst[0] = h.version;
    dst[1] = @intFromEnum(h.kind);
    dst[2] = @intFromEnum(h.opcode);
    dst[3] = @intFromEnum(h.status);
    dst[4] = h.flags;
    dst[5] = 0;
    dst[6] = 0;
    dst[7] = 0;
    std.mem.writeInt(u32, dst[8..12], h.request_id, .big);
    std.mem.writeInt(u32, dst[12..16], h.total_len, .big);
    std.mem.writeInt(u32, dst[16..20], h.offset, .big);
}

/// Parse and validate a header. Field-level validation happens before the
/// caller ever allocates reassembly state.
pub fn parseHeader(data: []const u8) ParseError!Header {
    if (data.len < header_len) return error.TooShort;

    const ver = data[0];
    if (ver != version) return error.UnsupportedVersion;

    const kind = std.enums.fromInt(Kind, data[1]) orelse return error.InvalidKind;
    const opcode = std.enums.fromInt(Opcode, data[2]) orelse return error.InvalidOpcode;
    const status = std.enums.fromInt(Status, data[3]) orelse return error.InvalidStatus;

    const flags = data[4];
    if (flags & ~(Flags.FIRST | Flags.LAST | Flags.STREAM) != 0) return error.InvalidFlags;

    if (data[5] != 0 or data[6] != 0 or data[7] != 0) return error.ReservedNotZero;

    return .{
        .version = ver,
        .kind = kind,
        .opcode = opcode,
        .status = status,
        .flags = flags,
        .request_id = std.mem.readInt(u32, data[8..12], .big),
        .total_len = std.mem.readInt(u32, data[12..16], .big),
        .offset = std.mem.readInt(u32, data[16..20], .big),
    };
}

pub const Chunk = struct {
    header: Header,
    payload: []const u8,
};

/// Parse a full frame (header + payload) and enforce chunk geometry:
/// aligned offset, in-bounds sizes, and canonical FIRST/LAST geometry.
pub fn parseChunk(data: []const u8) ParseError!Chunk {
    const h = try parseHeader(data);
    const payload = data[header_len..];

    if ((h.kind == .request or h.kind == .cancel) and h.status != .ok) {
        return error.InvalidStatusForKind;
    }
    if (h.total_len > max_total_len) return error.InvalidGeometry;
    if (payload.len > max_chunk_payload) return error.InvalidGeometry;

    // Empty request bodies still need one authenticated frame so tail and
    // label_clear can be represented without inventing a sentinel byte.
    if (h.total_len == 0) {
        if (payload.len != 0 or h.offset != 0 or h.flags != (Flags.FIRST | Flags.LAST)) {
            return error.InvalidGeometry;
        }
        if ((h.kind == .request or h.kind == .cancel) and h.flags & Flags.STREAM != 0) {
            return error.InvalidGeometry;
        }
        return .{ .header = h, .payload = payload };
    }

    if (h.offset > max_total_len or h.offset % max_chunk_payload != 0) return error.InvalidGeometry;

    const offset_len = @as(usize, h.offset) + payload.len;
    if (offset_len > h.total_len) return error.InvalidGeometry;
    // A non-final chunk must be full-size; the final chunk is whatever
    // remains. Enforced via alignment + the offset_len bound above, but a
    // short chunk claiming to be in the middle is malformed.
    if (offset_len < h.total_len and payload.len != max_chunk_payload) return error.InvalidGeometry;

    const expected_flags: u8 = (if (h.offset == 0) Flags.FIRST else 0) |
        (if (offset_len == h.total_len) Flags.LAST else 0);
    if (h.flags & (Flags.FIRST | Flags.LAST) != expected_flags) return error.InvalidGeometry;
    if ((h.kind == .request or h.kind == .cancel) and h.flags & Flags.STREAM != 0) {
        return error.InvalidGeometry;
    }

    return .{ .header = h, .payload = payload };
}

/// Build a frame in `dst`; returns the full frame slice.
pub fn writeFrame(dst: []u8, h: Header, payload: []const u8) error{NoSpace}![]u8 {
    if (dst.len < header_len + payload.len) return error.NoSpace;
    writeFrameHeaderOnly(dst, h);
    @memcpy(dst[header_len .. header_len + payload.len], payload);
    return dst[0 .. header_len + payload.len];
}

fn writeFrameHeaderOnly(dst: []u8, h: Header) void {
    writeHeader(dst[0..header_len], h);
}

// ---------------------------------------------------------------------------
// Request-body shape validation (applied to the reassembled message)
// ---------------------------------------------------------------------------

pub const BodyError = error{
    InvalidWriteBody,
    InvalidKillBody,
    InvalidTailBody,
    InvalidLabelClearBody,
};

/// Validate the opcode-specific shape of a complete request body. Content
/// validation (label syntax) belongs to the gateway, which reuses the
/// local command validators.
pub fn validateRequestBody(op: Opcode, body: []const u8) BodyError!void {
    switch (op) {
        .send, .print, .label_get, .label_set => {},
        .write => {
            // path_len:u32 BE | path | file bytes
            if (body.len < 4) return error.InvalidWriteBody;
            const path_len = std.mem.readInt(u32, body[0..4], .big);
            if (path_len == 0 or path_len > body.len - 4) return error.InvalidWriteBody;
            if (std.mem.indexOfScalar(u8, body[4 .. 4 + path_len], 0) != null) return error.InvalidWriteBody;
        },
        .kill => {
            // one byte: force=false/true
            if (body.len != 1 or (body[0] != 0 and body[0] != 1)) return error.InvalidKillBody;
        },
        .tail => {
            if (body.len != 0) return error.InvalidTailBody;
        },
        .label_clear => {
            if (body.len != 0) return error.InvalidLabelClearBody;
        },
    }
}

// ---------------------------------------------------------------------------
// Reassembly — one request per command gateway
// ---------------------------------------------------------------------------

pub const StartResult = enum {
    started,
    /// Same request_id already reassembled: serve from the response cache.
    already_complete,
};

pub const OnChunkResult = enum {
    progress,
    complete,
};

pub const ReassembleError = error{
    NotStarted,
    SecondRequest,
    ConflictingOverlap,
    ChunkAfterComplete,
    KindMismatch,
} || ParseError || std.mem.Allocator.Error;

pub const Reassembler = struct {
    request_id: u32 = 0,
    opcode: Opcode = .send,
    total_len: usize = 0,
    buf: []u8 = &.{},
    /// One entry per aligned chunk slot.
    covered: []bool = &.{},
    chunks_received: usize = 0,
    chunks_total: usize = 0,
    complete: bool = false,

    /// Begin (or resume) reassembly for a request's FIRST chunk. Only one
    /// request_id is accepted per gateway; the same id after completion
    /// reports `already_complete` so a duplicate is answered from cache.
    pub fn start(self: *Reassembler, alloc: std.mem.Allocator, h: Header) ReassembleError!StartResult {
        if (h.kind != .request) return error.KindMismatch;
        if (self.complete) {
            if (h.request_id != self.request_id) return error.SecondRequest;
            if (h.opcode != self.opcode or h.total_len != self.total_len) return error.ConflictingOverlap;
            return .already_complete;
        }
        if (self.chunks_total != 0) {
            // In progress: only the same request continues.
            if (h.request_id != self.request_id) return error.SecondRequest;
            if (h.opcode != self.opcode or h.total_len != self.total_len) return error.ConflictingOverlap;
            return .started;
        }
        if (h.total_len > max_total_len) return error.InvalidGeometry;

        const total: usize = h.total_len;
        const chunks_total = if (total == 0)
            1
        else
            std.math.divCeil(usize, total, max_chunk_payload) catch return error.InvalidGeometry;
        const buf = try alloc.alloc(u8, total);
        errdefer alloc.free(buf);
        const covered = try alloc.alloc(bool, chunks_total);
        @memset(covered, false);

        self.request_id = h.request_id;
        self.opcode = h.opcode;
        self.total_len = total;
        self.chunks_total = chunks_total;
        self.buf = buf;
        self.covered = covered;
        return .started;
    }

    /// Feed one raw frame. Byte-identical duplicates are ignored;
    /// conflicting overlaps are rejected. Returns `.complete` exactly once.
    pub fn onChunk(self: *Reassembler, data: []const u8) ReassembleError!OnChunkResult {
        if (self.chunks_total == 0) return error.NotStarted;
        const chunk = try parseChunk(data);
        const h = chunk.header;

        if (h.request_id != self.request_id) return error.SecondRequest;
        if (h.kind != .request) return error.KindMismatch;
        if (self.complete) return error.ChunkAfterComplete;
        if (h.opcode != self.opcode or h.total_len != self.total_len) return error.ConflictingOverlap;

        const idx = if (self.total_len == 0) 0 else h.offset / max_chunk_payload;
        if (idx >= self.chunks_total) return error.InvalidGeometry;

        if (self.covered[idx]) {
            // Duplicate: byte-identical is a no-op, conflicting is fatal.
            const existing = self.buf[h.offset .. h.offset + chunk.payload.len];
            if (!std.mem.eql(u8, existing, chunk.payload)) return error.ConflictingOverlap;
            return .progress;
        }

        @memcpy(self.buf[h.offset .. h.offset + chunk.payload.len], chunk.payload);
        self.covered[idx] = true;
        self.chunks_received += 1;
        if (self.chunks_received == self.chunks_total) {
            self.complete = true;
            return .complete;
        }
        return .progress;
    }

    /// The fully reassembled request body (valid once complete).
    pub fn message(self: *const Reassembler) []const u8 {
        return self.buf[0..self.total_len];
    }

    pub fn deinit(self: *Reassembler, alloc: std.mem.Allocator) void {
        if (self.buf.len > 0) alloc.free(self.buf);
        if (self.covered.len > 0) alloc.free(self.covered);
        self.* = .{};
    }
};

// ---------------------------------------------------------------------------
// Response cache — duplicates must never re-execute write or kill
// ---------------------------------------------------------------------------

pub const ResponseCache = struct {
    request_id: ?u32 = null,
    response: []u8 = &.{},

    pub fn store(self: *ResponseCache, alloc: std.mem.Allocator, request_id: u32, response: []const u8) !void {
        const copy = try alloc.dupe(u8, response);
        if (self.response.len > 0) alloc.free(self.response);
        self.response = copy;
        self.request_id = request_id;
    }

    /// Hit only on the exact request_id.
    pub fn get(self: *const ResponseCache, request_id: u32) ?[]const u8 {
        if (self.request_id == request_id) return self.response;
        return null;
    }

    pub fn deinit(self: *ResponseCache, alloc: std.mem.Allocator) void {
        if (self.response.len > 0) alloc.free(self.response);
        self.* = .{};
    }
};

// ---------------------------------------------------------------------------
// Sender-side flow-control accounting
// ---------------------------------------------------------------------------

pub const WindowError = error{WindowFull};

/// Tracks in-flight command frames against the 16-packet budget. The
/// sender queues additional chunks until ACKs release capacity.
pub const SendWindow = struct {
    in_flight: usize = 0,

    pub fn admit(self: *SendWindow) WindowError!void {
        if (self.in_flight >= max_inflight_chunks) return error.WindowFull;
        self.in_flight += 1;
    }

    pub fn release(self: *SendWindow, n: usize) void {
        self.in_flight -= @min(n, self.in_flight);
    }

    pub fn capacity(self: *const SendWindow) usize {
        return max_inflight_chunks - self.in_flight;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "golden header bytes" {
    var buf: [header_len]u8 = undefined;
    writeHeader(&buf, .{
        .version = 1,
        .kind = .request,
        .opcode = .send,
        .status = .ok,
        .flags = Flags.FIRST | Flags.LAST,
        .request_id = 0xDEADBEEF,
        .total_len = 5,
        .offset = 0,
    });
    const expected = [_]u8{
        1,    1,    1,    0,    3,    0,    0,    0,
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x05,
        0x00, 0x00, 0x00, 0x00,
    };
    try testing.expectEqualSlices(u8, &expected, &buf);
}

test "frozen enum values" {
    try testing.expectEqual(@as(u8, 1), @intFromEnum(Kind.request));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(Kind.response));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(Kind.cancel));

    try testing.expectEqual(@as(u8, 1), @intFromEnum(Opcode.send));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(Opcode.print));
    try testing.expectEqual(@as(u8, 3), @intFromEnum(Opcode.write));
    try testing.expectEqual(@as(u8, 4), @intFromEnum(Opcode.label_get));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(Opcode.label_set));
    try testing.expectEqual(@as(u8, 6), @intFromEnum(Opcode.label_clear));
    try testing.expectEqual(@as(u8, 7), @intFromEnum(Opcode.tail));
    try testing.expectEqual(@as(u8, 8), @intFromEnum(Opcode.kill));

    try testing.expectEqual(@as(u8, 0), @intFromEnum(Status.ok));
    try testing.expectEqual(@as(u8, 255), @intFromEnum(Status.internal_error));
}

test "header round-trip" {
    var buf: [header_len]u8 = undefined;
    const h = Header{
        .version = 1,
        .kind = .response,
        .opcode = .label_get,
        .status = .session_not_found,
        .flags = Flags.STREAM,
        .request_id = 7,
        .total_len = 1234,
        .offset = 1080,
    };
    writeHeader(&buf, h);
    const parsed = try parseHeader(&buf);
    try testing.expectEqual(h.version, parsed.version);
    try testing.expectEqual(h.kind, parsed.kind);
    try testing.expectEqual(h.opcode, parsed.opcode);
    try testing.expectEqual(h.status, parsed.status);
    try testing.expectEqual(h.flags, parsed.flags);
    try testing.expectEqual(h.request_id, parsed.request_id);
    try testing.expectEqual(h.total_len, parsed.total_len);
    try testing.expectEqual(h.offset, parsed.offset);
}

test "header validation rejects bad fields" {
    var buf: [header_len]u8 = undefined;
    const good = Header{ .version = 1, .kind = .request, .opcode = .kill, .status = .ok, .flags = 0, .request_id = 1, .total_len = 1, .offset = 0 };
    writeHeader(&buf, good);

    try testing.expectError(error.TooShort, parseHeader(buf[0 .. header_len - 1]));

    buf[0] = 2;
    try testing.expectError(error.UnsupportedVersion, parseHeader(&buf));
    buf[0] = 1;

    buf[1] = 4;
    try testing.expectError(error.InvalidKind, parseHeader(&buf));
    buf[1] = 1;

    buf[2] = 9;
    try testing.expectError(error.InvalidOpcode, parseHeader(&buf));
    buf[2] = 8;

    buf[3] = 10;
    try testing.expectError(error.InvalidStatus, parseHeader(&buf));
    buf[3] = 0;

    buf[4] = 8; // no such flag bit
    try testing.expectError(error.InvalidFlags, parseHeader(&buf));
    buf[4] = 0;

    buf[5] = 1;
    try testing.expectError(error.ReservedNotZero, parseHeader(&buf));
    buf[5] = 0;
}

test "empty request frame reassembles" {
    const alloc = testing.allocator;
    var frame: [header_len]u8 = undefined;
    writeHeader(&frame, .{
        .version = version,
        .kind = .request,
        .opcode = .tail,
        .status = .ok,
        .flags = Flags.FIRST | Flags.LAST,
        .request_id = 11,
        .total_len = 0,
        .offset = 0,
    });

    const chunk = try parseChunk(&frame);
    var r = Reassembler{};
    defer r.deinit(alloc);
    try testing.expectEqual(StartResult.started, try r.start(alloc, chunk.header));
    try testing.expectEqual(OnChunkResult.complete, try r.onChunk(&frame));
    try testing.expectEqual(@as(usize, 0), r.message().len);
    try validateRequestBody(.tail, r.message());
    try validateRequestBody(.label_clear, r.message());
}

test "chunk semantics reject nonzero request status, stream requests, and bad FIRST/LAST" {
    var buf: [header_len + max_chunk_payload]u8 = undefined;
    const total = max_chunk_payload + 1;
    const base = Header{
        .version = version,
        .kind = .request,
        .opcode = .send,
        .status = .ok,
        .flags = Flags.FIRST,
        .request_id = 12,
        .total_len = @intCast(total),
        .offset = 0,
    };

    writeHeader(buf[0..header_len], base);
    @memset(buf[header_len..], 'x');
    try testing.expectEqual(max_chunk_payload, (try parseChunk(buf[0 .. header_len + max_chunk_payload])).payload.len);

    var bad = base;
    bad.status = .internal_error;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidStatusForKind, parseChunk(buf[0 .. header_len + max_chunk_payload]));

    bad = base;
    bad.flags = Flags.FIRST | Flags.STREAM;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + max_chunk_payload]));

    bad = base;
    bad.flags = 0;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + max_chunk_payload]));

    bad = base;
    bad.flags = Flags.FIRST | Flags.LAST;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + max_chunk_payload]));

    bad = base;
    bad.offset = @intCast(max_chunk_payload);
    bad.flags = Flags.FIRST | Flags.LAST;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + 1]));
}

test "chunk geometry validation" {
    var buf: [header_len + max_chunk_payload]u8 = undefined;
    const base = Header{ .version = 1, .kind = .request, .opcode = .send, .status = .ok, .flags = Flags.FIRST, .request_id = 1, .total_len = max_chunk_payload + 10, .offset = 0 };

    // aligned, full first chunk: ok
    writeHeader(buf[0..header_len], base);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + 4])); // short non-final chunk
    const ok_chunk = try parseChunk(buf[0 .. header_len + max_chunk_payload]);
    try testing.expectEqual(@as(usize, max_chunk_payload), ok_chunk.payload.len);

    // unaligned offset
    var bad = base;
    bad.offset = @intCast(max_chunk_payload - 1);
    bad.flags = 0;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + 4]));

    // offset + payload beyond total_len
    bad = base;
    bad.offset = @intCast(max_chunk_payload);
    bad.total_len = @intCast(max_chunk_payload + 5);
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + 10]));

    // total_len over the shared cap
    bad = base;
    bad.total_len = @intCast(max_total_len + 1);
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + 10]));

    // FIRST with nonzero offset
    bad = base;
    bad.offset = @intCast(max_chunk_payload);
    bad.flags = Flags.FIRST;
    writeHeader(buf[0..header_len], bad);
    try testing.expectError(error.InvalidGeometry, parseChunk(buf[0 .. header_len + 10]));
}

fn frameFor(alloc: std.mem.Allocator, id: u32, total: usize, offset: usize, flags: u8, payload: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, header_len + payload.len);
    writeHeader(buf[0..header_len], .{
        .version = version,
        .kind = .request,
        .opcode = .send,
        .status = .ok,
        .flags = flags,
        .request_id = id,
        .total_len = @intCast(total),
        .offset = @intCast(offset),
    });
    @memcpy(buf[header_len..], payload);
    return buf;
}

test "reassemble single chunk" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const payload = "hello";
    const frame = try frameFor(alloc, 9, payload.len, 0, Flags.FIRST | Flags.LAST, payload);
    defer alloc.free(frame);

    const started = try r.start(alloc, (try parseChunk(frame)).header);
    try testing.expectEqual(StartResult.started, started);
    try testing.expectEqual(OnChunkResult.complete, try r.onChunk(frame));
    try testing.expectEqualStrings("hello", r.message());
}

test "reassemble out-of-order chunks" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const body = "A" ** (max_chunk_payload) ++ "B" ** 10;
    const f0 = try frameFor(alloc, 3, body.len, 0, Flags.FIRST, body[0..max_chunk_payload]);
    const f1 = try frameFor(alloc, 3, body.len, max_chunk_payload, Flags.LAST, body[max_chunk_payload..]);
    defer alloc.free(f0);
    defer alloc.free(f1);

    _ = try r.start(alloc, (try parseChunk(f1)).header);
    // Deliver the final chunk FIRST: header carried on it (FIRST flag on
    // the zero-offset chunk only matters for start(); accept either order.
    try testing.expectEqual(OnChunkResult.progress, try r.onChunk(f1));
    try testing.expectEqual(OnChunkResult.complete, try r.onChunk(f0));
    try testing.expectEqualStrings(body, r.message());
}

test "byte-identical duplicate is ignored; conflicting overlap rejected" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const body = "xy" ** 540;
    const f0 = try frameFor(alloc, 5, body.len, 0, Flags.FIRST | Flags.LAST, body);
    defer alloc.free(f0);

    _ = try r.start(alloc, (try parseChunk(f0)).header);
    try testing.expectEqual(OnChunkResult.complete, try r.onChunk(f0));
    // duplicate after completion is a chunk-after-complete, but the
    // duplicate-before-complete case:
    var r2 = Reassembler{};
    defer r2.deinit(alloc);
    const long = "z" ** (max_chunk_payload) ++ "tail";
    const g0 = try frameFor(alloc, 6, long.len, 0, Flags.FIRST, long[0..max_chunk_payload]);
    const g1 = try frameFor(alloc, 6, long.len, max_chunk_payload, Flags.LAST, long[max_chunk_payload..]);
    defer alloc.free(g0);
    defer alloc.free(g1);
    _ = try r2.start(alloc, (try parseChunk(g0)).header);
    try testing.expectEqual(OnChunkResult.progress, try r2.onChunk(g0));

    // identical duplicate: still progress, not complete
    try testing.expectEqual(OnChunkResult.progress, try r2.onChunk(g0));

    // conflicting duplicate: rejected
    const conflict = try alloc.dupe(u8, g0);
    defer alloc.free(conflict);
    conflict[header_len] ^= 0xFF;
    try testing.expectError(error.ConflictingOverlap, r2.onChunk(conflict));

    try testing.expectEqual(OnChunkResult.complete, try r2.onChunk(g1));
}

test "one request per gateway" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const a = try frameFor(alloc, 1, 4, 0, Flags.FIRST | Flags.LAST, "aaaa");
    const b = try frameFor(alloc, 2, 4, 0, Flags.FIRST | Flags.LAST, "bbbb");
    defer alloc.free(a);
    defer alloc.free(b);

    _ = try r.start(alloc, (try parseChunk(a)).header);
    try testing.expectEqual(OnChunkResult.complete, try r.onChunk(a));

    // same id after completion: already_complete (serve from cache)
    try testing.expectEqual(StartResult.already_complete, try r.start(alloc, (try parseChunk(a)).header));
    // different id: rejected
    try testing.expectError(error.SecondRequest, r.start(alloc, (try parseChunk(b)).header));
    try testing.expectError(error.SecondRequest, r.onChunk(b));
}

test "same request id with conflicting metadata is rejected" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const body = "a" ** max_chunk_payload ++ "b";
    const first = try frameFor(alloc, 13, body.len, 0, Flags.FIRST, body[0..max_chunk_payload]);
    defer alloc.free(first);
    const final = try frameFor(alloc, 13, body.len, max_chunk_payload, Flags.LAST, body[max_chunk_payload..]);
    defer alloc.free(final);

    _ = try r.start(alloc, (try parseChunk(first)).header);
    try testing.expectEqual(OnChunkResult.progress, try r.onChunk(first));

    var different_total = try alloc.dupe(u8, first);
    defer alloc.free(different_total);
    writeHeader(different_total[0..header_len], .{
        .version = version,
        .kind = .request,
        .opcode = .send,
        .status = .ok,
        .flags = Flags.FIRST,
        .request_id = 13,
        .total_len = @intCast(max_chunk_payload * 2),
        .offset = 0,
    });
    try testing.expectError(error.ConflictingOverlap, r.onChunk(different_total));

    var different_opcode = try alloc.dupe(u8, first);
    defer alloc.free(different_opcode);
    different_opcode[2] = @intFromEnum(Opcode.print);
    try testing.expectError(error.ConflictingOverlap, r.onChunk(different_opcode));

    try testing.expectEqual(OnChunkResult.complete, try r.onChunk(final));

    const complete_header = (try parseChunk(final)).header;
    try testing.expectError(error.ConflictingOverlap, r.start(alloc, .{
        .version = complete_header.version,
        .kind = complete_header.kind,
        .opcode = .print,
        .status = complete_header.status,
        .flags = complete_header.flags,
        .request_id = complete_header.request_id,
        .total_len = complete_header.total_len,
        .offset = complete_header.offset,
    }));
}

test "more than 32 chunks with loss, retransmission, and reorder" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const n_chunks = 40;
    const body = try alloc.alloc(u8, max_chunk_payload * n_chunks);
    defer alloc.free(body);
    for (body, 0..) |*b, i| b.* = @intCast((i * 7) % 251);

    // Simulate loss: deliver even indexes while odd indexes are lost, then
    // retransmit the odd indexes in a reordered pass.
    var frames = try alloc.alloc([]u8, n_chunks);
    defer {
        for (frames) |f| alloc.free(f);
        alloc.free(frames);
    }
    for (0..n_chunks) |i| {
        const flags: u8 = if (i == 0) Flags.FIRST else if (i == n_chunks - 1) Flags.LAST else 0;
        const end = @min((i + 1) * max_chunk_payload, body.len);
        frames[i] = try frameFor(alloc, 77, body.len, i * max_chunk_payload, flags, body[i * max_chunk_payload .. end]);
    }

    _ = try r.start(alloc, (try parseChunk(frames[0])).header);
    var i: usize = 0;
    while (i < n_chunks) : (i += 2) {
        try testing.expectEqual(OnChunkResult.progress, try r.onChunk(frames[i]));
    }

    // An identical retransmission is harmless; a changed payload for an
    // already-covered slot is a conflicting overlap.
    try testing.expectEqual(OnChunkResult.progress, try r.onChunk(frames[2]));
    const conflict = try alloc.dupe(u8, frames[2]);
    defer alloc.free(conflict);
    conflict[header_len] ^= 0xFF;
    try testing.expectError(error.ConflictingOverlap, r.onChunk(conflict));

    // The lost odd indexes now arrive as retransmissions, out of order.
    i = 1;
    while (i < n_chunks) : (i += 2) {
        const res = try r.onChunk(frames[i]);
        if (i == n_chunks - 1) {
            try testing.expectEqual(OnChunkResult.complete, res);
        } else {
            try testing.expectEqual(OnChunkResult.progress, res);
        }
    }
    try testing.expectEqualSlices(u8, body, r.message());
}

test "send window admits 16 then blocks until release" {
    var w = SendWindow{};
    var n: usize = 0;
    while (n < max_inflight_chunks) : (n += 1) try w.admit();
    try testing.expectError(error.WindowFull, w.admit());
    try testing.expectEqual(@as(usize, 0), w.capacity());
    w.release(4);
    try testing.expectEqual(@as(usize, 4), w.capacity());
    try w.admit();
    w.release(99); // over-release clamps
    try testing.expectEqual(@as(usize, 0), w.in_flight);
}

test "response cache: exact id hit, overwrite frees" {
    const alloc = testing.allocator;
    var cache = ResponseCache{};
    defer cache.deinit(alloc);

    try cache.store(alloc, 42, "OK");
    try testing.expectEqualStrings("OK", cache.get(42).?);
    try testing.expect(cache.get(43) == null);

    try cache.store(alloc, 42, "OK-longer");
    try testing.expectEqualStrings("OK-longer", cache.get(42).?);
}

test "request body validation" {
    try validateRequestBody(.send, "any bytes");
    try validateRequestBody(.tail, "");

    try testing.expectError(error.InvalidTailBody, validateRequestBody(.tail, "x"));
    try testing.expectError(error.InvalidKillBody, validateRequestBody(.kill, ""));
    try testing.expectError(error.InvalidKillBody, validateRequestBody(.kill, "\x01\x02"));
    try testing.expectError(error.InvalidKillBody, validateRequestBody(.kill, "\x02"));

    var wbuf: [16]u8 = undefined;
    // path_len = 3, path "abc", empty file bytes: valid
    std.mem.writeInt(u32, wbuf[0..4], 3, .big);
    @memcpy(wbuf[4..7], "abc");
    try validateRequestBody(.write, wbuf[0..7]);

    // path_len beyond body
    std.mem.writeInt(u32, wbuf[0..4], 99, .big);
    try testing.expectError(error.InvalidWriteBody, validateRequestBody(.write, wbuf[0..7]));

    // zero path
    std.mem.writeInt(u32, wbuf[0..4], 0, .big);
    try testing.expectError(error.InvalidWriteBody, validateRequestBody(.write, wbuf[0..7]));

    // NUL in path
    std.mem.writeInt(u32, wbuf[0..4], 3, .big);
    @memcpy(wbuf[4..7], "a\x00c");
    try testing.expectError(error.InvalidWriteBody, validateRequestBody(.write, wbuf[0..7]));

    try testing.expectError(error.InvalidLabelClearBody, validateRequestBody(.label_clear, "x"));
}

test "missing LAST flag never completes" {
    const alloc = testing.allocator;
    var r = Reassembler{};
    defer r.deinit(alloc);

    const body = "q" ** (max_chunk_payload) ++ "r";
    const f0 = try frameFor(alloc, 8, body.len, 0, Flags.FIRST, body[0..max_chunk_payload]);
    // final chunk WITHOUT the LAST flag
    const f1 = try frameFor(alloc, 8, body.len, max_chunk_payload, 0, body[max_chunk_payload..]);
    defer alloc.free(f0);
    defer alloc.free(f1);

    _ = try r.start(alloc, (try parseChunk(f0)).header);
    try testing.expectEqual(OnChunkResult.progress, try r.onChunk(f0));
    // Final chunk without LAST: all bytes present, geometry malformed.
    try testing.expectError(error.InvalidGeometry, r.onChunk(f1));
    try testing.expect(!r.complete);
}
