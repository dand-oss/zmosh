//! ZMQ1 wire protocol: the frozen stream preface, control frames, and
//! payload codecs shared by the gateway session (quic_session.zig) and
//! the client module (quic_client.zig). Pure framing — no sockets, no
//! quicz, no IPC. QUIC delivers arbitrary byte chunks, so every parser
//! here is an incremental state machine that resumes mid-field.

const std = @import("std");
const build_options = @import("build_options");

// ---------------------------------------------------------------------------
// Frozen constants
// ---------------------------------------------------------------------------

pub const magic = [4]u8{ 'Z', 'M', 'Q', '1' };
pub const preface_len = 8;
pub const control_header_len = 8;
pub const hello_payload_len = 48;
pub const max_control_payload = 64 * 1024;
pub const error_reason_max = 256;
pub const output_header_len = 16; // preface + epoch u64 BE

/// Bumped 1 → 2 for Q4 (Ghostty snapshot pin advance + snapshot stream);
/// mixed-version peers fail the HELLO fingerprint check.
pub const adapter_version: u32 = 2;

pub const capability_binary_snapshot: u32 = 0x01;
pub const capability_resettable_output: u32 = 0x02;
pub const capability_remote_commands: u32 = 0x04;
pub const capability_tail: u32 = 0x08;
pub const capability_dual_stack: u32 = 0x10;
/// v1 has exactly one capability profile: every bit set.
pub const capabilities_v1: u32 =
    capability_binary_snapshot | capability_resettable_output |
    capability_remote_commands | capability_tail | capability_dual_stack;

pub const mode_attach: u8 = 1;
pub const mode_command: u8 = 2;

pub const snapshot_limit_v1: u32 = 128 * 1024 * 1024;
pub const command_limit_v1: u32 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Roles, control types, error codes
// ---------------------------------------------------------------------------

pub const Role = enum(u8) {
    control = 1,
    input = 2,
    snapshot = 3,
    output = 4,
    command = 5,
};

pub const ControlType = enum(u8) {
    hello = 1,
    hello_ack = 2,
    resize = 3,
    detach = 4,
    snapshot_request = 5,
    snapshot_installed = 6,
    session_end = 7,
    err = 8,
};

/// The only defined control-frame flag bit: FINAL (0x01), legal on
/// ERROR alone. A fatal ERROR carries FINAL and the control-stream
/// FIN; a nonterminal ERROR (the SNAPSHOT_REQUEST response) carries
/// flags zero and no FIN. SESSION_END is intrinsically terminal and
/// also carries flags zero.
pub const control_flag_final: u8 = 0x01;

/// The legal flags byte for a frame: FINAL only exists on ERROR.
pub fn controlFlags(t: ControlType, final: bool) u8 {
    return if (final and t == .err) control_flag_final else 0;
}

/// Stable application error codes. The same numeric value is used as a
/// u32 in the ERROR frame payload and as a u64 in closeApplication /
/// resetStream / stopSending.
pub const ErrCode = enum(u32) {
    none = 0,
    protocol_violation = 1,
    version_mismatch = 2,
    capability_mismatch = 3,
    fingerprint_mismatch = 4,
    unknown_role = 5,
    unknown_frame = 6,
    stream_cardinality = 7,
    unimplemented = 8,
    session_ended = 9,
    internal_error = 10,

    pub fn code(self: ErrCode) u32 {
        return @intFromEnum(self);
    }
};

// ---------------------------------------------------------------------------
// Preface
// ---------------------------------------------------------------------------

/// Writes the v1 preface: magic, role, zero flags, zero reserved.
pub fn writePreface(out: *[preface_len]u8, role: Role) void {
    out[0..4].* = magic;
    out[4] = @intFromEnum(role);
    out[5] = 0;
    out[6] = 0;
    out[7] = 0;
}

pub const PrefaceError = error{
    BadMagic,
    UnknownRole,
    NonzeroFlags,
    NonzeroReserved,
};

/// Maps a rejected preface to its frozen wire error code.
pub fn prefaceErrCode(e: PrefaceError) ErrCode {
    return switch (e) {
        error.UnknownRole => .unknown_role,
        else => .protocol_violation,
    };
}

pub fn parsePreface(bytes: *const [preface_len]u8) PrefaceError!Role {
    if (!std.mem.eql(u8, bytes[0..4], &magic)) return error.BadMagic;
    const role = std.enums.fromInt(Role, bytes[4]) orelse return error.UnknownRole;
    if (bytes[5] != 0) return error.NonzeroFlags;
    const reserved = std.mem.readInt(u16, bytes[6..8], .big);
    if (reserved != 0) return error.NonzeroReserved;
    return role;
}

/// Incremental preface parser. Feed arbitrary chunks; the parser
/// consumes a prefix of each chunk and reports completion or rejection.
pub const PrefaceParser = struct {
    buf: [preface_len]u8 = undefined,
    filled: usize = 0,
    done: bool = false,

    pub const Result = union(enum) {
        /// All preface bytes validated; the role that was declared.
        done: Role,
        /// More bytes needed before validation can proceed.
        need: usize,
        /// The completed preface is invalid.
        invalid: PrefaceError,
    };

    /// Feeds up to `preface_len - filled` bytes from `chunk`; returns
    /// the number of bytes consumed (0 only when done and chunk empty).
    pub fn feed(self: *PrefaceParser, chunk: []const u8) struct { consumed: usize, result: Result } {
        if (self.done) return .{ .consumed = 0, .result = .{ .need = 0 } };
        const want = preface_len - self.filled;
        const take = @min(want, chunk.len);
        @memcpy(self.buf[self.filled .. self.filled + take], chunk[0..take]);
        self.filled += take;
        if (self.filled < preface_len) {
            return .{ .consumed = take, .result = .{ .need = preface_len - self.filled } };
        }
        const role = parsePreface(&self.buf) catch |e| {
            return .{ .consumed = take, .result = .{ .invalid = e } };
        };
        self.done = true;
        return .{ .consumed = take, .result = .{ .done = role } };
    }

    /// True when bytes of an INCOMPLETE preface have arrived — a FIN
    /// now is a truncation (terminal protocol_violation by the caller).
    pub fn expecting(self: *const PrefaceParser) bool {
        return !self.done and self.filled > 0;
    }

    /// Bytes still missing before the preface can validate. Callers
    /// read EXACTLY this many bytes so surplus consumption (and the
    /// body-byte loss that would follow) is impossible.
    pub fn remaining(self: *const PrefaceParser) usize {
        return if (self.done) 0 else preface_len - self.filled;
    }
};

// ---------------------------------------------------------------------------
// Control frames
// ---------------------------------------------------------------------------

pub fn writeControlHeader(
    out: *[control_header_len]u8,
    t: ControlType,
    payload_len: usize,
    flags: u8,
) void {
    out[0] = @intFromEnum(t);
    out[1] = flags;
    out[2] = 0;
    out[3] = 0; // reserved u16 BE: zero
    std.mem.writeInt(u32, out[4..8], @intCast(payload_len), .big);
}

pub const ControlHeader = struct {
    t: ControlType,
    flags: u8,
    reserved: u16,
    payload_len: usize,

    /// Whether this frame carries the FINAL flag.
    pub fn isFinal(self: ControlHeader) bool {
        return (self.flags & control_flag_final) != 0;
    }
};

pub const ControlHeaderError = error{
    UnknownType,
    IllegalFlags,
    FinalOnNonError,
    NonzeroReserved,
    OversizedPayload,
};

pub fn controlHeaderErrCode(e: ControlHeaderError) ErrCode {
    return switch (e) {
        error.UnknownType => .unknown_frame,
        else => .protocol_violation,
    };
}

pub fn parseControlHeader(bytes: *const [control_header_len]u8) ControlHeaderError!ControlHeader {
    const t = std.enums.fromInt(ControlType, bytes[0]) orelse return error.UnknownType;
    const flags = bytes[1];
    // FINAL is the only defined bit, and it exists on ERROR alone.
    if (flags & ~control_flag_final != 0) return error.IllegalFlags;
    if ((flags & control_flag_final) != 0 and t != .err) return error.FinalOnNonError;
    const reserved = std.mem.readInt(u16, bytes[2..4], .big);
    if (reserved != 0) return error.NonzeroReserved;
    const len = std.mem.readInt(u32, bytes[4..8], .big);
    if (len > max_control_payload) return error.OversizedPayload;
    return .{
        .t = t,
        .flags = flags,
        .reserved = reserved,
        .payload_len = len,
    };
}

/// Incremental control-frame parser: header (fixed, allocation-free)
/// then payload (allocated ONLY after the declared length passed
/// validation). Handles coalesced frames through repeated advance()
/// calls followed by reset(); resumes mid-field across chunks.
pub const ControlParser = struct {
    alloc: std.mem.Allocator,
    hdr: [control_header_len]u8 = undefined,
    hdr_filled: usize = 0,
    declared: usize = 0,
    payload_buf: std.ArrayList(u8) = .empty,
    state: enum { header, payload, complete } = .header,

    pub fn init(alloc: std.mem.Allocator) ControlParser {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *ControlParser) void {
        self.payload_buf.deinit(self.alloc);
    }

    pub const Result = union(enum) {
        /// A full frame is available via frameType()/frameFlags()/payload().
        done: ControlHeader,
        need: usize,
        invalid: ControlHeaderError,
    };

    pub const Advance = struct { consumed: usize, result: Result };

    pub fn advance(self: *ControlParser, chunk: []const u8) std.mem.Allocator.Error!Advance {
        var rest = chunk;
        switch (self.state) {
            .header => {
                const want = control_header_len - self.hdr_filled;
                const take = @min(want, rest.len);
                @memcpy(self.hdr[self.hdr_filled .. self.hdr_filled + take], rest[0..take]);
                self.hdr_filled += take;
                rest = rest[take..];
                if (self.hdr_filled < control_header_len) {
                    return .{ .consumed = chunk.len - rest.len, .result = .{ .need = control_header_len - self.hdr_filled } };
                }
                const parsed = parseControlHeader(&self.hdr) catch |e| {
                    self.state = .complete; // poisoned until reset
                    return .{ .consumed = chunk.len - rest.len, .result = .{ .invalid = e } };
                };
                // Length validated: allocation happens only past this point.
                try self.payload_buf.ensureTotalCapacity(self.alloc, parsed.payload_len);
                self.payload_buf.items.len = 0;
                self.declared = parsed.payload_len;
                self.state = .payload;
            },
            .complete => return .{ .consumed = 0, .result = .{ .need = 0 } },
            .payload => {},
        }
        // Payload phase (entered directly on resume).
        const want = self.declared - self.payload_buf.items.len;
        const take = @min(want, rest.len);
        try self.payload_buf.appendSlice(self.alloc, rest[0..take]);
        rest = rest[take..];
        if (self.payload_buf.items.len < self.declared) {
            return .{ .consumed = chunk.len - rest.len, .result = .{ .need = self.declared - self.payload_buf.items.len } };
        }
        const parsed = parseControlHeader(&self.hdr) catch unreachable;
        self.state = .complete;
        return .{ .consumed = chunk.len - rest.len, .result = .{ .done = parsed } };
    }

    /// Valid once advance() returned .done and before reset().
    pub fn frameType(self: *const ControlParser) ControlType {
        return std.enums.fromInt(ControlType, self.hdr[0]) orelse unreachable;
    }

    /// Valid once advance() returned .done and before reset(). FINAL
    /// is guaranteed legal here — parseControlHeader rejected it
    /// otherwise before the payload phase began.
    pub fn frameFlags(self: *const ControlParser) u8 {
        return self.hdr[1];
    }

    /// Valid once advance() returned .done and before reset().
    pub fn payload(self: *const ControlParser) []const u8 {
        return self.payload_buf.items;
    }

    /// True when the parser sits mid-frame — a FIN observed now is a
    /// truncated frame (terminal protocol_violation by the caller).
    pub fn midFrame(self: *const ControlParser) bool {
        return self.state != .complete;
    }

    /// True when bytes of an INCOMPLETE frame have arrived (a partial
    /// header or a partial payload). A FIN between complete frames —
    /// parser reset to a fresh header with zero bytes — is clean.
    pub fn expectingFrame(self: *const ControlParser) bool {
        return switch (self.state) {
            .header => self.hdr_filled > 0,
            .payload => true,
            .complete => false,
        };
    }

    pub fn reset(self: *ControlParser) void {
        self.hdr_filled = 0;
        self.declared = 0;
        self.payload_buf.items.len = 0;
        self.state = .header;
    }
};

// ---------------------------------------------------------------------------
// HELLO / HELLO_ACK payload (48 bytes, same shape both directions)
// ---------------------------------------------------------------------------

pub const Hello = struct {
    version_major: u8,
    version_minor: u8,
    mode: u8,
    required_capabilities: u32,
    snapshot_abi_id: [32]u8,
    snapshot_limit: u32,
    command_limit: u32,

    pub const v1_version_major: u8 = 1;
    pub const v1_version_minor: u8 = 0;

    /// The v1 server profile: fixed version, capability mask, limits,
    /// and the comptime fingerprint of the current build pins.
    pub fn serverV1(mode: u8) Hello {
        return .{
            .version_major = v1_version_major,
            .version_minor = v1_version_minor,
            .mode = mode,
            .required_capabilities = capabilities_v1,
            .snapshot_abi_id = snapshot_abi_id,
            .snapshot_limit = snapshot_limit_v1,
            .command_limit = command_limit_v1,
        };
    }

    pub fn encode(self: *const Hello, out: *[hello_payload_len]u8) void {
        out[0] = self.version_major;
        out[1] = self.version_minor;
        out[2] = self.mode;
        out[3] = 0; // reserved
        std.mem.writeInt(u32, out[4..8], self.required_capabilities, .big);
        @memcpy(out[8..40], &self.snapshot_abi_id);
        std.mem.writeInt(u32, out[40..44], self.snapshot_limit, .big);
        std.mem.writeInt(u32, out[44..48], self.command_limit, .big);
    }

    pub const DecodeError = error{ NonzeroReserved, WrongLength };

    pub fn decode(bytes: []const u8) DecodeError!Hello {
        if (bytes.len != hello_payload_len) return error.WrongLength;
        if (bytes[3] != 0) return error.NonzeroReserved;
        var abi: [32]u8 = undefined;
        @memcpy(&abi, bytes[8..40]);
        return .{
            .version_major = bytes[0],
            .version_minor = bytes[1],
            .mode = bytes[2],
            .required_capabilities = std.mem.readInt(u32, bytes[4..8], .big),
            .snapshot_abi_id = abi,
            .snapshot_limit = std.mem.readInt(u32, bytes[40..44], .big),
            .command_limit = std.mem.readInt(u32, bytes[44..48], .big),
        };
    }
};

// ---------------------------------------------------------------------------
// RESIZE payload (four u16 BE) and ERROR payload
// ---------------------------------------------------------------------------

pub fn writeResizePayload(out: *[8]u8, rows: u16, cols: u16, xpixel: u16, ypixel: u16) void {
    std.mem.writeInt(u16, out[0..2], rows, .big);
    std.mem.writeInt(u16, out[2..4], cols, .big);
    std.mem.writeInt(u16, out[4..6], xpixel, .big);
    std.mem.writeInt(u16, out[6..8], ypixel, .big);
}

pub const ResizeWire = struct { rows: u16, cols: u16, xpixel: u16, ypixel: u16 };

pub fn parseResizePayload(bytes: *const [8]u8) ResizeWire {
    return .{
        .rows = std.mem.readInt(u16, bytes[0..2], .big),
        .cols = std.mem.readInt(u16, bytes[2..4], .big),
        .xpixel = std.mem.readInt(u16, bytes[4..6], .big),
        .ypixel = std.mem.readInt(u16, bytes[6..8], .big),
    };
}

/// ERROR payload: code u32 BE + printable reason (reason ≤ 256 B).
pub fn writeErrorPayload(out: []u8, code: ErrCode, reason: []const u8) error{ ReasonTooLong, BufferTooSmall }!usize {
    if (reason.len > error_reason_max) return error.ReasonTooLong;
    if (out.len < 4 + reason.len) return error.BufferTooSmall;
    std.mem.writeInt(u32, out[0..4], code.code(), .big);
    @memcpy(out[4 .. 4 + reason.len], reason);
    return 4 + reason.len;
}

pub const ErrorWire = struct { code: u32, reason: []const u8 };

pub const ErrorPayloadError = error{ TooShort, NonPrintableReason };

pub fn parseErrorPayload(bytes: []const u8) ErrorPayloadError!ErrorWire {
    if (bytes.len < 4) return error.TooShort;
    const reason = bytes[4..];
    for (reason) |c| {
        if (c < 0x20 or c > 0x7E) return error.NonPrintableReason;
    }
    return .{ .code = std.mem.readInt(u32, bytes[0..4], .big), .reason = reason };
}

// ---------------------------------------------------------------------------
// Output stream header: preface(role=output) + epoch u64 BE
// ---------------------------------------------------------------------------

pub fn writeOutputHeader(out: *[output_header_len]u8, epoch: u64) void {
    writePreface(out[0..8], .output);
    std.mem.writeInt(u64, out[8..16], epoch, .big);
}

/// Incremental output-header parser (preface + epoch), after which the
/// stream carries raw bytes.
pub const OutputHeaderParser = struct {
    preface: PrefaceParser = .{},
    epoch_buf: [8]u8 = undefined,
    epoch_filled: usize = 0,
    done: bool = false,

    pub const Result = union(enum) {
        done: u64,
        need: usize,
        invalid: PrefaceError,
    };

    pub fn feed(self: *OutputHeaderParser, chunk: []const u8) struct { consumed: usize, result: Result } {
        var rest = chunk;
        if (!self.preface.done) {
            const r = self.preface.feed(rest);
            rest = rest[r.consumed..];
            switch (r.result) {
                .done => |role| {
                    // The output stream's preface must declare output.
                    if (role != .output) {
                        return .{ .consumed = chunk.len - rest.len, .result = .{ .invalid = error.UnknownRole } };
                    }
                },
                .need => |n| return .{ .consumed = chunk.len - rest.len, .result = .{ .need = n } },
                .invalid => |e| return .{ .consumed = chunk.len - rest.len, .result = .{ .invalid = e } },
            }
        }
        const want = 8 - self.epoch_filled;
        const take = @min(want, rest.len);
        @memcpy(self.epoch_buf[self.epoch_filled .. self.epoch_filled + take], rest[0..take]);
        self.epoch_filled += take;
        rest = rest[take..];
        if (self.epoch_filled < 8) {
            return .{ .consumed = chunk.len - rest.len, .result = .{ .need = 8 - self.epoch_filled } };
        }
        self.done = true;
        return .{
            .consumed = chunk.len - rest.len,
            .result = .{ .done = std.mem.readInt(u64, &self.epoch_buf, .big) },
        };
    }

    /// Bytes still missing before the output header can complete
    /// (preface + epoch). Callers read EXACTLY this many.
    pub fn remaining(self: *const OutputHeaderParser) usize {
        if (self.done) return 0;
        const pre = self.preface.remaining();
        return pre + (8 - self.epoch_filled);
    }
};

// ---------------------------------------------------------------------------
// Snapshot stream header (Q4): preface(role=snapshot) + epoch u64 BE +
// flags byte + 7 zero reserved bytes
// ---------------------------------------------------------------------------

pub const snapshot_header_len = preface_len + 8 + 1 + 7;
/// The only defined snapshot-header flag bit: PRESENT (0x01). Zero
/// means an empty snapshot (PRESENT=0) with no body and an immediate
/// FIN after the header.
pub const snapshot_flag_present: u8 = 0x01;
/// Q4 permits only the initial epoch 1 on both the output stream (3)
/// and the snapshot stream (7); replacement epochs remain Q5.
pub const snapshot_epoch_v1: u64 = 1;

pub fn writeSnapshotHeader(out: *[snapshot_header_len]u8, epoch: u64, present: bool) void {
    writePreface(out[0..preface_len], .snapshot);
    std.mem.writeInt(u64, out[preface_len .. preface_len + 8], epoch, .big);
    out[preface_len + 8] = if (present) snapshot_flag_present else 0;
    @memset(out[preface_len + 9 ..], 0);
}

pub const SnapshotHeader = struct { epoch: u64, present: bool };

pub const SnapshotHeaderError = error{
    BadMagic,
    UnknownRole,
    NonzeroFlags,
    NonzeroReserved,
    /// The preface is valid but does not declare the snapshot role.
    WrongRole,
    /// Bits other than PRESENT are set in the flags byte.
    BadFlags,
    /// Q4 permits epoch 1 only.
    BadEpoch,
};

pub fn parseSnapshotHeader(bytes: *const [snapshot_header_len]u8) SnapshotHeaderError!SnapshotHeader {
    const role = try parsePreface(bytes[0..preface_len]);
    if (role != .snapshot) return error.WrongRole;
    const flags = bytes[preface_len + 8];
    if (flags & ~snapshot_flag_present != 0) return error.BadFlags;
    for (bytes[preface_len + 9 ..]) |b| {
        if (b != 0) return error.NonzeroReserved;
    }
    const epoch = std.mem.readInt(u64, bytes[preface_len..][0..8], .big);
    if (epoch != snapshot_epoch_v1) return error.BadEpoch;
    return .{ .epoch = epoch, .present = (flags & snapshot_flag_present) != 0 };
}

/// Incremental snapshot-header parser (QUIC delivers arbitrary chunks;
/// the parser resumes mid-field and consumes only a prefix of each
/// chunk).
pub const SnapshotHeaderParser = struct {
    buf: [snapshot_header_len]u8 = undefined,
    filled: usize = 0,
    done: bool = false,

    pub const Result = union(enum) {
        done: SnapshotHeader,
        need: usize,
        invalid: SnapshotHeaderError,
    };

    /// Feeds up to `snapshot_header_len - filled` bytes from `chunk`;
    /// returns the number of bytes consumed.
    pub fn feed(self: *SnapshotHeaderParser, chunk: []const u8) struct { consumed: usize, result: Result } {
        if (self.done) return .{ .consumed = 0, .result = .{ .need = 0 } };
        const want = snapshot_header_len - self.filled;
        const take = @min(want, chunk.len);
        @memcpy(self.buf[self.filled .. self.filled + take], chunk[0..take]);
        self.filled += take;
        if (self.filled < snapshot_header_len) {
            return .{ .consumed = take, .result = .{ .need = snapshot_header_len - self.filled } };
        }
        const h = parseSnapshotHeader(&self.buf) catch |e| {
            return .{ .consumed = take, .result = .{ .invalid = e } };
        };
        self.done = true;
        return .{ .consumed = take, .result = .{ .done = h } };
    }

    /// True when bytes of an INCOMPLETE header have arrived — a FIN now
    /// is a truncation.
    pub fn expecting(self: *const SnapshotHeaderParser) bool {
        return !self.done and self.filled > 0;
    }

    /// Bytes still missing before the header can validate. Callers read
    /// EXACTLY this many so surplus consumption is impossible.
    pub fn remaining(self: *const SnapshotHeaderParser) usize {
        return if (self.done) 0 else snapshot_header_len - self.filled;
    }
};

// ---------------------------------------------------------------------------
// snapshot_abi_id
// ---------------------------------------------------------------------------

const abi_domain = "zmosh-snapshot-abi-v1\x00";

/// SHA-256(domain || ghostty_commit[40] || u16_be(hash.len) || hash ||
/// u32_be(adapter_version)). Pure function so tests can vary each input.
pub fn computeSnapshotAbiId(
    out: *[32]u8,
    ghostty_commit: []const u8,
    zig_package_hash_utf8: []const u8,
    adapter_ver: u32,
) void {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(abi_domain);
    h.update(ghostty_commit);
    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @intCast(zig_package_hash_utf8.len), .big);
    h.update(&len_be);
    h.update(zig_package_hash_utf8);
    var ver_be: [4]u8 = undefined;
    std.mem.writeInt(u32, &ver_be, adapter_ver, .big);
    h.update(&ver_be);
    h.final(out);
}

/// The fingerprint of THIS build's pins, computed at comptime. Q4's
/// Ghostty pin advance deliberately changes this value, rejecting
/// mixed-version peers.
pub const snapshot_abi_id: [32]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var id: [32]u8 = undefined;
    computeSnapshotAbiId(
        &id,
        build_options.ghostty_commit,
        build_options.ghostty_version,
        adapter_version,
    );
    break :blk id;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "preface golden bytes and accept matrix" {
    var buf: [preface_len]u8 = undefined;
    writePreface(&buf, .control);
    try testing.expectEqualSlices(u8, &.{ 'Z', 'M', 'Q', '1', 1, 0, 0, 0 }, &buf);
    writePreface(&buf, .input);
    try testing.expectEqualSlices(u8, &.{ 'Z', 'M', 'Q', '1', 2, 0, 0, 0 }, &buf);
    writePreface(&buf, .output);
    try testing.expectEqualSlices(u8, &.{ 'Z', 'M', 'Q', '1', 4, 0, 0, 0 }, &buf);

    for ([_]Role{ .control, .input, .snapshot, .output, .command }) |role| {
        writePreface(&buf, role);
        try testing.expectEqual(role, try parsePreface(&buf));
    }
}

test "preface reject matrix maps to frozen codes" {
    var buf: [preface_len]u8 = undefined;
    writePreface(&buf, .control);

    buf[0] = 'X';
    try testing.expectError(error.BadMagic, parsePreface(&buf));
    try testing.expectEqual(ErrCode.protocol_violation, prefaceErrCode(error.BadMagic));

    writePreface(&buf, .control);
    buf[4] = 0;
    try testing.expectError(error.UnknownRole, parsePreface(&buf));
    try testing.expectEqual(ErrCode.unknown_role, prefaceErrCode(error.UnknownRole));

    writePreface(&buf, .control);
    buf[4] = 6;
    try testing.expectError(error.UnknownRole, parsePreface(&buf));

    writePreface(&buf, .control);
    buf[5] = 1;
    try testing.expectError(error.NonzeroFlags, parsePreface(&buf));

    writePreface(&buf, .control);
    buf[6] = 0;
    buf[7] = 1;
    try testing.expectError(error.NonzeroReserved, parsePreface(&buf));
}

test "control header golden, unknown type, oversized length" {
    var buf: [control_header_len]u8 = undefined;
    writeControlHeader(&buf, .hello, hello_payload_len, 0);
    try testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0, 0, 0, 0, 48 }, &buf);

    const hdr = try parseControlHeader(&buf);
    try testing.expectEqual(ControlType.hello, hdr.t);
    try testing.expectEqual(@as(usize, 48), hdr.payload_len);
    try testing.expect(!hdr.isFinal());

    buf[0] = 9;
    try testing.expectError(error.UnknownType, parseControlHeader(&buf));
    try testing.expectEqual(ErrCode.unknown_frame, controlHeaderErrCode(error.UnknownType));

    buf[0] = 0;
    try testing.expectError(error.UnknownType, parseControlHeader(&buf));

    buf[0] = 8;
    // Declared length 0x00010001 (65537) exceeds the 64 KiB ceiling.
    buf[4] = 0x00;
    buf[5] = 0x01;
    buf[6] = 0x00;
    buf[7] = 0x01;
    try testing.expectError(error.OversizedPayload, parseControlHeader(&buf));

    buf[7] = 0;
    buf[1] = 1;
    // FINAL on a non-ERROR frame is a protocol violation (buf[0] is
    // still 8 = .err here, so use a RESIZE type).
    buf[0] = 3;
    try testing.expectError(error.FinalOnNonError, parseControlHeader(&buf));
    try testing.expectEqual(ErrCode.protocol_violation, controlHeaderErrCode(error.FinalOnNonError));
    buf[1] = 2;
    // Bits outside FINAL do not exist in v1.
    try testing.expectError(error.IllegalFlags, parseControlHeader(&buf));
    try testing.expectEqual(ErrCode.protocol_violation, controlHeaderErrCode(error.IllegalFlags));
    buf[1] = 0;
    buf[3] = 1;
    try testing.expectError(error.NonzeroReserved, parseControlHeader(&buf));
}

test "FINAL flag matrix: legal on ERROR alone, terminal metadata round-trips" {
    var buf: [control_header_len]u8 = undefined;

    // Fatal ERROR: FINAL set, parses back with the flag.
    writeControlHeader(&buf, .err, 4, controlFlags(.err, true));
    try testing.expectEqual(control_flag_final, buf[1]);
    const fatal = try parseControlHeader(&buf);
    try testing.expect(fatal.isFinal());
    try testing.expectEqualSlices(u8, &.{ 8, 1, 0, 0, 0, 0, 0, 4 }, &buf);

    // Nonterminal ERROR (snapshot response): flags zero.
    writeControlHeader(&buf, .err, 4, controlFlags(.err, false));
    try testing.expectEqual(@as(u8, 0), buf[1]);
    try testing.expect(!(try parseControlHeader(&buf)).isFinal());

    // SESSION_END is terminal WITHOUT the flag; controlFlags refuses
    // to set FINAL on it even if asked.
    writeControlHeader(&buf, .session_end, 0, controlFlags(.session_end, true));
    try testing.expectEqual(@as(u8, 0), buf[1]);
    try testing.expect(!(try parseControlHeader(&buf)).isFinal());

    // Client-side frames never carry FINAL.
    try testing.expectEqual(@as(u8, 0), controlFlags(.hello, true));
    try testing.expectEqual(@as(u8, 0), controlFlags(.resize, true));
    try testing.expectEqual(@as(u8, 0), controlFlags(.detach, true));
    try testing.expectEqual(@as(u8, 0), controlFlags(.snapshot_request, true));
    try testing.expectEqual(@as(u8, 0), controlFlags(.snapshot_installed, true));

    // Every non-ERROR type with the bit set is rejected.
    for ([_]ControlType{ .hello, .hello_ack, .resize, .detach, .snapshot_request, .snapshot_installed, .session_end }) |t| {
        writeControlHeader(&buf, t, 0, control_flag_final);
        try testing.expectError(error.FinalOnNonError, parseControlHeader(&buf));
    }
    // Unknown high bits are rejected on ERROR too.
    writeControlHeader(&buf, .err, 0, control_flag_final | 0x80);
    try testing.expectError(error.IllegalFlags, parseControlHeader(&buf));

    // The incremental parser surfaces the same metadata (header plus
    // the declared payload bytes).
    var p = ControlParser.init(testing.allocator);
    defer p.deinit();
    writeControlHeader(&buf, .err, 4, controlFlags(.err, true));
    var full: [control_header_len + 4]u8 = undefined;
    @memcpy(full[0..control_header_len], &buf);
    const a = try p.advance(&full);
    switch (a.result) {
        .done => |h| {
            try testing.expectEqual(ControlType.err, h.t);
            try testing.expect(h.isFinal());
            try testing.expectEqual(control_flag_final, p.frameFlags());
        },
        else => return error.TestUnexpectedResult,
    }
}

test "control parser: coalesced frames and full round trip" {
    var p = ControlParser.init(testing.allocator);
    defer p.deinit();

    var wire: [control_header_len + hello_payload_len + control_header_len + 8]u8 = undefined;
    var hello: [hello_payload_len]u8 = undefined;
    Hello.serverV1(mode_attach).encode(&hello);
    writeControlHeader(wire[0..8], .hello, hello.len, 0);
    @memcpy(wire[8 .. 8 + hello_payload_len], &hello);
    writeControlHeader(wire[56..64], .resize, 8, 0);
    writeResizePayload(wire[64..72], 24, 80, 0, 0);

    // Feed the whole coalesced buffer at once: the parser stops after
    // the FIRST complete frame (header 8 + payload 48 = 56 bytes).
    const a1 = try p.advance(&wire);
    try testing.expectEqual(@as(usize, 56), a1.consumed);
    switch (a1.result) {
        .done => |h| try testing.expectEqual(ControlType.hello, h.t),
        else => return error.TestUnexpectedResult,
    }
    const decoded = try Hello.decode(p.payload());
    try testing.expectEqual(mode_attach, decoded.mode);
    try testing.expectEqualSlices(u8, &snapshot_abi_id, &decoded.snapshot_abi_id);

    p.reset();
    const a2 = try p.advance(wire[56..]);
    switch (a2.result) {
        .done => |h| try testing.expectEqual(ControlType.resize, h.t),
        else => return error.TestUnexpectedResult,
    }
    const rz = parseResizePayload(p.payload()[0..8]);
    try testing.expectEqual(@as(u16, 24), rz.rows);
    try testing.expectEqual(@as(u16, 80), rz.cols);
}

test "control parser: every split boundary resumes mid-field" {
    var wire: [control_header_len + hello_payload_len]u8 = undefined;
    var hello: [hello_payload_len]u8 = undefined;
    Hello.serverV1(mode_command).encode(&hello);
    writeControlHeader(wire[0..8], .hello_ack, hello.len, 0);
    @memcpy(wire[8..], &hello);

    // One byte at a time.
    {
        var p = ControlParser.init(testing.allocator);
        defer p.deinit();
        var i: usize = 0;
        while (i < wire.len) : (i += 1) {
            const a = try p.advance(wire[i .. i + 1]);
            try testing.expectEqual(@as(usize, 1), a.consumed);
        }
        switch (p.state) {
            .complete => {},
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(ControlType.hello_ack, p.frameType());
        try testing.expectEqualSlices(u8, &hello, p.payload());
    }

    // Every single split point: chunk[:k] then chunk[k:].
    var k: usize = 1;
    while (k < wire.len) : (k += 1) {
        var p = ControlParser.init(testing.allocator);
        defer p.deinit();
        _ = try p.advance(wire[0..k]);
        _ = try p.advance(wire[k..]);
        try testing.expectEqual(ControlType.hello_ack, p.frameType());
        try testing.expectEqualSlices(u8, &hello, p.payload());
    }
}

test "control parser: invalid header poisons until reset" {
    var p = ControlParser.init(testing.allocator);
    defer p.deinit();
    var wire: [control_header_len]u8 = undefined;
    writeControlHeader(&wire, .resize, 8, 0);
    wire[0] = 99; // unknown type

    const a = try p.advance(&wire);
    switch (a.result) {
        .invalid => |e| try testing.expectEqual(error.UnknownType, e),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(p.midFrame() == false); // complete (poisoned), not mid-frame
    p.reset();
    wire[0] = @intFromEnum(ControlType.resize);
    const a2 = try p.advance(wire[0..8]);
    switch (a2.result) {
        .need => {},
        else => return error.TestUnexpectedResult,
    }
    const a3 = try p.advance(&[_]u8{0} ** 8);
    switch (a3.result) {
        .done => |h| try testing.expectEqual(ControlType.resize, h.t),
        else => return error.TestUnexpectedResult,
    }
}

test "preface parser: split and reject" {
    var full: [preface_len]u8 = undefined;
    writePreface(&full, .input);
    {
        var p: PrefaceParser = .{};
        const r1 = p.feed(full[0..3]);
        try testing.expectEqual(@as(usize, 3), r1.consumed);
        switch (r1.result) {
            .need => |n| try testing.expectEqual(@as(usize, 5), n),
            else => return error.TestUnexpectedResult,
        }
        const r2 = p.feed(full[3..]);
        switch (r2.result) {
            .done => |role| try testing.expectEqual(Role.input, role),
            else => return error.TestUnexpectedResult,
        }
    }
    var bad: [preface_len]u8 = undefined;
    writePreface(&bad, .control);
    bad[5] = 2;
    var p: PrefaceParser = .{};
    const r = p.feed(&bad);
    switch (r.result) {
        .invalid => |e| try testing.expectEqual(error.NonzeroFlags, e),
        else => return error.TestUnexpectedResult,
    }
}

test "hello payload golden 48 bytes with field offsets" {
    var hello = Hello.serverV1(mode_attach);
    var id: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) id[i] = @intCast(i);
    hello.snapshot_abi_id = id;
    var out: [hello_payload_len]u8 = undefined;
    hello.encode(&out);

    try testing.expectEqual(@as(u8, 1), out[0]);
    try testing.expectEqual(@as(u8, 0), out[1]);
    try testing.expectEqual(@as(u8, 1), out[2]); // mode attach
    try testing.expectEqual(@as(u8, 0), out[3]); // reserved
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x00, 0x1F }, out[4..8]);
    try testing.expectEqualSlices(u8, &id, out[8..40]);
    try testing.expectEqualSlices(u8, &.{ 0x08, 0x00, 0x00, 0x00 }, out[40..44]); // 128 MiB
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x10, 0x00, 0x00 }, out[44..48]); // 1 MiB

    const rt = try Hello.decode(&out);
    try testing.expectEqual(hello.version_major, rt.version_major);
    try testing.expectEqual(hello.mode, rt.mode);
    try testing.expectEqual(capabilities_v1, rt.required_capabilities);
    try testing.expectEqualSlices(u8, &id, &rt.snapshot_abi_id);
    try testing.expectEqual(snapshot_limit_v1, rt.snapshot_limit);
    try testing.expectEqual(command_limit_v1, rt.command_limit);

    out[3] = 1;
    try testing.expectError(error.NonzeroReserved, Hello.decode(&out));
    try testing.expectError(error.WrongLength, Hello.decode(out[1..]));
}

test "resize payload big-endian golden" {
    var buf: [8]u8 = undefined;
    writeResizePayload(&buf, 0x0102, 0x0304, 0x0506, 0x0708);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &buf);
    const parsed = parseResizePayload(&buf);
    try testing.expectEqual(@as(u16, 0x0102), parsed.rows);
    try testing.expectEqual(@as(u16, 0x0708), parsed.ypixel);
}

test "error payload round trip and bounds" {
    var buf: [4 + error_reason_max]u8 = undefined;
    const n = try writeErrorPayload(&buf, ErrCode.fingerprint_mismatch, "abi mismatch");
    try testing.expectEqual(@as(usize, 4 + "abi mismatch".len), n);
    const parsed = try parseErrorPayload(buf[0..n]);
    try testing.expectEqual(ErrCode.fingerprint_mismatch.code(), parsed.code);
    try testing.expectEqualStrings("abi mismatch", parsed.reason);

    // 256-byte reason fits; 257 does not.
    const long_reason = "a" ** 256;
    const n2 = try writeErrorPayload(&buf, ErrCode.unimplemented, long_reason);
    try testing.expectEqual(@as(usize, 260), n2);
    var short: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writeErrorPayload(&short, .none, "x"));
    try testing.expectError(error.ReasonTooLong, writeErrorPayload(&buf, .none, "a" ** 257));

    // Non-printable reason bytes are rejected on parse.
    var raw: [6]u8 = undefined;
    std.mem.writeInt(u32, raw[0..4], 1, .big);
    raw[4] = 0x01;
    raw[5] = 0x7F;
    try testing.expectError(error.NonPrintableReason, parseErrorPayload(&raw));
    try testing.expectError(error.TooShort, parseErrorPayload(raw[0..2]));
}

test "output header golden and split parse" {
    var buf: [output_header_len]u8 = undefined;
    writeOutputHeader(&buf, 1);
    try testing.expectEqualSlices(u8, &.{ 'Z', 'M', 'Q', '1', 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &buf);

    var p: OutputHeaderParser = .{};
    const r1 = p.feed(buf[0..11]);
    switch (r1.result) {
        .need => |n| try testing.expectEqual(@as(usize, 5), n),
        else => return error.TestUnexpectedResult,
    }
    const r2 = p.feed(buf[11..]);
    switch (r2.result) {
        .done => |epoch| try testing.expectEqual(@as(u64, 1), epoch),
        else => return error.TestUnexpectedResult,
    }

    // A non-output preface on the output stream is a role rejection.
    var bad: [output_header_len]u8 = undefined;
    writePreface(bad[0..8], .input);
    var p2: OutputHeaderParser = .{};
    const r3 = p2.feed(&bad);
    switch (r3.result) {
        .invalid => |e| try testing.expectEqual(error.UnknownRole, e),
        else => return error.TestUnexpectedResult,
    }
}

test "snapshot header golden, split parse, and field validation" {
    var buf: [snapshot_header_len]u8 = undefined;
    writeSnapshotHeader(&buf, snapshot_epoch_v1, true);
    // preface(role=snapshot) + epoch 1 BE + PRESENT + 7 zero bytes.
    try testing.expectEqualSlices(u8, &.{
        'Z',  'M', 'Q', '1', 3, 0, 0, 0,
        0,    0,   0,   0,   0, 0, 0, 1,
        0x01, 0,   0,   0,   0, 0, 0, 0,
    }, &buf);
    const h = try parseSnapshotHeader(&buf);
    try testing.expectEqual(snapshot_epoch_v1, h.epoch);
    try testing.expect(h.present);

    // PRESENT=0 is the empty snapshot.
    writeSnapshotHeader(&buf, snapshot_epoch_v1, false);
    try testing.expectEqual(@as(u8, 0), buf[16]);
    try testing.expect(!(try parseSnapshotHeader(&buf)).present);

    // Every split boundary resumes mid-field: 1 byte at a time, AND
    // every fresh two-part split (prefix [0..i], then the rest).
    writeSnapshotHeader(&buf, snapshot_epoch_v1, true);
    var i: usize = 0;
    while (i < snapshot_header_len - 1) : (i += 1) {
        var p2: SnapshotHeaderParser = .{};
        const ra = p2.feed(buf[0..i]);
        switch (ra.result) {
            .need => |n| try testing.expectEqual(snapshot_header_len - i, n),
            else => return error.TestUnexpectedResult,
        }
        const rb = p2.feed(buf[i..]);
        switch (rb.result) {
            .done => |hh| {
                try testing.expectEqual(snapshot_epoch_v1, hh.epoch);
                try testing.expect(hh.present);
            },
            else => return error.TestUnexpectedResult,
        }
    }
    var p: SnapshotHeaderParser = .{};
    i = 0;
    while (i < snapshot_header_len - 1) : (i += 1) {
        const r = p.feed(buf[i .. i + 1]);
        switch (r.result) {
            .need => |n| try testing.expectEqual(snapshot_header_len - (i + 1), n),
            else => return error.TestUnexpectedResult,
        }
        try testing.expectEqual(@as(usize, 1), r.consumed);
    }
    const done = p.feed(buf[i..]);
    switch (done.result) {
        .done => |hh| {
            try testing.expectEqual(snapshot_epoch_v1, hh.epoch);
            try testing.expect(hh.present);
        },
        else => return error.TestUnexpectedResult,
    }
    try testing.expectEqual(@as(usize, 0), p.remaining());

    // Invalid role, epoch, flags, and reserved bytes each reject with
    // their own error, through the incremental parser as well.
    const cases = [_]struct { mutate: usize, val: u8, err: SnapshotHeaderError }{
        .{ .mutate = 4, .val = 4, .err = error.WrongRole }, // output role
        .{ .mutate = 15, .val = 2, .err = error.BadEpoch }, // epoch 2
        .{ .mutate = 16, .val = 0x02, .err = error.BadFlags }, // unset bit
        .{ .mutate = 17, .val = 1, .err = error.NonzeroReserved },
        .{ .mutate = 23, .val = 0xFF, .err = error.NonzeroReserved },
    };
    for (cases) |c| {
        writeSnapshotHeader(&buf, snapshot_epoch_v1, true);
        buf[c.mutate] = c.val;
        try testing.expectError(c.err, parseSnapshotHeader(&buf));
        var pp: SnapshotHeaderParser = .{};
        const r = pp.feed(&buf);
        switch (r.result) {
            .invalid => |e| try testing.expectEqual(c.err, e),
            else => return error.TestUnexpectedResult,
        }
    }

    // A bad magic keeps the preface's own error; the parser reports it
    // after consuming the whole 24 bytes.
    writeSnapshotHeader(&buf, snapshot_epoch_v1, true);
    buf[0] = 'X';
    try testing.expectError(error.BadMagic, parseSnapshotHeader(&buf));
}

test "snapshot abi id: golden construction and comptime equality" {
    // Independent inline construction of the canonical bytes.
    const commit = "0123456789abcdef0123456789abcdef01234567";
    const hash_str = "ghostty-1.3.2-dev-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    var expected: [32]u8 = undefined;
    {
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("zmosh-snapshot-abi-v1\x00");
        h.update(commit);
        var len_be: [2]u8 = undefined;
        std.mem.writeInt(u16, &len_be, @intCast(hash_str.len), .big);
        h.update(&len_be);
        h.update(hash_str);
        var ver_be: [4]u8 = undefined;
        std.mem.writeInt(u32, &ver_be, 1, .big);
        h.update(&ver_be);
        h.final(&expected);
    }
    var got: [32]u8 = undefined;
    computeSnapshotAbiId(&got, commit, hash_str, 1);
    try testing.expectEqualSlices(u8, &expected, &got);

    // Sensitivity: each varied input changes the id.
    var varied: [32]u8 = undefined;
    computeSnapshotAbiId(&varied, "ffffffffffffffffffffffffffffffffffffffff", hash_str, 1);
    try testing.expect(!std.mem.eql(u8, &expected, &varied));
    computeSnapshotAbiId(&varied, commit, hash_str[0 .. hash_str.len - 1], 1);
    try testing.expect(!std.mem.eql(u8, &expected, &varied));
    computeSnapshotAbiId(&varied, commit, hash_str, 2);
    try testing.expect(!std.mem.eql(u8, &expected, &varied));

    // The comptime constant matches a runtime recomputation over the
    // exact build-option inputs.
    var runtime: [32]u8 = undefined;
    computeSnapshotAbiId(
        &runtime,
        build_options.ghostty_commit,
        build_options.ghostty_version,
        adapter_version,
    );
    try testing.expectEqualSlices(u8, &runtime, &snapshot_abi_id);
    try testing.expectEqual(@as(usize, 40), build_options.ghostty_commit.len);
}

test "snapshot abi id: frozen Q4 golden literal" {
    // The frozen Q4 fingerprint of the pinned build inputs (Ghostty
    // commit 6361b2eac73e8243a7042f517ea95ab87165f105, package hash
    // ghostty-1.3.2-dev-5UdBC5L2RQWfmtJwTX8gKITqL4rOJteCksb42xxDS9bD,
    // adapter_version 2). Deliberately NOT derived through
    // computeSnapshotAbiId: any input or construction drift must fail
    // here against the frozen bytes.
    const frozen_q4 = [_]u8{
        0x76, 0x98, 0x15, 0x04, 0x09, 0xab, 0x36, 0x81,
        0x79, 0x73, 0x55, 0xe5, 0xba, 0x81, 0x98, 0x98,
        0xa4, 0x22, 0x28, 0x3b, 0x3f, 0x3c, 0xe8, 0xee,
        0xe7, 0xcb, 0x15, 0xf6, 0xfb, 0x18, 0xd9, 0xad,
    };
    try testing.expectEqualSlices(u8, &frozen_q4, &snapshot_abi_id);
    try testing.expectEqual(@as(u32, 2), adapter_version);
}
