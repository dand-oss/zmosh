const std = @import("std");
const ipc = @import("ipc.zig");

pub const version: u8 = 1;
pub const max_payload_len: usize = 1100;
/// Default span bound: the receiver's ACK history is 32 sequences, so a
/// sequence more than 32 past the oldest unacknowledged one can never be
/// acknowledged. Advisory for attach traffic, enforced for commands.
pub const max_span_default: u32 = 32;
const header_len: usize = 20;

pub const Channel = enum(u8) {
    heartbeat = 0,
    reliable_ipc = 1,
    output = 2,
    control = 3,
    /// Remote one-shot command channel (remote_command.zig envelope).
    command = 4,
};

pub const Control = enum(u8) {
    resync_request = 1,
};

pub const Packet = struct {
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
};

pub const ReliableAction = enum {
    accept,
    duplicate,
    stale,
};

pub const OutputAction = enum {
    accept,
    duplicate,
    stale,
    gap,
};

pub const RecvState = struct {
    latest: u32 = 0,
    mask: u32 = 0,
    has_latest: bool = false,

    pub fn onReliable(self: *RecvState, seq: u32) ReliableAction {
        if (!self.has_latest) {
            self.latest = seq;
            self.mask = 0;
            self.has_latest = true;
            return .accept;
        }

        if (seq > self.latest) {
            const shift = seq - self.latest;
            if (shift >= 32) {
                self.mask = 0;
            } else {
                self.mask <<= @intCast(shift);
                self.mask |= @as(u32, 1) << @intCast(shift - 1);
            }
            self.latest = seq;
            return .accept;
        }

        const diff = self.latest - seq;
        if (diff == 0) return .duplicate;
        if (diff > 32) return .stale;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        if (self.mask & bit != 0) return .duplicate;
        self.mask |= bit;
        return .accept;
    }

    pub fn ack(self: *const RecvState) u32 {
        return if (self.has_latest) self.latest else 0;
    }

    pub fn ackBits(self: *const RecvState) u32 {
        return if (self.has_latest) self.mask else 0;
    }
};

pub const OutputRecvState = struct {
    latest: u32 = 0,
    has_latest: bool = false,

    pub fn onPacket(self: *OutputRecvState, seq: u32) OutputAction {
        if (!self.has_latest) {
            self.latest = seq;
            self.has_latest = true;
            return .accept;
        }

        if (seq == self.latest + 1) {
            self.latest = seq;
            return .accept;
        }

        if (seq <= self.latest) {
            return .duplicate;
        }

        // seq jumped ahead.
        self.latest = seq;
        return .gap;
    }
};

pub const ReliableSend = struct {
    alloc: std.mem.Allocator,
    next_seq: u32 = 1,
    pending: std.ArrayList(Pending),

    /// Largest gap allowed between `next_seq` and the oldest sequence
    /// still awaiting acknowledgement. Bounding the pending COUNT is not
    /// sufficient: with selective ACKs a lost early packet keeps the count
    /// low while later sequences advance, aging the hole out of the
    /// receiver's 32-sequence ACK history — after which the lost packet
    /// is unrecoverable no matter how few packets are in flight.
    max_span: u32 = max_span_default,

    /// When false (attach traffic today), a full span never errors — the
    /// caller keeps its historical fire-and-retransmit behavior. When
    /// true, `buildAndTrack` returns `error.SendWindowFull` once the span
    /// is exhausted and the sender must queue until ACKs release capacity.
    enforce_span: bool = false,

    const Pending = struct {
        seq: u32,
        sent_ns: i64,
        retries: u8,
        packet: []u8,
    };

    pub fn init(alloc: std.mem.Allocator) !ReliableSend {
        return .{
            .alloc = alloc,
            .pending = try std.ArrayList(Pending).initCapacity(alloc, 16),
        };
    }

    pub fn deinit(self: *ReliableSend) void {
        for (self.pending.items) |p| {
            self.alloc.free(p.packet);
        }
        self.pending.deinit(self.alloc);
    }

    pub fn hasPending(self: *const ReliableSend) bool {
        return self.pending.items.len > 0;
    }

    /// The oldest sequence still pending acknowledgement.
    pub fn oldestUnacked(self: *const ReliableSend) ?u32 {
        var oldest: ?u32 = null;
        for (self.pending.items) |p| {
            if (oldest == null or p.seq < oldest.?) oldest = p.seq;
        }
        return oldest;
    }

    /// True while a new sequence stays within `max_span` of the oldest
    /// unacknowledged one (trivially true with nothing pending).
    pub fn withinSpan(self: *const ReliableSend) bool {
        const oldest = self.oldestUnacked() orelse return true;
        return self.next_seq -% oldest < self.max_span;
    }

    pub fn buildAndTrack(
        self: *ReliableSend,
        channel: Channel,
        payload: []const u8,
        ack_seq: u32,
        ack_bits: u32,
        now_ns: i64,
    ) ![]const u8 {
        if (self.enforce_span and !self.withinSpan()) return error.SendWindowFull;
        const seq = self.next_seq;
        self.next_seq +%= 1;

        const packet = try self.alloc.alloc(u8, header_len + payload.len);
        writeHeader(packet[0..header_len], channel, seq, ack_seq, ack_bits, payload.len);
        if (payload.len > 0) {
            @memcpy(packet[header_len..], payload);
        }

        try self.pending.append(self.alloc, .{
            .seq = seq,
            .sent_ns = now_ns,
            .retries = 0,
            .packet = packet,
        });

        return packet;
    }

    pub fn ack(self: *ReliableSend, ack_seq: u32, ack_bits: u32) void {
        var i: usize = self.pending.items.len;
        while (i > 0) {
            i -= 1;
            const p = self.pending.items[i];
            if (isAcked(p.seq, ack_seq, ack_bits)) {
                self.alloc.free(p.packet);
                _ = self.pending.swapRemove(i);
            }
        }
    }

    pub fn collectRetransmits(
        self: *ReliableSend,
        alloc: std.mem.Allocator,
        now_ns: i64,
        rto_us: i64,
    ) !std.ArrayList([]const u8) {
        var out = try std.ArrayList([]const u8).initCapacity(alloc, 4);
        const interval_ns = @max(@as(i64, 1), rto_us) * std.time.ns_per_us;

        for (self.pending.items) |*p| {
            if (now_ns - p.sent_ns >= interval_ns) {
                p.sent_ns = now_ns;
                p.retries +%= 1;
                try out.append(alloc, p.packet);
            }
        }

        return out;
    }

    fn isAcked(seq: u32, ack_seq: u32, ack_bits: u32) bool {
        if (ack_seq == 0) return false;
        if (seq == ack_seq) return true;
        if (seq > ack_seq) return false;

        const diff = ack_seq - seq;
        if (diff == 0) return true;
        if (diff > 32) return false;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        return (ack_bits & bit) != 0;
    }
};

pub fn writeHeader(dst: []u8, channel: Channel, seq: u32, ack: u32, ack_bits: u32, payload_len: usize) void {
    std.debug.assert(dst.len >= header_len);
    std.debug.assert(payload_len <= std.math.maxInt(u16));

    dst[0] = version;
    dst[1] = @intFromEnum(channel);
    dst[2] = 0;
    dst[3] = 0;

    std.mem.writeInt(u32, dst[4..8], seq, .big);
    std.mem.writeInt(u32, dst[8..12], ack, .big);
    std.mem.writeInt(u32, dst[12..16], ack_bits, .big);
    std.mem.writeInt(u16, dst[16..18], @intCast(payload_len), .big);
    std.mem.writeInt(u16, dst[18..20], 0, .big);
}

pub fn parsePacket(data: []const u8) !Packet {
    if (data.len < header_len) return error.PacketTooShort;
    if (data[0] != version) return error.UnsupportedVersion;

    const channel_int = data[1];
    const channel = std.enums.fromInt(Channel, channel_int) orelse return error.InvalidChannel;

    const seq = std.mem.readInt(u32, data[4..8], .big);
    const ack = std.mem.readInt(u32, data[8..12], .big);
    const ack_bits = std.mem.readInt(u32, data[12..16], .big);
    const len = std.mem.readInt(u16, data[16..18], .big);

    if (data.len != header_len + len) return error.InvalidLength;

    return .{
        .channel = channel,
        .seq = seq,
        .ack = ack,
        .ack_bits = ack_bits,
        .payload = data[header_len..],
    };
}

pub fn buildUnreliable(
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    const total = header_len + payload.len;
    if (out.len < total) return error.BufferTooSmall;
    writeHeader(out[0..header_len], channel, seq, ack, ack_bits, payload.len);
    if (payload.len > 0) {
        @memcpy(out[header_len..total], payload);
    }
    return out[0..total];
}

pub fn buildControl(control: Control, out: *[8]u8) []const u8 {
    out[0] = @intFromEnum(control);
    @memset(out[1..], 0);
    return out[0..1];
}

pub fn parseControl(payload: []const u8) !Control {
    if (payload.len < 1) return error.InvalidControl;
    return std.enums.fromInt(Control, payload[0]) orelse return error.InvalidControl;
}

pub fn buildIpcBytes(tag: ipc.Tag, payload: []const u8, buf: []u8) []const u8 {
    const header = ipc.Header{ .tag = tag, .len = @intCast(payload.len) };
    const hdr_bytes = std.mem.asBytes(&header);
    const total = @sizeOf(ipc.Header) + payload.len;
    std.debug.assert(buf.len >= total);
    @memcpy(buf[0..@sizeOf(ipc.Header)], hdr_bytes);
    if (payload.len > 0) {
        @memcpy(buf[@sizeOf(ipc.Header)..total], payload);
    }
    return buf[0..total];
}

test "transport header round trip" {
    var buf: [64]u8 = undefined;
    const payload = "abc";
    const pkt = try buildUnreliable(.output, 7, 6, 0x55, payload, &buf);
    const parsed = try parsePacket(pkt);
    try std.testing.expect(parsed.channel == .output);
    try std.testing.expectEqual(@as(u32, 7), parsed.seq);
    try std.testing.expectEqual(@as(u32, 6), parsed.ack);
    try std.testing.expectEqual(@as(u32, 0x55), parsed.ack_bits);
    try std.testing.expectEqualStrings(payload, parsed.payload);
}

test "reliable recv window" {
    var recv = RecvState{};
    try std.testing.expect(recv.onReliable(10) == .accept);
    try std.testing.expect(recv.onReliable(9) == .accept);
    try std.testing.expect(recv.onReliable(9) == .duplicate);
    try std.testing.expect(recv.onReliable(11) == .accept);
    try std.testing.expectEqual(@as(u32, 11), recv.ack());
}

test "output gap detection" {
    var out = OutputRecvState{};
    try std.testing.expect(out.onPacket(1) == .accept);
    try std.testing.expect(out.onPacket(3) == .gap);
    try std.testing.expect(out.onPacket(2) == .duplicate);
}

// ---------------------------------------------------------------------------
// Span-window tests: genuine loss, selective ACK, and retransmission
// ---------------------------------------------------------------------------

test "span window blocks new sequences until the oldest hole is recovered" {
    const alloc = std.testing.allocator;
    var rs = try ReliableSend.init(alloc);
    defer rs.deinit();
    rs.max_span = 16;
    rs.enforce_span = true;

    // Receiver-side ACK generation.
    var recv = RecvState{};
    const t0: i64 = 1_000_000;

    // Send sequences 1..16.
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        _ = try rs.buildAndTrack(.command, "x", 0, 0, t0);
    }
    try std.testing.expectEqual(@as(?u32, 1), rs.oldestUnacked());

    // The receiver gets 2..16 but DROPS sequence 1.
    var r: usize = 2;
    while (r <= 16) : (r += 1) {
        _ = recv.onReliable(@intCast(r));
    }
    rs.ack(recv.ack(), recv.ackBits());

    // Only the hole is pending: count is 1, but the span is exhausted —
    // exactly the case a count-only window would wrongly admit.
    try std.testing.expectEqual(@as(usize, 1), rs.pending.items.len);
    try std.testing.expect(!rs.withinSpan());
    try std.testing.expectError(error.SendWindowFull, rs.buildAndTrack(.command, "y", 0, 0, t0));

    // Retransmit after the RTO; the receiver finally accepts sequence 1.
    var re = try rs.collectRetransmits(alloc, t0 + 10 * std.time.ns_per_s, 50_000);
    defer re.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), re.items.len);
    _ = recv.onReliable(1);
    rs.ack(recv.ack(), recv.ackBits());
    try std.testing.expect(!rs.hasPending());
    try std.testing.expect(rs.withinSpan());

    // Span released: new sequences flow again.
    _ = try rs.buildAndTrack(.command, "z", 0, 0, t0);
}

test "attach traffic keeps historical behavior beyond the span" {
    const alloc = std.testing.allocator;
    var rs = try ReliableSend.init(alloc);
    defer rs.deinit();
    rs.max_span = 4;
    // enforce_span stays false: the attach gateway and client never see
    // SendWindowFull; retransmission remains the recovery path.
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        _ = try rs.buildAndTrack(.reliable_ipc, "x", 0, 0, 1);
    }
    try std.testing.expectEqual(@as(usize, 16), rs.pending.items.len);
}
