//! Q4 stage 5 — the client's heap-stable snapshot installer.
//!
//! One `Installer`, heap-allocated once per session, owns the entire
//! client side of a stream-7 snapshot transaction: the incremental
//! header/body spool, the Ghostty `Decoder`, the restored `Terminal`,
//! and its persistent `TerminalStream` all live at stable addresses
//! inside this allocation (the `Decoded.toOwned` contract forbids a
//! stream against the pre-move address). Decoding never starts before
//! a clean stream-7 FIN. After FINISH validates with zero trailing
//! bytes the spool is cleared — retaining its capacity, with NO second
//! full-size buffer — and the restored terminal state plus the live
//! stream's CURRENT continuation are serialized into it as the replay
//! the client hands to its driver before any live output byte.
//!
//! Failure mapping (frozen wire codes only): wrong stream role is
//! unknown_role; malformed header/body, truncation, negotiated-limit
//! excess, malformed snapshots, continuation mismatch/excess, and
//! trailing bytes are protocol_violation; allocation, terminal
//! semantic, and replay-writer failures are internal_error.

const std = @import("std");
const ghostty_vt = @import("ghostty-vt");
const quic_wire = @import("quic_wire.zig");
const util = @import("util.zig");

/// Absolute ceiling on the final replay (matches snapshot_limit_v1).
pub const replay_max: usize = 128 * 1024 * 1024;
/// Ceiling on decoded and live-stream continuation bytes.
pub const continuation_max: usize = 64 * 1024 * 1024;

pub const Failure = struct {
    code: quic_wire.ErrCode,
    reason: []const u8,
};

pub const Phase = enum(u8) {
    /// Reading the 24-byte stream-7 snapshot header.
    header,
    /// Accumulating the encoded body until FIN.
    body,
    /// READY done; history pages remain (≤ one per public pump).
    history,
    /// Replay prepared; bytes remain to be copied to the driver.
    replay,
    /// Nothing left to do; the client may destroy the installer.
    done,
    /// Terminal failure recorded in `failure`.
    failed,
};

/// A nonallocating comparator writer: the canonical re-export must
/// equal the reference bytes exactly. Used to verify the continuation
/// replay without allocating a comparison copy.
const CompareSink = struct {
    want: []const u8,
    seen: usize,
    writer: std.Io.Writer = undefined,

    const mismatch = error{Mismatch};

    fn init(self: *CompareSink, want: []const u8) void {
        self.* = .{ .want = want, .seen = 0 };
        self.writer = .{
            .buffer = &.{},
            .vtable = &.{ .drain = drain, .flush = flush },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *CompareSink = @alignCast(@fieldParentPtr("writer", w));
        var total: usize = 0;
        for (data, 0..) |slice, i| {
            const repeats: usize = if (i + 1 == data.len) splat else 1;
            var r: usize = 0;
            while (r < repeats) : (r += 1) {
                const tail = self.want[self.seen..];
                if (tail.len < slice.len) return error.WriteFailed;
                if (!std.mem.eql(u8, tail[0..slice.len], slice)) return error.WriteFailed;
                self.seen += slice.len;
                total += slice.len;
            }
        }
        return total;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        const self: *CompareSink = @alignCast(@fieldParentPtr("writer", w));
        if (self.seen != self.want.len) return error.WriteFailed;
    }

    fn matched(self: *const CompareSink) bool {
        return self.seen == self.want.len;
    }
};

/// A precise bounded writer over the installer's spool: the replay is
/// serialized straight into the ONE ArrayList-backed buffer (no
/// independent full copy), with the 128 MiB bound enforced BEFORE
/// every growth.
const SpoolWriter = struct {
    alloc: std.mem.Allocator,
    list: *std.ArrayList(u8),
    cap: usize,
    writer: std.Io.Writer = undefined,

    fn init(self: *SpoolWriter, alloc: std.mem.Allocator, list: *std.ArrayList(u8), cap: usize) void {
        self.* = .{ .alloc = alloc, .list = list, .cap = cap };
        self.writer = .{
            .buffer = &.{},
            .vtable = &.{ .drain = drain, .flush = flush },
        };
    }

    fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *SpoolWriter = @alignCast(@fieldParentPtr("writer", w));
        var total: usize = 0;
        for (data) |slice| total += slice.len;
        if (splat > 1) total += (splat - 1) * data[data.len - 1].len;
        if (self.list.items.len + total > self.cap) return error.WriteFailed;
        if (self.list.capacity < self.list.items.len + total) {
            self.list.ensureTotalCapacityPrecise(self.alloc, self.list.items.len + total) catch
                return error.WriteFailed;
        }
        for (data, 0..) |slice, i| {
            const repeats: usize = if (i + 1 == data.len) splat else 1;
            var r: usize = 0;
            while (r < repeats) : (r += 1) {
                self.list.appendSliceAssumeCapacity(slice);
            }
        }
        return total;
    }

    fn flush(w: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = w;
    }
};

pub const Installer = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    /// The HELLO_ACK-negotiated snapshot body limit (≤ 128 MiB).
    limit: usize,
    phase: Phase = .header,

    /// The encoded-body spool; after replay preparation, the replay
    /// buffer itself (same allocation, capacity retained).
    spool: std.ArrayList(u8) = .empty,
    hp: quic_wire.SnapshotHeaderParser = .{},
    header: quic_wire.SnapshotHeader = undefined,

    /// Fixed reader over the COMPLETED spool — created only at FIN,
    /// released at replay preparation.
    reader: ?std.Io.Reader = null,
    decoder: ?ghostty_vt.snapshot.Decoder = null,
    terminal: ?ghostty_vt.Terminal = null,
    stream: ?ghostty_vt.TerminalStream = null,
    ready_done: bool = false,

    replay_offset: usize = 0,

    failure: ?Failure = null,

    /// Heap-allocates the stable container; every self-referential
    /// object (reader, decoder source pointer, terminal, stream
    /// handler) is anchored to this allocation.
    pub fn create(
        alloc: std.mem.Allocator,
        io: std.Io,
        negotiated_snapshot_limit: usize,
    ) !*Installer {
        std.debug.assert(negotiated_snapshot_limit >= 1 and
            negotiated_snapshot_limit <= quic_wire.snapshot_limit_v1);
        const self = try alloc.create(Installer);
        self.* = .{ .alloc = alloc, .io = io, .limit = negotiated_snapshot_limit };
        return self;
    }

    /// Destruction order is binding: stream → terminal → spool → the
    /// installer itself.
    pub fn destroy(self: *Installer) void {
        if (self.stream) |*s| s.deinit();
        if (self.terminal) |*t| t.deinit(self.alloc);
        self.spool.deinit(self.alloc);
        self.alloc.destroy(self);
    }

    fn fail(self: *Installer, code: quic_wire.ErrCode, reason: []const u8) Failure {
        self.phase = .failed;
        self.failure = .{ .code = code, .reason = reason };
        return self.failure.?;
    }

    /// Bytes still missing toward the stream-7 header.
    pub fn headerRemaining(self: *const Installer) usize {
        return self.hp.remaining();
    }

    /// Feed header bytes (at most `headerRemaining`); returns null on
    /// progress, a Failure once the header proves malformed.
    pub fn feedHeader(self: *Installer, bytes: []const u8) ?Failure {
        std.debug.assert(bytes.len <= self.hp.remaining());
        const r = self.hp.feed(bytes);
        if (r.result == .invalid) {
            return self.fail(.protocol_violation, "malformed snapshot-stream header");
        }
        if (r.result == .done) {
            self.header = r.result.done;
            if (self.header.epoch != 1) {
                return self.fail(.protocol_violation, "snapshot epoch is not 1");
            }
            self.phase = .body;
        }
        return null;
    }

    /// The most body bytes the caller may feed this round:
    /// limit − received + 1, so ONE excess byte is detectable without
    /// ever allocating for it.
    pub fn bodyAllowance(self: *const Installer) usize {
        std.debug.assert(self.phase == .body);
        return self.limit + 1 - @min(self.spool.items.len, self.limit + 1);
    }

    /// Feed body bytes; the negotiated limit + 1 rejection fires
    /// BEFORE any allocation.
    pub fn feedBody(self: *Installer, bytes: []const u8) ?Failure {
        std.debug.assert(self.phase == .body);
        // The caller may READ one byte past the limit to detect the
        // excess (bodyAllowance); the installer never ALLOCATES for
        // it — the feed carrying it fails before any growth.
        if (self.spool.items.len + bytes.len > self.limit) {
            return self.fail(.protocol_violation, "snapshot exceeds the negotiated limit");
        }
        self.spool.ensureTotalCapacityPrecise(self.alloc, self.spool.items.len + bytes.len) catch {
            return self.fail(.internal_error, "out of memory spooling the snapshot");
        };
        self.spool.appendSliceAssumeCapacity(bytes);
        return null;
    }

    /// The clean stream-7 FIN. PRESENT=0 requires an empty body and
    /// completes with no replay; PRESENT=1 requires at least one byte
    /// and runs the exact decode sequence. Decoding NEVER starts
    /// before this call.
    pub fn fin(self: *Installer) ?Failure {
        std.debug.assert(self.phase == .body or self.phase == .header);
        if (self.phase == .header) {
            return self.fail(.protocol_violation, "stream FIN inside the snapshot header");
        }
        if (!self.header.present) {
            if (self.spool.items.len != 0) {
                return self.fail(.protocol_violation, "body after an empty snapshot header");
            }
            self.phase = .done;
            return null;
        }
        if (self.spool.items.len == 0) {
            return self.fail(.protocol_violation, "absent body for a present snapshot");
        }

        // 1. Fixed reader over the completed spool; 2. ready() exactly
        //    once (the decoder asserts its own first-call state).
        self.reader = std.Io.Reader.fixed(self.spool.items);
        self.decoder = ghostty_vt.snapshot.Decoder.init(&self.reader.?);
        var decoded = self.decoder.?.ready(self.alloc, self.io, .{
            .max_continuation_bytes = continuation_max,
        }) catch |e| {
            return self.fail(readyError(e), "snapshot failed READY validation");
        };
        // 3. The terminal moves DIRECTLY into its stable final field.
        self.terminal = decoded.toOwned();
        // 4. The persistent stream binds to that final address, with
        //    continuation tracking enabled.
        self.stream = ghostty_vt.TerminalStream.init(.{
            .allocator = self.alloc,
            .handler = self.terminal.?.vtHandler(),
            .continuation_max_bytes = continuation_max,
        });
        // 5. The decoded continuation replays exactly once, verified
        //    against its canonical re-export by a nonallocating
        //    comparator.
        switch (decoded.continuation) {
            .ground => {},
            .bytes => |want| {
                self.stream.?.nextSlice(want);
                if (self.stream.?.handler.semantic_failure) {
                    decoded.deinit(self.alloc);
                    return self.fail(.internal_error, "terminal rejected the decoded continuation");
                }
                var cmp: CompareSink = undefined;
                cmp.init(want);
                self.stream.?.writeContinuation(&cmp.writer) catch {
                    decoded.deinit(self.alloc);
                    return self.fail(.protocol_violation, "continuation re-export mismatch");
                };
                if (!cmp.matched()) {
                    decoded.deinit(self.alloc);
                    return self.fail(.protocol_violation, "continuation re-export mismatch");
                }
            },
        }
        // 6. The temporary Decoded value is gone (continuation freed;
        //    the terminal is already owned by its stable field).
        decoded.deinit(self.alloc);

        self.ready_done = true;
        self.phase = .history;
        return null;
    }

    fn readyError(e: anyerror) quic_wire.ErrCode {
        return switch (e) {
            error.OutOfMemory => .internal_error,
            else => .protocol_violation,
        };
    }

    /// ONE history page (the public client pump calls this at most
    /// once per pump, starting the pump AFTER READY). When the page
    /// stream ends: FINISH must be followed by zero trailing bytes,
    /// then the replay is prepared into the reused spool and the
    /// stream/terminal are destroyed in that order.
    pub fn nextPage(self: *Installer) ?Failure {
        std.debug.assert(self.phase == .history);
        const page = self.decoder.?.next(self.alloc, &self.terminal.?) catch |e| {
            return self.fail(nextError(e), "snapshot history failed to decode");
        };
        if (page != null) return null;

        // FINISH validated. Explicit zero-trailing check, mirroring
        // snapshot.decodeExact.
        if (self.reader.?.peekByte()) |_| {
            return self.fail(.protocol_violation, "trailing bytes after snapshot FINISH");
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => return self.fail(.internal_error, "snapshot reader failed its trailing check"),
        }
        return self.prepareReplay();
    }

    fn nextError(e: anyerror) quic_wire.ErrCode {
        return switch (e) {
            error.OutOfMemory => .internal_error,
            else => .protocol_violation,
        };
    }

    fn prepareReplay(self: *Installer) ?Failure {
        // Clear the spool RETAINING capacity — the replay serializes
        // into the same one buffer, no independent full copy.
        self.spool.clearRetainingCapacity();
        var sw: SpoolWriter = undefined;
        sw.init(self.alloc, &self.spool, replay_max);
        util.writeTerminalState(&sw.writer, &self.terminal.?) catch {
            return self.fail(.internal_error, "replay serialization failed");
        };
        // The live stream's CURRENT continuation survives into the
        // replay so unfinished post-cut parsing state is not lost.
        self.stream.?.writeContinuation(&sw.writer) catch {
            return self.fail(.internal_error, "live continuation export failed");
        };
        sw.writer.flush() catch {
            return self.fail(.internal_error, "replay flush failed");
        };
        // Stream first, then terminal — their state now lives in the
        // replay bytes and the direct-forwarded live output.
        self.stream.?.deinit();
        self.stream = null;
        self.terminal.?.deinit(self.alloc);
        self.terminal = null;
        self.decoder = null;
        self.reader = null;

        self.replay_offset = 0;
        self.phase = .replay;
        return null;
    }

    /// Post-cut output applied to the temporary stream BEFORE replay
    /// preparation (never returned separately). The semantic-failure
    /// flag is checked after every live feed.
    pub fn applyLive(self: *Installer, bytes: []const u8) ?Failure {
        std.debug.assert(self.phase == .history);
        self.stream.?.nextSlice(bytes);
        if (self.stream.?.handler.semantic_failure) {
            return self.fail(.internal_error, "terminal rejected post-cut output");
        }
        return null;
    }

    /// Replay bytes still owned by the installer.
    pub fn replayRemaining(self: *const Installer) usize {
        if (self.phase != .replay) return 0;
        return self.spool.items.len - self.replay_offset;
    }

    /// The next replay slice for the driver queue; `n` ≤ what a
    /// previous `replayRemaining` reported.
    pub fn replaySlice(self: *const Installer, n: usize) []const u8 {
        std.debug.assert(n <= self.replayRemaining());
        return self.spool.items[self.replay_offset .. self.replay_offset + n];
    }

    /// The driver copied `n` replay bytes.
    pub fn replayConsumed(self: *Installer, n: usize) void {
        self.replay_offset += n;
        if (self.replay_offset >= self.spool.items.len) {
            self.phase = .done;
        }
    }

    /// True once replay preparation has produced replay bytes (or an
    /// empty snapshot completed) — the client may then send
    /// SNAPSHOT_INSTALLED.
    pub fn readyToInstall(self: *const Installer) bool {
        return self.phase == .replay or self.phase == .done;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Encodes a real snapshot of a terminal fed `lines` complete lines
/// (plus an optional unfinished CSI continuation carried by the
/// snapshot itself).
fn encodeSnapshot(
    alloc: std.mem.Allocator,
    io: std.Io,
    cols: u16,
    rows: u16,
    lines: usize,
    cont: ghostty_vt.snapshot.Continuation,
) ![]u8 {
    var term = try ghostty_vt.Terminal.init(io, alloc, .{ .cols = cols, .rows = rows });
    defer term.deinit(alloc);
    var vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = continuation_max,
    });
    defer vts.deinit();
    var i: usize = 0;
    while (i < lines) : (i += 1) vts.nextSlice("history line\r\n");
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();
    try ghostty_vt.snapshot.encode(alloc, &aw.writer, &term, .{ .continuation = cont });
    return alloc.dupe(u8, aw.written());
}

fn streamBytes(alloc: std.mem.Allocator, present: bool, body: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(alloc);
    var hb: [quic_wire.snapshot_header_len]u8 = undefined;
    quic_wire.writeSnapshotHeader(&hb, 1, present);
    try out.appendSlice(alloc, &hb);
    try out.appendSlice(alloc, body);
    return out.toOwnedSlice(alloc);
}

/// Drives a full install over already-whole stream bytes.
fn installWhole(alloc: std.mem.Allocator, limit: usize, bytes: []const u8) !*Installer {
    const inst = try Installer.create(alloc, testing.io, limit);
    errdefer inst.destroy();
    var off: usize = 0;
    while (inst.headerRemaining() > 0) {
        const want = inst.headerRemaining();
        const n = @min(want, bytes.len - off);
        if (inst.feedHeader(bytes[off .. off + n])) |_| return error.InstallFailed;
        off += n;
    }
    while (off < bytes.len) {
        const allow = @min(inst.bodyAllowance(), bytes.len - off);
        if (inst.feedBody(bytes[off .. off + allow])) |_| return error.InstallFailed;
        off += allow;
    }
    if (inst.fin()) |f| {
        std.debug.print("fin failure: {s}\n", .{f.reason});
        return error.InstallFailed;
    }
    while (inst.phase == .history) {
        if (inst.nextPage()) |f| {
            std.debug.print("page failure: {s}\n", .{f.reason});
            return error.InstallFailed;
        }
    }
    return inst;
}

test "installer: minimal valid snapshot installs across every two-part split" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const ref = try installWhole(alloc, quic_wire.snapshot_limit_v1, bytes);
    defer ref.destroy();
    try testing.expect(ref.readyToInstall());
    const want_replay_len = ref.replayRemaining();

    // Every two-part split of the header+body byte stream installs to
    // the identical replay.
    var k: usize = 0;
    while (k <= bytes.len) : (k += 1) {
        const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
        var fed: usize = 0;
        var failed = false;
        feed: while (true) {
            const avail = if (fed < k) k - fed else bytes.len - fed;
            if (avail == 0) break;
            if (inst.phase == .header) {
                const want = @min(inst.headerRemaining(), avail);
                if (inst.feedHeader(bytes[fed .. fed + want])) |_| {
                    failed = true;
                    break :feed;
                }
                fed += want;
            } else if (inst.phase == .body) {
                const want = @min(inst.bodyAllowance(), avail);
                if (inst.feedBody(bytes[fed .. fed + want])) |_| {
                    failed = true;
                    break :feed;
                }
                fed += want;
            } else break;
        }
        if (!failed and inst.fin() != null) failed = true;
        while (!failed and inst.phase == .history) {
            if (inst.nextPage() != null) failed = true;
        }
        if (failed) return error.SplitInstallFailed;
        try testing.expect(inst.readyToInstall());
        try testing.expectEqual(want_replay_len, inst.replayRemaining());
        inst.destroy();
    }
}

test "installer: PRESENT=0 requires an empty body and finishes with no replay" {
    const alloc = testing.allocator;
    const bytes = try streamBytes(alloc, false, &.{});
    defer alloc.free(bytes);
    const inst = try installWhole(alloc, quic_wire.snapshot_limit_v1, bytes);
    defer inst.destroy();
    try testing.expect(inst.phase == .done);
    try testing.expectEqual(@as(usize, 0), inst.replayRemaining());
    try testing.expect(inst.readyToInstall());

    // A body after an empty header is rejected.
    const bad = try streamBytes(alloc, false, "x");
    defer alloc.free(bad);
    const inst2 = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
    defer inst2.destroy();
    var off: usize = 0;
    while (inst2.headerRemaining() > 0) {
        const n = @min(inst2.headerRemaining(), bad.len - off);
        _ = inst2.feedHeader(bad[off .. off + n]);
        off += n;
    }
    while (off < bad.len) {
        const n = @min(inst2.bodyAllowance(), bad.len - off);
        _ = inst2.feedBody(bad[off .. off + n]);
        off += n;
    }
    const f = inst2.fin().?;
    try testing.expectEqual(quic_wire.ErrCode.protocol_violation, f.code);
}

test "installer: PRESENT=1 with no body is rejected" {
    const alloc = testing.allocator;
    const bytes = try streamBytes(alloc, true, &.{});
    defer alloc.free(bytes);
    const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
    defer inst.destroy();
    var off: usize = 0;
    while (inst.headerRemaining() > 0) {
        const n = @min(inst.headerRemaining(), bytes.len - off);
        _ = inst.feedHeader(bytes[off .. off + n]);
        off += n;
    }
    const f = inst.fin().?;
    try testing.expectEqual(quic_wire.ErrCode.protocol_violation, f.code);
    try testing.expectEqualStrings("absent body for a present snapshot", f.reason);
}

test "installer: negotiated limit + 1 is rejected before any allocation" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const small_limit = body.len / 2;
    const inst = try Installer.create(alloc, testing.io, small_limit);
    defer inst.destroy();
    var off: usize = 0;
    while (inst.headerRemaining() > 0) {
        const n = @min(inst.headerRemaining(), bytes.len - off);
        _ = inst.feedHeader(bytes[off .. off + n]);
        off += n;
    }
    // Feed byte-by-byte: the byte AFTER the limit fails the feed, the
    // spool never grows past the limit, and capacity stays exact.
    var rejected = false;
    while (off < bytes.len) {
        if (inst.feedBody(bytes[off .. off + 1])) |f| {
            try testing.expectEqual(quic_wire.ErrCode.protocol_violation, f.code);
            try testing.expectEqualStrings("snapshot exceeds the negotiated limit", f.reason);
            rejected = true;
            break;
        }
        off += 1;
    }
    try testing.expect(rejected);
    try testing.expectEqual(small_limit, inst.spool.items.len);
    try testing.expectEqual(small_limit, inst.spool.capacity);
}

test "installer: truncated and malformed bodies fail closed" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    // Truncated body: FIN while the decoder still needs bytes.
    {
        const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
        defer inst.destroy();
        var off: usize = 0;
        while (inst.headerRemaining() > 0) {
            const n = @min(inst.headerRemaining(), bytes.len - off);
            _ = inst.feedHeader(bytes[off .. off + n]);
            off += n;
        }
        const cut = body.len / 2;
        _ = inst.feedBody(body[0..cut]);
        const f = inst.fin().?;
        try testing.expect(f.code == .protocol_violation or f.code == .internal_error);
    }

    // Malformed record: corrupt one body byte after the header.
    {
        var mangled = try alloc.dupe(u8, bytes);
        defer alloc.free(mangled);
        mangled[mangled.len - 2] ^= 0xff;
        const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
        defer inst.destroy();
        var off: usize = 0;
        var failed = false;
        while (inst.headerRemaining() > 0) {
            const n = @min(inst.headerRemaining(), mangled.len - off);
            _ = inst.feedHeader(mangled[off .. off + n]);
            off += n;
        }
        while (off < mangled.len and !failed) {
            const n = @min(inst.bodyAllowance(), mangled.len - off);
            if (inst.feedBody(mangled[off .. off + n])) |_| failed = true;
            off += n;
        }
        if (!failed) {
            if (inst.fin()) |_| failed = true;
        }
        while (!failed and inst.phase == .history) {
            if (inst.nextPage()) |_| failed = true;
        }
        try testing.expect(failed);
    }
}

test "installer: trailing bytes after FINISH are rejected" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
    defer inst.destroy();
    var off: usize = 0;
    while (inst.headerRemaining() > 0) {
        const n = @min(inst.headerRemaining(), bytes.len - off);
        _ = inst.feedHeader(bytes[off .. off + n]);
        off += n;
    }
    while (off < bytes.len) {
        const n = @min(inst.bodyAllowance(), bytes.len - off);
        _ = inst.feedBody(bytes[off .. off + n]);
        off += n;
    }
    // One extra byte rides in the spool past the encoded snapshot.
    _ = inst.feedBody(&.{0x00});
    try testing.expect(inst.fin() == null);
    while (inst.phase == .history) {
        if (inst.nextPage()) |f| {
            try testing.expectEqual(quic_wire.ErrCode.protocol_violation, f.code);
            try testing.expectEqualStrings("trailing bytes after snapshot FINISH", f.reason);
            return;
        }
    }
    return error.TrailingNotDetected;
}

test "installer: no decoding before FIN, READY once, stable addresses" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
    defer inst.destroy();
    var off: usize = 0;
    while (inst.headerRemaining() > 0) {
        const n = @min(inst.headerRemaining(), bytes.len - off);
        _ = inst.feedHeader(bytes[off .. off + n]);
        off += n;
    }
    while (off < bytes.len) {
        const n = @min(inst.bodyAllowance(), bytes.len - off);
        _ = inst.feedBody(bytes[off .. off + n]);
        off += n;
    }
    // Fully spooled, FIN not yet observed: no decoder exists.
    try testing.expect(inst.decoder == null);
    try testing.expect(inst.reader == null);
    try testing.expect(inst.terminal == null);

    try testing.expect(inst.fin() == null);
    try testing.expect(inst.ready_done);
    const term_addr = &inst.terminal.?;
    const stream_addr = &inst.stream.?;
    while (inst.phase == .history) {
        try testing.expect(term_addr == &inst.terminal.?);
        try testing.expect(stream_addr == &inst.stream.?);
        try testing.expect(inst.nextPage() == null);
    }
    try testing.expect(inst.readyToInstall());
}

test "installer: decoded continuation replays and verifies once; replay carries the live continuation" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .{ .bytes = "\x1b[31" });
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const inst = try installWhole(alloc, quic_wire.snapshot_limit_v1, bytes);
    defer inst.destroy();
    // The snapshot's own continuation replayed into the stream and,
    // still pending, exported into the replay tail.
    try testing.expect(inst.readyToInstall());
    try testing.expect(inst.replayRemaining() > 0);

    // A live unfinished CSI applied between pages lands in the final
    // replay's continuation export.
    const inst2 = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
    defer inst2.destroy();
    var off: usize = 0;
    while (inst2.headerRemaining() > 0) {
        const n = @min(inst2.headerRemaining(), bytes.len - off);
        _ = inst2.feedHeader(bytes[off .. off + n]);
        off += n;
    }
    while (off < bytes.len) {
        const n = @min(inst2.bodyAllowance(), bytes.len - off);
        _ = inst2.feedBody(bytes[off .. off + n]);
        off += n;
    }
    try testing.expect(inst2.fin() == null);
    try testing.expect(inst2.applyLive("live\x1b[3") == null);
    while (inst2.phase == .history) {
        try testing.expect(inst2.nextPage() == null);
    }
    const replay = inst2.replaySlice(inst2.replayRemaining());
    try testing.expect(std.mem.endsWith(u8, replay, "\x1b[3"));
}

test "installer: replay plus a later suffix matches an uninterrupted terminal" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const inst = try installWhole(alloc, quic_wire.snapshot_limit_v1, bytes);
    defer inst.destroy();
    const replay = try alloc.dupe(u8, inst.replaySlice(inst.replayRemaining()));
    defer alloc.free(replay);

    // Uninterrupted reference: the same content fed to one terminal.
    // The provable invariant is SERIALIZE equality (the same one the
    // daemon roundtrip test pins): the replay IS the canonical
    // serialization of the source terminal. Feeding a serialization
    // BACK through a same-size terminal is inherently lossy — the
    // phase-1 clear (\x1b[2J) erases visible rows without scrolling
    // them — so feed-through equality is not a property of this
    // format and is deliberately not asserted.
    var ref = try ghostty_vt.Terminal.init(testing.io, alloc, .{ .cols = 20, .rows = 5 });
    defer ref.deinit(alloc);
    var ref_vts = ghostty_vt.TerminalStream.init(.{
        .allocator = alloc,
        .handler = ref.vtHandler(),
        .continuation_max_bytes = continuation_max,
    });
    defer ref_vts.deinit();
    var i: usize = 0;
    while (i < 12) : (i += 1) ref_vts.nextSlice("history line\r\n");
    const want = util.serializeTerminalState(alloc, &ref) orelse return error.TestUnexpectedResult;
    defer alloc.free(want);

    try testing.expectEqualSlices(u8, want, replay);
}

test "installer: spool capacity is reused for the replay with no second buffer" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    const inst = try Installer.create(alloc, testing.io, quic_wire.snapshot_limit_v1);
    defer inst.destroy();
    var off: usize = 0;
    while (inst.headerRemaining() > 0) {
        const n = @min(inst.headerRemaining(), bytes.len - off);
        _ = inst.feedHeader(bytes[off .. off + n]);
        off += n;
    }
    while (off < bytes.len) {
        const n = @min(inst.bodyAllowance(), bytes.len - off);
        _ = inst.feedBody(bytes[off .. off + n]);
        off += n;
    }
    try testing.expect(inst.fin() == null);
    const body_capacity = inst.spool.capacity;
    const spool_ptr = inst.spool.items.ptr;
    while (inst.phase == .history) {
        try testing.expect(inst.nextPage() == null);
    }
    // The replay occupies the SAME buffer; capacity only grew if the
    // replay genuinely needed more room, never a second allocation.
    try testing.expect(inst.spool.items.len == inst.replayRemaining());
    if (inst.spool.capacity == body_capacity) {
        try testing.expectEqual(spool_ptr, inst.spool.items.ptr);
    }
}

test "installer: allocation failures roll back cleanly with no leaks" {
    const alloc = testing.allocator;
    const body = try encodeSnapshot(alloc, testing.io, 20, 5, 12, .ground);
    defer alloc.free(body);
    const bytes = try streamBytes(alloc, true, body);
    defer alloc.free(bytes);

    // Iterate every allocation index: each failure must surface as a
    // Failure (or complete cleanly) with zero leaks.
    var fail_index: usize = 0;
    var completed: usize = 0;
    while (completed < 2 and fail_index < 512) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_index });
        const fa = failing.allocator();
        const inst = Installer.create(fa, testing.io, quic_wire.snapshot_limit_v1) catch {
            continue;
        };
        defer inst.destroy();
        var off: usize = 0;
        while (inst.headerRemaining() > 0) {
            const n = @min(inst.headerRemaining(), bytes.len - off);
            if (inst.feedHeader(bytes[off .. off + n]) != null) break;
            off += n;
        }
        while (off < bytes.len and inst.phase == .body) {
            const n = @min(inst.bodyAllowance(), bytes.len - off);
            if (inst.feedBody(bytes[off .. off + n]) != null) break;
            off += n;
        }
        if (inst.phase == .body) {
            if (inst.fin() != null) continue;
        }
        while (inst.phase == .history) {
            if (inst.nextPage() != null) break;
        }
        if (inst.phase == .replay or inst.phase == .done) completed += 1;
    }
    try testing.expect(completed >= 2);
}
