//! Gateway-side ZMQ1 application session. Owns NO file descriptors:
//! serve.Gateway hands it the borrowed established transport and the
//! daemon-bound write buffer, and calls processTurn each poll turn.
//! quic_gateway.zig stays connection-lifecycle only.

const std = @import("std");
const quic_wire = @import("quic_wire.zig");
const quic_transport = @import("quic_transport.zig");
const ipc = @import("ipc.zig");

pub const control_stream_id: u64 = 0;
pub const input_stream_id: u64 = 2;
pub const output_stream_id: u64 = 3;
/// Q4's server uni snapshot stream: epoch 1 only, opened once at
/// SnapshotBegin, FINed after the validated End count.
pub const snapshot_stream_id: u64 = 7;
/// One snapshot chunk as the daemon frames it (ipc.snapshot_chunk_max).
pub const snapshot_chunk_cap = ipc.snapshot_chunk_max;
/// The daemon's frozen transaction bound — the wire's negotiated-limit
/// ceiling (128 MiB of Ghostty bytes).
pub const snapshot_total_max: u64 = quic_wire.snapshot_limit_v1;
/// The single bounded pending snapshot unit: the 24-byte header plus
/// one chunk. A second chunk is never accepted while one is blocked.
pub const pending_snapshot_cap = quic_wire.snapshot_header_len + snapshot_chunk_cap;

/// Every client stream id the frozen 4-bidi/8-uni transport limits can
/// surface beyond the two expected ones: bidi {4,8,12}, uni {6,...,30}.
/// Unexpected ids are detected through PUBLIC streamState() — no quicz
/// internals.
const scan_bidi_ids = [_]u64{ 4, 8, 12 };
const scan_uni_ids = [_]u64{ 6, 10, 14, 18, 22, 26, 30 };

pub const unix_write_cap = 64 * 1024;
pub const pending_output_cap = 64 * 1024;
pub const input_chunk = 4096;
pub const app_byte_budget_per_turn = 64 * 1024;
pub const control_frame_budget_per_turn = 64;
pub const settle_deadline_ns: i64 = std.time.ns_per_s;
/// The control stash's hard bound: reads happen only while the stash
/// is empty and are capped at min(4096, budget), so 4096 is its true
/// maximum; it is preallocated once and never grown.
pub const control_stash_cap = 4096;
/// The largest single encoded control emission: preface 8 + header 8
/// + ERROR payload 4 + reason 256.
pub const max_control_emission = quic_wire.preface_len +
    quic_wire.control_header_len + 4 + quic_wire.error_reason_max;

// ---------------------------------------------------------------------------
// Bounded daemon-bound write buffer (owned by serve.Gateway, the fd
// owner; flushed on the dynamic POLL.OUT arm)
// ---------------------------------------------------------------------------

pub const UnixWriteBuf = struct {
    alloc: std.mem.Allocator,
    list: std.ArrayList(u8) = .empty,

    /// Fallible construction that RESERVES the full bounded capacity
    /// up front: after this, `append` performs only the logical bound
    /// check and writes with assumed capacity — no allocation exists
    /// on the consume path to fail after QUIC bytes were consumed.
    pub fn init(alloc: std.mem.Allocator) error{OutOfMemory}!UnixWriteBuf {
        var list: std.ArrayList(u8) = .empty;
        try list.ensureTotalCapacity(alloc, unix_write_cap);
        return .{ .alloc = alloc, .list = list };
    }

    pub fn deinit(self: *UnixWriteBuf) void {
        self.list.deinit(self.alloc);
    }

    /// Appends one framed IPC message; error.Full means the bounded
    /// buffer cannot accept it whole — the caller applies backpressure
    /// (never a silent drop). With the reserved capacity, the write
    /// itself cannot allocate.
    pub fn append(self: *UnixWriteBuf, tag: ipc.Tag, payload: []const u8) error{ Full, OutOfMemory }!void {
        if (self.list.items.len + @sizeOf(ipc.Header) + payload.len > unix_write_cap) {
            return error.Full;
        }
        try ipc.appendMessage(self.alloc, &self.list, tag, payload);
    }

    pub fn bytes(self: *const UnixWriteBuf) []const u8 {
        return self.list.items;
    }

    pub fn consume(self: *UnixWriteBuf, n: usize) void {
        const remaining = self.list.items.len - n;
        std.mem.copyForwards(u8, self.list.items[0..remaining], self.list.items[n..]);
        self.list.items.len = remaining;
    }

    pub fn empty(self: *const UnixWriteBuf) bool {
        return self.list.items.len == 0;
    }
};

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

pub const Phase = enum {
    /// Waiting for the control preface + HELLO on stream 0.
    awaiting_hello,
    /// HELLO_ACK sent, output stream opened; the first RESIZE (mapped
    /// to daemon `.InitSnapshot`) is pending. Input on stream 2 is
    /// PARKED.
    awaiting_resize,
    /// `.InitSnapshot` queued (input may flow behind it in the ordered
    /// Unix buffer); waiting for the daemon's SnapshotBegin. Pre-Begin
    /// daemon `.Output` is discarded — it predates the cut.
    awaiting_snapshot_begin,
    /// SnapshotBegin seen: stream 7 open, header staged, chunks
    /// relaying. Interleaved daemon `.Output` is a terminal violation.
    snapshot_streaming,
    /// Validated SnapshotEnd fully sent and stream 7 FINed; waiting
    /// for the client's SNAPSHOT_INSTALLED.
    awaiting_snapshot_installed,
    /// Installation complete; relaying.
    active,
    /// Terminal, waiting for the daemon-bound buffer to flush.
    ending_unix,
    /// Terminal, waiting for stream settlement or the 1 s deadline.
    ending_streams,
};

const FinalFrame = enum {
    /// Clean detach: FIN the control stream, no final frame.
    none,
    /// SESSION_END + FIN (daemon EOF).
    session_end,
    /// ERROR(code, reason) + FIN.
    error_frame,
};

pub const Counters = struct {
    protocol_errors: usize = 0,
    control_frames: usize = 0,
    input_bytes: usize = 0,
    output_bytes: usize = 0,
    daemon_output_frames: usize = 0,
    /// Snapshot chunks accepted from the daemon and their Ghostty
    /// bytes (End-count validation runs against the byte total).
    snapshot_chunks: usize = 0,
    snapshot_bytes: usize = 0,
    /// Pre-cut `.Output` bytes discarded before SnapshotBegin.
    discarded_pre_cut_output: usize = 0,
};

pub const QuicSession = struct {
    alloc: std.mem.Allocator,
    transport: *quic_transport.Transport,
    phase: Phase = .awaiting_hello,

    control_preface: quic_wire.PrefaceParser = .{},
    control: quic_wire.ControlParser,

    input_preface: quic_wire.PrefaceParser = .{},
    input_done: bool = false,

    /// The last client-declared size; seeds `.Init` and answers daemon
    /// `.Resize` (never a second `.Init`).
    last_size: ipc.Resize = .{ .rows = 24, .cols = 80 },
    init_sent: bool = false,
    /// The snapshot byte limit NEGOTIATED in HELLO (the min the client
    /// declared and the server default from the wire constant).
    snapshot_limit: u64 = quic_wire.snapshot_limit_v1,

    output_opened: bool = false,
    output_fin_sent: bool = false,
    control_fin_sent: bool = false,
    /// True until a whole encoded control buffer (which begins with
    /// the stream preface) has been SENT. A parked frame was never
    /// sent, so a terminal replacement re-emits the preface.
    control_preface_pending: bool = true,

    /// Daemon→client bytes awaiting stream credit (the output header
    /// sits at its head).
    pending_output: std.ArrayList(u8) = .empty,
    /// The ONE bounded pending snapshot unit (header + at most one
    /// chunk) awaiting stream-7 credit; nonempty also blocks daemon
    /// reads and further chunk acceptance.
    pending_snapshot: std.ArrayList(u8) = .empty,
    /// Latest client RESIZE during installation; forwarded once (and
    /// only after) SNAPSHOT_INSTALLED activates the session.
    pending_install_resize: ?ipc.Resize = null,
    snapshot_opened: bool = false,
    snapshot_present: bool = false,
    /// Set when the daemon's SnapshotEnd count validated; the stream-7
    /// FIN is sent only after this AND full pending acceptance.
    snapshot_end_validated: bool = false,
    snapshot_fin_sent: bool = false,
    /// Ghostty bytes accepted from SnapshotChunk frames; the End count
    /// must equal this exactly.
    snapshot_total: u64 = 0,
    /// Control bytes read but not yet parsed (budget-exit tails are
    /// never dropped).
    control_stash: std.ArrayList(u8) = .empty,
    /// ONE bounded encoded control response awaiting credit; while it
    /// exists no further control frames are consumed. A TERMINAL frame
    /// replaces a parked nonterminal one (the session is closing).
    pending_control: std.ArrayList(u8) = .empty,
    pending_control_fin: bool = false,

    end_code: quic_wire.ErrCode = .none,
    end_reason: [64]u8 = undefined,
    end_reason_len: usize = 0,
    end_deadline_ns: i64 = 0,
    final_frame: FinalFrame = .none,
    /// The peer STOPPED_SENDING a stream we relay onto: end cleanly
    /// with session_ended at the next turn boundary.
    send_stopped: bool = false,
    closed: bool = false,

    counters: Counters = .{},

    /// Fallible construction that PRE-ALLOCATES every bounded buffer
    /// the turn loop writes into with assumed capacity: the control
    /// stash (its read bound), the pending control frame (its ≤ 276 B
    /// maximum), and the pending output (cap + header). After this,
    /// the input-stream → UnixWriteBuf consume path performs no
    /// allocation. The ControlParser payload buffer may still allocate
    /// (validated, bounded).
    pub fn init(alloc: std.mem.Allocator, transport: *quic_transport.Transport) error{OutOfMemory}!QuicSession {
        var stash: std.ArrayList(u8) = .empty;
        errdefer stash.deinit(alloc);
        try stash.ensureTotalCapacity(alloc, control_stash_cap);
        var pending: std.ArrayList(u8) = .empty;
        errdefer pending.deinit(alloc);
        try pending.ensureTotalCapacity(alloc, max_control_emission);
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(alloc);
        try output.ensureTotalCapacity(alloc, pending_output_cap + quic_wire.output_header_len);
        var snapshot: std.ArrayList(u8) = .empty;
        errdefer snapshot.deinit(alloc);
        try snapshot.ensureTotalCapacity(alloc, pending_snapshot_cap);
        return .{
            .alloc = alloc,
            .transport = transport,
            .control = quic_wire.ControlParser.init(alloc),
            .control_stash = stash,
            .pending_control = pending,
            .pending_output = output,
            .pending_snapshot = snapshot,
        };
    }

    pub fn deinit(self: *QuicSession) void {
        self.pending_output.deinit(self.alloc);
        self.pending_snapshot.deinit(self.alloc);
        self.pending_control.deinit(self.alloc);
        self.control_stash.deinit(self.alloc);
        self.control.deinit();
    }

    pub fn closedOrEnding(self: *const QuicSession) bool {
        return self.closed or self.phase == .ending_unix or self.phase == .ending_streams;
    }

    /// The earliest session deadline (the terminal settle deadline),
    /// always in the future so a poll timeout of 0 never busy-loops.
    pub fn nextDeadline(self: *const QuicSession, now: i64) ?i64 {
        if (self.closed) return null;
        if (self.phase == .ending_unix or self.phase == .ending_streams) {
            return @max(self.end_deadline_ns, now + 1);
        }
        return null;
    }

    /// Whether the frame pump may CONSUME the buffered head frame now.
    /// Discard-only output (pre-cut) and frames that fail the session
    /// (interleaves, malformed markers, SnapshotError) are always
    /// consumable — they need no storage. Only valid relay data that
    /// would wait in occupied bounded storage blocks: post-End Output
    /// needs pending_output space, a legal data chunk needs the free
    /// single pending snapshot unit.
    pub fn canConsumeDaemonFrame(self: *const QuicSession, tag: ipc.Tag, payload_len: usize) bool {
        if (self.closedOrEnding()) return false;
        switch (tag) {
            .Output => switch (self.phase) {
                // Discarded pre-cut output (or a terminal interleave
                // once consumed): no storage required.
                .awaiting_hello, .awaiting_resize, .awaiting_snapshot_begin => return true,
                // Between Begin and End an Output is a terminal
                // interleave (always consumable); AFTER the validated
                // End it is legal post-cut output — capacity-gated
                // even while the stream-7 FIN is still pending.
                .snapshot_streaming => {
                    if (!self.snapshot_end_validated) return true;
                    return payload_len <= pending_output_cap - self.pending_output.items.len;
                },
                else => return payload_len <= pending_output_cap - self.pending_output.items.len,
            },
            .SnapshotChunk => {
                // A chunk the session will reject terminally is
                // ALWAYS consumable — client-withheld stream-7 credit
                // can never delay fail-closed handling: outside
                // streaming, after a validated End, under PRESENT=0,
                // with an illegal length, or over the negotiated
                // limit.
                if (self.phase != .snapshot_streaming) return true;
                if (self.snapshot_end_validated or !self.snapshot_present) return true;
                if (payload_len == 0 or payload_len > snapshot_chunk_cap) return true;
                if (self.snapshot_total + payload_len > self.snapshot_limit) return true;
                return self.pending_snapshot.items.len == 0;
            },
            // Begin/End/Error/Resize/Switch and unknown tags carry no
            // relay storage on this side.
            else => return true,
        }
    }

    // -- daemon-side events ------------------------------------------------

    /// A complete daemon `.Output` frame's payload. Phase-ordered
    /// against the snapshot transaction: output before Begin (any
    /// pre-cut phase) predates the authoritative cut and is DISCARDED
    /// (counted); output interleaved between Begin and End is a
    /// terminal violation; output after the validated End relays as
    /// epoch-1 output even while the snapshot FIN is still pending.
    /// The bounded reader already rejected oversized declarations;
    /// Overflow is an invariant (the frame pump prechecks
    /// canConsumeDaemonFrame).
    pub fn offerDaemonOutput(self: *QuicSession, payload: []const u8, now: i64) !void {
        switch (self.phase) {
            .awaiting_hello, .awaiting_resize, .awaiting_snapshot_begin => {
                self.counters.discarded_pre_cut_output += payload.len;
                return;
            },
            .snapshot_streaming => {
                // Before the validated End this is a terminal
                // interleave; after it, the Output is legal post-cut
                // output even while the stream-7 FIN is still pending
                // (capacity was prechecked by canConsumeDaemonFrame).
                if (!self.snapshot_end_validated) {
                    return self.failSnapshot(now, "output interleaved with snapshot");
                }
            },
            else => {},
        }
        if (payload.len > pending_output_cap - self.pending_output.items.len) {
            return error.Overflow;
        }
        try self.pending_output.appendSlice(self.alloc, payload);
        self.counters.daemon_output_frames += 1;
    }

    /// Centralized snapshot-transaction failure: resets the unfinished
    /// snapshot stream (opened, FIN not yet sent) so the client never
    /// sees a half-delivered epoch, then runs the existing bounded
    /// terminal internal_error settlement. Every malformed sequence,
    /// limit, count, PRESENT, interleave, and SnapshotError failure
    /// routes through here.
    pub fn failSnapshot(self: *QuicSession, now: i64, reason: []const u8) !void {
        if (self.snapshot_opened and !self.snapshot_fin_sent) {
            self.transport.connection().resetStream(
                snapshot_stream_id,
                quic_wire.ErrCode.internal_error.code(),
            ) catch {};
        }
        return self.enterTerminal(now, .internal_error, reason, .error_frame, null);
    }

    /// Daemon SnapshotBegin: open stream 7, stage the epoch-1 header
    /// (PRESENT from the payload byte), and enter snapshot_streaming.
    pub fn onDaemonSnapshotBegin(self: *QuicSession, payload: []const u8, now: i64) !void {
        if (self.phase != .awaiting_snapshot_begin) {
            return self.failSnapshot(now, "unexpected SnapshotBegin");
        }
        if (payload.len != 1 or payload[0] > 1) {
            return self.failSnapshot(now, "bad SnapshotBegin payload");
        }
        const conn = self.transport.connection();
        const id = conn.openUniStream() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.failSnapshot(now, "cannot open snapshot stream"),
        };
        if (id != snapshot_stream_id) {
            return self.failSnapshot(now, "unexpected snapshot stream id");
        }
        self.snapshot_opened = true;
        self.snapshot_present = payload[0] == 1;
        var hdr: [quic_wire.snapshot_header_len]u8 = undefined;
        quic_wire.writeSnapshotHeader(&hdr, quic_wire.snapshot_epoch_v1, self.snapshot_present);
        self.pending_snapshot.clearRetainingCapacity();
        self.pending_snapshot.appendSlice(self.alloc, &hdr) catch return error.OutOfMemory;
        self.phase = .snapshot_streaming;
        try self.pumpSnapshot();
    }

    /// Daemon SnapshotChunk: one bounded unit at a time, only between
    /// Begin and End, only when PRESENT=1, and never after a validated
    /// End. The frame pump's canConsumeDaemonFrame keeps a LEGAL chunk
    /// buffered while the pending unit is occupied; a chunk seen here
    /// despite that is an invariant break and fails closed.
    pub fn onDaemonSnapshotChunk(self: *QuicSession, payload: []const u8, now: i64) !void {
        if (self.phase != .snapshot_streaming or self.snapshot_end_validated) {
            return self.failSnapshot(now, "SnapshotChunk outside streaming");
        }
        if (payload.len == 0 or payload.len > snapshot_chunk_cap) {
            return self.failSnapshot(now, "bad SnapshotChunk length");
        }
        if (!self.snapshot_present) {
            return self.failSnapshot(now, "chunk after empty snapshot");
        }
        if (self.pending_snapshot.items.len != 0) {
            return self.failSnapshot(now, "snapshot chunk while blocked");
        }
        const new_total = self.snapshot_total + payload.len;
        if (new_total > self.snapshot_limit) {
            return self.failSnapshot(now, "snapshot limit exceeded");
        }
        self.snapshot_total = new_total;
        self.counters.snapshot_chunks += 1;
        self.counters.snapshot_bytes += payload.len;
        self.pending_snapshot.appendSlice(self.alloc, payload) catch return error.OutOfMemory;
        try self.pumpSnapshot();
    }

    /// Daemon SnapshotEnd: the u64 BE count of Ghostty bytes only,
    /// exactly once. PRESENT=0 requires zero; PRESENT=1 requires at
    /// least one byte. The stream-7 FIN is deferred until the count
    /// validates AND every pending byte was accepted (pumpSnapshot
    /// owns that transition).
    pub fn onDaemonSnapshotEnd(self: *QuicSession, payload: []const u8, now: i64) !void {
        if (self.phase != .snapshot_streaming or self.snapshot_end_validated) {
            return self.failSnapshot(now, "unexpected SnapshotEnd");
        }
        if (payload.len != 8) {
            return self.failSnapshot(now, "bad SnapshotEnd length");
        }
        const count = std.mem.readInt(u64, payload[0..8], .big);
        if (count != self.snapshot_total) {
            return self.failSnapshot(now, "snapshot count mismatch");
        }
        if (self.snapshot_present and count == 0) {
            return self.failSnapshot(now, "empty snapshot with PRESENT");
        }
        if (!self.snapshot_present and count != 0) {
            return self.failSnapshot(now, "nonempty snapshot without PRESENT");
        }
        self.snapshot_end_validated = true;
        try self.pumpSnapshot();
    }

    /// Daemon SnapshotError: terminal internal_error through the
    /// centralized failure (an unfinished stream 7 is reset first).
    /// Unknown codes and malformed payloads fail identically.
    pub fn onDaemonSnapshotError(self: *QuicSession, payload: []const u8, now: i64) !void {
        const ew = ipc.parseSnapshotErrorPayload(payload) catch {
            return self.failSnapshot(now, "malformed SnapshotError");
        };
        if (!ipc.snapshotErrorKnown(ew.code)) {
            return self.failSnapshot(now, "unknown snapshot error code");
        }
        return self.failSnapshot(now, "daemon snapshot failed");
    }

    /// Daemon `.Resize`: answered LOCALLY with `.Resize` carrying the
    /// last client size — exactly the local attach client's behavior;
    /// a fresh `.Init` would re-trigger terminal replay. During an
    /// active snapshot transaction only Chunk/End/Error are legal.
    pub fn onDaemonResize(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        if (self.phase == .snapshot_streaming) {
            return self.failSnapshot(now, "resize during snapshot");
        }
        unix_out.append(.Resize, std.mem.asBytes(&self.last_size)) catch |e| switch (e) {
            error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
            error.OutOfMemory => return error.OutOfMemory,
        };
    }

    /// Daemon `.Switch` is Q5-deferred: terminal unimplemented. During
    /// an active snapshot transaction it is an interleave instead.
    pub fn onDaemonSwitch(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        if (self.phase == .snapshot_streaming) {
            return self.failSnapshot(now, "switch during snapshot");
        }
        return self.enterTerminal(now, .unimplemented, "switch is deferred to Q5", .error_frame, unix_out);
    }

    /// Any other daemon frame during an active snapshot transaction is
    /// an interleave; outside one it is counted and ignored (the local
    /// attach client's behavior) — the caller reports the count.
    pub fn onDaemonOtherFrame(self: *QuicSession, now: i64) !void {
        if (self.phase == .snapshot_streaming) {
            return self.failSnapshot(now, "unexpected daemon frame");
        }
    }

    /// Daemon EOF: stop daemon reads, drain pending output, FIN the
    /// output stream, send SESSION_END+FIN, settle, close with code 9.
    /// The daemon is gone: pending daemon-bound writes are dropped.
    pub fn onDaemonEof(self: *QuicSession, now: i64) !void {
        return self.enterTerminal(now, .session_ended, "daemon closed", .session_end, null);
    }

    /// An oversized daemon frame failed the bounded reader's cap before
    /// its payload accumulated: fail closed (a large legacy VT replay
    /// does not fit Q3; Q4's chunked snapshots are the durable fix).
    pub fn onDaemonOversizedFrame(self: *QuicSession, now: i64) !void {
        return self.enterTerminal(now, .internal_error, "oversized daemon frame", .error_frame, null);
    }

    /// serve calls this once the daemon-bound buffer has fully flushed;
    /// it advances an ending_unix session to stream settlement.
    pub fn onUnixFlushed(self: *QuicSession, now: i64) !void {
        if (self.phase != .ending_unix or self.closed) return;
        return self.continueEnding(now);
    }

    // -- per-turn pump -----------------------------------------------------

    pub fn processTurn(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        if (self.closed) return;
        if (self.phase == .ending_unix) {
            if (now >= self.end_deadline_ns) return self.finishClose();
            return;
        }
        if (self.phase == .ending_streams) return self.serviceEnding(now);

        try self.scanUnexpectedStreams(now, unix_out);
        if (self.closedOrEnding()) return;

        try self.trySendPendingControl();
        // The snapshot unit is serviced BEFORE output: a blocked output
        // stream can never starve snapshot or control progress.
        try self.pumpSnapshot();
        try self.pumpPendingOutput(false);
        if (self.send_stopped and !self.closedOrEnding()) {
            return self.enterTerminal(now, .session_ended, "peer stopped the stream", .session_end, null);
        }

        var byte_budget: usize = app_byte_budget_per_turn;
        var frame_budget: usize = control_frame_budget_per_turn;
        try self.pumpControl(now, unix_out, &byte_budget, &frame_budget);
        if (self.closedOrEnding()) return;
        if (self.inputUnlocked()) {
            try self.pumpInput(now, unix_out, &byte_budget);
        }
    }

    /// Input may flow once `.InitSnapshot` is already ahead of it in
    /// the ordered Unix write buffer — from the first installation
    /// phase onward.
    fn inputUnlocked(self: *const QuicSession) bool {
        return switch (self.phase) {
            .awaiting_snapshot_begin, .snapshot_streaming, .awaiting_snapshot_installed, .active => true,
            .awaiting_hello, .awaiting_resize, .ending_unix, .ending_streams => false,
        };
    }

    // -- unexpected streams / pre-HELLO enforcement ------------------------

    fn hasControlStream(self: *QuicSession) bool {
        const st = (self.transport.connection().streamState(control_stream_id) catch return false) orelse return false;
        return st.receive != .none;
    }

    fn hasBufferedData(self: *QuicSession, id: u64) bool {
        const st = (self.transport.connection().streamState(id) catch return false) orelse return false;
        const buffered = st.receive_buffered orelse 0;
        const read = st.receive_read_offset orelse 0;
        return buffered > read;
    }

    fn scanUnexpectedStreams(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        for (&scan_bidi_ids) |id| {
            const st = (self.transport.connection().streamState(id) catch null);
            if (st != null) {
                return self.enterTerminal(now, .stream_cardinality, "unexpected client stream", .error_frame, unix_out);
            }
        }
        for (&scan_uni_ids) |id| {
            const st = (self.transport.connection().streamState(id) catch null);
            if (st != null) {
                return self.enterTerminal(now, .stream_cardinality, "unexpected client stream", .error_frame, unix_out);
            }
        }
        // Pre-HELLO non-control data is a terminal ordering violation.
        // Post-HELLO (awaiting_resize) input may legitimately arrive
        // first: it stays PARKED (unconsumed, credit withheld).
        if (self.phase == .awaiting_hello and self.hasBufferedData(input_stream_id)) {
            return self.enterTerminal(now, .protocol_violation, "input before HELLO", .error_frame, unix_out);
        }
    }

    // -- control stream ----------------------------------------------------

    fn pumpControl(
        self: *QuicSession,
        now: i64,
        unix_out: *UnixWriteBuf,
        byte_budget: *usize,
        frame_budget: *usize,
    ) !void {
        // While one response is parked, parsing pauses (lossless
        // control-response backpressure).
        if (self.pending_control.items.len != 0) return;

        // Read ONLY while the stash is empty and the shared byte budget
        // allows, capped at the stash's hard bound: the stash can never
        // exceed one bounded read.
        if (self.control_stash.items.len == 0 and byte_budget.* > 0) {
            var rbuf: [control_stash_cap]u8 = undefined;
            const want = @min(rbuf.len, byte_budget.*);
            const n = self.transport.connection().recvOnStream(control_stream_id, rbuf[0..want]) catch |e| switch (e) {
                error.StreamClosed => return self.enterTerminal(now, .protocol_violation, "control stream reset", .error_frame, unix_out),
                error.ConnectionClosed => return self.enterTerminal(now, .session_ended, "connection closing", .session_end, null),
                else => return e,
            } orelse 0;
            if (n > 0) {
                byte_budget.* -|= n;
                try self.control_stash.appendSlice(self.alloc, rbuf[0..n]);
            }
        }
        if (self.control_stash.items.len == 0) {
            return self.checkControlTruncation(now, unix_out);
        }

        var rest: []const u8 = self.control_stash.items;
        // Bytes not consumed before an early return stay in the stash.
        var consumed_total: usize = 0;
        defer {
            const keep = self.control_stash.items.len - consumed_total;
            std.mem.copyForwards(u8, self.control_stash.items[0..keep], self.control_stash.items[consumed_total..]);
            self.control_stash.items.len = keep;
        }
        while (rest.len > 0) {
            if (!self.control_preface.done) {
                const r = self.control_preface.feed(rest);
                consumed_total += r.consumed;
                rest = rest[r.consumed..];
                switch (r.result) {
                    .done => |role| {
                        if (role != .control) {
                            return self.enterTerminal(now, quic_wire.prefaceErrCode(error.UnknownRole), "wrong role on control stream", .error_frame, unix_out);
                        }
                    },
                    .need => return,
                    .invalid => |e| {
                        return self.enterTerminal(now, quic_wire.prefaceErrCode(e), "bad control preface", .error_frame, unix_out);
                    },
                }
                continue;
            }
            const adv = try self.control.advance(rest);
            consumed_total += adv.consumed;
            rest = rest[adv.consumed..];
            switch (adv.result) {
                .need => return,
                .invalid => |e| {
                    const code = quic_wire.controlHeaderErrCode(e);
                    return self.enterTerminal(now, code, "bad control frame", .error_frame, unix_out);
                },
                .done => |h| {
                    try self.handleControlFrame(h, self.control.payload(), now, unix_out);
                    self.control.reset();
                    frame_budget.* -= 1;
                    // A response that remains parked STOPS parsing — a
                    // later frame can never be answered (or dropped)
                    // while one is pending. Bytes stay in the stash.
                    if (frame_budget.* == 0 or
                        self.pending_control.items.len != 0 or
                        self.closedOrEnding()) return;
                },
            }
        }
        return self.checkControlTruncation(now, unix_out);
    }

    /// Truncation: a FIN that lands mid-structure is a violation. A FIN
    /// between complete frames is clean.
    fn checkControlTruncation(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        const finished = self.transport.connection().recvStreamFinished(control_stream_id) catch false;
        if (finished and (self.control_preface.expecting() or self.control.expectingFrame())) {
            return self.enterTerminal(now, .protocol_violation, "truncated control stream", .error_frame, unix_out);
        }
    }

    fn handleControlFrame(
        self: *QuicSession,
        h: quic_wire.ControlHeader,
        payload: []const u8,
        now: i64,
        unix_out: *UnixWriteBuf,
    ) !void {
        const t = h.t;
        self.counters.control_frames += 1;
        switch (self.phase) {
            .awaiting_hello => switch (t) {
                .hello => return self.handleHello(payload, now, unix_out),
                else => return self.enterTerminal(now, .protocol_violation, "control frame before HELLO", .error_frame, unix_out),
            },
            .awaiting_resize => switch (t) {
                .resize => {
                    if (payload.len != 8) {
                        return self.enterTerminal(now, .protocol_violation, "bad RESIZE length", .error_frame, unix_out);
                    }
                    const rz = quic_wire.parseResizePayload(payload[0..8]);
                    self.last_size = .{ .rows = rz.rows, .cols = rz.cols, .xpixel = rz.xpixel, .ypixel = rz.ypixel };
                    // Q4: the first RESIZE requests the transactional
                    // binary snapshot, not the legacy `.Init` replay.
                    unix_out.append(.InitSnapshot, std.mem.asBytes(&self.last_size)) catch |e| switch (e) {
                        error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    self.init_sent = true;
                    self.phase = .awaiting_snapshot_begin;
                },
                else => return self.enterTerminal(now, .protocol_violation, "RESIZE must be the first frame", .error_frame, unix_out),
            },
            // During installation a RESIZE never reaches the daemon:
            // it coalesces to one latest value, forwarded only after
            // SNAPSHOT_INSTALLED activates the session.
            .awaiting_snapshot_begin, .snapshot_streaming, .awaiting_snapshot_installed => switch (t) {
                .resize => {
                    if (payload.len != 8) {
                        return self.enterTerminal(now, .protocol_violation, "bad RESIZE length", .error_frame, unix_out);
                    }
                    const rz = quic_wire.parseResizePayload(payload[0..8]);
                    self.last_size = .{ .rows = rz.rows, .cols = rz.cols, .xpixel = rz.xpixel, .ypixel = rz.ypixel };
                    self.pending_install_resize = self.last_size;
                },
                .snapshot_installed => {
                    if (payload.len != 0) {
                        return self.enterTerminal(now, .protocol_violation, "bad SNAPSHOT_INSTALLED length", .error_frame, unix_out);
                    }
                    // Accepted ONLY after the snapshot FIN was sent —
                    // this phase is unreachable before it.
                    if (self.phase != .awaiting_snapshot_installed) {
                        return self.enterTerminal(now, .protocol_violation, "premature SNAPSHOT_INSTALLED", .error_frame, unix_out);
                    }
                    self.phase = .active;
                    if (self.pending_install_resize) |rz| {
                        unix_out.append(.Resize, std.mem.asBytes(&rz)) catch |e| switch (e) {
                            error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                            error.OutOfMemory => return error.OutOfMemory,
                        };
                        self.pending_install_resize = null;
                    }
                },
                .detach, .snapshot_request => {
                    // Unavailable during installation (the frozen
                    // client contract); sending either is a violation.
                    return self.enterTerminal(
                        now,
                        .protocol_violation,
                        if (t == .detach) "detach during installation" else "snapshot request during installation",
                        .error_frame,
                        unix_out,
                    );
                },
                .hello, .hello_ack, .session_end, .err => {
                    return self.enterTerminal(now, .protocol_violation, "client may not send that frame", .error_frame, unix_out);
                },
            },
            .active => switch (t) {
                .resize => {
                    if (payload.len != 8) {
                        return self.enterTerminal(now, .protocol_violation, "bad RESIZE length", .error_frame, unix_out);
                    }
                    const rz = quic_wire.parseResizePayload(payload[0..8]);
                    self.last_size = .{ .rows = rz.rows, .cols = rz.cols, .xpixel = rz.xpixel, .ypixel = rz.ypixel };
                    unix_out.append(.Resize, std.mem.asBytes(&self.last_size)) catch |e| switch (e) {
                        error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                },
                .detach => {
                    if (payload.len != 0) {
                        return self.enterTerminal(now, .protocol_violation, "bad DETACH length", .error_frame, unix_out);
                    }
                    unix_out.append(.Detach, "") catch |e| switch (e) {
                        error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    return self.enterTerminal(now, .none, "detach", .none, unix_out);
                },
                .snapshot_request => {
                    if (payload.len != 0) {
                        return self.enterTerminal(now, .protocol_violation, "bad SNAPSHOT_REQUEST length", .error_frame, unix_out);
                    }
                    // NONTERMINAL: answered, session continues.
                    return self.queueError(.unimplemented, "replacement snapshots are Q5", false);
                },
                .snapshot_installed => {
                    if (payload.len != 0) {
                        return self.enterTerminal(now, .protocol_violation, "bad SNAPSHOT_INSTALLED length", .error_frame, unix_out);
                    }
                    return self.enterTerminal(now, .protocol_violation, "duplicate SNAPSHOT_INSTALLED", .error_frame, unix_out);
                },
                .hello, .hello_ack, .session_end, .err => {
                    return self.enterTerminal(now, .protocol_violation, "client may not send that frame", .error_frame, unix_out);
                },
            },
            else => {},
        }
    }

    fn handleHello(self: *QuicSession, payload: []const u8, now: i64, unix_out: *UnixWriteBuf) !void {
        const hello = quic_wire.Hello.decode(payload) catch |e| switch (e) {
            error.WrongLength => return self.enterTerminal(now, .protocol_violation, "bad HELLO length", .error_frame, unix_out),
            error.NonzeroReserved => return self.enterTerminal(now, .protocol_violation, "bad HELLO reserved", .error_frame, unix_out),
        };
        // Frozen validation order: version → capability → fingerprint →
        // mode. A rejection never initializes the daemon.
        if (hello.version_major != quic_wire.Hello.v1_version_major) {
            return self.enterTerminal(now, .version_mismatch, "version mismatch", .error_frame, unix_out);
        }
        if (hello.required_capabilities != quic_wire.capabilities_v1) {
            return self.enterTerminal(now, .capability_mismatch, "capability mismatch", .error_frame, unix_out);
        }
        if (!std.mem.eql(u8, &hello.snapshot_abi_id, &quic_wire.snapshot_abi_id)) {
            return self.enterTerminal(now, .fingerprint_mismatch, "snapshot abi mismatch", .error_frame, unix_out);
        }
        switch (hello.mode) {
            quic_wire.mode_attach => {},
            quic_wire.mode_command => {
                return self.enterTerminal(now, .unimplemented, "command mode is Q6", .error_frame, unix_out);
            },
            else => return self.enterTerminal(now, .protocol_violation, "unknown mode", .error_frame, unix_out),
        }

        // Accept: HELLO_ACK on stream 0, then open the output stream
        // and queue its header (epoch 1) behind it.
        var ack: [quic_wire.hello_payload_len]u8 = undefined;
        var server = quic_wire.Hello.serverV1(quic_wire.mode_attach);
        server.snapshot_limit = @min(hello.snapshot_limit, server.snapshot_limit);
        server.command_limit = @min(hello.command_limit, server.command_limit);
        // The negotiated snapshot limit is what the transaction
        // enforces — stored at the same moment it is acknowledged.
        self.snapshot_limit = server.snapshot_limit;
        server.encode(&ack);
        try self.queueControl(quic_wire.ControlType.hello_ack, &ack, false);

        const conn = self.transport.connection();
        const id = conn.openUniStream() catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return self.enterTerminal(now, .internal_error, "cannot open output stream", .error_frame, unix_out),
        };
        if (id != output_stream_id) {
            return self.enterTerminal(now, .internal_error, "unexpected output stream id", .error_frame, unix_out);
        }
        self.output_opened = true;
        var hdr: [quic_wire.output_header_len]u8 = undefined;
        quic_wire.writeOutputHeader(&hdr, 1);
        try self.pending_output.appendSlice(self.alloc, &hdr);
        try self.pumpPendingOutput(false);
        self.phase = .awaiting_resize;
    }

    /// Encodes one bounded response frame; the send is attempted at
    /// queue time and retried each turn while credit is withheld. The
    /// control stream's preface precedes the first frame and is
    /// re-emitted by a terminal replacement of a parked (never sent)
    /// nonterminal response — atomic sends make partial states
    /// impossible, so the preface can never be half-transmitted.
    /// A nonterminal queue while one is pending is an invariant
    /// violation (the parse stop forbids it) and errors loudly.
    fn queueControl(self: *QuicSession, t: quic_wire.ControlType, payload: []const u8, fin: bool) !void {
        if (self.pending_control.items.len != 0) {
            if (!fin) return error.ControlResponsePending;
            if (self.pending_control_fin) return error.ControlResponsePending;
            self.pending_control.clearRetainingCapacity();
        }
        if (self.control_preface_pending) {
            var pre: [quic_wire.preface_len]u8 = undefined;
            quic_wire.writePreface(&pre, .control);
            try self.pending_control.appendSlice(self.alloc, &pre);
        }
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        // FINAL rides on fatal ERROR frames alone (it travels with the
        // control FIN); every other frame — SESSION_END included —
        // carries flags zero.
        quic_wire.writeControlHeader(&hdr, t, payload.len, quic_wire.controlFlags(t, fin));
        try self.pending_control.appendSlice(self.alloc, &hdr);
        errdefer self.pending_control.clearRetainingCapacity();
        try self.pending_control.appendSlice(self.alloc, payload);
        self.pending_control_fin = fin;
        try self.trySendPendingControl();
    }

    fn queueError(self: *QuicSession, code: quic_wire.ErrCode, reason: []const u8, fin: bool) !void {
        var buf: [4 + quic_wire.error_reason_max]u8 = undefined;
        // Constant, bounded inputs: encoding cannot fail.
        const n = quic_wire.writeErrorPayload(&buf, code, reason) catch unreachable;
        return self.queueControl(.err, buf[0..n], fin);
    }

    /// Sends the WHOLE encoded buffer (≤ 276 B, preface included) in
    /// ONE all-or-nothing sendOnStream: quicz accepts it entirely or
    /// not at all, so a parked frame is never partially transmitted
    /// and a later frame can never truncate it. FlowControlBlocked
    /// parks it whole; parsing stays paused until it leaves.
    fn trySendPendingControl(self: *QuicSession) !void {
        if (self.pending_control.items.len == 0 or self.control_fin_sent) return;
        self.transport.connection().sendOnStream(control_stream_id, self.pending_control.items, self.pending_control_fin) catch |e| switch (e) {
            error.FlowControlBlocked => return,
            // The peer STOPPED_SENDING: stop relaying, close cleanly.
            error.StreamClosed => {
                self.send_stopped = true;
                return;
            },
            // A close is already in flight — the session is done.
            error.ConnectionClosed => {
                self.closed = true;
                return;
            },
            else => return e,
        };
        self.pending_control.clearRetainingCapacity();
        self.control_preface_pending = false;
        if (self.pending_control_fin) self.control_fin_sent = true;
    }

    // -- input stream ------------------------------------------------------

    fn pumpInput(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf, byte_budget: *usize) !void {
        if (self.input_done) return;
        const conn = self.transport.connection();

        if (!self.input_preface.done) {
            // Read EXACTLY the missing preface bytes (capped by the
            // leftover shared budget): surplus body bytes can never be
            // consumed into this read, so nothing can be lost.
            var pbuf: [quic_wire.preface_len]u8 = undefined;
            const want = @min(self.input_preface.remaining(), byte_budget.*);
            if (want == 0) return;
            const n = conn.recvOnStream(input_stream_id, pbuf[0..want]) catch |e| switch (e) {
                error.StreamClosed => {
                    self.input_done = true;
                    return;
                },
                error.ConnectionClosed => return,
                else => return e,
            } orelse return;
            if (n == 0) return;
            byte_budget.* -|= n;
            const r = self.input_preface.feed(pbuf[0..n]);
            switch (r.result) {
                .done => |role| {
                    if (role != .input) {
                        return self.enterTerminal(now, quic_wire.prefaceErrCode(error.UnknownRole), "wrong role on input stream", .error_frame, unix_out);
                    }
                },
                .need => return,
                .invalid => |e| {
                    return self.enterTerminal(now, quic_wire.prefaceErrCode(e), "bad input preface", .error_frame, unix_out);
                },
            }
            const finished = conn.recvStreamFinished(input_stream_id) catch false;
            if (finished and !self.input_preface.done) {
                return self.enterTerminal(now, .protocol_violation, "truncated input preface", .error_frame, unix_out);
            }
            if (!self.input_preface.done) return;
        }

        // Capacity BEFORE consuming: recvOnStream consumes and grants
        // credit, so consumed bytes can never be dropped afterward.
        // The unix_out capacity is RESERVED, so the append cannot
        // allocate; Full is unreachable through the precheck and fails
        // closed rather than dropping accepted bytes.
        while (byte_budget.* > 0) {
            const free = unix_write_cap - unix_out.list.items.len;
            if (free < input_chunk + @sizeOf(ipc.Header)) return;
            const want = @min(input_chunk, byte_budget.*);
            var buf: [input_chunk]u8 = undefined;
            const n = conn.recvOnStream(input_stream_id, buf[0..want]) catch |e| switch (e) {
                error.StreamClosed => {
                    self.input_done = true;
                    return;
                },
                error.ConnectionClosed => return,
                else => return e,
            } orelse return;
            if (n == 0) return;
            unix_out.append(.Input, buf[0..n]) catch |e| switch (e) {
                error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                error.OutOfMemory => return error.OutOfMemory,
            };
            self.counters.input_bytes += n;
            byte_budget.* -|= n;
        }
    }

    /// Immediate QUIC pump of the two relay units (snapshot first, so
    /// a blocked output stream can never starve snapshot progress).
    /// Safe to call from the frame pump right after each accepted
    /// unit — including the post-session-turn pump — because it is NOT
    /// a session turn: no control/input processing, no budget resets.
    pub fn pumpRelayUnits(self: *QuicSession) !void {
        try self.pumpSnapshot();
        try self.pumpPendingOutput(false);
    }

    // -- snapshot stream (7) ------------------------------------------------

    /// Moves the ONE pending snapshot unit (header + at most one
    /// chunk) into stream 7 chunked to AVAILABLE credit
    /// (sendOnStream is all-or-nothing under flow control). The FIN
    /// goes out only after the validated End count AND every pending
    /// byte were accepted; only then does the phase advance to
    /// awaiting_snapshot_installed.
    fn pumpSnapshot(self: *QuicSession) !void {
        if (!self.snapshot_opened or self.snapshot_fin_sent) return;
        const conn = self.transport.connection();
        while (self.pending_snapshot.items.len > 0) {
            const cap = self.sendCapacityHint(snapshot_stream_id);
            const n: usize = switch (cap) {
                .unknown => self.pending_snapshot.items.len,
                .known_zero => return,
                .known => |c| @intCast(@min(self.pending_snapshot.items.len, c)),
            };
            conn.sendOnStream(snapshot_stream_id, self.pending_snapshot.items[0..n], false) catch |e| switch (e) {
                error.FlowControlBlocked => return,
                // The peer STOP_SENDING the snapshot stream: stop
                // relaying and end the session cleanly.
                error.StreamClosed => {
                    self.send_stopped = true;
                    return;
                },
                error.ConnectionClosed => {
                    self.closed = true;
                    return;
                },
                else => return e,
            };
            const remaining = self.pending_snapshot.items.len - n;
            std.mem.copyForwards(u8, self.pending_snapshot.items[0..remaining], self.pending_snapshot.items[n..]);
            self.pending_snapshot.items.len = remaining;
        }
        if (!self.snapshot_end_validated) return;
        conn.sendOnStream(snapshot_stream_id, &.{}, true) catch |e| switch (e) {
            error.FlowControlBlocked => return,
            // No receiver is left to reach: treat the snapshot side as
            // done and end cleanly.
            error.StreamClosed => {
                self.snapshot_fin_sent = true;
                self.send_stopped = true;
                return;
            },
            error.ConnectionClosed => {
                self.closed = true;
                return;
            },
            else => return e,
        };
        self.snapshot_fin_sent = true;
        if (self.phase == .snapshot_streaming) self.phase = .awaiting_snapshot_installed;
    }

    // -- output stream -----------------------------------------------------

    const SendCapacity = union(enum) {
        /// No send-side state yet (quicz creates it at the first send):
        /// attempt the send; FlowControlBlocked is caught by the caller.
        unknown,
        known_zero,
        known: u64,
    };

    fn sendCapacityHint(self: *QuicSession, id: u64) SendCapacity {
        const st = (self.transport.connection().streamState(id) catch return .known_zero) orelse return .known_zero;
        const max = st.send_max_data orelse return .unknown;
        const off = st.send_offset orelse return .unknown;
        const cap = max -| off;
        if (cap == 0) return .known_zero;
        return .{ .known = cap };
    }

    /// Moves pending bytes into the output stream chunked to AVAILABLE
    /// credit (sendOnStream is all-or-nothing under flow control);
    /// `fin_wanted` FINs only after every pending byte is accepted.
    fn pumpPendingOutput(self: *QuicSession, fin_wanted: bool) !void {
        const conn = self.transport.connection();
        while (self.pending_output.items.len > 0) {
            const cap = self.sendCapacityHint(output_stream_id);
            const n: usize = switch (cap) {
                .unknown => self.pending_output.items.len,
                .known_zero => return,
                .known => |c| @intCast(@min(self.pending_output.items.len, c)),
            };
            conn.sendOnStream(output_stream_id, self.pending_output.items[0..n], false) catch |e| switch (e) {
                error.FlowControlBlocked => return,
                // The peer STOP_SENDING the output stream: stop
                // relaying and end the session cleanly.
                error.StreamClosed => {
                    self.send_stopped = true;
                    return;
                },
                // A close is already in flight — the session is done.
                error.ConnectionClosed => {
                    self.closed = true;
                    return;
                },
                else => return e,
            };
            self.counters.output_bytes += n;
            const remaining = self.pending_output.items.len - n;
            std.mem.copyForwards(u8, self.pending_output.items[0..remaining], self.pending_output.items[n..]);
            self.pending_output.items.len = remaining;
        }
        if (fin_wanted and self.output_opened and !self.output_fin_sent) {
            conn.sendOnStream(output_stream_id, &.{}, true) catch |e| switch (e) {
                error.FlowControlBlocked => return,
                // The peer STOPPED_SENDING this stream: the FIN has no
                // receiver to reach — treat the output side as done.
                error.StreamClosed => {
                    self.output_fin_sent = true;
                    self.send_stopped = true;
                    return;
                },
                // A close is already in flight — the session is done.
                error.ConnectionClosed => {
                    self.closed = true;
                    return;
                },
                else => return e,
            };
            self.output_fin_sent = true;
        }
    }

    // -- terminal state ----------------------------------------------------

    /// Terminal entry with both fatal arms: when the control stream
    /// exists, the bounded ERROR/SESSION_END+FIN settle sequence; when
    /// it does not (no send side exists), an immediate application
    /// close with the correct code and bounded reason.
    fn enterTerminal(
        self: *QuicSession,
        now: i64,
        code: quic_wire.ErrCode,
        reason: []const u8,
        final_frame: FinalFrame,
        unix_out: ?*UnixWriteBuf,
    ) !void {
        if (self.closedOrEnding()) return;
        if (code != .none and code != .session_ended) self.counters.protocol_errors += 1;
        const rlen = @min(reason.len, self.end_reason.len);
        @memcpy(self.end_reason[0..rlen], reason[0..rlen]);
        self.end_reason_len = rlen;
        self.end_code = code;
        self.final_frame = final_frame;
        self.end_deadline_ns = now + settle_deadline_ns;

        if (!self.hasControlStream()) {
            // Arm 2: no control send side — close immediately.
            return self.finishClose();
        }
        if (unix_out != null and !unix_out.?.empty()) {
            self.phase = .ending_unix; // serve flushes, then onUnixFlushed
            return;
        }
        return self.continueEnding(now);
    }

    fn continueEnding(self: *QuicSession, now: i64) !void {
        self.phase = .ending_streams;
        // Drain everything, then FIN the output stream.
        try self.pumpPendingOutput(true);
        // Final control frame with FIN (the bare-FIN detach case is
        // completed by serviceEnding once pending bytes are out).
        switch (self.final_frame) {
            .none => {},
            .session_end => try self.queueControl(.session_end, "", true),
            .error_frame => try self.queueError(self.end_code, self.end_reason[0..self.end_reason_len], true),
        }
        return self.serviceEnding(now);
    }

    fn serviceEnding(self: *QuicSession, now: i64) !void {
        try self.pumpPendingOutput(true);
        try self.trySendPendingControl();
        // A clean detach FINs only AFTER every pending control byte has
        // left — a FIN at the current offset would strand them.
        if (self.final_frame == .none and self.pending_control.items.len == 0 and !self.control_fin_sent) {
            self.transport.connection().sendOnStream(control_stream_id, &.{}, true) catch |e| switch (e) {
                error.FlowControlBlocked => {},
                else => return e,
            };
            self.control_fin_sent = true;
        }
        if (self.settled() or now >= self.end_deadline_ns) {
            return self.finishClose();
        }
    }

    /// Settlement proof: both FINed streams fully acknowledged.
    fn settled(self: *QuicSession) bool {
        if (!self.control_fin_sent) return false;
        if (!self.streamAcked(control_stream_id)) return false;
        if (self.output_opened and !self.output_fin_sent) return false;
        if (self.output_opened and !self.streamAcked(output_stream_id)) return false;
        return true;
    }

    fn streamAcked(self: *QuicSession, id: u64) bool {
        const st = (self.transport.connection().streamState(id) catch return false) orelse return false;
        return st.send == .data_acked;
    }

    fn finishClose(self: *QuicSession) !void {
        if (self.closed) return;
        self.closed = true;
        try self.transport.shutdown(self.end_code.code(), self.end_reason[0..self.end_reason_len]);
    }
};

// ---------------------------------------------------------------------------
// Tests (pair-free units)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "UnixWriteBuf append bound and consume" {
    var b = try UnixWriteBuf.init(testing.allocator);
    defer b.deinit();
    try b.append(.Input, "hello");
    try testing.expectEqual(@as(usize, @sizeOf(ipc.Header) + 5), b.bytes().len);
    try testing.expect(!b.empty());
    b.consume(b.bytes().len);
    try testing.expect(b.empty());

    // The bound refuses a whole message that would not fit.
    var big: [unix_write_cap]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectError(error.Full, b.append(.Output, &big));
    try testing.expect(b.empty()); // nothing partially appended
}
