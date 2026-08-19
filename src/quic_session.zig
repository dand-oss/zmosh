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

// ---------------------------------------------------------------------------
// Bounded daemon-bound write buffer (owned by serve.Gateway, the fd
// owner; flushed on the dynamic POLL.OUT arm)
// ---------------------------------------------------------------------------

pub const UnixWriteBuf = struct {
    alloc: std.mem.Allocator,
    list: std.ArrayList(u8) = .empty,

    pub fn init(alloc: std.mem.Allocator) UnixWriteBuf {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *UnixWriteBuf) void {
        self.list.deinit(self.alloc);
    }

    /// Appends one framed IPC message; error.Full means the bounded
    /// buffer cannot accept it whole — the caller applies backpressure
    /// (never a silent drop).
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
    /// to daemon `.Init`) is pending. Input on stream 2 is PARKED.
    awaiting_resize,
    /// `.Init` queued; relaying.
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

    output_opened: bool = false,
    output_fin_sent: bool = false,
    control_fin_sent: bool = false,
    control_preface_sent: bool = false,

    /// Daemon→client bytes awaiting stream credit (the output header
    /// sits at its head).
    pending_output: std.ArrayList(u8) = .empty,
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
    closed: bool = false,

    counters: Counters = .{},

    pub fn init(alloc: std.mem.Allocator, transport: *quic_transport.Transport) QuicSession {
        return .{
            .alloc = alloc,
            .transport = transport,
            .control = quic_wire.ControlParser.init(alloc),
        };
    }

    pub fn deinit(self: *QuicSession) void {
        self.pending_output.deinit(self.alloc);
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

    /// Whether serve may poll the daemon fd for POLL.IN this turn:
    /// never while terminal, and only while the pending output buffer
    /// is fully drained (one legal frame always fits the empty buffer).
    pub fn wantsDaemonRead(self: *const QuicSession) bool {
        if (self.closedOrEnding()) return false;
        return self.pending_output.items.len == 0;
    }

    // -- daemon-side events ------------------------------------------------

    /// A complete daemon `.Output` frame's payload. The bounded reader
    /// already rejected oversized declarations; Overflow here is an
    /// invariant (serve gates reads on wantsDaemonRead).
    pub fn offerDaemonOutput(self: *QuicSession, payload: []const u8) error{ Overflow, OutOfMemory }!void {
        if (payload.len > pending_output_cap - self.pending_output.items.len) {
            return error.Overflow;
        }
        try self.pending_output.appendSlice(self.alloc, payload);
        self.counters.daemon_output_frames += 1;
    }

    /// Daemon `.Resize`: answered LOCALLY with `.Resize` carrying the
    /// last client size — exactly the local attach client's behavior;
    /// a fresh `.Init` would re-trigger terminal replay.
    pub fn onDaemonResize(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        unix_out.append(.Resize, std.mem.asBytes(&self.last_size)) catch |e| switch (e) {
            error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
            error.OutOfMemory => return error.OutOfMemory,
        };
    }

    /// Daemon `.Switch` is Q5-deferred: terminal unimplemented.
    pub fn onDaemonSwitch(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf) !void {
        return self.enterTerminal(now, .unimplemented, "switch is deferred to Q5", .error_frame, unix_out);
    }

    /// Daemon EOF: stop daemon reads, drain pending output, FIN the
    /// output stream, send SESSION_END+FIN, settle, close with code 9.
    /// The daemon is gone: pending daemon-bound writes are dropped.
    pub fn onDaemonEof(self: *QuicSession, now: i64) !void {
        return self.enterTerminal(now, .session_ended, "daemon closed", .session_end, null);
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
        try self.pumpPendingOutput(false);

        var byte_budget: usize = app_byte_budget_per_turn;
        var frame_budget: usize = control_frame_budget_per_turn;
        try self.pumpControl(now, unix_out, &byte_budget, &frame_budget);
        if (self.closedOrEnding()) return;
        if (self.phase == .active) {
            try self.pumpInput(now, unix_out, &byte_budget);
        }
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

        var rbuf: [input_chunk]u8 = undefined;
        const n = self.transport.connection().recvOnStream(control_stream_id, &rbuf) catch |e| switch (e) {
            error.StreamClosed => return self.enterTerminal(now, .protocol_violation, "control stream reset", .error_frame, unix_out),
            error.ConnectionClosed => return self.enterTerminal(now, .session_ended, "connection closing", .session_end, null),
            else => return e,
        } orelse 0;

        if (n > 0) {
            byte_budget.* -|= n;
            try self.control_stash.appendSlice(self.alloc, rbuf[0..n]);
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
                .done => |t| {
                    try self.handleControlFrame(t, self.control.payload(), now, unix_out);
                    self.control.reset();
                    frame_budget.* -= 1;
                    if (frame_budget.* == 0 or self.closedOrEnding()) return;
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
        t: quic_wire.ControlType,
        payload: []const u8,
        now: i64,
        unix_out: *UnixWriteBuf,
    ) !void {
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
                    unix_out.append(.Init, std.mem.asBytes(&self.last_size)) catch |e| switch (e) {
                        error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    self.init_sent = true;
                    self.phase = .active;
                },
                else => return self.enterTerminal(now, .protocol_violation, "RESIZE must be the first frame", .error_frame, unix_out),
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
                    unix_out.append(.Detach, "") catch |e| switch (e) {
                        error.Full => return self.enterTerminal(now, .internal_error, "unix write buffer full", .error_frame, unix_out),
                        error.OutOfMemory => return error.OutOfMemory,
                    };
                    return self.enterTerminal(now, .none, "detach", .none, unix_out);
                },
                .snapshot_request => {
                    // NONTERMINAL: answered, session continues.
                    return self.queueError(.unimplemented, "snapshot is Q4", false);
                },
                .snapshot_installed => return self.enterTerminal(now, .protocol_violation, "SNAPSHOT_INSTALLED before Q4", .error_frame, unix_out),
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
    /// queue time and retried each turn while credit is withheld. A
    /// terminal frame replaces a parked nonterminal response. The
    /// control stream's own preface precedes the first frame.
    fn queueControl(self: *QuicSession, t: quic_wire.ControlType, payload: []const u8, fin: bool) !void {
        if (self.pending_control.items.len != 0) {
            if (!fin or self.pending_control_fin) return;
            self.pending_control.clearRetainingCapacity();
        }
        if (!self.control_preface_sent) {
            var pre: [quic_wire.preface_len]u8 = undefined;
            quic_wire.writePreface(&pre, .control);
            try self.pending_control.appendSlice(self.alloc, &pre);
            self.control_preface_sent = true;
        }
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, t, payload.len);
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

    fn trySendPendingControl(self: *QuicSession) !void {
        if (self.pending_control.items.len == 0 or self.control_fin_sent) return;
        // The send-side stream state is created lazily by quicz at the
        // first sendOnStream — before that there is no capacity hint,
        // and the whole buffer is attempted (it is small).
        const cap = self.sendCapacityHint(control_stream_id);
        const n: usize = switch (cap) {
            .unknown => self.pending_control.items.len,
            .known_zero => return, // blocked; control parsing stays paused
            .known => |c| @intCast(@min(self.pending_control.items.len, c)),
        };
        const fin = self.pending_control_fin and n == self.pending_control.items.len;
        self.transport.connection().sendOnStream(control_stream_id, self.pending_control.items[0..n], fin) catch |e| switch (e) {
            error.FlowControlBlocked => return,
            else => return e,
        };
        const remaining = self.pending_control.items.len - n;
        std.mem.copyForwards(u8, self.pending_control.items[0..remaining], self.pending_control.items[n..]);
        self.pending_control.items.len = remaining;
        if (remaining == 0 and fin) self.control_fin_sent = true;
    }

    // -- input stream ------------------------------------------------------

    fn pumpInput(self: *QuicSession, now: i64, unix_out: *UnixWriteBuf, byte_budget: *usize) !void {
        if (self.input_done) return;
        const conn = self.transport.connection();

        if (!self.input_preface.done) {
            var pbuf: [quic_wire.preface_len]u8 = undefined;
            const n = conn.recvOnStream(input_stream_id, &pbuf) catch |e| switch (e) {
                error.StreamClosed => {
                    self.input_done = true;
                    return;
                },
                error.ConnectionClosed => return,
                else => return e,
            } orelse return;
            if (n == 0) return;
            var rest: []const u8 = pbuf[0..n];
            while (rest.len > 0) {
                const r = self.input_preface.feed(rest);
                rest = rest[r.consumed..];
                switch (r.result) {
                    .done => |role| {
                        if (role != .input) {
                            return self.enterTerminal(now, quic_wire.prefaceErrCode(error.UnknownRole), "wrong role on input stream", .error_frame, unix_out);
                        }
                    },
                    .need => break,
                    .invalid => |e| {
                        return self.enterTerminal(now, quic_wire.prefaceErrCode(e), "bad input preface", .error_frame, unix_out);
                    },
                }
            }
            const finished = conn.recvStreamFinished(input_stream_id) catch false;
            if (finished and !self.input_preface.done) {
                return self.enterTerminal(now, .protocol_violation, "truncated input preface", .error_frame, unix_out);
            }
            if (!self.input_preface.done) return;
        }

        // Capacity BEFORE consuming: recvOnStream consumes and grants
        // credit, so consumed bytes can never be dropped afterward.
        while (byte_budget.* > 0) {
            const free = unix_write_cap - unix_out.list.items.len;
            if (free < input_chunk + @sizeOf(ipc.Header)) return;
            var buf: [input_chunk]u8 = undefined;
            const n = conn.recvOnStream(input_stream_id, &buf) catch |e| switch (e) {
                error.StreamClosed => {
                    self.input_done = true;
                    return;
                },
                error.ConnectionClosed => return,
                else => return e,
            } orelse return;
            if (n == 0) return;
            unix_out.append(.Input, buf[0..n]) catch return; // capacity checked above
            self.counters.input_bytes += n;
            byte_budget.* -|= n;
        }
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
    var b = UnixWriteBuf.init(testing.allocator);
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
