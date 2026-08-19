//! Client-side ZMQ1 protocol session. ClientSession is the state
//! machine over a borrowed client Transport (gateway tests drive it
//! directly on the Loop fixture); the socket-owning wrapper for the
//! Q5 attach client composes it. Ordering contract: ONLY the control
//! stream (preface + HELLO) is sent first; after HELLO_ACK validates,
//! RESIZE is the first control frame, then the input stream flows.
//! Symmetric parking: output stream bytes may arrive before the
//! HELLO_ACK packet — they are neither exposed nor rejected until the
//! control stream authorizes the session.

const std = @import("std");
const quic_wire = @import("quic_wire.zig");
const quic_transport = @import("quic_transport.zig");

pub const control_stream_id: u64 = 0;
pub const input_stream_id: u64 = 2;
/// The server's first unidirectional stream is the output epoch stream.
pub const output_stream_id: u64 = 3;

pub const ControlEvent = union(enum) {
    hello_ack: quic_wire.Hello,
    session_end,
    err: struct { code: u32, reason: []const u8 },
};

pub const ClientPhase = enum {
    /// HELLO sent; awaiting HELLO_ACK. Output bytes stay parked
    /// (unconsumed, credit withheld).
    awaiting_ack,
    /// HELLO_ACK validated; RESIZE + input may flow.
    active,
    /// Terminal observed (SESSION_END, ERROR, or stream failure).
    ended,
};

pub const ClientSession = struct {
    alloc: std.mem.Allocator,
    transport: *quic_transport.Transport,
    phase: ClientPhase = .awaiting_ack,

    control_preface: quic_wire.PrefaceParser = .{},
    control: quic_wire.ControlParser,
    err_reason: std.ArrayList(u8) = .empty,
    /// Control bytes read but not yet parsed (an event is returned per
    /// call; the remainder is never dropped).
    control_stash: std.ArrayList(u8) = .empty,

    input_preface: quic_wire.PrefaceParser = .{},
    input_opened: bool = false,
    resize_sent: bool = false,

    output_preface: quic_wire.OutputHeaderParser = .{},
    output_epoch: u64 = 0,
    output_authorized: bool = false,

    pub fn init(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        // Open the control stream and send preface + HELLO — nothing
        // else on any stream before this.
        const id = try transport.connection().openStream();
        if (id != control_stream_id) return error.UnexpectedControlStreamId;
        var pre: [quic_wire.preface_len]u8 = undefined;
        quic_wire.writePreface(&pre, .control);
        try transport.connection().sendOnStream(control_stream_id, &pre, false);
        var hello: [quic_wire.hello_payload_len]u8 = undefined;
        quic_wire.Hello.serverV1(quic_wire.mode_attach).encode(&hello);
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .hello, hello.len);
        try transport.connection().sendOnStream(control_stream_id, &hdr, false);
        try transport.connection().sendOnStream(control_stream_id, &hello, false);
        return .{
            .alloc = alloc,
            .transport = transport,
            .control = quic_wire.ControlParser.init(alloc),
        };
    }

    /// Constructs WITHOUT opening or sending anything: for harnesses
    /// that craft the client's first frames themselves.
    pub fn initSilent(alloc: std.mem.Allocator, transport: *quic_transport.Transport) ClientSession {
        return .{
            .alloc = alloc,
            .transport = transport,
            .control = quic_wire.ControlParser.init(alloc),
        };
    }

    pub fn deinit(self: *ClientSession) void {
        self.control.deinit();
        self.err_reason.deinit(self.alloc);
        self.control_stash.deinit(self.alloc);
    }

    pub fn ended(self: *const ClientSession) bool {
        return self.phase == .ended;
    }

    // -- control stream (client receive side) ------------------------------

    /// Pumps the control stream; returns at most one event per call so
    /// callers observe HELLO_ACK before any output is exposed. Bytes
    /// beyond the returned event are stashed, never dropped.
    pub fn pollControl(self: *ClientSession) !?ControlEvent {
        if (self.phase == .ended and self.control_stash.items.len == 0) return null;
        var rbuf: [4096]u8 = undefined;
        const n = self.transport.connection().recvOnStream(control_stream_id, &rbuf) catch |e| switch (e) {
            error.StreamClosed => {
                self.phase = .ended;
                return null;
            },
            error.ConnectionClosed => {
                self.phase = .ended;
                return null;
            },
            else => return e,
        } orelse 0;
        if (n > 0) {
            try self.control_stash.appendSlice(self.alloc, rbuf[0..n]);
        }
        if (self.control_stash.items.len == 0) return null;

        var rest: []const u8 = self.control_stash.items;
        // Bytes not consumed before returning stay in the stash.
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
                            self.phase = .ended;
                            return null;
                        }
                    },
                    .need => return null,
                    .invalid => {
                        self.phase = .ended;
                        return null;
                    },
                }
                continue;
            }
            const adv = try self.control.advance(rest);
            consumed_total += adv.consumed;
            rest = rest[adv.consumed..];
            switch (adv.result) {
                .need => return null,
                .invalid => {
                    self.phase = .ended;
                    return null;
                },
                .done => |t| {
                    const ev = try self.handleFrame(t, self.control.payload());
                    self.control.reset();
                    if (ev) |e| return e;
                },
            }
        }
        return null;
    }

    fn handleFrame(self: *ClientSession, t: quic_wire.ControlType, payload: []const u8) !?ControlEvent {
        switch (t) {
            .hello_ack => {
                const ack = quic_wire.Hello.decode(payload) catch {
                    self.phase = .ended;
                    return null;
                };
                if (self.phase == .awaiting_ack) {
                    self.phase = .active;
                    // Output parking ends: the stream is now authorized.
                    self.output_authorized = true;
                }
                return .{ .hello_ack = ack };
            },
            .session_end => {
                self.phase = .ended;
                return .session_end;
            },
            .err => {
                const parsed = quic_wire.parseErrorPayload(payload) catch {
                    self.phase = .ended;
                    return .{ .err = .{ .code = quic_wire.ErrCode.protocol_violation.code(), .reason = "" } };
                };
                self.err_reason.clearRetainingCapacity();
                self.err_reason.appendSlice(self.alloc, parsed.reason) catch {};
                // Terminal ERRORs arrive with a control FIN; a
                // nonterminal response (e.g. unimplemented snapshot)
                // carries none and the session continues.
                const fin = self.transport.connection().recvStreamFinished(control_stream_id) catch true;
                if (fin) self.phase = .ended;
                return .{ .err = .{ .code = parsed.code, .reason = self.err_reason.items } };
            },
            // The server never sends these in v1.
            else => {
                self.phase = .ended;
                return null;
            },
        }
    }

    // -- client sends -------------------------------------------------------

    /// RESIZE — must be the FIRST control frame after HELLO_ACK.
    pub fn sendResize(self: *ClientSession, rows: u16, cols: u16, xpixel: u16, ypixel: u16) !void {
        std.debug.assert(self.phase == .active);
        var payload: [8]u8 = undefined;
        quic_wire.writeResizePayload(&payload, rows, cols, xpixel, ypixel);
        try self.sendControl(.resize, &payload);
        self.resize_sent = true;
    }

    pub fn sendDetach(self: *ClientSession) !void {
        try self.sendControl(.detach, "");
    }

    pub fn sendSnapshotRequest(self: *ClientSession) !void {
        try self.sendControl(.snapshot_request, "");
    }

    fn sendControl(self: *ClientSession, t: quic_wire.ControlType, payload: []const u8) !void {
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, t, payload.len);
        try self.transport.connection().sendOnStream(control_stream_id, &hdr, false);
        if (payload.len > 0) {
            try self.transport.connection().sendOnStream(control_stream_id, payload, false);
        }
    }

    /// Opens the input stream (preface first) and writes raw bytes.
    pub fn sendInput(self: *ClientSession, bytes: []const u8) !void {
        const conn = self.transport.connection();
        if (!self.input_opened) {
            const id = try conn.openUniStream();
            if (id != input_stream_id) return error.UnexpectedInputStreamId;
            var pre: [quic_wire.preface_len]u8 = undefined;
            quic_wire.writePreface(&pre, .input);
            try conn.sendOnStream(input_stream_id, &pre, false);
            self.input_opened = true;
        }
        if (bytes.len > 0) {
            try conn.sendOnStream(input_stream_id, bytes, false);
        }
    }

    // -- output stream (server → client), parked until authorized ---------

    /// Reads output bytes into `buf` ONLY once HELLO_ACK validated the
    /// session; before that, bytes stay parked in QUIC (unconsumed,
    /// credit withheld). The first 16 bytes are the output header
    /// (preface + epoch); `epochOut` reports it once.
    pub fn pollOutput(self: *ClientSession, buf: []u8, epoch_out: ?*u64) !?usize {
        // After SESSION_END the buffered pre-end output stays readable;
        // only stream/connection closure ends reads.
        if (!self.output_authorized) return null;
        const conn = self.transport.connection();
        if (!self.output_preface.done) {
            var hbuf: [quic_wire.output_header_len]u8 = undefined;
            const n = conn.recvOnStream(output_stream_id, &hbuf) catch |e| switch (e) {
                error.StreamClosed => {
                    self.phase = .ended;
                    return null;
                },
                error.ConnectionClosed => {
                    self.phase = .ended;
                    return null;
                },
                else => return e,
            } orelse return null;
            if (n == 0) return null;
            var rest: []const u8 = hbuf[0..n];
            while (rest.len > 0) {
                const r = self.output_preface.feed(rest);
                rest = rest[r.consumed..];
                switch (r.result) {
                    .done => |epoch| {
                        self.output_epoch = epoch;
                        if (epoch_out) |o| o.* = epoch;
                    },
                    .need => return null,
                    .invalid => {
                        self.phase = .ended;
                        return null;
                    },
                }
            }
            if (rest.len == 0 and !self.output_preface.done) return null;
            if (rest.len == 0) return null;
            // Bytes beyond the header in the same read.
            const take = @min(rest.len, buf.len);
            @memcpy(buf[0..take], rest[0..take]);
            if (take < rest.len) return error.OutputReadBufferTooSmall;
            return take;
        }
        const n = conn.recvOnStream(output_stream_id, buf) catch |e| switch (e) {
            error.StreamClosed => {
                self.phase = .ended;
                return null;
            },
            error.ConnectionClosed => {
                self.phase = .ended;
                return null;
            },
            else => return e,
        } orelse return null;
        // Zero means only flow-control bookkeeping was emitted: no
        // body bytes are available.
        if (n == 0) return null;
        return n;
    }
};

// ---------------------------------------------------------------------------
// Tests: parser-level client behavior against the wire module itself
// (gateway-pair integration lives in serve.zig's loop tests).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "client event union carries hello_ack, session_end, and error shapes" {
    // Compile-shape test: the union fields the Q5 attach client will
    // switch on all exist with the right payload types.
    const ev: ControlEvent = .{ .hello_ack = quic_wire.Hello.serverV1(quic_wire.mode_attach) };
    switch (ev) {
        .hello_ack => |h| try testing.expectEqual(quic_wire.mode_attach, h.mode),
        else => return error.TestUnexpectedResult,
    }
    const ev2: ControlEvent = .session_end;
    try testing.expect(ev2 == .session_end);
    const ev3: ControlEvent = .{ .err = .{ .code = 8, .reason = "snapshot is Q4" } };
    switch (ev3) {
        .err => |e| {
            try testing.expectEqual(@as(u32, 8), e.code);
            try testing.expectEqualStrings("snapshot is Q4", e.reason);
        },
        else => return error.TestUnexpectedResult,
    }
}
