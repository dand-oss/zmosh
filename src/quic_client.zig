//! Client-side ZMQ1 protocol session. ClientSession is the state
//! machine over a borrowed client Transport (gateway tests drive it
//! directly on the Loop fixture); the socket-owning `Client` driver
//! (below) composes it for the Q5 attach client and Q6 command
//! client.
//!
//! Ordering contract: ONLY the control stream (preface + HELLO) is
//! sent first; after HELLO_ACK validates, RESIZE is the first control
//! frame; input flows after it. Every malformed receive condition is
//! converted by ONE helper (`failControl`) into a queued
//! `.err(protocol_violation)` event plus an application close — the
//! event lives in the one-event slot and survives a following
//! CONNECTION_CLOSE. Every control write is ONE all-or-nothing send
//! of an encoded copy; a second write while one is parked is
//! `error.ControlWritePending`.

const std = @import("std");
const quic_wire = @import("quic_wire.zig");
const quic_transport = @import("quic_transport.zig");

pub const control_stream_id: u64 = 0;
pub const input_stream_id: u64 = 2;
/// The server's first unidirectional stream is the output epoch stream.
pub const output_stream_id: u64 = 3;

/// The largest client control emission: preface 8 + header 8 + the
/// 48-byte HELLO payload.
pub const client_max_frame = quic_wire.preface_len +
    quic_wire.control_header_len + quic_wire.hello_payload_len;

pub const ControlEvent = union(enum) {
    hello_ack: quic_wire.Hello,
    session_end,
    err: struct { code: u32, reason: []const u8 },
};

pub const ClientPhase = enum {
    /// HELLO sent (or parked); awaiting HELLO_ACK. Output bytes stay
    /// parked (unconsumed, credit withheld).
    awaiting_ack,
    /// HELLO_ACK validated; the first RESIZE must still be accepted.
    /// Input API calls are rejected here.
    awaiting_first_resize,
    /// The first RESIZE was accepted in full; input may flow.
    active,
    /// Terminal: local failure, server terminal frame, or closure.
    ended,
};

pub const InputState = enum { closed, opening, open };

pub const ClientSession = struct {
    alloc: std.mem.Allocator,
    transport: *quic_transport.Transport,
    phase: ClientPhase = .awaiting_ack,

    control_preface: quic_wire.PrefaceParser = .{},
    control: quic_wire.ControlParser,
    /// Control bytes read but not yet parsed — PREALLOCATED to its
    /// 4096 B hard bound and never grown; existing bytes are
    /// processed before more are received.
    control_stash: std.ArrayList(u8),
    /// Fixed reason storage: an event's reason slice points here and
    /// is valid until the next event is produced.
    err_buf: [quic_wire.error_reason_max]u8 = undefined,
    err_len: usize = 0,
    /// The one-event slot: holds at most one event; consumed when
    /// returned. A stored event survives a following CONNECTION_CLOSE.
    pending_event: ?ControlEvent = null,
    connection_closed: bool = false,

    /// One parked, fully encoded control frame awaiting credit
    /// (atomic retry through `retryPendingSends`).
    control_pending: [client_max_frame]u8 = undefined,
    control_pending_len: usize = 0,
    /// Set when the parked frame is the first (preface + HELLO).
    control_pending_is_hello: bool = false,

    input_state: InputState = .closed,
    /// The input stream's preface when its send blocked: retried by
    /// `retryPendingSends`; `openUniStream` is never called twice.
    input_pending_preface: [quic_wire.preface_len]u8 = undefined,
    input_preface_pending: bool = false,

    output_preface: quic_wire.OutputHeaderParser = .{},
    output_epoch: u64 = 0,

    /// Constructs and sends preface + HELLO as ONE atomic frame
    /// (parked if credit is withheld — nothing else is ever sent
    /// first).
    pub fn init(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        var s = try ClientSession.initSilentPreallocated(alloc, transport);
        const id = try transport.connection().openStream();
        if (id != control_stream_id) return error.UnexpectedControlStreamId;
        var frame: [client_max_frame]u8 = undefined;
        var flen: usize = 0;
        quic_wire.writePreface(frame[flen..][0..quic_wire.preface_len], .control);
        flen += quic_wire.preface_len;
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .hello, quic_wire.hello_payload_len);
        @memcpy(frame[flen..][0..quic_wire.control_header_len], &hdr);
        flen += quic_wire.control_header_len;
        var hello: [quic_wire.hello_payload_len]u8 = undefined;
        quic_wire.Hello.serverV1(quic_wire.mode_attach).encode(&hello);
        @memcpy(frame[flen..][0..quic_wire.hello_payload_len], &hello);
        flen += quic_wire.hello_payload_len;
        try s.sendFrameAtomic(frame[0..flen], true);
        return s;
    }

    /// Constructs WITHOUT opening or sending anything: for harnesses
    /// that craft the client's first frames themselves.
    pub fn initSilent(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        return ClientSession.initSilentPreallocated(alloc, transport);
    }

    fn initSilentPreallocated(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        var stash: std.ArrayList(u8) = .empty;
        try stash.ensureTotalCapacity(alloc, client_stash_cap);
        return .{
            .alloc = alloc,
            .transport = transport,
            .control = quic_wire.ControlParser.init(alloc),
            .control_stash = stash,
        };
    }

    pub fn deinit(self: *ClientSession) void {
        self.control.deinit();
        self.control_stash.deinit(self.alloc);
    }

    pub fn ended(self: *const ClientSession) bool {
        return self.phase == .ended;
    }

    pub fn connectionClosed(self: *const ClientSession) bool {
        return self.connection_closed;
    }

    // -- the one failure path ---------------------------------------------

    /// Every malformed receive condition funnels here: the event is
    /// STORED (it survives a following CONNECTION_CLOSE) and the
    /// connection closes with the same application code.
    fn failControl(self: *ClientSession, code: quic_wire.ErrCode, reason: []const u8) !?ControlEvent {
        if (self.pending_event == null) {
            const rlen = @min(reason.len, self.err_buf.len);
            @memcpy(self.err_buf[0..rlen], reason[0..rlen]);
            self.err_len = rlen;
            self.pending_event = .{ .err = .{ .code = code.code(), .reason = self.err_buf[0..rlen] } };
        }
        self.phase = .ended;
        self.transport.shutdown(code.code(), reason) catch {};
        return self.pending_event;
    }

    // -- atomic control writes --------------------------------------------

    /// Sends one fully encoded frame in a single all-or-nothing
    /// sendOnStream. On FlowControlBlocked the frame stays parked
    /// (nothing partially transmitted, nothing reordered past it).
    fn sendFrameAtomic(self: *ClientSession, frame: []const u8, is_hello: bool) !void {
        if (self.control_pending_len != 0) return error.ControlWritePending;
        self.transport.connection().sendOnStream(control_stream_id, frame, false) catch |e| switch (e) {
            error.FlowControlBlocked => {
                @memcpy(self.control_pending[0..frame.len], frame);
                self.control_pending_len = frame.len;
                self.control_pending_is_hello = is_hello;
                return error.WouldBlock;
            },
            error.StreamClosed => {
                self.phase = .ended;
                return;
            },
            else => return e,
        };
    }

    /// Retries the parked frame and the parked input preface. A
    /// successful first RESIZE here completes the phase transition;
    /// retrying can never duplicate bytes or open a second stream.
    pub fn retryPendingSends(self: *ClientSession) !void {
        if (self.control_pending_len != 0) {
            const frame = self.control_pending[0..self.control_pending_len];
            const is_hello = self.control_pending_is_hello;
            self.control_pending_len = 0;
            self.transport.connection().sendOnStream(control_stream_id, frame, false) catch |e| switch (e) {
                error.FlowControlBlocked => {
                    self.control_pending_len = frame.len;
                    self.control_pending_is_hello = is_hello;
                },
                error.StreamClosed => self.phase = .ended,
                else => return e,
            };
        }
        if (self.input_preface_pending) {
            self.transport.connection().sendOnStream(input_stream_id, &self.input_pending_preface, false) catch |e| switch (e) {
                error.FlowControlBlocked => return,
                error.StreamClosed => self.phase = .ended,
                else => return e,
            };
            self.input_preface_pending = false;
            self.input_state = .open;
        }
    }

    // -- control stream (client receive side) ------------------------------

    /// Pumps the control stream. Returns the stored event first
    /// (consuming the slot); parses at most the bounded stash per
    /// call. Malformed anything → failControl; ConnectionClosed sets
    /// explicit state rather than vanishing.
    pub fn pollControl(self: *ClientSession) !?ControlEvent {
        if (self.pending_event) |e| {
            self.pending_event = null;
            return e;
        }
        if (self.phase == .ended) return null;

        if (self.control_stash.items.len == 0) {
            var rbuf: [client_stash_cap]u8 = undefined;
            const n = self.transport.connection().recvOnStream(control_stream_id, &rbuf) catch |e| switch (e) {
                error.StreamClosed => {
                    self.phase = .ended;
                    return null;
                },
                error.ConnectionClosed => {
                    self.connection_closed = true;
                    self.phase = .ended;
                    return null;
                },
                else => return e,
            } orelse 0;
            if (n > 0) try self.control_stash.appendSlice(self.alloc, rbuf[0..n]);
        }
        if (self.control_stash.items.len == 0) return null;

        var rest: []const u8 = self.control_stash.items;
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
                        if (role != .control) return self.failControl(quic_wire.prefaceErrCode(error.UnknownRole), "wrong role on control stream");
                    },
                    .need => return null,
                    .invalid => |e| return self.failControl(quic_wire.prefaceErrCode(e), "bad control preface"),
                }
                continue;
            }
            const adv = try self.control.advance(rest);
            consumed_total += adv.consumed;
            rest = rest[adv.consumed..];
            switch (adv.result) {
                .need => return null,
                .invalid => |e| return self.failControl(quic_wire.controlHeaderErrCode(e), "bad control frame"),
                .done => |t| {
                    const ev = try self.handleFrame(t, self.control.payload());
                    self.control.reset();
                    if (ev) |e| {
                        self.pending_event = e;
                        self.pending_event = null;
                        return e;
                    }
                },
            }
        }
        return null;
    }

    fn handleFrame(self: *ClientSession, t: quic_wire.ControlType, payload: []const u8) !?ControlEvent {
        switch (t) {
            .hello_ack => {
                if (self.phase != .awaiting_ack) {
                    return self.failControl(.protocol_violation, "duplicate HELLO_ACK");
                }
                const ack = quic_wire.Hello.decode(payload) catch {
                    return self.failControl(.protocol_violation, "bad HELLO_ACK encoding");
                };
                // The frozen validation order; a mismatch closes with
                // its code — mixed versions/fingerprints can never
                // reach session data.
                if (ack.version_major != quic_wire.Hello.v1_version_major) {
                    return self.failControl(.version_mismatch, "version mismatch");
                }
                if (ack.required_capabilities != quic_wire.capabilities_v1) {
                    return self.failControl(.capability_mismatch, "capability mismatch");
                }
                if (!std.mem.eql(u8, &ack.snapshot_abi_id, &quic_wire.snapshot_abi_id)) {
                    return self.failControl(.fingerprint_mismatch, "snapshot abi mismatch");
                }
                if (ack.mode != quic_wire.mode_attach) {
                    return self.failControl(.protocol_violation, "bad ack mode");
                }
                if (ack.snapshot_limit > quic_wire.snapshot_limit_v1 or
                    ack.command_limit > quic_wire.command_limit_v1)
                {
                    return self.failControl(.protocol_violation, "bad negotiated limits");
                }
                self.phase = .awaiting_first_resize;
                return .{ .hello_ack = ack };
            },
            .session_end => {
                if (payload.len != 0) {
                    return self.failControl(.protocol_violation, "bad SESSION_END length");
                }
                self.phase = .ended;
                return .session_end;
            },
            .err => {
                const parsed = quic_wire.parseErrorPayload(payload) catch {
                    return self.failControl(.protocol_violation, "bad ERROR payload");
                };
                if (parsed.reason.len > quic_wire.error_reason_max) {
                    return self.failControl(.protocol_violation, "oversized ERROR reason");
                }
                const rlen = @min(parsed.reason.len, self.err_buf.len);
                @memcpy(self.err_buf[0..rlen], parsed.reason[0..rlen]);
                self.err_len = rlen;
                // Terminal ERRORs arrive with a control FIN; a
                // nonterminal response carries none and the session
                // continues.
                const fin = self.transport.connection().recvStreamFinished(control_stream_id) catch true;
                if (fin) self.phase = .ended;
                return .{ .err = .{ .code = parsed.code, .reason = self.err_buf[0..rlen] } };
            },
            // The server never sends these in v1 — anything else on
            // the client's receive side is a protocol failure.
            .hello, .resize, .detach, .snapshot_request, .snapshot_installed => {
                return self.failControl(.protocol_violation, "illegal server frame");
            },
        }
    }

    // -- client sends -------------------------------------------------------

    /// RESIZE — the FIRST control frame after HELLO_ACK. The encoded
    /// copy is made at queue time; the queued call succeeds, and the
    /// phase advances only once the whole frame was ACCEPTED (a
    /// parked frame is retried by `retryPendingSends`).
    pub fn sendResize(self: *ClientSession, rows: u16, cols: u16, xpixel: u16, ypixel: u16) !void {
        if (self.phase == .awaiting_first_resize or self.phase == .active) {} else {
            return error.NotActive;
        }
        var frame: [quic_wire.control_header_len + 8]u8 = undefined;
        quic_wire.writeControlHeader(frame[0..quic_wire.control_header_len], .resize, 8);
        quic_wire.writeResizePayload(frame[quic_wire.control_header_len..][0..8], rows, cols, xpixel, ypixel);
        const first = self.phase == .awaiting_first_resize;
        const blocked = error.WouldBlock;
        self.sendFrameAtomic(frame[0..], false) catch |e| {
            if (e == blocked) return error.WouldBlock;
            return e;
        };
        if (first) self.phase = .active;
    }

    pub fn sendDetach(self: *ClientSession) !void {
        if (self.phase != .active) return error.NotActive;
        var frame: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&frame, .detach, 0);
        return self.sendFrameAtomic(frame[0..], false);
    }

    pub fn sendSnapshotRequest(self: *ClientSession) !void {
        if (self.phase != .active) return error.NotActive;
        var frame: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&frame, .snapshot_request, 0);
        return self.sendFrameAtomic(frame[0..], false);
    }

    /// Raw terminal input. Blocking semantics: when the input
    /// preface send blocks, the preface stays internally pending, the
    /// body bytes remain CALLER-OWNED and unsent, and the call
    /// returns error.WouldBlock; retrying after a pump can neither
    /// duplicate bytes nor open a second stream.
    pub fn sendInput(self: *ClientSession, bytes: []const u8) !void {
        if (self.phase != .active) return error.NotActive;
        const conn = self.transport.connection();
        if (self.input_state == .closed) {
            const id = try conn.openUniStream();
            if (id != input_stream_id) return error.UnexpectedInputStreamId;
            self.input_state = .opening;
            quic_wire.writePreface(&self.input_pending_preface, .input);
            conn.sendOnStream(input_stream_id, &self.input_pending_preface, false) catch |e| switch (e) {
                error.FlowControlBlocked => {
                    // The preface copy is already staged; nothing else
                    // has been sent on this stream.
                    return error.WouldBlock;
                },
                else => return e,
            };
            self.input_state = .open;
        }
        if (self.input_state == .opening) return error.WouldBlock;
        if (bytes.len == 0) return;
        conn.sendOnStream(input_stream_id, bytes, false) catch |e| switch (e) {
            error.FlowControlBlocked => return error.WouldBlock,
            else => return e,
        };
    }

    // -- output stream (server → client), parked until authorized ---------

    /// Reads output bytes ONLY once HELLO_ACK validated the session;
    /// before that, bytes stay parked in QUIC (unconsumed, credit
    /// withheld). Header reads take EXACTLY the missing bytes; an
    /// epoch other than 1 is invalid in Q3 and takes the failure
    /// path. `epoch_out` reports the epoch once.
    pub fn pollOutput(self: *ClientSession, buf: []u8, epoch_out: ?*u64) !?usize {
        if (self.phase == .awaiting_ack or self.phase == .ended) return null;
        const conn = self.transport.connection();
        if (!self.output_preface.done) {
            const want = self.output_preface.remaining();
            if (want == 0) return null;
            var hbuf: [quic_wire.output_header_len]u8 = undefined;
            const n = conn.recvOnStream(output_stream_id, hbuf[0..want]) catch |e| switch (e) {
                error.StreamClosed => {
                    self.phase = .ended;
                    return null;
                },
                error.ConnectionClosed => {
                    self.connection_closed = true;
                    self.phase = .ended;
                    return null;
                },
                else => return e,
            } orelse return null;
            if (n == 0) return null;
            const r = self.output_preface.feed(hbuf[0..n]);
            switch (r.result) {
                .done => |epoch| {
                    if (epoch != 1) {
                        _ = try self.failControl(.protocol_violation, "invalid output epoch");
                        return null;
                    }
                    self.output_epoch = epoch;
                    if (epoch_out) |o| o.* = epoch;
                },
                .need => return null,
                .invalid => |e| {
                    _ = try self.failControl(quic_wire.prefaceErrCode(e), "bad output header");
                    return null;
                },
            }
            return null;
        }
        const n = conn.recvOnStream(output_stream_id, buf) catch |e| switch (e) {
            error.StreamClosed => {
                self.phase = .ended;
                return null;
            },
            error.ConnectionClosed => {
                self.connection_closed = true;
                self.phase = .ended;
                return null;
            },
            else => return e,
        } orelse return null;
        // Zero means only flow-control bookkeeping was emitted.
        if (n == 0) return null;
        return n;
    }
};

/// The client control stash's hard bound: reads happen only while the
/// stash is empty, so one bounded read is its true maximum.
pub const client_stash_cap = 4096;

// ---------------------------------------------------------------------------
// The socket-owning client driver (Q5 attach client, Q6 command client)
// ---------------------------------------------------------------------------

const lib_posix = @import("posix.zig");
const udp = @import("udp.zig");
const quic_gateway = @import("quic_gateway.zig");

/// Application versus transport peer close, distinctly surfaced.
pub const PeerCloseInfo = struct {
    kind: enum { application, transport },
    code: u64,
    reason: []const u8,
};

/// The client control/event pump bounds, mirroring the gateway's turn.
pub const pump_max_inbound = 64;
pub const pump_max_outbound = 64;
/// The bounded terminal/output accumulation: receiving STOPS while it
/// is full; `pollOutput` drains it.
pub const client_output_cap = 64 * 1024;
/// Parked handshake datagrams bound; beyond it a drop is recovered by
/// QUIC retransmission.
pub const parked_max = 16;
pub const handshake_deadline_ns: i64 = 10 * std.time.ns_per_s;

pub const Client = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
    sock: udp.UdpSocket,
    transport: *quic_transport.Transport,
    session: ClientSession,
    /// The stable remote the connection was opened to (v1: fixed).
    remote: lib_posix.Address,
    remote_udp: quicz.endpoint.UdpAddress,
    local_udp: quicz.endpoint.UdpAddress,
    challenge: [8]u8,
    handshake_deadline_ns: i64,

    /// Bounded output accumulation (linear buffer with compaction).
    out_buf: [client_output_cap]u8 = undefined,
    out_len: usize = 0,
    out_head: usize = 0,

    /// Handshake-space datagrams that raced key installation: parked
    /// (bounded; QUIC retransmission recovers an overflow drop) and
    /// replayed once the keys exist — the same recovery the fixtures
    /// perform.
    parked: std.ArrayList([]u8) = .empty,
    /// Whether parked[i] is a short-form (1-RTT) datagram gated on
    /// handshake CONFIRMATION (long-form entries gate on keys).
    parked_short: [parked_max]bool = [_]bool{false} ** parked_max,
    /// Malformed inbound datagrams discarded at the driver boundary.
    junk_received: usize = 0,
    /// An allocation failure observed inside feed (surfaced by pump).
    oom: bool = false,

    const quicz = @import("quicz");

    /// One client turn. Returns and CONSUMES the one-event slot; the
    /// event's reason stays valid in the session's fixed storage until
    /// the next pump.
    pub fn connect(alloc: std.mem.Allocator, io: std.Io, psk: *const [32]u8, remote: lib_posix.Address, now: i64) !Client {
        const family: u32 = switch (remote.any.family) {
            lib_posix.AF.INET => lib_posix.AF.INET,
            lib_posix.AF.INET6 => lib_posix.AF.INET6,
            else => return error.UnsupportedAddressFamily,
        };
        var sock = try udp.UdpSocket.bindEphemeral(family);
        errdefer sock.close();
        var scid: [4]u8 = undefined;
        var odcid: [8]u8 = undefined;
        var challenge: [8]u8 = undefined;
        io.random(&scid);
        io.random(&odcid);
        io.random(&challenge);
        const transport = try quic_transport.Transport.createClient(alloc, .{
            .psk = psk,
            .scid = scid,
            .original_dcid = odcid,
        });
        errdefer transport.destroy();
        const remote_udp = quic_gateway.sockaddrToUdpAddress(remote) orelse return error.UnsupportedAddressFamily;
        var bound: lib_posix.Address = std.mem.zeroes(lib_posix.Address);
        var bound_len: lib_posix.socklen_t = @sizeOf(lib_posix.Address);
        try lib_posix.getsockname(sock.getFd(), &bound.any, &bound_len);
        const local_udp = quic_gateway.sockaddrToUdpAddress(bound) orelse return error.UnsupportedAddressFamily;
        try transport.registerRoute(local_udp, remote_udp);
        const session = try ClientSession.init(alloc, transport);
        var c = Client{
            .alloc = alloc,
            .io = io,
            .sock = sock,
            .transport = transport,
            .session = session,
            .remote = remote,
            .remote_udp = remote_udp,
            .local_udp = local_udp,
            .challenge = challenge,
            .handshake_deadline_ns = now + handshake_deadline_ns,
        };
        try c.parked.ensureTotalCapacity(alloc, parked_max);
        return c;
    }

    pub fn deinit(self: *Client) void {
        for (self.parked.items) |dg| self.alloc.free(dg);
        self.parked.deinit(self.alloc);
        self.session.deinit();
        self.transport.destroy();
        self.sock.close();
    }

    pub fn handshakeConfirmed(self: *const Client) bool {
        return self.transport.handshakeConfirmed();
    }

    /// The composed deadline: the 10 s handshake anchor until the
    /// handshake confirms, then the transport's own deadlines. Always
    /// in the future so a poll timeout of zero never busy-loops.
    pub fn nextDeadline(self: *const Client, now: i64) ?i64 {
        const transport_deadline = self.transport.nextDeadlineNanos();
        var d: i64 = undefined;
        if (!self.transport.handshakeConfirmed()) {
            d = self.handshake_deadline_ns;
            if (transport_deadline) |td| d = @min(td, d);
        } else if (transport_deadline) |td| {
            d = td;
        } else {
            return null;
        }
        return @max(d, now + 1);
    }

    /// The peer's close, distinctly application versus transport.
    pub fn peerClose(self: *const Client) ?PeerCloseInfo {
        const pc = (self.transport.connection().peerClose() orelse return null);
        return switch (pc) {
            .application => |a| .{ .kind = .application, .code = a.error_code, .reason = a.reason_phrase },
            .connection => |c| .{ .kind = .transport, .code = c.error_code, .reason = c.reason_phrase },
        };
    }

    /// Drains accumulated output into `dst` (bounded queue; receiving
    /// stops while it is full).
    pub fn pollOutput(self: *Client, dst: []u8) !?usize {
        const available = self.out_len - self.out_head;
        if (available == 0) {
            self.compactOutput();
            return null;
        }
        const n = @min(available, dst.len);
        @memcpy(dst[0..n], self.out_buf[self.out_head .. self.out_head + n]);
        self.out_head += n;
        self.compactOutput();
        return n;
    }

    fn compactOutput(self: *Client) void {
        if (self.out_head == 0) return;
        const keep = self.out_len - self.out_head;
        std.mem.copyForwards(u8, self.out_buf[0..keep], self.out_buf[self.out_head..self.out_len]);
        self.out_len = keep;
        self.out_head = 0;
    }

    fn outputFull(self: *const Client) bool {
        return self.out_len - self.out_head >= self.out_buf.len;
    }

    fn drainOutput(self: *Client) !void {
        var scratch: [4096]u8 = undefined;
        while (!self.outputFull()) {
            const space = self.out_buf.len - self.out_len;
            if (space == 0) return;
            const dst = scratch[0..@min(scratch.len, space)];
            const n = (try self.session.pollOutput(dst, null)) orelse return;
            @memcpy(self.out_buf[self.out_len .. self.out_len + n], dst[0..n]);
            self.out_len += n;
        }
    }

    /// One bounded turn. Enforces the 10 s handshake timeout (a bare
    /// nextDeadline would busy-loop after expiry), retries parked
    /// atomic writes, sends ≤ 64 outbound datagrams (including PTO
    /// output), drains existing state, then receives ≤ 64 inbound
    /// datagrams — draining control/output after EACH, and stopping
    /// when the event slot is occupied or the output queue is full.
    pub fn pump(self: *Client, now: i64) !?ControlEvent {
        if (!self.transport.handshakeConfirmed() and now >= self.handshake_deadline_ns) {
            return self.failLocal(.session_ended, "handshake timeout");
        }
        if (!self.transport.handshakeConfirmed()) {
            try self.transport.driveCrypto(.initial, now);
            try self.transport.driveCrypto(.handshake, now);
        }
        try self.session.retryPendingSends();

        var outbound: usize = 0;
        while (outbound < pump_max_outbound) : (outbound += 1) {
            const dg = (try self.transport.pollOutbound(now)) orelse break;
            defer self.alloc.free(dg);
            self.sock.sendTo(dg, self.remote) catch |e| switch (e) {
                error.WouldBlock => break,
                else => return e,
            };
        }
        if (outbound < pump_max_outbound) {
            switch (try self.transport.serviceDueDeadline(now)) {
                .datagram => |tagged| {
                    defer self.alloc.free(tagged.dg);
                    self.sock.sendTo(tagged.dg, quic_gateway.udpAddressToSockaddr(tagged.dst.remote)) catch {};
                },
                else => {},
            }
        }

        // Drain existing state BEFORE receiving.
        var ev: ?ControlEvent = null;
        if (try self.session.pollControl()) |e| ev = e;
        try self.drainOutput();

        var inbound: usize = 0;
        var buf: [quic_transport.max_udp_payload]u8 = undefined;
        while (inbound < pump_max_inbound and ev == null and !self.outputFull()) : (inbound += 1) {
            const r = self.sock.recvFrom(&buf) catch break;
            const arrival = quicz.endpoint.UdpTuple{ .local = self.local_udp, .remote = self.remote_udp };
            // Park Handshake-space datagrams that race key
            // installation; replay them once the keys exist.
            const info = quicz.protection.peekProtectedLongPacketInfo(buf[0..r.len]) catch {
                self.feed(arrival, now, buf[0..r.len]);
                if (try self.session.pollControl()) |e| ev = e;
                try self.drainOutput();
                continue;
            };
            const is_short = (buf[0] & 0x80) == 0;
            const gate_on_keys = info.packet_type == .handshake and !self.transport.conn.hasHandshakeProtectionKeys();
            // A short-form (1-RTT) datagram that races handshake
            // CONFIRMATION would be silently discarded by the keyless
            // path — park it too; replay order preserves arrival.
            const gate_on_confirm = is_short and !self.transport.handshakeConfirmed();
            if (gate_on_keys or gate_on_confirm) {
                if (self.parked.items.len < parked_max) {
                    const dg = self.alloc.dupe(u8, buf[0..r.len]) catch return error.OutOfMemory;
                    self.parked.appendAssumeCapacity(dg);
                    self.parked_short[self.parked.items.len - 1] = gate_on_confirm;
                }
                continue;
            }
            self.feed(arrival, now, buf[0..r.len]);
            if (try self.session.pollControl()) |e| ev = e;
            try self.drainOutput();
        }
        // Replay parked datagrams whose gate has opened (handshake
        // keys for long-form entries, confirmation for short-form).
        var gate_i: usize = 0;
        while (gate_i < self.parked.items.len) : (gate_i += 1) {
            const ready = if (self.parked_short[gate_i])
                self.transport.handshakeConfirmed()
            else
                self.transport.conn.hasHandshakeProtectionKeys();
            if (!ready) continue;
            const dg = self.parked.items[gate_i];
            const arrival = quicz.endpoint.UdpTuple{ .local = self.local_udp, .remote = self.remote_udp };
            _ = try self.transport.handleDatagram(arrival, now, dg, &self.challenge);
            self.feed(arrival, now, dg);
            if (try self.session.pollControl()) |e| ev = e;
            try self.drainOutput();
            self.alloc.free(dg);
            _ = self.parked.orderedRemove(gate_i);
            // Compact the short flags with the list.
            var s_i = gate_i;
            while (s_i < self.parked.items.len) : (s_i += 1) {
                self.parked_short[s_i] = self.parked_short[s_i + 1];
            }
            if (ev != null) break;
        }
        return ev;
    }

    /// Feeds one datagram; malformed network junk is discarded and
    /// counted (the adapter's own discard-and-count discipline for the
    /// paths its route layer covers), only allocation failure aborts.
    fn feed(self: *Client, arrival: quicz.endpoint.UdpTuple, now: i64, data: []const u8) void {
        _ = self.transport.handleDatagram(arrival, now, data, &self.challenge) catch |e| switch (e) {
            error.OutOfMemory => {
                self.oom = true;
                return;
            },
            else => self.junk_received += 1,
        };
    }

    /// A local failure surfaced exactly like a wire one.
    pub fn failLocal(self: *Client, code: quic_wire.ErrCode, reason: []const u8) !?ControlEvent {
        return self.session.failControl(code, reason);
    }

    pub fn sendInput(self: *Client, bytes: []const u8) !void {
        return self.session.sendInput(bytes);
    }

    pub fn sendResize(self: *Client, rows: u16, cols: u16, xpixel: u16, ypixel: u16) !void {
        return self.session.sendResize(rows, cols, xpixel, ypixel);
    }

    pub fn sendDetach(self: *Client) !void {
        return self.session.sendDetach();
    }

    pub fn sendSnapshotRequest(self: *Client) !void {
        return self.session.sendSnapshotRequest();
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "client event union carries hello_ack, session_end, and error shapes" {
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

test "client max frame bound is the preface + header + HELLO" {
    try testing.expectEqual(@as(usize, 64), client_max_frame);
    try testing.expectEqual(quic_wire.preface_len + quic_wire.control_header_len + quic_wire.hello_payload_len, client_max_frame);
}
