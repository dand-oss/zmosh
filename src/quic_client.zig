//! Client-side ZMQ1 protocol session. ClientSession is the state
//! machine over a borrowed client Transport (gateway tests drive it
//! directly on the Loop fixture); the socket-owning `Client` driver
//! (below) composes it for the Q5 attach client and Q6 command
//! client.
//!
//! Ordering contract: ONLY the control stream (preface + HELLO) is
//! sent first; after HELLO_ACK validates, RESIZE is the first control
//! frame; input flows after it.
//!
//! State model: one hierarchical protocol FSM. The top-level state is
//! the application lifecycle; each live variant embeds ONLY the
//! stream substates possible there, so invalid combinations (output
//! readable before authorization, input before the first RESIZE, a
//! parked first RESIZE without its transition metadata) are
//! unrepresentable. QUIC streams advance independently, so the
//! substates are separate small unions rather than one flat
//! cross-product. Every top-level transition goes through exactly one
//! of five helpers — nothing else assigns `state`.
//!
//! Events: every event is STORED in the one-event slot and delivered
//! exactly once through `takeEvent`; the reason slice stays valid in
//! the fixed buffer until the next event is produced. Every control
//! write is ONE all-or-nothing send of an encoded copy; a blocked
//! send parks the copy and SUCCEEDS (ownership transferred), and a
//! second write while one is parked is `error.ControlWritePending`.

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
    /// `terminal` is true for a FINAL ERROR (fatal, control FIN to
    /// follow) and false for a nonterminal response (flags zero, the
    /// session continues). Locally generated failures are terminal.
    err: struct { code: u32, reason: []const u8, terminal: bool },
};

// -- typed stream substates --------------------------------------------------

/// The client's control-send side: idle, one parked whole frame
/// (ownership transferred at park time), or closed.
pub const ControlTx = union(enum) {
    idle,
    pending: struct {
        kind: PendingKind,
        len: usize,
        bytes: [client_max_frame]u8,
    },
    closed,
};

pub const PendingKind = enum { hello, first_resize, ordinary };

/// The client's input-send side. `preface_pending` holds the staged
/// preface; the body bytes remain caller-owned.
pub const InputTx = union(enum) {
    unopened,
    preface_pending: [quic_wire.preface_len]u8,
    open,
    closed,
};

/// The control-receive side. A clean FIN is legal only from
/// `terminal_wait_fin` (after a terminal SESSION_END or FINAL ERROR).
pub const ControlRx = enum {
    preface,
    frames,
    terminal_wait_fin,
    finished,
    reset,
};

/// The output-receive side: unauthorized until HELLO_ACK, then header
/// → body, finishing at a clean FIN. `unavailable_after_close` marks
/// an output FIN the peer close made unreachable (queued output still
/// drains).
pub const OutputRx = union(enum) {
    unauthorized,
    header,
    body: struct { epoch: u64 },
    finished: struct { epoch: u64 },
    reset,
    unavailable_after_close,
};

/// Which terminal frame began the drain (evidence for the deferred
/// event and the FIN contract). `detach_fin` is the clean-detach arm:
/// the server's bare FIN (no final frame) completes a client DETACH.
pub const TerminalMeta = struct {
    kind: enum { session_end, err, detach_fin },
    code: u32,
};

pub const CloseKind = enum { application, transport };

/// The top-level application protocol FSM.
pub const ProtocolState = union(enum) {
    /// HELLO sent or parked; control receive active; output
    /// unauthorized; no input.
    awaiting_ack: struct {
        control_tx: ControlTx = .idle,
        control_rx: ControlRx = .preface,
    },
    /// HELLO_ACK validated; the first RESIZE is idle or parked;
    /// output authorized; input still rejected.
    awaiting_first_resize: struct {
        control_tx: ControlTx,
        control_rx: ControlRx,
        output_rx: OutputRx,
    },
    /// The first RESIZE was accepted in full; input may flow.
    active: struct {
        control_tx: ControlTx,
        control_rx: ControlRx,
        input_tx: InputTx = .unopened,
        output_rx: OutputRx,
        /// A DETACH was accepted (sent or parked): the server's bare
        /// control FIN completes the session cleanly.
        detach_sent: bool = false,
    },
    /// A terminal marker was received after authorization: no new
    /// sends; control FIN validation and output draining continue.
    /// `peer` records a later peer close WITHOUT discarding the
    /// stream evidence still needed to judge the FIN contract.
    draining: struct {
        peer: enum { open, closed } = .open,
        control_rx: ControlRx,
        output_rx: OutputRx,
        terminal: TerminalMeta,
    },
    /// One local/protocol failure recorded; application close
    /// initiated.
    failed: struct { code: u32 },
    /// Peer connection close recorded outside draining (or after
    /// terminal delivery completed); no further transport operations.
    closed: CloseKind,
};

pub const StateTag = enum {
    awaiting_ack,
    awaiting_first_resize,
    active,
    draining,
    failed,
    closed,
};

pub const ClientSession = struct {
    alloc: std.mem.Allocator,
    transport: *quic_transport.Transport,
    state: ProtocolState = .{ .awaiting_ack = .{} },

    // Stable parser/storage members — variants carry only semantic
    // state and owned fixed-size pending data.
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

    output_hdr: quic_wire.OutputHeaderParser = .{},

    /// Constructs and sends preface + HELLO as ONE atomic frame
    /// (parked whole if credit is withheld — nothing else is ever
    /// sent first).
    pub fn init(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        var s = try ClientSession.initSilentPreallocated(alloc, transport);
        errdefer s.deinit();
        const id = try transport.connection().openStream();
        if (id != control_stream_id) return error.UnexpectedControlStreamId;
        var frame: [client_max_frame]u8 = undefined;
        var flen: usize = 0;
        quic_wire.writePreface(frame[flen..][0..quic_wire.preface_len], .control);
        flen += quic_wire.preface_len;
        var hdr: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&hdr, .hello, quic_wire.hello_payload_len, 0);
        @memcpy(frame[flen..][0..quic_wire.control_header_len], &hdr);
        flen += quic_wire.control_header_len;
        var hello: [quic_wire.hello_payload_len]u8 = undefined;
        quic_wire.Hello.serverV1(quic_wire.mode_attach).encode(&hello);
        @memcpy(frame[flen..][0..quic_wire.hello_payload_len], &hello);
        flen += quic_wire.hello_payload_len;
        try s.sendFrameAtomic(.hello, frame[0..flen]);
        return s;
    }

    /// Constructs WITHOUT opening or sending anything: for harnesses
    /// that craft the client's first frames themselves.
    pub fn initSilent(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        return ClientSession.initSilentPreallocated(alloc, transport);
    }

    fn initSilentPreallocated(alloc: std.mem.Allocator, transport: *quic_transport.Transport) !ClientSession {
        var stash: std.ArrayList(u8) = .empty;
        errdefer stash.deinit(alloc);
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
        return switch (self.state) {
            .draining, .failed, .closed => true,
            else => false,
        };
    }

    pub fn connectionClosed(self: *const ClientSession) bool {
        return switch (self.state) {
            .closed => true,
            .draining => |d| d.peer == .closed,
            else => false,
        };
    }

    /// The live top-level state tag (transition-test assertions).
    pub fn stateTag(self: *const ClientSession) StateTag {
        return switch (self.state) {
            .awaiting_ack => .awaiting_ack,
            .awaiting_first_resize => .awaiting_first_resize,
            .active => .active,
            .draining => .draining,
            .failed => .failed,
            .closed => .closed,
        };
    }

    // -- the five transition helpers (nothing else assigns state) ----------

    /// Valid HELLO_ACK: awaiting_ack → awaiting_first_resize; output
    /// becomes authorized (header phase).
    fn acceptHelloAck(self: *ClientSession) void {
        const a = switch (self.state) {
            .awaiting_ack => |a| a,
            else => return,
        };
        self.state = .{
            .awaiting_first_resize = .{
                .control_tx = a.control_tx,
                // The control preface is necessarily validated by now.
                .control_rx = .frames,
                .output_rx = .header,
            },
        };
    }

    /// The first RESIZE was accepted in full (immediately or by
    /// retry): awaiting_first_resize → active, exactly once.
    fn acceptFirstResize(self: *ClientSession) void {
        const a = switch (self.state) {
            .awaiting_first_resize => |a| a,
            else => return,
        };
        self.state = .{ .active = .{
            .control_tx = .idle,
            .control_rx = a.control_rx,
            .input_tx = .unopened,
            .output_rx = a.output_rx,
        } };
    }

    /// A terminal SESSION_END or FINAL ERROR after authorization: the
    /// live state enters draining, keeps its output evidence, and
    /// stops all new sends.
    fn beginDrain(self: *ClientSession, meta: TerminalMeta) void {
        const output_rx = switch (self.state) {
            .awaiting_first_resize => |a| a.output_rx,
            .active => |a| a.output_rx,
            else => return,
        };
        self.state = .{ .draining = .{
            .control_rx = .terminal_wait_fin,
            .output_rx = output_rx,
            .terminal = meta,
        } };
    }

    /// One local/protocol failure: the event is STORED (it survives a
    /// following CONNECTION_CLOSE) and the connection closes with the
    /// same application code. A second failure never replaces the
    /// first.
    fn failProtocol(self: *ClientSession, code: quic_wire.ErrCode, reason: []const u8) void {
        if (self.state == .failed) return;
        if (self.pending_event == null) {
            self.storeErrorEvent(code, reason, true);
        }
        self.state = .{ .failed = .{ .code = code.code() } };
        self.transport.shutdown(code.code(), reason) catch {};
    }

    /// A wire terminal frame received before authorization (the
    /// HELLO-rejection arm): surfaced IMMEDIATELY with the wire's own
    /// code — no drain contract exists yet — and the session fails
    /// closed.
    fn failBeforeAuthorization(self: *ClientSession, code: u32, reason: []const u8) void {
        if (self.state == .failed) return;
        if (self.pending_event == null) {
            self.storeErrorEventCode(code, reason, true);
        }
        self.state = .{ .failed = .{ .code = code } };
        self.transport.shutdown(code, reason) catch {};
    }

    /// A peer connection close. Outside draining this is the clean
    /// top-level `.closed`. INSIDE draining it flips only
    /// `draining.peer` and preserves the stream evidence: a missing
    /// control FIN is a protocol violation (the terminal frame
    /// promised one), and an output FIN the close made unreachable
    /// degrades to `.unavailable_after_close` so the queued output
    /// still drains.
    fn recordPeerClose(self: *ClientSession, kind: CloseKind) void {
        switch (self.state) {
            .draining => {
                self.state.draining.peer = .closed;
                if (self.state.draining.control_rx == .terminal_wait_fin) {
                    self.failProtocol(.protocol_violation, "peer closed without control FIN");
                } else if (self.state.draining.control_rx == .finished) {
                    switch (self.state.draining.output_rx) {
                        .body => self.state.draining.output_rx = .unavailable_after_close,
                        else => {},
                    }
                }
            },
            .failed, .closed => {},
            else => self.state = .{ .closed = kind },
        }
    }

    /// Classifies an observed close from the transport and records it.
    fn recordPeerCloseFromTransport(self: *ClientSession) void {
        if (self.transport.connection().peerClose()) |pc| {
            self.recordPeerClose(switch (pc) {
                .application => .application,
                .connection => .transport,
            });
        }
        // No close frame observed (e.g. our own close racing): no
        // transition.
    }

    // -- the one event slot -------------------------------------------------

    fn storeErrorEventCode(self: *ClientSession, code: u32, reason: []const u8, terminal: bool) void {
        const rlen = @min(reason.len, self.err_buf.len);
        @memcpy(self.err_buf[0..rlen], reason[0..rlen]);
        self.err_len = rlen;
        self.pending_event = .{ .err = .{
            .code = code,
            .reason = self.err_buf[0..rlen],
            .terminal = terminal,
        } };
    }

    fn storeErrorEvent(self: *ClientSession, code: quic_wire.ErrCode, reason: []const u8, terminal: bool) void {
        self.storeErrorEventCode(code.code(), reason, terminal);
    }

    /// THE delivery point: every event is returned exactly once and
    /// the slot cleared atomically with the return.
    fn takeEvent(self: *ClientSession) ?ControlEvent {
        const e = self.pending_event orelse return null;
        self.pending_event = null;
        return e;
    }

    /// A local failure surfaced exactly like a wire one: stores the
    /// terminal event and hands it over once.
    pub fn failLocal(self: *ClientSession, code: quic_wire.ErrCode, reason: []const u8) ?ControlEvent {
        self.failProtocol(code, reason);
        return self.takeEvent();
    }

    // -- substate accessors --------------------------------------------------

    fn controlTx(self: *ClientSession) ?*ControlTx {
        return switch (self.state) {
            .awaiting_ack => |*a| &a.control_tx,
            .awaiting_first_resize => |*a| &a.control_tx,
            .active => |*a| &a.control_tx,
            else => null,
        };
    }

    fn inputTx(self: *ClientSession) ?*InputTx {
        return switch (self.state) {
            .active => |*a| &a.input_tx,
            else => null,
        };
    }

    fn controlRx(self: *ClientSession) ?*ControlRx {
        return switch (self.state) {
            .awaiting_ack => |*a| &a.control_rx,
            .awaiting_first_resize => |*a| &a.control_rx,
            .active => |*a| &a.control_rx,
            .draining => |*d| &d.control_rx,
            else => null,
        };
    }

    fn outputRx(self: *ClientSession) ?*OutputRx {
        return switch (self.state) {
            .awaiting_first_resize => |*a| &a.output_rx,
            .active => |*a| &a.output_rx,
            .draining => |*d| &d.output_rx,
            else => null,
        };
    }

    // -- atomic control writes ---------------------------------------------

    /// Sends one fully encoded frame in a single all-or-nothing
    /// sendOnStream. On FlowControlBlocked the COMPLETE frame is
    /// copied into the pending slot and the call SUCCEEDS — ownership
    /// transferred, nothing partially transmitted, nothing reordered
    /// past it. Stream or connection closure FAILS: an ended session
    /// never counts an unaccepted frame as sent.
    fn sendFrameAtomic(self: *ClientSession, kind: PendingKind, frame: []const u8) !void {
        const tx = self.controlTx() orelse return error.NotActive;
        switch (tx.*) {
            .pending => return error.ControlWritePending,
            .closed => return error.StreamClosed,
            .idle => {},
        }
        if (self.transport.connection().sendOnStream(control_stream_id, frame, false)) {
            tx.* = .idle;
            if (kind == .first_resize) self.acceptFirstResize();
        } else |e| switch (e) {
            error.FlowControlBlocked => {
                var bytes: [client_max_frame]u8 = undefined;
                @memcpy(bytes[0..frame.len], frame);
                tx.* = .{ .pending = .{ .kind = kind, .len = frame.len, .bytes = bytes } };
            },
            error.StreamClosed => {
                tx.* = .closed;
                return error.StreamClosed;
            },
            error.ConnectionClosed => {
                self.recordPeerCloseFromTransport();
                return error.ConnectionClosed;
            },
            else => return e,
        }
    }

    /// Retries the parked control frame and the parked input
    /// preface. A successful first-RESIZE retry activates the session
    /// exactly once; a retry can never duplicate bytes or open a
    /// second stream.
    pub fn retryPendingSends(self: *ClientSession) !void {
        if (self.controlTx()) |tx| switch (tx.*) {
            .pending => |p| {
                if (self.transport.connection().sendOnStream(control_stream_id, p.bytes[0..p.len], false)) {
                    tx.* = .idle;
                    if (p.kind == .first_resize) self.acceptFirstResize();
                } else |e| switch (e) {
                    error.FlowControlBlocked => return, // stays parked, whole
                    error.StreamClosed => {
                        tx.* = .closed;
                        self.failProtocol(.protocol_violation, "control stream reset");
                    },
                    error.ConnectionClosed => self.recordPeerCloseFromTransport(),
                    else => return e,
                }
            },
            else => {},
        };
        if (self.inputTx()) |t| switch (t.*) {
            .preface_pending => |pre| {
                if (self.transport.connection().sendOnStream(input_stream_id, &pre, false)) {
                    t.* = .open;
                } else |e| switch (e) {
                    error.FlowControlBlocked => return, // stays staged
                    error.StreamClosed => t.* = .closed,
                    error.ConnectionClosed => self.recordPeerCloseFromTransport(),
                    else => return e,
                }
            },
            else => {},
        };
    }

    // -- control stream (client receive side) ------------------------------

    /// Pumps the control stream. Delivers the stored event first
    /// (exactly once), reads one bounded stash, then parses. Every
    /// malformed condition funnels into `failProtocol`; a peer close
    /// is recorded distinctly and never masquerades as a protocol
    /// failure.
    pub fn pollControl(self: *ClientSession) !?ControlEvent {
        if (self.takeEvent()) |e| return e;
        switch (self.state) {
            .awaiting_ack, .awaiting_first_resize, .active, .draining => {},
            .failed, .closed => return null,
        }

        if (self.control_stash.items.len == 0) {
            var rbuf: [client_stash_cap]u8 = undefined;
            const got = self.transport.connection().recvOnStream(control_stream_id, &rbuf) catch |e| switch (e) {
                // RST_STREAM / STOP_SENDING: the stream was reset.
                error.StreamClosed => {
                    if (self.controlRx()) |crx| crx.* = .reset;
                    self.failProtocol(.protocol_violation, "control stream reset");
                    return self.takeEvent();
                },
                error.ConnectionClosed => {
                    self.recordPeerCloseFromTransport();
                    return null;
                },
                else => return e,
            };
            if (got) |n| {
                if (n > 0) try self.control_stash.appendSlice(self.alloc, rbuf[0..n]);
            }
            if (self.control_stash.items.len == 0) {
                self.resolveControlFin();
                return self.takeEvent();
            }
        }

        // Any byte after the terminal marker starts an illegal frame.
        if (self.state == .draining and self.control_stash.items.len != 0) {
            self.failProtocol(.protocol_violation, "frame after terminal marker");
            return self.takeEvent();
        }

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
                        if (role != .control) {
                            self.failProtocol(quic_wire.prefaceErrCode(error.UnknownRole), "wrong role on control stream");
                            return self.takeEvent();
                        }
                        if (self.controlRx()) |crx| crx.* = .frames;
                    },
                    .need => return null,
                    .invalid => |e| {
                        self.failProtocol(quic_wire.prefaceErrCode(e), "bad control preface");
                        return self.takeEvent();
                    },
                }
                continue;
            }
            const adv = try self.control.advance(rest);
            consumed_total += adv.consumed;
            rest = rest[adv.consumed..];
            switch (adv.result) {
                .need => return null,
                .invalid => |e| {
                    self.failProtocol(quic_wire.controlHeaderErrCode(e), "bad control frame");
                    return self.takeEvent();
                },
                .done => |h| {
                    try self.handleFrame(h, self.control.payload());
                    self.control.reset();
                    if (self.pending_event != null) return self.takeEvent();
                },
            }
        }
        self.resolveControlFin();
        return self.takeEvent();
    }

    /// A FIN observed while no bytes remain: clean ONLY from
    /// `terminal_wait_fin`. Mid-preface, mid-frame, between frames
    /// without a terminal, or before any preface — truncated-stream
    /// protocol violation.
    fn resolveControlFin(self: *ClientSession) void {
        const crx = self.controlRx() orelse return;
        const finished = self.transport.connection().recvStreamFinished(control_stream_id) catch return;
        if (!finished) return;
        switch (crx.*) {
            .terminal_wait_fin => crx.* = .finished,
            .finished, .reset => {},
            .preface => self.failProtocol(.protocol_violation, "FIN before control preface"),
            .frames => {
                if (self.control_preface.expecting() or self.control.expectingFrame()) {
                    self.failProtocol(.protocol_violation, "truncated control stream");
                } else if (self.state == .active and self.state.active.detach_sent) {
                    // The clean-detach arm: the server FINs without a
                    // final frame once our DETACH was flushed.
                    self.beginDrain(.{ .kind = .detach_fin, .code = 0 });
                    if (self.controlRx()) |c2| c2.* = .finished;
                } else {
                    self.failProtocol(.protocol_violation, "control FIN without terminal frame");
                }
            },
        }
    }

    fn handleFrame(self: *ClientSession, h: quic_wire.ControlHeader, payload: []const u8) !void {
        switch (h.t) {
            .hello_ack => {
                switch (self.state) {
                    .awaiting_ack => {},
                    else => return self.failProtocol(.protocol_violation, "duplicate HELLO_ACK"),
                }
                const ack = quic_wire.Hello.decode(payload) catch {
                    return self.failProtocol(.protocol_violation, "bad HELLO_ACK encoding");
                };
                // The frozen validation order; a mismatch closes with
                // its code — mixed versions/fingerprints can never
                // reach session data.
                if (ack.version_major != quic_wire.Hello.v1_version_major) {
                    return self.failProtocol(.version_mismatch, "version mismatch");
                }
                if (ack.required_capabilities != quic_wire.capabilities_v1) {
                    return self.failProtocol(.capability_mismatch, "capability mismatch");
                }
                if (!std.mem.eql(u8, &ack.snapshot_abi_id, &quic_wire.snapshot_abi_id)) {
                    return self.failProtocol(.fingerprint_mismatch, "snapshot abi mismatch");
                }
                if (ack.mode != quic_wire.mode_attach) {
                    return self.failProtocol(.protocol_violation, "bad ack mode");
                }
                if (ack.snapshot_limit > quic_wire.snapshot_limit_v1 or
                    ack.command_limit > quic_wire.command_limit_v1)
                {
                    return self.failProtocol(.protocol_violation, "bad negotiated limits");
                }
                self.acceptHelloAck();
                self.pending_event = .{ .hello_ack = ack };
            },
            .session_end => {
                if (payload.len != 0) {
                    return self.failProtocol(.protocol_violation, "bad SESSION_END length");
                }
                switch (self.state) {
                    .awaiting_ack => return self.failBeforeAuthorization(quic_wire.ErrCode.session_ended.code(), "session ended"),
                    .awaiting_first_resize, .active => {
                        self.beginDrain(.{ .kind = .session_end, .code = 0 });
                        self.pending_event = .session_end;
                    },
                    else => return self.failProtocol(.protocol_violation, "frame after terminal marker"),
                }
            },
            .err => {
                const parsed = quic_wire.parseErrorPayload(payload) catch {
                    return self.failProtocol(.protocol_violation, "bad ERROR payload");
                };
                if (parsed.reason.len > quic_wire.error_reason_max) {
                    return self.failProtocol(.protocol_violation, "oversized ERROR reason");
                }
                const rlen = @min(parsed.reason.len, self.err_buf.len);
                @memcpy(self.err_buf[0..rlen], parsed.reason[0..rlen]);
                self.err_len = rlen;
                // FINAL marks the fatal ERROR (control FIN follows);
                // flags zero is a nonterminal response and the
                // session continues. Pre-authorization, a terminal is
                // surfaced immediately with the wire's own code.
                if (h.isFinal()) {
                    switch (self.state) {
                        .awaiting_ack => return self.failBeforeAuthorization(parsed.code, parsed.reason),
                        .awaiting_first_resize, .active => {
                            self.beginDrain(.{ .kind = .err, .code = parsed.code });
                        },
                        else => return self.failProtocol(.protocol_violation, "frame after terminal marker"),
                    }
                }
                self.pending_event = .{ .err = .{
                    .code = parsed.code,
                    .reason = self.err_buf[0..rlen],
                    .terminal = h.isFinal(),
                } };
            },
            // The server never sends these in v1 — anything else on
            // the client's receive side is a protocol failure.
            .hello, .resize, .detach, .snapshot_request, .snapshot_installed => {
                return self.failProtocol(.protocol_violation, "illegal server frame");
            },
        }
    }

    // -- client sends -------------------------------------------------------

    /// RESIZE — the FIRST control frame after HELLO_ACK. A blocked
    /// send parks the whole encoded copy and SUCCEEDS; the state
    /// advances to active only once the frame was ACCEPTED in full
    /// (immediately or by `retryPendingSends`), exactly once.
    pub fn sendResize(self: *ClientSession, rows: u16, cols: u16, xpixel: u16, ypixel: u16) !void {
        const first = switch (self.state) {
            .awaiting_first_resize => true,
            .active => false,
            else => return error.NotActive,
        };
        var frame: [quic_wire.control_header_len + 8]u8 = undefined;
        quic_wire.writeControlHeader(frame[0..quic_wire.control_header_len], .resize, 8, 0);
        quic_wire.writeResizePayload(frame[quic_wire.control_header_len..][0..8], rows, cols, xpixel, ypixel);
        return self.sendFrameAtomic(if (first) .first_resize else .ordinary, frame[0..]);
    }

    pub fn sendDetach(self: *ClientSession) !void {
        switch (self.state) {
            .active => {},
            else => return error.NotActive,
        }
        var frame: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&frame, .detach, 0, 0);
        try self.sendFrameAtomic(.ordinary, frame[0..]);
        // Accepted (sent whole or parked whole): the bare FIN that
        // follows now completes the session cleanly.
        if (self.state == .active) self.state.active.detach_sent = true;
    }

    pub fn sendSnapshotRequest(self: *ClientSession) !void {
        switch (self.state) {
            .active => {},
            else => return error.NotActive,
        }
        var frame: [quic_wire.control_header_len]u8 = undefined;
        quic_wire.writeControlHeader(&frame, .snapshot_request, 0, 0);
        return self.sendFrameAtomic(.ordinary, frame[0..]);
    }

    /// Raw terminal input. Blocking semantics: when the input-preface
    /// send blocks, the preface stays staged in `preface_pending`
    /// (same stream, retried by `retryPendingSends`), the body bytes
    /// remain CALLER-OWNED and unsent, and the call returns
    /// error.WouldBlock. Retrying can neither duplicate bytes nor
    /// open a second stream.
    pub fn sendInput(self: *ClientSession, bytes: []const u8) !void {
        switch (self.state) {
            .active => {},
            else => return error.NotActive,
        }
        const t = self.inputTx() orelse return error.NotActive;
        switch (t.*) {
            .unopened => {
                const id = try self.transport.connection().openUniStream();
                if (id != input_stream_id) return error.UnexpectedInputStreamId;
                var pre: [quic_wire.preface_len]u8 = undefined;
                quic_wire.writePreface(&pre, .input);
                if (self.transport.connection().sendOnStream(input_stream_id, &pre, false)) {
                    t.* = .open;
                } else |e| switch (e) {
                    error.FlowControlBlocked => {
                        // The preface copy is staged; nothing else has
                        // been sent on this stream.
                        t.* = .{ .preface_pending = pre };
                        return error.WouldBlock;
                    },
                    error.StreamClosed => {
                        t.* = .closed;
                        return error.StreamClosed;
                    },
                    error.ConnectionClosed => {
                        self.recordPeerCloseFromTransport();
                        return error.ConnectionClosed;
                    },
                    else => return e,
                }
            },
            .preface_pending => return error.WouldBlock,
            .closed => return error.StreamClosed,
            .open => {},
        }
        if (bytes.len == 0) return;
        if (self.transport.connection().sendOnStream(input_stream_id, bytes, false)) {} else |e| switch (e) {
            error.FlowControlBlocked => return error.WouldBlock,
            error.StreamClosed => {
                t.* = .closed;
                return error.StreamClosed;
            },
            error.ConnectionClosed => {
                self.recordPeerCloseFromTransport();
                return error.ConnectionClosed;
            },
            else => return e,
        }
    }

    // -- output stream (server → client), parked until authorized ---------

    /// Reads output bytes ONLY once HELLO_ACK validated the session;
    /// before that, bytes stay parked in QUIC (unconsumed, credit
    /// withheld) — `outputRx()` is null in awaiting_ack. Header reads
    /// take EXACTLY the missing bytes; on header completion the same
    /// call continues directly into a body read; an epoch other than
    /// 1 is invalid in Q3 and takes the failure path. `epoch_out`
    /// reports the epoch once. Output stays readable through
    /// `.draining` — a terminal control frame never strands it.
    pub fn pollOutput(self: *ClientSession, buf: []u8, epoch_out: ?*u64) !?usize {
        const orx = self.outputRx() orelse return null;
        const conn = self.transport.connection();
        if (orx.* == .header) {
            const want = self.output_hdr.remaining();
            var header_done = false;
            if (want > 0) {
                var hbuf: [quic_wire.output_header_len]u8 = undefined;
                const got = conn.recvOnStream(output_stream_id, hbuf[0..want]) catch |e| switch (e) {
                    error.StreamClosed => {
                        orx.* = .reset;
                        self.failProtocol(.protocol_violation, "output stream reset");
                        return null;
                    },
                    error.ConnectionClosed => {
                        self.recordPeerCloseFromTransport();
                        return null;
                    },
                    else => return e,
                };
                const n = got orelse 0;
                if (n > 0) {
                    const r = self.output_hdr.feed(hbuf[0..n]);
                    switch (r.result) {
                        .done => |epoch| {
                            if (epoch != 1) {
                                self.failProtocol(.protocol_violation, "invalid output epoch");
                                return null;
                            }
                            orx.* = .{ .body = .{ .epoch = epoch } };
                            if (epoch_out) |o| o.* = epoch;
                            header_done = true;
                        },
                        .need => return null,
                        .invalid => |e| {
                            self.failProtocol(quic_wire.prefaceErrCode(e), "bad output header");
                            return null;
                        },
                    }
                } else {
                    self.resolveOutputFin(orx);
                    return null;
                }
            } else {
                header_done = true;
            }
            if (!header_done) return null;
        }
        switch (orx.*) {
            .body => {},
            else => return null,
        }
        const got = conn.recvOnStream(output_stream_id, buf) catch |e| switch (e) {
            error.StreamClosed => {
                orx.* = .reset;
                self.failProtocol(.protocol_violation, "output stream reset");
                return null;
            },
            error.ConnectionClosed => {
                self.recordPeerCloseFromTransport();
                return null;
            },
            else => return e,
        };
        const n = got orelse {
            self.resolveOutputFin(orx);
            return null;
        };
        // Zero means only flow-control bookkeeping was emitted.
        if (n == 0) {
            self.resolveOutputFin(orx);
            return null;
        }
        return n;
    }

    /// A FIN observed while no output bytes remain: clean from the
    /// body phase (record the epoch and finish); a FIN before the
    /// complete header is a truncated-stream violation.
    fn resolveOutputFin(self: *ClientSession, orx: *OutputRx) void {
        const finished = self.transport.connection().recvStreamFinished(output_stream_id) catch return;
        if (!finished) return;
        switch (orx.*) {
            .body => |b| orx.* = .{ .finished = .{ .epoch = b.epoch } },
            .header => self.failProtocol(.protocol_violation, "truncated output header"),
            else => {},
        }
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
        var session = try ClientSession.init(alloc, transport);
        errdefer session.deinit();
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
        errdefer c.parked.deinit(alloc);
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
        return self.session.failLocal(code, reason);
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
    const ev3: ControlEvent = .{ .err = .{ .code = 8, .reason = "snapshot is Q4", .terminal = false } };
    switch (ev3) {
        .err => |e| {
            try testing.expectEqual(@as(u32, 8), e.code);
            try testing.expectEqualStrings("snapshot is Q4", e.reason);
            try testing.expect(!e.terminal);
        },
        else => return error.TestUnexpectedResult,
    }
    const ev4: ControlEvent = .{ .err = .{ .code = 1, .reason = "fatal", .terminal = true } };
    switch (ev4) {
        .err => |e| try testing.expect(e.terminal),
        else => return error.TestUnexpectedResult,
    }
}

test "client max frame bound is the preface + header + HELLO" {
    try testing.expectEqual(@as(usize, 64), client_max_frame);
    try testing.expectEqual(quic_wire.preface_len + quic_wire.control_header_len + quic_wire.hello_payload_len, client_max_frame);
}
