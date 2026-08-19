//! Thin QUIC transport adapter over the quicz sans-I/O API (Phase Q2).
//!
//! One `Transport` is one QUIC endpoint — the client side or the gateway
//! side of a zmosh connection. It owns the quicz
//! `EndpointConnectionLifecycle`, `Connection`, and TLS backend, and
//! nothing else: datagrams in (every long datagram routes first — one
//! whose DCID does not route to this endpoint on its registered path is
//! discarded before any processing), datagrams out (checked against the
//! fixed payload invariants), deadlines, and counters. It owns no
//! terminal or command semantics; the socket fd, poll() integration,
//! stream roles, and the Retry boundary (token policy,
//! `PendingRetrySlot`, candidate adoption) live in the gateway layer
//! above it.
//!
//! Authentication is the frozen Q1 contract: certificate-free
//! external-PSK TLS 1.3, PSK = HKDF-SHA256(salt `zmosh quic psk v1`,
//! IKM = the 32-byte SSH-bootstrap secret) expanded with info
//! `zmosh-ssh-bootstrap-v1`; no session tickets, no resumption, no
//! 0-RTT. Callers own the mutable bootstrap original and wipe it; every
//! secret this struct holds is wiped through one internal path on
//! `destroy` before any storage is freed.
//!
//! Payload sizes are fixed: Initial datagrams at least 1200 bytes,
//! every emitted datagram at most `max_udp_payload` (1232) — checked
//! at runtime, an oversized emission frees the datagram and returns an
//! error — and oversized inbound datagrams are discarded and counted.

const std = @import("std");
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

const log = std.log.scoped(.quic_transport);

/// Fixed external-PSK identity (non-secret).
pub const psk_identity = "zmosh-ssh-bootstrap-v1";

// ─── Frozen production parameters (plan Q2 correction contract) ──────

/// QUIC Initial datagram minimum: the 1200-byte floor.
pub const min_initial_dgram = 1200;
/// Fixed v1 maximum UDP payload. No DPLPMTUD; never an IP-fragmenting
/// datagram. 1232 rather than exactly 1200 because quicz pads Initial
/// datagrams up to the floor and the varint length field can converge
/// 1-2 bytes above it; 1232 stays within the IPv6-minimum-MTU payload.
pub const max_udp_payload = 1232;
/// Connection flow-control credit.
pub const connection_credit: u64 = 4 * 1024 * 1024;
/// Per-stream initial flow-control credit.
pub const stream_credit: u64 = 2 * 1024;
pub const max_bidi_streams: u64 = 4;
pub const max_uni_streams: u64 = 8;
/// Negotiated idle lifetime (scaled-down timer proofs, never a literal
/// 24-hour run).
pub const idle_timeout_ms: u64 = 24 * 60 * 60 * 1000;

/// Plan Q2: PSK = HKDF-SHA256(bootstrap secret) with the fixed context
/// `zmosh quic psk v1`. Writes the derived PSK into `out` in place; the
/// caller owns the mutable bootstrap original and wipes it. The
/// extracted PRK is wiped by an immediate defer so every exit path
/// scrubs it.
pub fn derivePsk(out: *[32]u8, bootstrap_secret: *const [32]u8) void {
    const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
    var prk = HkdfSha256.extract("zmosh quic psk v1", bootstrap_secret);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&prk));
    HkdfSha256.expand(out, psk_identity, prk);
}

/// Counters and durations only — never session content, command
/// bodies, labels, paths, snapshot bytes, or secrets.
pub const Counters = struct {
    datagrams_received: usize = 0,
    datagrams_sent: usize = 0,
    datagrams_discarded: usize = 0,
    protocol_violations: usize = 0,
    migrations_committed: usize = 0,
};

/// Options for the CLIENT endpoint. The Retry exchange is driven by
/// the network: a `.retry` datagram handed to `handleDatagram` runs
/// the true quicz client sequence and rekeys Initial space.
pub const ClientOptions = struct {
    /// Derived PSK: a pointer, so callers own and wipe the mutable
    /// bootstrap original; this struct retains no copy.
    psk: *const [32]u8,
    /// This endpoint's Initial Source CID (random in production; four
    /// bytes keeps the padded Initial within the fixed payload).
    scid: [4]u8,
    /// The client's chosen first-flight DCID (random in production);
    /// its Initial secrets derive from it until a Retry rekeys them.
    original_dcid: [8]u8,
};

/// Options for the VALIDATED SERVER CANDIDATE. Created only after the
/// gateway's Retry boundary has classified the follow-up Initial: the
/// stored exchange comes from the slot above this adapter, and Initial
/// secrets derive from the Retry SCID — never the first-flight ODCID.
pub const ServerCandidateOptions = struct {
    psk: *const [32]u8,
    /// The Retry SCID the gateway issued: this connection's SCID.
    retry_scid: [4]u8,
    /// The stored exchange, from the slot: the first flight's original
    /// DCID and client SCID, and the issued token bytes.
    original_dcid: [8]u8,
    client_scid: [4]u8,
    token: []const u8,
    now_nanos: i64,
};

/// One QUIC endpoint. Heap-held: nothing moves after creation.
pub const Transport = struct {
    alloc: std.mem.Allocator,
    lifecycle: *quicz.EndpointConnectionLifecycle,
    conn: *Connection,
    backend: *Tls13Backend,
    /// Initial-space secrets: derived at creation (client: from its
    /// original DCID; server candidate: from the Retry SCID) and
    /// re-derived on the client when a Retry rekeys Initial space.
    secrets: ?protection.InitialSecrets,
    is_server: bool,
    /// This endpoint's own SCID.
    scid: [4]u8,
    /// The handshake's original destination CID (the client's
    /// first-flight DCID, supplied by the slot for a server candidate).
    /// The post-Retry key DCID is NOT duplicated here: quicz owns it
    /// (`retrySourceConnectionId`).
    odcid_buf: [20]u8 = undefined,
    odcid_len: usize = 0,
    scratch: [16384]u8 = undefined,
    counters: Counters = .{},

    /// Build every resource as a local with an adjacent errdefer that
    /// releases exactly what exists, then transfer ownership in one
    /// assignment; no partially initialized transport is observable.
    pub fn createClient(alloc: std.mem.Allocator, opts: ClientOptions) !*Transport {
        var secrets = try protection.deriveInitialSecrets(.v1, &opts.original_dcid);
        errdefer protection.secureWipeInitialSecrets(&secrets);
        const t = try createEndpoint(alloc, .client, opts.psk, opts.scid, &secrets);
        // The constructor's stack original is dead from here on; wipe
        // it so exactly one live copy remains.
        protection.secureWipeInitialSecrets(&secrets);
        t.odcid_buf[0..opts.original_dcid.len].* = opts.original_dcid;
        t.odcid_len = opts.original_dcid.len;
        return t;
    }

    /// The server candidate exists only after the gateway's Retry
    /// boundary. Its Initial secrets derive from the Retry SCID; the
    /// stored exchange is installed via `issueRetryDatagram`, whose
    /// reconstruction datagram is freed here and never sent (the slot
    /// already answered the first flight). The validated Retry-slot
    /// client SCID is pre-bound as the peer's Initial source CID, so
    /// the protected follow-up Initial verifies against it and all
    /// server output is addressed from quicz's own stored state.
    pub fn createServerCandidate(alloc: std.mem.Allocator, opts: ServerCandidateOptions) !*Transport {
        var secrets = try protection.deriveInitialSecrets(.v1, &opts.retry_scid);
        errdefer protection.secureWipeInitialSecrets(&secrets);
        const t = try createEndpoint(alloc, .server, opts.psk, opts.retry_scid, &secrets);
        errdefer t.destroy();
        protection.secureWipeInitialSecrets(&secrets);

        try t.conn.setPeerInitialSourceConnectionId(&opts.client_scid);
        // The gateway validated the peer address out-of-band (SSH
        // bootstrap + Retry) before this candidate was adopted.
        try t.conn.validatePeerAddress();
        const reconstruction = try t.conn.issueRetryDatagram(
            opts.now_nanos,
            &opts.original_dcid,
            &opts.client_scid,
            &opts.retry_scid,
            opts.token,
        );
        // Never sent: the slot's Retry already answered the first
        // flight. Freed immediately.
        alloc.free(reconstruction);
        if (t.conn.pendingRetryTokenCount() != 1) return error.RetryExchangeNotInstalled;

        t.odcid_buf[0..opts.original_dcid.len].* = opts.original_dcid;
        t.odcid_len = opts.original_dcid.len;
        return t;
    }

    fn createEndpoint(
        alloc: std.mem.Allocator,
        side: quicz.ConnectionSide,
        psk: *const [32]u8,
        scid: [4]u8,
        secrets: *const protection.InitialSecrets,
    ) !*Transport {
        const lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
        errdefer alloc.destroy(lifecycle);
        lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
        errdefer lifecycle.deinit();

        const conn = try alloc.create(Connection);
        errdefer alloc.destroy(conn);
        conn.* = try Connection.init(alloc, side, .{
            .initial_max_data = connection_credit,
            .initial_max_stream_data = stream_credit,
            .initial_max_streams_bidi = max_bidi_streams,
            .initial_max_streams_uni = max_uni_streams,
            .max_datagram_size = max_udp_payload,
            .max_idle_timeout_ms = idle_timeout_ms,
        });
        errdefer conn.deinit();
        try conn.setLocalInitialSourceConnectionId(&scid);

        const backend = try alloc.create(Tls13Backend);
        errdefer alloc.destroy(backend);
        backend.* = if (side == .server)
            Tls13Backend.initServerWithPsk(.{
                .alpn = &alpn_zmosh,
                .disable_session_resumption = true,
                // No certificate material: PSK-only or fail.
            }, psk.*)
        else
            Tls13Backend.initClientWithPsk(.{
                .alpn = &alpn_zmosh,
                .server_name = "zmosh",
                .disable_session_resumption = true,
            }, psk.*);
        errdefer backend.secureWipe();
        if (side == .server)
            try backend.setServerPskIdentity(psk_identity)
        else
            try backend.setClientPskIdentity(psk_identity);

        const t = try alloc.create(Transport);
        errdefer alloc.destroy(t);
        t.* = .{
            .alloc = alloc,
            .lifecycle = lifecycle,
            .conn = conn,
            .backend = backend,
            .secrets = secrets.*,
            .is_server = side == .server,
            .scid = scid,
        };
        return t;
    }

    /// The single wipe path: every secret this transport holds — the
    /// TLS backend (key schedules, PSK, ephemeral keys) and the
    /// Initial secrets — zeroed here and nowhere else.
    fn wipeSecrets(self: *Transport) void {
        self.backend.secureWipe();
        if (self.secrets) |*s| protection.secureWipeInitialSecrets(s);
    }

    /// Teardown: wipe through `wipeSecrets`, then free.
    pub fn destroy(self: *Transport) void {
        const alloc = self.alloc;
        self.wipeSecrets();
        self.conn.deinit();
        self.lifecycle.deinit();
        alloc.destroy(self.backend);
        alloc.destroy(self.conn);
        alloc.destroy(self.lifecycle);
        alloc.destroy(self);
    }

    /// The connection, for the protocol layer's stream calls. Thin
    /// escape hatch: stream semantics stay out of this module.
    pub fn connection(self: *Transport) *Connection {
        return self.conn;
    }

    pub fn handshakeConfirmed(self: *const Transport) bool {
        return self.conn.handshakeConfirmed();
    }

    /// Register one destination CID this endpoint receives on, under
    /// the path its socket is bound to. The gateway registers CIDs as
    /// the handshake establishes them; the server candidate registers
    /// its Retry SCID (the follow-up Initial's DCID).
    pub fn registerRouteCid(self: *Transport, cid: []const u8, local: quicz.endpoint.UdpAddress, remote: quicz.endpoint.UdpAddress) !void {
        try self.lifecycle.router.registerConnectionIdAddress(
            handle,
            cid,
            .{ .local = local, .remote = remote },
            .{},
        );
    }

    /// Register this endpoint's own SCID as a destination CID.
    pub fn registerRoute(self: *Transport, local: quicz.endpoint.UdpAddress, remote: quicz.endpoint.UdpAddress) !void {
        try self.registerRouteCid(&self.scid, local, remote);
    }

    /// Next deadline (recovery, close, idle) in absolute nanoseconds,
    /// for the caller's poll()-timeout composition.
    pub fn nextDeadlineNanos(self: *Transport) ?i64 {
        const d = self.lifecycle.nextDeadline(handle, self.conn) orelse return null;
        return d.deadline_nanos;
    }

    const handle: u64 = 1;

    /// Feed one received datagram with its arrival path. Oversized
    /// datagrams are discarded and counted. Network-originated
    /// malformed packets never fail the caller's loop; authenticated
    /// protocol violations close the connection through quicz's own
    /// OrClose processors; local errors propagate.
    /// Feed one received datagram with its arrival path and the
    /// caller's pre-generated migration challenge. Returns whether the
    /// challenge bytes were CONSUMED — queued as exactly one
    /// path-bound PATH_CHALLENGE by authenticated changed-path
    /// processing; Initial, Handshake, Retry, and invalid traffic never
    /// consume it. The caller rotates its challenge only on `true`.
    pub fn handleDatagram(
        self: *Transport,
        arrival: quicz.endpoint.UdpTuple,
        now_nanos: i64,
        data: []const u8,
        challenge: *const [8]u8,
    ) !bool {
        self.counters.datagrams_received += 1;
        if (data.len > max_udp_payload) {
            self.counters.datagrams_discarded += 1;
            return false;
        }
        const info = protection.peekProtectedLongPacketInfo(data) catch |peek_err| switch (peek_err) {
            // Retry packets are long headers that carry no header
            // protection, so the peek rejects them; classify by the
            // long-header type bits (0b11 = Retry, RFC 9000 §17.2.2).
            error.UnsupportedPacketType => {
                if (data.len > 0 and (data[0] & 0xC0) == 0xC0 and (data[0] & 0x30) == 0x30) {
                    if (try self.routeVerified(arrival, data)) try self.processRetry(now_nanos, data);
                } else {
                    self.counters.datagrams_discarded += 1;
                }
                return false;
            },
            // Anything the long-prefix parser rejects as non-long is a
            // short header: 1-RTT application data through the
            // canonical guarded entry that also commits validated
            // route changes and carries the migration challenge.
            else => {
                return try self.processShort(arrival, now_nanos, data, challenge);
            },
        };
        switch (info.packet_type) {
            .initial => if (try self.routeVerified(arrival, data)) try self.processInitial(now_nanos, data),
            .handshake => if (try self.routeVerified(arrival, data)) try self.processHandshake(now_nanos, data),
            // v1 sends no 0-RTT and accepts no Version Negotiation
            // beyond the pinned version: both are foreign traffic.
            else => self.counters.datagrams_discarded += 1,
        }
        return false;
    }

    /// Route-first dispatch for every long datagram: its DCID must
    /// route to THIS transport's handle on the REGISTERED path. Any
    /// network routing failure — unknown or ambiguous CID, malformed
    /// header — or a changed path discards the datagram before any
    /// packet processing; a locally generated `OutOfMemory` propagates
    /// loudly instead of masquerading as network traffic. Path
    /// migration is validated 1-RTT behavior (the short entry), never
    /// a long-space event.
    fn routeVerified(self: *Transport, arrival: quicz.endpoint.UdpTuple, data: []const u8) !bool {
        const route = self.lifecycle.routeAndVerifyDatagramAddress(handle, arrival, data) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                self.counters.datagrams_discarded += 1;
                return false;
            },
        };
        if (route.path_changed) {
            self.counters.datagrams_discarded += 1;
            return false;
        }
        return true;
    }

    /// quicz's own OrClose processor for Initial space, behind the one
    /// shared receive-error classification. The stored secrets are
    /// BORROWED by pointer — the transport stays their sole owner and
    /// no stack copy is ever taken.
    fn processInitial(self: *Transport, now_nanos: i64, data: []const u8) !void {
        const was_active = self.conn.connectionState() == .active;
        if (self.secrets) |*secrets| {
            _ = self.lifecycle.processProtectedLongDatagramOrClose(
                handle,
                self.conn,
                now_nanos,
                .{ .initial = if (self.is_server) secrets.client else secrets.server },
                data,
            ) catch |err| return self.classifyReceive(was_active, err);
            self.noteViolation(was_active);
        } else {
            self.counters.datagrams_discarded += 1;
        }
    }

    fn processHandshake(self: *Transport, now_nanos: i64, data: []const u8) !void {
        if (!self.conn.hasHandshakeProtectionKeys()) {
            // A Handshake-space datagram racing ahead of key
            // installation is dropped; retransmission recovers.
            self.counters.datagrams_discarded += 1;
            return;
        }
        const was_active = self.conn.connectionState() == .active;
        self.lifecycle.processProtectedHandshakeDatagramWithInstalledKeysOrClose(
            handle,
            self.conn,
            now_nanos,
            data,
        ) catch |err| return self.classifyReceive(was_active, err);
        self.noteViolation(was_active);
    }

    fn processShort(
        self: *Transport,
        arrival: quicz.endpoint.UdpTuple,
        now_nanos: i64,
        data: []const u8,
        challenge: *const [8]u8,
    ) !bool {
        const was_active = self.conn.connectionState() == .active;
        const res = self.lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndUpdatePathOrCloseAddressWithOptions(
            handle,
            self.conn,
            arrival,
            now_nanos,
            data,
            .{ .path_challenge_data = challenge.* },
        ) catch |err| {
            try self.classifyReceive(was_active, err);
            return false;
        };
        self.noteViolation(was_active);
        if (res.updated_route != null) self.counters.migrations_committed += 1;
        return res.path_challenge_queued;
    }

    /// The client's Retry sequence: validate the integrity tag, record
    /// token + Retry SCID, re-cache the ClientHello, rewind Initial
    /// send state, and rekey Initial space from the Retry SCID — the
    /// post-Retry key DCID, recorded separately from the first-flight
    /// ODCID. The replacement secrets exist on the stack only under an
    /// immediately-deferred wipe, so a reset failure can never leave
    /// them behind.
    fn processRetry(self: *Transport, now_nanos: i64, data: []const u8) !void {
        if (self.is_server) {
            self.counters.datagrams_discarded += 1;
            return;
        }
        const was_active = self.conn.connectionState() == .active;
        self.conn.processRetryDatagram(now_nanos, self.odcid_buf[0..self.odcid_len], data) catch |err| return self.classifyReceive(was_active, err);
        const rscid = self.conn.retrySourceConnectionId() orelse return error.NoRetryScid;
        var replacement = try protection.deriveInitialSecrets(.v1, rscid);
        defer protection.secureWipeInitialSecrets(&replacement);
        self.backend.retryReceived();
        try self.conn.resetInitialCryptoSendForRetry();
        if (self.secrets) |*s| protection.secureWipeInitialSecrets(s);
        self.secrets = replacement;
    }

    /// The one classification for every receive failure. A classified
    /// network-invalid result (`InvalidPacket`, `ConnectionClosed`)
    /// never fails the caller's loop: an authenticated violation — the
    /// packet decrypted and drove the connection active → closing —
    /// counts once as a protocol violation and returns normally so the
    /// queued close leaves through `pollOutbound`; anything else
    /// (still active, already closing/draining, or a tolerated close)
    /// is a discard. Every other error propagates loudly.
    fn classifyReceive(self: *Transport, was_active: bool, err: anyerror) !void {
        switch (err) {
            error.InvalidPacket, error.ConnectionClosed => {
                if (was_active and self.conn.connectionState() == .closing) {
                    self.counters.protocol_violations += 1;
                } else {
                    self.counters.datagrams_discarded += 1;
                }
            },
            else => return err,
        }
    }

    fn noteViolation(self: *Transport, was_active: bool) void {
        if (was_active and self.conn.connectionState() == .closing) {
            self.counters.protocol_violations += 1;
        }
    }

    /// Drive the TLS backend in one packet-number space (skipping
    /// spaces whose keys are already discarded).
    pub fn driveCrypto(self: *Transport, space: quicz.PacketNumberSpace, now_nanos: i64) !void {
        if (self.conn.packetNumberSpaceDiscarded(space)) return;
        _ = try self.lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            handle,
            self.conn,
            space,
            self.backend.cryptoBackend(),
            &self.scratch,
        );
        _ = now_nanos;
    }

    /// Poll the next outbound datagram (Initial, Handshake, or 1-RTT
    /// space, in that order) — the shared per-space helpers, path
    /// facts discarded. Caller owns and frees the result. Every
    /// emission is checked against the fixed cap: an oversized
    /// datagram is freed and reported as a local error (never a
    /// debug-only assertion). Only polling a closed endpoint is a
    /// tolerated non-event; encoding/invariant errors propagate.
    pub fn pollOutbound(self: *Transport, now_nanos: i64) !?[]u8 {
        if (try self.pollInitialSpace(now_nanos)) |e| return e.dg;
        if (try self.pollHandshakeSpace(now_nanos)) |e| return e.dg;
        if (try self.pollShortSpace(now_nanos)) |e| return e.dg;
        return null;
    }

    /// One datagram in hand plus the egress facts quicz derived from
    /// the packet actually built: the path-validation binding (null =
    /// the committed route applies) and whether the packet carries a
    /// PING frame.
    const SpaceEgress = struct {
        dg: []u8,
        path_override: ?quicz.endpoint.UdpTuple = null,
        emitted_ping: bool = false,
    };

    /// The Initial-space emission, invariant-checked
    /// (`initialChecked`).
    fn pollInitialSpace(self: *Transport, now_nanos: i64) !?SpaceEgress {
        if (self.conn.packetNumberSpaceDiscarded(.initial)) return null;
        if (self.secrets) |*secrets| {
            if (self.lifecycle.pollProtectedLongDatagram(
                handle,
                self.conn,
                now_nanos,
                self.initialDst(),
                &self.scid,
                &[_]u8{},
                .{ .initial = if (self.is_server) secrets.server else secrets.client },
            )) |maybe| {
                if (maybe) |dg| return .{ .dg = (try self.initialChecked(dg)).? };
            } else |err| switch (err) {
                error.ConnectionClosed => {},
                else => return err,
            }
        }
        return null;
    }

    /// The Handshake-space emission with installed keys.
    fn pollHandshakeSpace(self: *Transport, now_nanos: i64) !?SpaceEgress {
        if (self.conn.packetNumberSpaceDiscarded(.handshake)) return null;
        if (!self.conn.hasHandshakeProtectionKeys()) return null;
        if (self.lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
            handle,
            self.conn,
            now_nanos,
            self.dstCid(),
            &self.scid,
        )) |maybe| {
            if (maybe) |dg| return .{ .dg = (try self.checked(dg)).? };
        } else |err| switch (err) {
            error.ConnectionClosed => {},
            else => return err,
        }
        return null;
    }

    /// The 1-RTT short-space emission with installed keys, carrying
    /// quicz's atomic egress facts.
    fn pollShortSpace(self: *Transport, now_nanos: i64) !?SpaceEgress {
        if (!self.conn.hasOneRttProtectionKeys()) return null;
        if (self.lifecycle.pollProtectedShortDatagramWithInstalledKeysAndPath(
            handle,
            self.conn,
            now_nanos,
            self.dstCid(),
        )) |maybe| {
            if (maybe) |egress| return .{
                .dg = (try self.checked(egress.datagram)).?,
                .path_override = egress.path_override,
                .emitted_ping = egress.emitted_ping,
            };
        } else |err| switch (err) {
            error.ConnectionClosed => {},
            else => return err,
        }
        return null;
    }

    /// The fixed-cap invariant: free an oversized emission and report
    /// it as a local error.
    fn checked(self: *Transport, dg: []u8) !?[]u8 {
        if (dg.len > max_udp_payload) {
            self.alloc.free(dg);
            return error.DatagramExceedsFixedCap;
        }
        self.counters.datagrams_sent += 1;
        return dg;
    }

    /// One outbound datagram together with the UDP path it must be
    /// sent on — never inferred from pending state: short-space output
    /// carries quicz's atomic egress binding (the frame the packet
    /// actually contains, plus whether it holds a PING);
    /// Initial/Handshake output uses the committed route for THIS
    /// endpoint's own CID. Caller owns and frees `dg`.
    pub const TaggedDatagram = struct {
        dg: []u8,
        dst: quicz.endpoint.UdpTuple,
        emitted_ping: bool = false,
    };

    /// Bind one in-hand emission to its destination, freeing the
    /// datagram when the committed route cannot be resolved.
    fn tagRouted(self: *Transport, e: SpaceEgress) !TaggedDatagram {
        errdefer self.alloc.free(e.dg);
        return .{
            .dg = e.dg,
            .dst = e.path_override orelse try self.routePath(),
            .emitted_ping = e.emitted_ping,
        };
    }

    pub fn pollOutboundPath(self: *Transport, now_nanos: i64) !?TaggedDatagram {
        if (try self.pollInitialSpace(now_nanos)) |e| return try self.tagRouted(e);
        if (try self.pollHandshakeSpace(now_nanos)) |e| return try self.tagRouted(e);
        if (try self.pollShortSpace(now_nanos)) |e| return try self.tagRouted(e);
        return null;
    }

    /// The committed route for this endpoint's own CID — the
    /// destination for every emission without an explicit path
    /// binding.
    fn routePath(self: *Transport) !quicz.endpoint.UdpTuple {
        return self.lifecycle.currentRoutePathAddress(&self.scid) catch error.NoRegisteredPath;
    }

    /// The result of servicing a due QUIC deadline: the full tagged
    /// datagram when recovery produced output, or the retirement arm
    /// when the lifecycle retired the connection (its routes are
    /// already gone — the owner drops the record, it does not
    /// re-retire).
    pub const ServiceResult = union(enum) {
        datagram: TaggedDatagram,
        idle_retired,
        close_retired,
        no_output,
    };

    /// Service the earliest due deadline: idle/close expiry retires
    /// the connection through the lifecycle; key-discard and PTO
    /// recovery are serviced. The CAPTURED deadline kind gates the
    /// recovery arm — on a delayed wakeup an earlier key-discard and a
    /// later recovery deadline can BOTH be due, and
    /// `processPendingWork` services both; the frozen key-discard
    /// contract stays `no_output`. The space dispatched is the
    /// AUTHORITATIVE serviced timer, and a serviced PTO's
    /// retransmission comes from exactly that space — never from
    /// unrelated pending output. Plain `nextDeadlineNanos` only
    /// REPORTS a deadline — this services it.
    pub fn serviceDueDeadline(self: *Transport, now_nanos: i64) !ServiceResult {
        const deadline = self.lifecycle.nextDeadline(handle, self.conn) orelse return .no_output;
        if (deadline.deadline_nanos > now_nanos) return .no_output;
        const work = try self.lifecycle.processPendingWork(handle, self.conn, now_nanos);
        if (work.idle_retired != null) return .idle_retired;
        if (work.close_retired != null) return .close_retired;
        if (deadline.kind != .recovery) return .no_output;
        const serviced = work.recovery_serviced orelse return .no_output;
        const egress = switch (serviced.timer.space) {
            .initial => try self.pollInitialSpace(now_nanos),
            .handshake => try self.pollHandshakeSpace(now_nanos),
            .application => try self.pollShortSpace(now_nanos),
        } orelse return .no_output;
        return .{ .datagram = try self.tagRouted(egress) };
    }

    /// Initial-space destination. The client sends to the Retry SCID
    /// once a Retry has been processed (else its first-flight ODCID);
    /// the server sends to the authenticated peer CID. All of it is
    /// quicz's own stored state — the connection inserts its stored
    /// Retry token automatically.
    fn initialDst(self: *const Transport) []const u8 {
        if (self.is_server) return self.dstCid();
        return self.clientInitialDst();
    }

    fn clientInitialDst(self: *const Transport) []const u8 {
        return self.conn.retrySourceConnectionId() orelse self.odcid_buf[0..self.odcid_len];
    }

    /// Destination CID for Handshake/1-RTT datagrams: the peer's
    /// selected CID, falling back to the peer's Initial source CID and
    /// then the client's Initial destination.
    fn dstCid(self: *const Transport) []const u8 {
        return self.conn.peerDestinationConnectionId() orelse self.clientInitialDst();
    }

    /// The Initial emission invariants, checked by re-parsing the
    /// ENCODED header through the same quicz peek used everywhere else
    /// and comparing against quicz's own stored CID state — an
    /// authority independent of the value handed to the encoder:
    /// every Initial is an Initial within the fixed cap and addressed
    /// to the authoritative destination; client Initials additionally
    /// meet the 1200 floor. A violation frees the datagram and is a
    /// local error. No ack-eliciting inference: a valid server
    /// ACK-only Initial may be under the floor.
    fn initialChecked(self: *Transport, dg: []u8) !?[]u8 {
        const authority = if (self.is_server)
            self.conn.peerInitialSourceConnectionId()
        else
            self.conn.retrySourceConnectionId() orelse self.odcid_buf[0..self.odcid_len];
        const info = protection.peekProtectedLongPacketInfo(dg) catch {
            self.alloc.free(dg);
            return error.InitialInvariantViolated;
        };
        const ok = info.packet_type == .initial and
            dg.len <= max_udp_payload and
            (self.is_server or dg.len >= min_initial_dgram) and
            authority != null and
            std.mem.eql(u8, info.dcid, authority.?);
        if (!ok) {
            self.alloc.free(dg);
            return error.InitialInvariantViolated;
        }
        self.counters.datagrams_sent += 1;
        return dg;
    }

    /// Queue an application CONNECTION_CLOSE and enter the closing
    /// state; the close frame leaves through `pollOutbound`.
    pub fn shutdown(self: *Transport, error_code: u64, reason: []const u8) !void {
        try self.conn.closeApplication(error_code, reason);
    }
};

const alpn_zmosh = [_][]const u8{"zmosh/1"};

const testing = std.testing;

// ─── Test fixture: the Retry boundary ABOVE the adapter ──────────────

/// One adopted candidate for the test registry: the server Transport
/// itself. The registry's deinit_record destroys the transport (whose
/// single wipe path runs first).
const CandidateRecord = struct {
    transport: *Transport,

    fn connectionOf(record: *CandidateRecord) *Connection {
        return record.transport.conn;
    }

    fn deinit(record: *CandidateRecord) void {
        // The registry destroys the record allocation itself; release
        // the contents only.
        record.transport.destroy();
    }
};

const CandidateRegistry = quicz.EndpointConnectionRegistry(
    CandidateRecord,
    CandidateRecord.connectionOf,
    CandidateRecord.deinit,
);

/// The gateway-side machinery the adapter deliberately does not own:
/// token policy, PendingRetrySlot, and private adoption. The token
/// secret's mutable original exists only inside `init`, wiped by an
/// immediate defer; the policy retains the sole copy and its `deinit`
/// wipes it.
const RetryBoundary = struct {
    policy: quicz.endpoint.AddressValidationPolicy,
    slot: quicz.pending_retry_slot.PendingRetrySlot = .{},
    registry: CandidateRegistry,
    nonce: quicz.address_validation_token.Nonce,

    fn init(alloc: std.mem.Allocator) !RetryBoundary {
        var secret: quicz.address_validation_token.Secret = undefined;
        try testing.io.randomSecure(&secret);
        defer std.crypto.secureZero(u8, &secret);
        var policy = quicz.endpoint.AddressValidationPolicy.init(alloc, secret, .{});
        errdefer policy.deinit();
        var registry = try CandidateRegistry.initWithCapacity(alloc, 1);
        errdefer registry.deinit();
        return .{
            .policy = policy,
            .registry = registry,
            .nonce = [_]u8{0x42} ** quicz.address_validation_token.nonce_len,
        };
    }

    /// Full cleanup, run exactly once per boundary: removes the
    /// adopted candidate if present (whose deinit_record destroys the
    /// transport through its single wipe path), then releases the
    /// registry and the policy (whose deinit wipes its retained token
    /// secret).
    fn deinit(self: *RetryBoundary) void {
        self.registry.remove(1) catch {};
        self.registry.deinit();
        self.policy.deinit();
    }
};

const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const retry_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const test_challenge = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };

/// Create the server candidate and adopt it into the boundary's
/// private capacity-one registry WITHOUT installing a CID route. On
/// success the registry owns the record and the transport; the caller
/// cleans up through `RetryBoundary.deinit` (exactly once).
fn adoptCandidate(
    alloc: std.mem.Allocator,
    boundary: *RetryBoundary,
    opts: ServerCandidateOptions,
) !*Transport {
    const server = try Transport.createServerCandidate(alloc, opts);
    errdefer server.destroy();
    const record = try alloc.create(CandidateRecord);
    errdefer alloc.destroy(record);
    record.* = .{ .transport = server };
    try boundary.registry.adopt(1, record);
    return server;
}

/// Adopt as above, then install the CID route.
fn createAndAdopt(
    alloc: std.mem.Allocator,
    boundary: *RetryBoundary,
    opts: ServerCandidateOptions,
    local: quicz.endpoint.UdpAddress,
    remote: quicz.endpoint.UdpAddress,
) !*Transport {
    const server = try adoptCandidate(alloc, boundary, opts);
    try server.registerRoute(local, remote);
    return server;
}

/// The pre-candidate exchange everything upstream of adoption needs:
/// first flight → Retry → rekeyed follow-up Initial → classification.
/// The slot stays uncommitted; `commit_token` aliases bytes inside
/// `followup` (both die together in `deinit` — never freed separately).
const FirstExchange = struct {
    boundary: RetryBoundary,
    client: *Transport,
    client_path: quicz.endpoint.UdpTuple,
    server_path: quicz.endpoint.UdpTuple,
    followup: []u8,
    token: []u8,
    commit_token: []const u8,
    now_nanos: i64,

    fn open(alloc: std.mem.Allocator, psk: *const [32]u8) !FirstExchange {
        var boundary = try RetryBoundary.init(alloc);
        errdefer boundary.deinit();

        const client_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 40000);
        const server_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 41000);
        const client_path = quicz.endpoint.UdpTuple{ .local = client_local, .remote = server_local };
        const server_path = quicz.endpoint.UdpTuple{ .local = server_local, .remote = client_local };

        const client = try Transport.createClient(alloc, .{
            .psk = psk,
            .scid = client_scid,
            .original_dcid = original_dcid,
        });
        errdefer client.destroy();
        try client.registerRoute(client_local, server_local);

        // ── First flight: tokenless Initial. ─────────────────────────
        var now: i64 = 1000;
        try client.driveCrypto(.initial, now);
        const first = (try client.pollOutbound(now)) orelse return error.NoFirstInitial;
        defer alloc.free(first);
        try testing.expect(first.len >= min_initial_dgram);
        const supported = [_]quicz.packet.Version{.v1};
        const accept1 = (try quicz.endpoint.peekInitialAcceptDatagram(server_path, first, &supported)) orelse return error.FirstNotAccepted;

        // ── The boundary answers with a Retry through the slot. ──────
        const token = try boundary.policy.issueTokenForPath(alloc, .retry, now, 10 * std.time.ns_per_s, server_path, boundary.nonce);
        errdefer alloc.free(token);
        const retry = try boundary.slot.open(alloc, now, 10 * std.time.ns_per_s, server_path, .v1, accept1.original_destination_connection_id, accept1.source_connection_id, &retry_scid, token);
        _ = try client.handleDatagram(client_path, now, retry, &test_challenge);

        // ── Follow-up Initial: rekeyed, token echoed. ────────────────
        now += 1;
        try client.driveCrypto(.initial, now);
        const followup = (try client.pollOutbound(now)) orelse return error.NoFollowupInitial;
        errdefer alloc.free(followup);
        try testing.expect(followup.len >= min_initial_dgram);
        const accept2 = (try quicz.endpoint.peekInitialAcceptDatagram(server_path, followup, &supported)) orelse return error.FollowupNotAccepted;

        // ── Classify the exact stored exchange (still uncommitted). ──
        const decision = try boundary.slot.classify(
            &boundary.policy,
            now,
            server_path,
            .v1,
            accept2.original_destination_connection_id,
            accept2.source_connection_id,
            &retry_scid,
            accept2.token,
            followup.len,
            true,
        );
        switch (decision) {
            .validated => {},
            else => return error.ExpectedValidated,
        }
        try testing.expectEqual(@as(usize, 0), boundary.policy.replayFilterEntryCount());

        return .{
            .boundary = boundary,
            .client = client,
            .client_path = client_path,
            .server_path = server_path,
            .followup = followup,
            .token = token,
            .commit_token = accept2.token,
            .now_nanos = now,
        };
    }

    fn deinit(self: *FirstExchange, alloc: std.mem.Allocator) void {
        alloc.free(self.followup);
        alloc.free(self.token);
        self.client.destroy();
        self.boundary.deinit();
    }
};

/// One client/server transport pair performing the COMPLETE Retry
/// transaction — the loopback the Q2 gate requires before any custom
/// module is removed. Every datagram moves through `handleDatagram`
/// with route verification active: no direct-delivery bypass exists
/// anywhere in this fixture. Handshake-space datagrams that race ahead
/// of receiver key installation are parked and replayed after the next
/// drive (the same recovery the gateway's poll loop will own).
const TestPair = struct {
    client: *Transport,
    server: *Transport,
    boundary: RetryBoundary,
    client_path: quicz.endpoint.UdpTuple,
    server_path: quicz.endpoint.UdpTuple,
    now_nanos: i64 = 1000,
    parked: std.ArrayList([]u8) = .empty,
    parked_from_server: std.ArrayList(bool) = .empty,
    followup: []u8,
    token: []u8,
    /// Test-only injection: normal initialization uses 16 attempts; a
    /// zero-attempt regression test forces failure after the ownership
    /// transfer into the pair.
    handshake_attempts: usize = 16,

    fn init(alloc: std.mem.Allocator, psk: *const [32]u8) !TestPair {
        return initAttempts(alloc, psk, 16);
    }

    fn initAttempts(alloc: std.mem.Allocator, psk: *const [32]u8, handshake_attempts: usize) !TestPair {
        var ex = try FirstExchange.open(alloc, psk);
        // Exactly one owner cleans up on every return path: the
        // exchange until the pair is constructed, the pair after —
        // never both.
        var ex_owned = true;
        errdefer {
            if (ex_owned) ex.deinit(alloc);
        }
        const now = ex.now_nanos;

        // ── Create and PRIVATELY adopt the validated candidate. ──────
        // Ownership transfers to the registry inside the helper;
        // failures in this window unwind through `ex.deinit` alone.
        const server = try createAndAdopt(alloc, &ex.boundary, .{
            .psk = psk,
            .retry_scid = retry_scid,
            .original_dcid = original_dcid,
            .client_scid = client_scid,
            .token = ex.token,
            .now_nanos = now,
        }, ex.server_path.local, ex.server_path.remote);
        // Private ownership is not publication.
        try testing.expectEqual(@as(usize, 1), ex.boundary.registry.count());
        try testing.expectEqual(@as(usize, 1), ex.boundary.registry.activeCount());
        try testing.expectEqual(@as(usize, 1), server.lifecycle.router.routeCount());

        // ── Authenticate the follow-up Initial (routed: its DCID must
        // be this candidate's Retry SCID). ───────────────────────────
        _ = try server.handleDatagram(ex.server_path, now, ex.followup, &test_challenge);
        try server.driveCrypto(.initial, now);
        const sh = (try server.pollOutbound(now)) orelse return error.NotAuthenticated;
        defer alloc.free(sh);

        // The ServerHello is asserted by re-parsing its encoded header
        // through the same quicz peek production uses — an Initial,
        // addressed to the client's SCID, padded within the fixed
        // invariants (quicz pads ack-eliciting server Initials to the
        // 1200 floor).
        const sh_info = try protection.peekProtectedLongPacketInfo(sh);
        try testing.expect(sh_info.packet_type == .initial);
        try testing.expect(sh.len >= min_initial_dgram);
        try testing.expect(sh.len <= max_udp_payload);
        try testing.expectEqualSlices(u8, &client_scid, sh_info.dcid);

        // ── Commit BEFORE publication or echo. ───────────────────────
        try ex.boundary.slot.commit(&ex.boundary.policy, now, ex.commit_token);
        try testing.expect(!ex.boundary.slot.occupied);
        try testing.expectEqual(@as(usize, 1), ex.boundary.policy.replayFilterEntryCount());

        // Publication: the ServerHello (already authenticated) is now
        // delivered to the client — routed like every datagram here.
        _ = try ex.client.handleDatagram(ex.client_path, now, sh, &test_challenge);

        var pair = TestPair{
            .client = ex.client,
            .server = server,
            .boundary = ex.boundary,
            .client_path = ex.client_path,
            .server_path = ex.server_path,
            .now_nanos = now,
            .followup = ex.followup,
            .token = ex.token,
            .handshake_attempts = handshake_attempts,
        };
        // Ownership transfer: disarm the exchange's cleanup BEFORE
        // installing the pair's, so exactly one runs from here on.
        ex_owned = false;
        errdefer pair.deinit(alloc);
        try pair.completeHandshake(alloc);
        return pair;
    }

    fn deinit(self: *TestPair, alloc: std.mem.Allocator) void {
        for (self.parked.items) |dg| alloc.free(dg);
        self.parked.deinit(alloc);
        self.parked_from_server.deinit(alloc);
        alloc.free(self.followup);
        alloc.free(self.token);
        // Retire the adopted candidate (wipe-then-destroy), then the
        // boundary and the client.
        _ = self.boundary.registry.retire(self.server.lifecycle, 1) catch {};
        self.boundary.deinit();
        self.client.destroy();
    }

    /// Deliver one datagram, parking Handshake-space packets whose
    /// receiver has no keys yet.
    fn deliverOrPark(self: *TestPair, alloc: std.mem.Allocator, from_server: bool, dg: []const u8) !void {
        const receiver = if (from_server) self.client else self.server;
        const info = protection.peekProtectedLongPacketInfo(dg) catch {
            _ = try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg, &test_challenge);
            return;
        };
        if (info.packet_type == .handshake and !receiver.conn.hasHandshakeProtectionKeys()) {
            try self.parked.append(alloc, try alloc.dupe(u8, dg));
            try self.parked_from_server.append(alloc, from_server);
            return;
        }
        _ = try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg, &test_challenge);
    }

    fn arrivalFor(self: *const TestPair, from_server: bool) quicz.endpoint.UdpTuple {
        return if (from_server) self.client_path else self.server_path;
    }

    /// Replay parked Handshake-space datagrams whose receiver now has
    /// keys; still-early entries stay parked.
    fn flushParked(self: *TestPair, alloc: std.mem.Allocator) !void {
        var i: usize = 0;
        while (i < self.parked.items.len) {
            const dg = self.parked.items[i];
            const from_server = self.parked_from_server.items[i];
            const receiver = if (from_server) self.client else self.server;
            if (!receiver.conn.hasHandshakeProtectionKeys()) {
                i += 1;
                continue;
            }
            _ = try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg, &test_challenge);
            alloc.free(dg);
            _ = self.parked.orderedRemove(i);
            _ = self.parked_from_server.orderedRemove(i);
        }
    }

    /// Hand one side's outbound datagram to the other — ONE per call,
    /// mirroring a real poll() loop (recv, handle, try-send once);
    /// draining unboundedly would re-poll unacknowledged datagrams
    /// forever, and batching would fatten ACK ranges past the Initial
    /// padding floor.
    fn pump(self: *TestPair, alloc: std.mem.Allocator, from_server: bool) !void {
        const sender = if (from_server) self.server else self.client;
        const dg = (try sender.pollOutbound(self.now_nanos)) orelse return;
        defer alloc.free(dg);
        try self.deliverOrPark(alloc, from_server, dg);
    }

    /// Drive both backends in the spike-proven flight order until the
    /// handshake confirms on both sides. The attempt limit is the
    /// test-only injection point: 16 in normal initialization, 0 to
    /// force failure after the ownership transfer.
    fn completeHandshake(self: *TestPair, alloc: std.mem.Allocator) !void {
        var attempt: usize = 0;
        while (attempt < self.handshake_attempts) : (attempt += 1) {
            self.now_nanos += 1;

            // Flight 1-2: client Initial -> server drive -> ServerHello.
            try self.client.driveCrypto(.initial, self.now_nanos);
            try self.pump(alloc, false);
            try self.server.driveCrypto(.initial, self.now_nanos);
            try self.pump(alloc, true);

            // Flight 3: client processes the ServerHello, installs
            // handshake keys BEFORE any Handshake-space flight lands.
            try self.client.driveCrypto(.initial, self.now_nanos);
            try self.flushParked(alloc);

            // Flight 4-5: server's PSK-only Handshake flight, then the
            // client's Finished.
            try self.server.driveCrypto(.handshake, self.now_nanos);
            try self.pump(alloc, true);
            try self.client.driveCrypto(.handshake, self.now_nanos);
            try self.pump(alloc, false);

            // Flight 6: server confirms.
            try self.server.driveCrypto(.handshake, self.now_nanos);
            if (!self.server.handshakeConfirmed()) continue;
            // Flight 7: HANDSHAKE_DONE so the client confirms too.
            try self.server.conn.sendHandshakeDone();
            try self.pump(alloc, true);
            try self.client.driveCrypto(.handshake, self.now_nanos);
            try self.pump(alloc, false);
            if (self.server.handshakeConfirmed() and self.client.handshakeConfirmed()) {
                return;
            }
        }
        return error.HandshakeNotConfirmed;
    }
};

fn testPsk(bootstrap: *[32]u8, psk: *[32]u8) !void {
    try testing.io.randomSecure(bootstrap);
    derivePsk(psk, bootstrap);
}

/// Field-wise comparison of two InitialSecrets, both BORROWED by
/// pointer: every secret/key/IV/header-protection array by slices and
/// the cipher enums separately — the complete InitialSecrets value is
/// never extracted or passed.
fn expectInitialSecretsEqual(
    expected: *const protection.InitialSecrets,
    actual: *const protection.InitialSecrets,
) !void {
    try testing.expectEqualSlices(u8, &expected.initial_secret, &actual.initial_secret);
    const sides = .{ .{ &expected.client, &actual.client }, .{ &expected.server, &actual.server } };
    inline for (sides) |side| {
        try testing.expectEqual(side[0].cipher, side[1].cipher);
        try testing.expectEqualSlices(u8, &side[0].secret, &side[1].secret);
        try testing.expectEqualSlices(u8, &side[0].key, &side[1].key);
        try testing.expectEqualSlices(u8, &side[0].iv, &side[1].iv);
        try testing.expectEqualSlices(u8, &side[0].hp, &side[1].hp);
    }
}

test "Retry transaction loopback: adopt, authenticate, commit, echo both ways" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);
    try testing.expect(pair.client.handshakeConfirmed());
    try testing.expect(pair.server.handshakeConfirmed());
    // The transaction's after-state: exactly one adopted candidate,
    // the slot cleared, the replay filter consumed exactly once.
    try testing.expectEqual(@as(usize, 1), pair.boundary.registry.count());
    try testing.expect(!pair.boundary.slot.occupied);
    try testing.expectEqual(@as(usize, 1), pair.boundary.policy.replayFilterEntryCount());

    // Real bidirectional 1-RTT echo on one stream.
    const stream_id = try pair.client.connection().openStream();
    try pair.client.connection().sendOnStream(stream_id, "q2-loopback", false);
    var up: usize = 0;
    while (up < 8) : (up += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        _ = try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg, &test_challenge);
    }
    var buf: [128]u8 = undefined;
    const n = (try pair.server.connection().recvOnStream(stream_id, &buf)) orelse return error.NoUplink;
    try testing.expectEqualStrings("q2-loopback", buf[0..n]);

    try pair.server.connection().sendOnStream(stream_id, "q2-echo", true);
    var down: usize = 0;
    while (down < 8) : (down += 1) {
        const dg = (try pair.server.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        _ = try pair.client.handleDatagram(pair.client_path, pair.now_nanos, dg, &test_challenge);
    }
    var cbuf: [128]u8 = undefined;
    const cn = (try pair.client.connection().recvOnStream(stream_id, &cbuf)) orelse return error.NoDownlink;
    try testing.expectEqualStrings("q2-echo", cbuf[0..cn]);
    try testing.expect(pair.client.counters.datagrams_sent >= 1);
    try testing.expect(pair.server.counters.datagrams_received >= 1);
}

test "negotiated parameters match the frozen production limits" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);
    for ([_]*Transport{ pair.client, pair.server }) |t| {
        const params = t.conn.localTransportParameters();
        try testing.expectEqual(connection_credit, params.initial_max_data);
        try testing.expectEqual(stream_credit, params.initial_max_stream_data_bidi_local);
        try testing.expectEqual(stream_credit, params.initial_max_stream_data_bidi_remote);
        try testing.expectEqual(max_bidi_streams, params.initial_max_streams_bidi);
        try testing.expectEqual(max_uni_streams, params.initial_max_streams_uni);
        try testing.expectEqual(idle_timeout_ms, t.conn.effectiveIdleTimeout() orelse 0);
    }
}

test "migration: rebind + validate through the guarded feed" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);

    // The client rebinds to a new source port. Data still delivers by
    // DCID routing; the server's committed route must NOT move until
    // path validation completes.
    const old_remote = pair.server_path.remote;
    const new_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 40999);
    pair.client_path.local = new_local;
    pair.server_path.remote = new_local;

    const s = try pair.client.connection().openStream();
    try pair.client.connection().sendOnStream(s, "from-new-path", false);
    // The first authenticated changed-path packet CONSUMES the
    // caller's pre-generated challenge — the bridge queues exactly
    // one path-bound challenge — and no later packet consumes another.
    var bridge_consumed: usize = 0;
    var up: usize = 0;
    while (up < 8) : (up += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        if (try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg, &test_challenge)) bridge_consumed += 1;
    }
    try testing.expectEqual(@as(usize, 1), bridge_consumed);
    var buf: [128]u8 = undefined;
    const n = (try pair.server.connection().recvOnStream(s, &buf)) orelse return error.NoData;
    try testing.expectEqualStrings("from-new-path", buf[0..n]);

    // The bridge-queued challenge is pending; it becomes outstanding
    // once polled and sent, and the server answers nothing else
    // manually — the caller-supplied bytes were the only challenge.
    try testing.expectEqual(@as(usize, 1), pair.server.connection().pendingPathChallengeCount());

    // Transmit the challenge so it becomes outstanding, then answer it
    // until consumed and the route commits to the rebound path.
    try pair.pump(alloc, true);
    try testing.expectEqual(@as(usize, 1), pair.server.connection().outstandingPathChallengeCount());
    var rounds: usize = 0;
    while (pair.server.connection().outstandingPathChallengeCount() > 0 and rounds < 8) : (rounds += 1) {
        pair.now_nanos += 1;
        try pair.pump(alloc, false);
        try pair.pump(alloc, true);
    }
    try testing.expectEqual(@as(usize, 0), pair.server.connection().outstandingPathChallengeCount());
    const committed = try pair.server.lifecycle.currentRoutePathAddress(&retry_scid);
    try testing.expect(committed.remote.eql(new_local));
    try testing.expect(!committed.remote.eql(old_remote));
    try testing.expectEqual(@as(usize, 1), pair.server.counters.migrations_committed);

    // Traffic continues on the committed path.
    try pair.client.connection().sendOnStream(s, "after-migration", true);
    var up2: usize = 0;
    while (up2 < 8) : (up2 += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        _ = try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg, &test_challenge);
    }
    const n2 = (try pair.server.connection().recvOnStream(s, &buf)) orelse return error.NoDataAfterMigration;
    try testing.expectEqualStrings("after-migration", buf[0..n2]);
}

test "shutdown: initiator closing, peer draining, single wipe path" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    errdefer pair.deinit(alloc);

    // Application close: the frame leaves through pollOutbound.
    try pair.client.shutdown(0, "done");
    try testing.expect(pair.client.connection().connectionState() == .closing);
    var saw_close = false;
    var close_budget: usize = 0;
    while (close_budget < 8) : (close_budget += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        _ = try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg, &test_challenge);
        saw_close = true;
    }
    try testing.expect(saw_close);
    // The PEER receiving CONNECTION_CLOSE enters draining (both sides
    // reach closed only after their close deadlines).
    try testing.expect(pair.server.connection().connectionState() == .draining);

    // The single wipe path, exercised directly: the same fn destroy()
    // calls. Both secret sets zeroed while the transport exists.
    pair.client.wipeSecrets();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&pair.client.backend.hs.key_schedule.early_secret), 0));
    if (pair.client.secrets) |*s| {
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&s.client.secret), 0));
    }
    // destroy() wipes again (idempotent) and frees everything under
    // the testing allocator.
    pair.deinit(alloc);
}

test "wrong-PSK candidate: binder failure, no commit, registry retirement" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    var wrong_bootstrap: [32]u8 = undefined;
    var wrong_psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);
    try testing.io.randomSecure(&wrong_bootstrap);
    derivePsk(&wrong_psk, &wrong_bootstrap);
    defer std.crypto.secureZero(u8, &wrong_bootstrap);
    defer std.crypto.secureZero(u8, &wrong_psk);

    var ex = try FirstExchange.open(alloc, &psk);
    defer ex.deinit(alloc);

    // Adopted with the WRONG PSK: Initial protection is
    // PSK-independent, so the follow-up Initial still decrypts and its
    // CRYPTO frame lands in the server's buffer.
    const server = try createAndAdopt(alloc, &ex.boundary, .{
        .psk = &wrong_psk,
        .retry_scid = retry_scid,
        .original_dcid = original_dcid,
        .client_scid = client_scid,
        .token = ex.token,
        .now_nanos = ex.now_nanos,
    }, ex.server_path.local, ex.server_path.remote);
    _ = try server.handleDatagram(ex.server_path, ex.now_nanos, ex.followup, &test_challenge);

    // The TLS drive fails at the pre-shared-key binder (surfaced by
    // the lifecycle as CryptoError).
    try testing.expectError(error.CryptoError, server.driveCrypto(.initial, ex.now_nanos));

    // No commit: the slot is still occupied and the replay filter empty.
    try testing.expect(ex.boundary.slot.occupied);
    try testing.expectEqual(@as(usize, 0), ex.boundary.policy.replayFilterEntryCount());

    // Retirement destroys the server AND its lifecycle as one
    // operation — nothing is read from either afterward.
    const retired = try ex.boundary.registry.retire(server.lifecycle, 1);
    try testing.expectEqual(@as(usize, 1), retired.routes_retired);
    try testing.expectEqual(@as(usize, 0), ex.boundary.registry.count());
    try testing.expectEqual(@as(usize, 0), ex.boundary.registry.activeCount());
    try testing.expect(ex.boundary.slot.occupied);
    try testing.expectEqual(@as(usize, 0), ex.boundary.policy.replayFilterEntryCount());
}

test "unknown-CID Initial is discarded by routing; the same datagram is accepted once routed" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var ex = try FirstExchange.open(alloc, &psk);
    defer ex.deinit(alloc);

    // A real post-Retry server candidate, adopted into the private
    // registry but with NO CID route installed.
    const server = try adoptCandidate(alloc, &ex.boundary, .{
        .psk = &psk,
        .retry_scid = retry_scid,
        .original_dcid = original_dcid,
        .client_scid = client_scid,
        .token = ex.token,
        .now_nanos = ex.now_nanos,
    });

    // The GENUINE protected follow-up Initial — a datagram that would
    // decrypt and advance packet numbers if it ever reached packet
    // processing — is discarded by route lookup alone. This fails if
    // route-first dispatch is bypassed.
    try testing.expectEqual(@as(u64, 0), server.conn.nextPeerPacketNumber(.initial));
    const discards = server.counters.datagrams_discarded;
    _ = try server.handleDatagram(ex.server_path, ex.now_nanos, ex.followup, &test_challenge);
    try testing.expectEqual(discards + 1, server.counters.datagrams_discarded);
    try testing.expectEqual(@as(u64, 0), server.conn.nextPeerPacketNumber(.initial));
    try testing.expect(server.conn.connectionState() == .active);

    // Positive control: install the route and the IDENTICAL datagram
    // is accepted — the rejection above was routing, not AEAD.
    try server.registerRoute(ex.server_path.local, ex.server_path.remote);
    _ = try server.handleDatagram(ex.server_path, ex.now_nanos, ex.followup, &test_challenge);
    try testing.expect(server.conn.nextPeerPacketNumber(.initial) > 0);
}

test "initialChecked rejects an altered destination CID and frees the datagram" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var ex = try FirstExchange.open(alloc, &psk);
    defer ex.deinit(alloc);

    // A genuine emitted client Initial, duplicated and altered ONLY
    // in its encoded DCID — located through the same quicz peek
    // production uses, not by byte offsets.
    const bad = try alloc.dupe(u8, ex.followup);
    const info = try protection.peekProtectedLongPacketInfo(bad);
    @constCast(info.dcid)[0] ^= 0xff;

    const sent = ex.client.counters.datagrams_sent;
    try testing.expectError(error.InitialInvariantViolated, ex.client.initialChecked(bad));
    try testing.expectEqual(sent, ex.client.counters.datagrams_sent);
    // The rejected datagram was freed; the testing allocator proves it.
}

test "changed-path Initial is discarded before state change; correct path still delivers" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var ex = try FirstExchange.open(alloc, &psk);
    defer ex.deinit(alloc);

    const server = try createAndAdopt(alloc, &ex.boundary, .{
        .psk = &psk,
        .retry_scid = retry_scid,
        .original_dcid = original_dcid,
        .client_scid = client_scid,
        .token = ex.token,
        .now_nanos = ex.now_nanos,
    }, ex.server_path.local, ex.server_path.remote);

    // The same otherwise-valid follow-up Initial arrives from a
    // rebound source port: route verification discards it before
    // packet-number state changes.
    var moved = ex.server_path;
    moved.remote = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 40001);
    try testing.expectEqual(@as(u64, 0), server.conn.nextPeerPacketNumber(.initial));
    const discards = server.counters.datagrams_discarded;
    _ = try server.handleDatagram(moved, ex.now_nanos, ex.followup, &test_challenge);
    try testing.expectEqual(discards + 1, server.counters.datagrams_discarded);
    try testing.expectEqual(@as(u64, 0), server.conn.nextPeerPacketNumber(.initial));
    try testing.expect(server.conn.connectionState() == .active);

    // Delivered afterward on the registered path, the same datagram
    // still processes.
    _ = try server.handleDatagram(ex.server_path, ex.now_nanos, ex.followup, &test_challenge);
    try testing.expect(server.conn.nextPeerPacketNumber(.initial) > 0);
}

test "malformed Retry: integrity-tag corruption discards without rekey" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var boundary = try RetryBoundary.init(alloc);
    defer boundary.deinit();
    const client_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 40000);
    const server_local = quicz.endpoint.UdpAddress.init4([_]u8{ 127, 0, 0, 1 }, 41000);
    const client_path = quicz.endpoint.UdpTuple{ .local = client_local, .remote = server_local };
    const server_path = quicz.endpoint.UdpTuple{ .local = server_local, .remote = client_local };

    const client = try Transport.createClient(alloc, .{
        .psk = &psk,
        .scid = client_scid,
        .original_dcid = original_dcid,
    });
    defer client.destroy();
    try client.registerRoute(client_local, server_local);

    const now: i64 = 1000;
    try client.driveCrypto(.initial, now);
    const first = (try client.pollOutbound(now)) orelse return error.NoFirstInitial;
    defer alloc.free(first);
    const supported = [_]quicz.packet.Version{.v1};
    const accept1 = (try quicz.endpoint.peekInitialAcceptDatagram(server_path, first, &supported)) orelse return error.FirstNotAccepted;

    const token = try boundary.policy.issueTokenForPath(alloc, .retry, now, 10 * std.time.ns_per_s, server_path, boundary.nonce);
    defer alloc.free(token);
    const retry = try boundary.slot.open(alloc, now, 10 * std.time.ns_per_s, server_path, .v1, accept1.original_destination_connection_id, accept1.source_connection_id, &retry_scid, token);

    // Corrupt ONLY the Retry integrity tag (the trailing 16 bytes): a
    // correct path, the registered client CID, and a valid header, so
    // only the property under test — integrity — can reject it. The
    // slot's datagram is a view of its internal buffer: corrupt a
    // copy, leaving the slot itself untouched.
    const corrupt = try alloc.dupe(u8, retry);
    defer alloc.free(corrupt);
    corrupt[corrupt.len - 1] ^= 0xff;

    // Expected Initial secrets for a client that has NOT rekeyed:
    // derived from the first-flight ODCID into a mutable temporary
    // wiped the moment construction finishes — no by-value capture of
    // the transport's stored secrets.
    var expected = try protection.deriveInitialSecrets(.v1, &original_dcid);
    defer protection.secureWipeInitialSecrets(&expected);
    const discards = client.counters.datagrams_discarded;
    _ = try client.handleDatagram(client_path, now, corrupt, &test_challenge);
    try testing.expectEqual(discards + 1, client.counters.datagrams_discarded);
    // No rekey: no Retry SCID recorded, Initial secrets unchanged —
    // compared field-wise through borrowed pointers, never by
    // extracting the stored value.
    try testing.expect(client.conn.retrySourceConnectionId() == null);
    if (client.secrets) |*actual| {
        try expectInitialSecretsEqual(&expected, actual);
    } else {
        return error.NoInitialSecrets;
    }
    try testing.expect(client.conn.connectionState() == .active);
}

test "authenticated violation: fresh PN, closing, close via pollOutbound, peer drains" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);

    // A short packet the server will decrypt and authenticate — the
    // client's valid 1-RTT send keys (the server's peer keys) at the
    // exact packet number the server expects next — whose payload is
    // the fork's own unknown-frame pattern. Only the frame layer can
    // reject it.
    const pn = pair.server.conn.nextPeerPacketNumber(.application);
    const invalid_plaintext = [_]u8{0x1f} ++ ([_]u8{0} ** 31);
    // The key state is BORROWED from the connection, not retained as
    // a local copy.
    const bad = try protection.protectShortPacketAes128(alloc, .{
        .dcid = &retry_scid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = pn,
    }, try quicz.packet.encodePacketNumberForHeader(pn, null), pair.client.conn.local_one_rtt_key_phase_state.?.current, &invalid_plaintext);
    defer alloc.free(bad);

    const violations = pair.server.counters.protocol_violations;
    // Returns NORMALLY: the authenticated violation closed the
    // connection; the close frame leaves through pollOutbound.
    _ = try pair.server.handleDatagram(pair.server_path, pair.now_nanos, bad, &test_challenge);
    try testing.expectEqual(violations + 1, pair.server.counters.protocol_violations);
    try testing.expect(pair.server.conn.connectionState() == .closing);

    var saw_close = false;
    var budget: usize = 0;
    while (budget < 8) : (budget += 1) {
        const dg = (try pair.server.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        _ = try pair.client.handleDatagram(pair.client_path, pair.now_nanos, dg, &test_challenge);
        saw_close = true;
    }
    try testing.expect(saw_close);
    // The peer receiving CONNECTION_CLOSE enters draining.
    try testing.expect(pair.client.conn.connectionState() == .draining);
}

test "datagram bounds: oversized inbound discarded, oversized outbound freed" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);

    // Inbound: one byte past the fixed cap is discarded and counted
    // before any parsing, with no connection mutation.
    const oversize_in = try alloc.alloc(u8, max_udp_payload + 1);
    defer alloc.free(oversize_in);
    @memset(oversize_in, 0);
    const discards = pair.server.counters.datagrams_discarded;
    const state = pair.server.conn.connectionState();
    const oversize_queued = try pair.server.handleDatagram(pair.server_path, pair.now_nanos, oversize_in, &test_challenge);
    try testing.expect(!oversize_queued);
    try testing.expectEqual(discards + 1, pair.server.counters.datagrams_discarded);
    try testing.expectEqual(state, pair.server.conn.connectionState());

    // Outbound: a 1233-byte allocation through the checked-emission
    // path is freed and reported as a local error — the testing
    // allocator proves the free (a leak would fail the test).
    const oversize_out = try alloc.alloc(u8, max_udp_payload + 1);
    try testing.expectError(error.DatagramExceedsFixedCap, pair.client.checked(oversize_out));
}

test "failed handshake after ownership transfer cleans up exactly once" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    // Zero attempts: completeHandshake fails immediately AFTER the
    // pair owns every resource — exactly one cleanup (the pair's; the
    // exchange's errdefer is disarmed by the transfer) must run. The
    // testing allocator proves neither leaks nor double frees.
    try testing.expectError(
        error.HandshakeNotConfirmed,
        TestPair.initAttempts(alloc, &psk, 0),
    );
}

test "lost ServerHello recovers through Initial PTO via serviceDueDeadline" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var ex = try FirstExchange.open(alloc, &psk);
    defer ex.deinit(alloc);

    const server = try createAndAdopt(alloc, &ex.boundary, .{
        .psk = &psk,
        .retry_scid = retry_scid,
        .original_dcid = original_dcid,
        .client_scid = client_scid,
        .token = ex.token,
        .now_nanos = ex.now_nanos,
    }, ex.server_path.local, ex.server_path.remote);

    _ = try server.handleDatagram(ex.server_path, ex.now_nanos, ex.followup, &test_challenge);
    try server.driveCrypto(.initial, ex.now_nanos);
    const sh = (try server.pollOutbound(ex.now_nanos)) orelse return error.NotAuthenticated;
    // LOST: the ServerHello never reaches the client, no fd is
    // readable, and only the QUIC timer can make progress — the exact
    // scenario the installed-key-only due helper cannot service.
    alloc.free(sh);

    var now = ex.now_nanos;
    var attempt: usize = 0;
    while (attempt < 8) : (attempt += 1) {
        const deadline = server.nextDeadlineNanos() orelse break;
        now = @max(now, deadline) + 1;
        const result = try server.serviceDueDeadline(now);
        if (result == .datagram) {
            const tagged = result.datagram;
            defer alloc.free(tagged.dg);
            // The Initial-space retransmission is path-tagged with the
            // committed route for this endpoint's own CID — and it IS
            // an Initial: a long-header datagram, never a pending
            // Handshake/1-RTT emission standing in for the due probe.
            try testing.expect(tagged.dg[0] & 0x80 != 0);
            try testing.expect(tagged.dg.len >= min_initial_dgram);
            const committed = try server.lifecycle.currentRoutePathAddress(&retry_scid);
            try testing.expect(tagged.dst.local.eql(committed.local));
            try testing.expect(tagged.dst.remote.eql(committed.remote));
            return;
        }
    }
    return error.ExpectedInitialPto;
}

test "serviceDueDeadline surfaces idle retirement after the deadline" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);

    // Established and idle: the earliest deadline is the idle timeout.
    // Servicing past it retires the connection through the lifecycle;
    // the record owner then DROPS the record rather than re-retiring.
    const deadline = pair.server.nextDeadlineNanos() orelse return error.NoDeadline;
    const result = try pair.server.serviceDueDeadline(deadline + 1);
    try testing.expect(result == .idle_retired);
    try testing.expect(pair.server.conn.connectionState() == .closed);
}

test "due application recovery emits only the application-space probe" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);

    // An unacknowledged application PING arms the application PTO;
    // the client never answers it.
    const t = pair.now_nanos + 1;
    try pair.server.conn.sendPing();
    const ping = (try pair.server.pollOutboundPath(t)) orelse return error.NoPingEmission;
    defer alloc.free(ping.dg);
    try testing.expect(ping.emitted_ping);

    // Past the PTO the serviced space is application, and the returned
    // probe is a SHORT-header datagram: no pending long-header
    // Initial/Handshake output can stand in for the due space's probe.
    const result = try pair.server.serviceDueDeadline(t + 60 * std.time.ns_per_s);
    if (result != .datagram) return error.ExpectedApplicationProbe;
    const probe = result.datagram;
    defer alloc.free(probe.dg);
    try testing.expect(probe.dg[0] & 0x80 == 0);
    const committed = try pair.server.lifecycle.currentRoutePathAddress(&retry_scid);
    try testing.expect(probe.dst.local.eql(committed.local));
    try testing.expect(probe.dst.remote.eql(committed.remote));
}

test "tagRouted frees the datagram when the committed route is missing" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var ex = try FirstExchange.open(alloc, &psk);
    defer ex.deinit(alloc);

    // Adopted WITHOUT a route (the round-3 route-first idiom). An
    // emission in hand with no `path_override` must resolve the
    // committed route through this endpoint's own CID; the failure
    // path is tagRouted — the ONE allocation-cleanup site every
    // egress entry (`pollOutboundPath`, `serviceDueDeadline`) shares.
    const server = try adoptCandidate(alloc, &ex.boundary, .{
        .psk = &psk,
        .retry_scid = retry_scid,
        .original_dcid = original_dcid,
        .client_scid = client_scid,
        .token = ex.token,
        .now_nanos = ex.now_nanos,
    });
    const dg = try alloc.alloc(u8, 64);
    // The in-hand datagram is freed on the route failure — the testing
    // allocator fails the test on any leak.
    try testing.expectError(error.NoRegisteredPath, server.tagRouted(.{ .dg = dg }));
}

test "key-discard earliest keeps a simultaneously due recovery probe silent" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    var psk: [32]u8 = undefined;
    try testPsk(&bootstrap, &psk);
    defer std.crypto.secureZero(u8, &bootstrap);
    defer std.crypto.secureZero(u8, &psk);

    var pair = try TestPair.init(alloc, &psk);
    defer pair.deinit(alloc);

    // A key update retains the previous generation with a discard
    // deadline — the EARLIEST deadline on the now-idle connection.
    const t_update = pair.now_nanos + 1;
    pair.server.conn.last_packet_activity_nanos = t_update;
    try pair.server.conn.initiateOneRttKeyUpdate();
    const discard_deadline = pair.server.nextDeadlineNanos() orelse return error.NoDiscardDeadline;

    // An application PING emitted just before that deadline arms a
    // LATER recovery timer — both become due by the service time.
    const t_ping = discard_deadline - 10;
    try pair.server.conn.sendPing();
    const ping = (try pair.server.pollOutboundPath(t_ping)) orelse return error.NoPingEmission;
    defer alloc.free(ping.dg);
    try testing.expect(ping.emitted_ping);
    try testing.expectEqual(discard_deadline, pair.server.nextDeadlineNanos().?);

    // Delayed wakeup: `processPendingWork` services BOTH the expired
    // key discard and the due PTO, but the CAPTURED earliest kind is
    // key-discard — the frozen contract returns no output.
    const t_service = t_ping + 60 * std.time.ns_per_s;
    try testing.expect(pair.server.nextDeadlineNanos().? <= t_service);
    const silenced = try pair.server.serviceDueDeadline(t_service);
    try testing.expect(silenced == .no_output);

    // The queued recovery probe is untouched and remains available to
    // normal polling.
    const probe = (try pair.server.pollOutbound(t_service)) orelse return error.NoProbeAvailable;
    defer alloc.free(probe);
    try testing.expect(probe[0] & 0x80 == 0);
}
