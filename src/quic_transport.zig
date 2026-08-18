//! Thin QUIC transport adapter over the quicz sans-I/O API (Phase Q2).
//!
//! One `Transport` is one QUIC endpoint — the client side or the gateway
//! side of a zmosh connection. It owns the quicz
//! `EndpointConnectionLifecycle`, `Connection`, and TLS backend, and
//! nothing else: datagrams in, datagrams out, deadlines, and counters.
//! It owns no terminal or command semantics; the socket fd, poll()
//! integration, stream roles, and the Retry boundary (token policy,
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
    odcid_buf: [20]u8 = undefined,
    odcid_len: usize = 0,
    /// The Retry SCID once a client has processed a Retry: the
    /// post-Retry Initial key DCID, recorded separately from the ODCID.
    retry_scid_buf: [20]u8 = undefined,
    retry_scid_len: usize = 0,
    scratch: [16384]u8 = undefined,
    counters: Counters = .{},

    /// Build every resource as a local with an adjacent errdefer that
    /// releases exactly what exists, then transfer ownership in one
    /// assignment; no partially initialized transport is observable.
    pub fn createClient(alloc: std.mem.Allocator, opts: ClientOptions) !*Transport {
        var secrets = try protection.deriveInitialSecrets(.v1, &opts.original_dcid);
        errdefer protection.secureWipeInitialSecrets(&secrets);
        const t = try createEndpoint(alloc, .client, opts.psk, opts.scid, secrets);
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
    /// already answered the first flight).
    pub fn createServerCandidate(alloc: std.mem.Allocator, opts: ServerCandidateOptions) !*Transport {
        var secrets = try protection.deriveInitialSecrets(.v1, &opts.retry_scid);
        errdefer protection.secureWipeInitialSecrets(&secrets);
        const t = try createEndpoint(alloc, .server, opts.psk, opts.retry_scid, secrets);
        protection.secureWipeInitialSecrets(&secrets);

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
        secrets: protection.InitialSecrets,
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
            .secrets = secrets,
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
    pub fn handleDatagram(self: *Transport, arrival: quicz.endpoint.UdpTuple, now_nanos: i64, data: []const u8) !void {
        self.counters.datagrams_received += 1;
        if (data.len > max_udp_payload) {
            self.counters.datagrams_discarded += 1;
            return;
        }
        const info = protection.peekProtectedLongPacketInfo(data) catch |peek_err| switch (peek_err) {
            // Retry packets are long headers that carry no header
            // protection, so the peek rejects them; classify by the
            // long-header type bits (0b11 = Retry, RFC 9000 §17.2.2).
            error.UnsupportedPacketType => {
                if (data.len > 0 and (data[0] & 0xC0) == 0xC0 and (data[0] & 0x30) == 0x30) {
                    try self.processRetry(now_nanos, data);
                } else {
                    self.counters.datagrams_discarded += 1;
                }
                return;
            },
            // Anything the long-prefix parser rejects as non-long is a
            // short header: 1-RTT application data through the
            // canonical guarded entry that also commits validated
            // route changes.
            else => {
                try self.processShort(arrival, now_nanos, data);
                return;
            },
        };
        switch (info.packet_type) {
            .initial => try self.processInitial(now_nanos, data),
            .handshake => try self.processHandshake(now_nanos, data),
            // v1 sends no 0-RTT and accepts no Version Negotiation
            // beyond the pinned version: both are foreign traffic.
            else => self.counters.datagrams_discarded += 1,
        }
    }

    /// quicz's own OrClose processor for Initial space. Classification
    /// by observed state: `InvalidPacket` with the connection still
    /// active is network-originated (discarded); an active → closing
    /// transition is an authenticated protocol violation (counted; the
    /// queued close leaves via pollOutbound).
    fn processInitial(self: *Transport, now_nanos: i64, data: []const u8) !void {
        const secrets = self.secrets orelse {
            self.counters.datagrams_discarded += 1;
            return;
        };
        const was_active = self.conn.connectionState() == .active;
        _ = self.lifecycle.processProtectedLongDatagramOrClose(
            handle,
            self.conn,
            now_nanos,
            .{ .initial = if (self.is_server) secrets.client else secrets.server },
            data,
        ) catch |err| switch (err) {
            error.InvalidPacket => {
                if (self.conn.connectionState() == .active) {
                    self.counters.datagrams_discarded += 1;
                    return;
                }
                return err;
            },
            else => return err,
        };
        self.noteViolation(was_active);
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
        ) catch |err| switch (err) {
            error.InvalidPacket => {
                if (self.conn.connectionState() == .active) {
                    self.counters.datagrams_discarded += 1;
                    return;
                }
                return err;
            },
            else => return err,
        };
        self.noteViolation(was_active);
    }

    fn processShort(self: *Transport, arrival: quicz.endpoint.UdpTuple, now_nanos: i64, data: []const u8) !void {
        const was_active = self.conn.connectionState() == .active;
        const res = self.lifecycle.processRoutedProtectedShortDatagramWithInstalledKeysAndUpdatePathOrCloseAddress(
            handle,
            self.conn,
            arrival,
            now_nanos,
            data,
        ) catch |err| switch (err) {
            error.InvalidPacket, error.ConnectionClosed => {
                self.counters.datagrams_discarded += 1;
                return;
            },
            else => return err,
        };
        self.noteViolation(was_active);
        if (res.updated_route != null) self.counters.migrations_committed += 1;
    }

    /// The client's Retry sequence: validate the integrity tag, record
    /// token + Retry SCID, re-cache the ClientHello, rewind Initial
    /// send state, and rekey Initial space from the Retry SCID — the
    /// post-Retry key DCID, recorded separately from the first-flight
    /// ODCID.
    fn processRetry(self: *Transport, now_nanos: i64, data: []const u8) !void {
        if (self.is_server) {
            self.counters.datagrams_discarded += 1;
            return;
        }
        try self.conn.processRetryDatagram(now_nanos, self.odcid_buf[0..self.odcid_len], data);
        const rscid = self.conn.retrySourceConnectionId() orelse return error.NoRetryScid;
        self.backend.retryReceived();
        try self.conn.resetInitialCryptoSendForRetry();
        if (self.secrets) |*s| protection.secureWipeInitialSecrets(s);
        self.secrets = try protection.deriveInitialSecrets(.v1, rscid);
        const n = @min(rscid.len, self.retry_scid_buf.len);
        @memcpy(self.retry_scid_buf[0..n], rscid[0..n]);
        self.retry_scid_len = n;
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
    /// space, in that order). Caller owns and frees the result. Every
    /// emission is checked against the fixed cap: an oversized
    /// datagram is freed and reported as a local error (never a
    /// debug-only assertion). Only polling a closed endpoint is a
    /// tolerated non-event; encoding/invariant errors propagate.
    pub fn pollOutbound(self: *Transport, now_nanos: i64) !?[]u8 {
        if (!self.conn.packetNumberSpaceDiscarded(.initial)) {
            if (self.secrets) |secrets| {
                if (self.lifecycle.pollProtectedLongDatagram(
                    handle,
                    self.conn,
                    now_nanos,
                    self.initialDst(),
                    &self.scid,
                    &[_]u8{},
                    .{ .initial = if (self.is_server) secrets.server else secrets.client },
                )) |maybe| {
                    if (maybe) |dg| return self.checked(dg);
                } else |err| switch (err) {
                    error.ConnectionClosed => {},
                    else => return err,
                }
            }
        }
        if (!self.conn.packetNumberSpaceDiscarded(.handshake) and self.conn.hasHandshakeProtectionKeys()) {
            if (self.lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
                handle,
                self.conn,
                now_nanos,
                self.dstCid(),
                &self.scid,
            )) |maybe| {
                if (maybe) |dg| return self.checked(dg);
            } else |err| switch (err) {
                error.ConnectionClosed => {},
                else => return err,
            }
        }
        if (self.conn.hasOneRttProtectionKeys()) {
            if (self.lifecycle.pollProtectedShortDatagramWithInstalledKeys(
                handle,
                self.conn,
                now_nanos,
                self.dstCid(),
            )) |maybe| {
                if (maybe) |dg| return self.checked(dg);
            } else |err| switch (err) {
                error.ConnectionClosed => {},
                else => return err,
            }
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

    /// Initial-space destination: the Retry SCID once a client has
    /// processed a Retry, otherwise the first-flight ODCID. The
    /// connection inserts its stored Retry token automatically.
    fn initialDst(self: *const Transport) []const u8 {
        if (self.retry_scid_len != 0) return self.retry_scid_buf[0..self.retry_scid_len];
        return self.odcid_buf[0..self.odcid_len];
    }

    /// Destination CID for Handshake/1-RTT datagrams: the peer's real
    /// SCID once the handshake has revealed it, otherwise the Initial
    /// destination.
    fn dstCid(self: *const Transport) []const u8 {
        if (self.conn.peerInitialSourceConnectionId()) |peer| {
            return peer;
        }
        return self.initialDst();
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
    alloc: std.mem.Allocator,
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
/// token policy, PendingRetrySlot, and private adoption.
const RetryBoundary = struct {
    alloc: std.mem.Allocator,
    secret: quicz.address_validation_token.Secret,
    policy: quicz.endpoint.AddressValidationPolicy,
    slot: quicz.pending_retry_slot.PendingRetrySlot = .{},
    registry: CandidateRegistry,
    nonce: quicz.address_validation_token.Nonce,

    fn init(alloc: std.mem.Allocator) !RetryBoundary {
        var secret: quicz.address_validation_token.Secret = undefined;
        try testing.io.randomSecure(&secret);
        return .{
            .alloc = alloc,
            .secret = secret,
            .policy = quicz.endpoint.AddressValidationPolicy.init(alloc, secret, .{}),
            .registry = try CandidateRegistry.initWithCapacity(alloc, 1),
            .nonce = [_]u8{0x42} ** quicz.address_validation_token.nonce_len,
        };
    }

    /// Idempotent full cleanup: removes the adopted candidate (whose
    /// deinit_record destroys the transport through its single wipe
    /// path) before releasing the policy and wiping the secret.
    fn deinit(self: *RetryBoundary) void {
        self.registry.remove(1) catch {};
        self.registry.deinit();
        self.policy.deinit();
        std.crypto.secureZero(u8, &self.secret);
    }
};

const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const retry_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

/// Create the server candidate and adopt it into the boundary's
/// private capacity-one registry. On success the registry owns the
/// record and the transport; the caller cleans up through
/// `RetryBoundary.deinit` (idempotent).
fn createAndAdopt(
    alloc: std.mem.Allocator,
    boundary: *RetryBoundary,
    opts: ServerCandidateOptions,
    local: quicz.endpoint.UdpAddress,
    remote: quicz.endpoint.UdpAddress,
) !*Transport {
    const server = try Transport.createServerCandidate(alloc, opts);
    errdefer server.destroy();
    try server.registerRoute(local, remote);
    const record = try alloc.create(CandidateRecord);
    errdefer alloc.destroy(record);
    record.* = .{ .alloc = alloc, .transport = server };
    try boundary.registry.adopt(1, record);
    return server;
}

/// One client/server transport pair performing the COMPLETE Retry
/// transaction — the loopback the Q2 gate requires before any custom
/// module is removed. Handshake-space datagrams that race ahead of
/// receiver key installation are parked and replayed after the next
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

    fn init(alloc: std.mem.Allocator, psk: *const [32]u8) !TestPair {
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
        defer alloc.free(token);
        const retry = try boundary.slot.open(alloc, now, 10 * std.time.ns_per_s, server_path, .v1, accept1.original_destination_connection_id, accept1.source_connection_id, &retry_scid, token);
        try client.handleDatagram(client_path, now, retry);

        // ── Follow-up Initial: rekeyed, token echoed. ────────────────
        now += 1;
        try client.driveCrypto(.initial, now);
        const followup = (try client.pollOutbound(now)) orelse return error.NoFollowupInitial;
        defer alloc.free(followup);
        try testing.expect(followup.len >= min_initial_dgram);
        const accept2 = (try quicz.endpoint.peekInitialAcceptDatagram(server_path, followup, &supported)) orelse return error.FollowupNotAccepted;

        // ── Classify the exact stored exchange. ──────────────────────
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

        // ── Create and PRIVATELY adopt the validated candidate. ──────
        // Ownership transfers to the registry inside the helper; its
        // errdefers are valid only up to the adopt, so later failures
        // unwind through boundary.deinit (idempotent) alone.
        const server = try createAndAdopt(alloc, &boundary, .{
            .psk = psk,
            .retry_scid = retry_scid,
            .original_dcid = original_dcid,
            .client_scid = client_scid,
            .token = token,
            .now_nanos = now,
        }, server_local, client_local);
        // Private ownership is not publication.
        try testing.expectEqual(@as(usize, 1), boundary.registry.count());
        try testing.expectEqual(@as(usize, 1), boundary.registry.activeCount());
        try testing.expectEqual(@as(usize, 1), server.lifecycle.router.routeCount());

        // ── Authenticate the follow-up Initial. ──────────────────────
        try server.handleDatagram(server_path, now, followup);
        try server.driveCrypto(.initial, now);
        const sh = (try server.pollOutbound(now)) orelse return error.NotAuthenticated;
        defer alloc.free(sh);

        // ── Commit BEFORE publication or echo. ───────────────────────
        try boundary.slot.commit(&boundary.policy, now, accept2.token);
        try testing.expect(!boundary.slot.occupied);
        try testing.expectEqual(@as(usize, 1), boundary.policy.replayFilterEntryCount());

        // Publication: the ServerHello (already authenticated) is now
        // delivered to the client.
        try client.handleDatagram(client_path, now, sh);

        var pair = TestPair{
            .client = client,
            .server = server,
            .boundary = boundary,
            .client_path = client_path,
            .server_path = server_path,
            .now_nanos = now,
        };
        try pair.completeHandshake(alloc);
        return pair;
    }

    fn deinit(self: *TestPair, alloc: std.mem.Allocator) void {
        for (self.parked.items) |dg| alloc.free(dg);
        self.parked.deinit(alloc);
        self.parked_from_server.deinit(alloc);
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
            try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg);
            return;
        };
        if (info.packet_type == .handshake and !receiver.conn.hasHandshakeProtectionKeys()) {
            try self.parked.append(alloc, try alloc.dupe(u8, dg));
            try self.parked_from_server.append(alloc, from_server);
            return;
        }
        try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg);
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
            try receiver.handleDatagram(self.arrivalFor(from_server), self.now_nanos, dg);
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
    /// handshake confirms on both sides (bounded attempts).
    fn completeHandshake(self: *TestPair, alloc: std.mem.Allocator) !void {
        var attempt: usize = 0;
        while (attempt < 16) : (attempt += 1) {
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
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
    }
    var buf: [128]u8 = undefined;
    const n = (try pair.server.connection().recvOnStream(stream_id, &buf)) orelse return error.NoUplink;
    try testing.expectEqualStrings("q2-loopback", buf[0..n]);

    try pair.server.connection().sendOnStream(stream_id, "q2-echo", true);
    var down: usize = 0;
    while (down < 8) : (down += 1) {
        const dg = (try pair.server.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        try pair.client.handleDatagram(pair.client_path, pair.now_nanos, dg);
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
    var up: usize = 0;
    while (up < 8) : (up += 1) {
        const dg = (try pair.client.pollOutbound(pair.now_nanos)) orelse break;
        defer alloc.free(dg);
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
    }
    var buf: [128]u8 = undefined;
    const n = (try pair.server.connection().recvOnStream(s, &buf)) orelse return error.NoData;
    try testing.expectEqualStrings("from-new-path", buf[0..n]);

    // The gateway initiates validation for a changed path by queueing
    // an unpredictable challenge bound to the candidate path.
    const challenge_data = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    try pair.server.conn.sendPathChallengeForPath(challenge_data, pair.server_path);
    // Queued as pending; it becomes outstanding once polled and sent.
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
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
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
        try pair.server.handleDatagram(pair.server_path, pair.now_nanos, dg);
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
    if (pair.client.secrets) |s| {
        try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&s.client.secret), 0));
    }
    // destroy() wipes again (idempotent) and frees everything under
    // the testing allocator.
    pair.deinit(alloc);
}
