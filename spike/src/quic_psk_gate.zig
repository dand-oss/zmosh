//! Q1 hard gate: certificate-free external-PSK TLS 1.3 through quicz's
//! public sans-I/O APIs, against the unmodified pinned commit.
//!
//! Drives one complete QUIC v1 handshake between two in-process
//! `Connection`s over `EndpointConnectionLifecycle` (the layer zmosh will
//! integrate: caller-owned datagram exchange, no runtime, no threads):
//!
//!   - client offers an external PSK (fixed non-secret identity
//!     "zmosh-ssh-bootstrap-v1", PSK derived per plan: HKDF-SHA256 over the
//!     32-byte bootstrap secret with context "zmosh quic psk v1");
//!   - server holds the same PSK, binds selection to that exact identity,
//!     and configures NO certificate material — when the PSK is selected
//!     the flight is EncryptedExtensions + Finished with no Certificate;
//!   - no session tickets, no resumption, no 0-RTT: the client never marks
//!     the identity as early-data-capable and both sides must report
//!     0-RTT not accepted;
//!   - wrong PSK, wrong identity, and ALPN mismatch must each fail the
//!     handshake loudly (binder failure, certificate-path rejection with no
//!     certificate configured, and no-application-protocol respectively).
//!
//! Everything is exercised through public quicz surface: backend
//! constructors `initClientWithPsk`/`initServerWithPsk`, the public
//! `setServerPskIdentity` binding, and public backend fields for the
//! identity seed (the same seeding quicz's own connection tests perform).

const std = @import("std");
const testing = std.testing;
const quicz = @import("quicz");

const Connection = quicz.Connection;
const Tls13Backend = quicz.tls13_backend.Tls13Backend;
const protection = quicz.protection;

const original_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
const client_scid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
const server_scid = [_]u8{ 0x31, 0x32, 0x33, 0x34 };
const client_handle: u64 = 1;
const server_handle: u64 = 2;

const alpn_zmosh = [_][]const u8{"zmosh/1"};
const psk_identity = "zmosh-ssh-bootstrap-v1";

/// Plan Q1 authentication proof: PSK = HKDF-SHA256(bootstrap secret) with
/// the fixed derivation context `zmosh quic psk v1`.
fn derivePsk(bootstrap_secret: [32]u8) [32]u8 {
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract("zmosh quic psk v1", &bootstrap_secret);
    var psk: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&psk, psk_identity, prk);
    return psk;
}

/// One client/server pair, heap-held so nothing is moved after
/// registration. `wrong_server_identity` and `server_alpn` configure the
/// failure variants.
const Pair = struct {
    alloc: std.mem.Allocator,
    client_lifecycle: *quicz.EndpointConnectionLifecycle,
    server_lifecycle: *quicz.EndpointConnectionLifecycle,
    client: *Connection,
    server: *Connection,
    client_backend: *Tls13Backend,
    server_backend: *Tls13Backend,
    client_path: quicz.endpoint.Udp4Tuple,
    server_path: quicz.endpoint.Udp4Tuple,
    secrets: protection.InitialSecrets,
    scratch: [8192]u8 = undefined,

    fn init(
        alloc: std.mem.Allocator,
        client_psk: [32]u8,
        server_psk: [32]u8,
        server_identity: ?[]const u8,
        server_alpn: []const []const u8,
    ) !Pair {
        const client_path = quicz.endpoint.Udp4Tuple{
            .local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40000),
            .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 41000),
        };
        const server_path = quicz.endpoint.Udp4Tuple{
            .local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 41000),
            .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40000),
        };

        const client_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
        const server_lifecycle = try alloc.create(quicz.EndpointConnectionLifecycle);
        client_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
        server_lifecycle.* = quicz.EndpointConnectionLifecycle.init(alloc);
        errdefer {
            client_lifecycle.deinit();
            server_lifecycle.deinit();
            alloc.destroy(client_lifecycle);
            alloc.destroy(server_lifecycle);
        }
        try client_lifecycle.registerConnectionId(client_handle, &client_scid, client_path, .{ .active_migration_disabled = true });
        try server_lifecycle.registerConnectionId(server_handle, &original_dcid, server_path, .{ .active_migration_disabled = true });
        try server_lifecycle.registerConnectionId(server_handle, &server_scid, server_path, .{ .active_migration_disabled = true });

        const conn_cfg = quicz.Config{
            .initial_max_data = 8192,
            .initial_max_stream_data = 2048,
            .initial_max_streams_bidi = 8,
            .max_datagram_size = 8192,
        };
        const client = try alloc.create(Connection);
        const server = try alloc.create(Connection);
        client.* = try Connection.init(alloc, .client, conn_cfg);
        errdefer {
            client.deinit();
            alloc.destroy(client);
        }
        server.* = try Connection.init(alloc, .server, conn_cfg);
        errdefer {
            server.deinit();
            alloc.destroy(server);
        }
        // The zmosh gateway validates the peer address out-of-band (SSH
        // bootstrap + Retry) before allocating per-client state.
        try server.validatePeerAddress();
        try client.setLocalInitialSourceConnectionId(&client_scid);
        try server.setLocalInitialSourceConnectionId(&server_scid);

        const client_backend = try alloc.create(Tls13Backend);
        client_backend.* = Tls13Backend.initClientWithPsk(.{
            .alpn = &alpn_zmosh,
            .server_name = "zmosh",
        }, client_psk);
        // The offered PSK identity rides in the public session-ticket slot
        // (the identity blob of the pre_shared_key extension); early data
        // stays disabled because session_ticket_allows_early_data is false.
        client_backend.hs.session_ticket_len = psk_identity.len;
        @memcpy(client_backend.hs.session_ticket[0..psk_identity.len], psk_identity);

        const server_backend = try alloc.create(Tls13Backend);
        server_backend.* = Tls13Backend.initServerWithPsk(.{
            .alpn = server_alpn,
            // No cert_chain_der, no private key: PSK-only or fail.
        }, server_psk);
        if (server_identity) |identity| try server_backend.setServerPskIdentity(identity);

        return .{
            .alloc = alloc,
            .client_lifecycle = client_lifecycle,
            .server_lifecycle = server_lifecycle,
            .client = client,
            .server = server,
            .client_backend = client_backend,
            .server_backend = server_backend,
            .client_path = client_path,
            .server_path = server_path,
            .secrets = try protection.deriveInitialSecrets(.v1, &original_dcid),
        };
    }

    fn deinit(self: *Pair) void {
        self.client.deinit();
        self.server.deinit();
        self.client_lifecycle.deinit();
        self.server_lifecycle.deinit();
        self.alloc.destroy(self.client_backend);
        self.alloc.destroy(self.server_backend);
        self.alloc.destroy(self.client);
        self.alloc.destroy(self.server);
        self.alloc.destroy(self.client_lifecycle);
        self.alloc.destroy(self.server_lifecycle);
    }

    fn buildClientHello(self: *Pair) ![]u8 {
        _ = try self.client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            client_handle,
            self.client,
            .initial,
            self.client_backend.cryptoBackend(),
            &self.scratch,
        );
        return (try self.client_lifecycle.pollProtectedLongDatagram(
            client_handle,
            self.client,
            10,
            &original_dcid,
            &client_scid,
            &[_]u8{},
            .{ .initial = self.secrets.client },
        )) orelse error.NoClientHello;
    }

    /// Feed `ch` to the server and drive it. Returns the drive error, if
    /// any, without asserting.
    fn serverConsumeClientHello(self: *Pair, ch: []const u8) !void {
        _ = try self.server_lifecycle.processRoutedProtectedInitialDatagram(
            server_handle,
            self.server,
            self.server_path,
            11,
            &original_dcid,
            ch,
        );
        _ = try self.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            server_handle,
            self.server,
            .initial,
            self.server_backend.cryptoBackend(),
            &self.scratch,
        );
    }
};

test "certificate-free external-PSK handshake and 1-RTT echo" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    const psk = derivePsk(bootstrap);

    var p = try Pair.init(alloc, psk, psk, psk_identity, &alpn_zmosh);
    defer p.deinit();

    // Flight 1-2: ClientHello -> ServerHello.
    const ch = try p.buildClientHello();
    defer alloc.free(ch);
    try p.serverConsumeClientHello(ch);
    try testing.expect(p.server_backend.hs.psk_selected);
    const sh = (try p.server_lifecycle.pollProtectedLongDatagram(
        server_handle,
        p.server,
        12,
        &client_scid,
        &server_scid,
        &[_]u8{},
        .{ .initial = p.secrets.server },
    )) orelse return error.NoServerHello;
    defer alloc.free(sh);

    // Flight 3: client processes ServerHello, installs handshake keys.
    _ = try p.client_lifecycle.processRoutedProtectedInitialDatagram(
        client_handle,
        p.client,
        p.client_path,
        13,
        &original_dcid,
        sh,
    );
    const cprog = try p.client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        client_handle,
        p.client,
        .initial,
        p.client_backend.cryptoBackend(),
        &p.scratch,
    );
    try testing.expect(cprog.handshake_keys_installed);
    try testing.expect(p.client_backend.hs.psk_selected);

    // Flight 4: server's PSK-only handshake flight (EE + Finished, no
    // Certificate) reaches the client; client answers with its Finished.
    _ = try p.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        server_handle,
        p.server,
        .handshake,
        p.server_backend.cryptoBackend(),
        &p.scratch,
    );
    const server_flight = (try p.server_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        p.server,
        14,
        &client_scid,
        &server_scid,
    )) orelse return error.NoServerFlight;
    defer alloc.free(server_flight);
    _ = try p.client_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        p.client,
        p.client_path,
        15,
        server_flight,
    );
    _ = try p.client_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        client_handle,
        p.client,
        .handshake,
        p.client_backend.cryptoBackend(),
        &p.scratch,
    );
    const client_fin = (try p.client_lifecycle.pollProtectedHandshakeDatagramWithInstalledKeys(
        client_handle,
        p.client,
        16,
        &server_scid,
        &client_scid,
    )) orelse return error.NoClientFinished;
    defer alloc.free(client_fin);

    // Flight 5: server confirms the handshake.
    _ = try p.server_lifecycle.processRoutedProtectedHandshakeDatagramWithInstalledKeys(
        server_handle,
        p.server,
        p.server_path,
        17,
        client_fin,
    );
    const sfinal = try p.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
        server_handle,
        p.server,
        .handshake,
        p.server_backend.cryptoBackend(),
        &p.scratch,
    );
    try testing.expect(sfinal.handshake_confirmed);

    // No resumption, no 0-RTT on either side.
    try testing.expect(!p.client.zeroRttAccepted());
    try testing.expect(!p.server.zeroRttAccepted());

    // 1-RTT application data both directions.
    const stream_id = try p.client.openStream();
    try p.client.sendOnStream(stream_id, "zmosh-psk-gate", true);
    const req = (try p.client_lifecycle.pollProtectedShortDatagramWithInstalledKeys(
        client_handle,
        p.client,
        20,
        &server_scid,
    )) orelse return error.NoRequestDatagram;
    defer alloc.free(req);
    _ = try p.server_lifecycle.processRoutedProtectedShortDatagramWithInstalledKeys(
        server_handle,
        p.server,
        p.server_path,
        21,
        req,
    );
    var buf: [128]u8 = undefined;
    const n = (try p.server.recvOnStream(stream_id, &buf)) orelse return error.NoServerStreamData;
    try testing.expectEqualStrings("zmosh-psk-gate", buf[0..n]);
}

test "wrong PSK fails the handshake at the binder" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    const good = derivePsk(bootstrap);
    var attacker: [32]u8 = undefined;
    try testing.io.randomSecure(&attacker);
    const wrong = derivePsk(attacker);

    var p = try Pair.init(alloc, wrong, good, psk_identity, &alpn_zmosh);
    defer p.deinit();

    const ch = try p.buildClientHello();
    defer alloc.free(ch);
    _ = try p.server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        p.server,
        p.server_path,
        11,
        &original_dcid,
        ch,
    );
    // Binder verification against the configured PSK must fail loudly. The
    // lifecycle boundary reports error.CryptoError; the underlying
    // serverProcessClientHello failure is error.BadFinished (asserted in
    // the spike report via the test stack trace).
    try testing.expectError(
        error.CryptoError,
        p.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            server_handle,
            p.server,
            .initial,
            p.server_backend.cryptoBackend(),
            &p.scratch,
        ),
    );
    try testing.expect(!p.server_backend.hs.psk_selected);
    try testing.expect(!p.server.hasHandshakeProtectionKeys());
}

test "wrong identity cannot fall back to a certificate path" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    const psk = derivePsk(bootstrap);

    // Server binds to a different identity and configures no certificate:
    // an unmatched PSK offer must fail instead of silently downgrading.
    var p = try Pair.init(alloc, psk, psk, "zmosh-other-v1", &alpn_zmosh);
    defer p.deinit();

    const ch = try p.buildClientHello();
    defer alloc.free(ch);
    _ = try p.server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        p.server,
        p.server_path,
        11,
        &original_dcid,
        ch,
    );
    // Unmatched identity + no configured certificate: the server drives
    // into error.BadCertificate internally (see stack trace in the report);
    // the lifecycle boundary reports error.CryptoError.
    try testing.expectError(
        error.CryptoError,
        p.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            server_handle,
            p.server,
            .initial,
            p.server_backend.cryptoBackend(),
            &p.scratch,
        ),
    );
}

test "ALPN mismatch is rejected" {
    const alloc = testing.allocator;
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    const psk = derivePsk(bootstrap);
    const wrong_alpn = [_][]const u8{"zmosh/2"};

    var p = try Pair.init(alloc, psk, psk, psk_identity, &wrong_alpn);
    defer p.deinit();

    const ch = try p.buildClientHello();
    defer alloc.free(ch);
    _ = try p.server_lifecycle.processRoutedProtectedInitialDatagram(
        server_handle,
        p.server,
        p.server_path,
        11,
        &original_dcid,
        ch,
    );
    // ALPN mismatch drives error.NoApplicationProtocol internally; the
    // lifecycle boundary reports error.CryptoError.
    try testing.expectError(
        error.CryptoError,
        p.server_lifecycle.driveCryptoBackendInSpaceAndArmConnection(
            server_handle,
            p.server,
            .initial,
            p.server_backend.cryptoBackend(),
            &p.scratch,
        ),
    );
}
