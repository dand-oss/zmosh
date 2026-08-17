//! Q1 transport and resource proofs over the sans-I/O harness:
//! negotiated bounds, RESET_STREAM / STOP_SENDING observability, idle
//! lifetime negotiation with scaled timer expiry, keepalive across
//! multiple original idle deadlines, send-progress accounting, and the
//! deterministic fault matrix (loss, duplication, reordering, corruption,
//! delay, blackout, NAT rebinding, slow reader, datagram-size caps).

const std = @import("std");
const testing = std.testing;
const harness = @import("quic_harness.zig");
const quicz = @import("quicz");

const Pair = harness.Pair;

fn stdOpts(psk: [32]u8) harness.PairOptions {
    return .{ .client_psk = psk, .server_psk = psk };
}

fn randomPsk() !harness.PairOptions {
    var bootstrap: [32]u8 = undefined;
    try testing.io.randomSecure(&bootstrap);
    return stdOpts(harness.derivePsk(bootstrap));
}

test "negotiated connection bounds: 4 MiB credit, 4 bidi / 8 uni streams" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.max_data = 4 * 1024 * 1024;
    opts.max_streams_bidi = 4;
    opts.max_streams_uni = 8;

    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    // The advertised local transport parameters carry the configured
    // bounds on both sides.
    const ctp = p.client.localTransportParameters();
    try testing.expectEqual(@as(u64, 4 * 1024 * 1024), ctp.initial_max_data);
    try testing.expectEqual(@as(u64, 4), ctp.initial_max_streams_bidi);
    try testing.expectEqual(@as(u64, 8), ctp.initial_max_streams_uni);
    const stp = p.server.localTransportParameters();
    try testing.expectEqual(@as(u64, 4 * 1024 * 1024), stp.initial_max_data);

    // Four bidirectional streams open within the advertised bound; the
    // fifth is refused with flow-control blocking until the peer raises
    // the limit — the negotiated bound is enforced, not advisory.
    var opened: u64 = 0;
    while (opened < 4) : (opened += 1) {
        _ = try p.client.openStream();
    }
    try testing.expectError(error.FlowControlBlocked, p.client.openStream());
}

test "RESET_STREAM is observable by the application" {
    const alloc = testing.allocator;
    var p = try Pair.create(alloc, try randomPsk());
    defer p.destroy();
    try p.completeHandshake();

    const stream_id = try p.client.openStream();
    if (try p.clientToServer(stream_id, "before-reset", false)) |got| alloc.free(got);
    try p.client.resetStream(stream_id, 4242);
    // Deliver the RESET_STREAM.
    try p.flushClientShort();
    const state = (try p.server.streamState(stream_id)).?;
    try testing.expect(state.receive_reset_error_code != null);
    try testing.expectEqual(@as(u64, 4242), state.receive_reset_error_code.?);
}

test "STOP_SENDING produces RESET_STREAM with the same code at the peer" {
    const alloc = testing.allocator;
    var p = try Pair.create(alloc, try randomPsk());
    defer p.destroy();
    try p.completeHandshake();

    const stream_id = try p.client.openStream();
    if (try p.clientToServer(stream_id, "early", false)) |got| alloc.free(got);

    // The server asks the client to stop sending with code 7777...
    try p.server.stopSending(stream_id, 7777);
    try p.flushServerShort();
    const server_state = (try p.server.streamState(stream_id)).?;
    try testing.expect(server_state.receive_stop_sending_sent == true);

    // ...and the peer observes it: quicz queues RESET_STREAM carrying the
    // SAME application error code, which the server receives.
    try p.flushClientShort();
    const client_state = (try p.client.streamState(stream_id)).?;
    try testing.expect(client_state.send == .reset_sent or client_state.send == .reset_acked);
    const after = (try p.server.streamState(stream_id)).?;
    try testing.expect(after.receive_reset_error_code != null);
    try testing.expectEqual(@as(u64, 7777), after.receive_reset_error_code.?);
}

test "24h idle lifetime negotiated; scaled idle expiry closes" {
    const alloc = testing.allocator;

    // Negotiation: both sides advertise 24h; effective timeout = 24h.
    {
        var opts = try randomPsk();
        opts.idle_timeout_ms = 24 * 60 * 60 * 1000;
        var p = try Pair.create(alloc, opts);
        defer p.destroy();
        try p.completeHandshake();
        const effective = p.client.effectiveIdleTimeout();
        try testing.expect(effective != null);
        try testing.expectEqual(@as(u64, 24 * 60 * 60 * 1000), effective.?);
    }

    // Scaled timer proof: 100 ms negotiated idle closes after the
    // deadline passes with no authenticated packets.
    {
        var opts = try randomPsk();
        opts.idle_timeout_ms = 100;
        var p = try Pair.create(alloc, opts);
        defer p.destroy();
        try p.completeHandshake();
        try testing.expectEqual(@as(u64, 100), p.client.effectiveIdleTimeout().?);

        const deadline = p.client.idleTimeoutDeadline();
        try testing.expect(deadline != null);
        // Advance far past the deadline; the connection must report a
        // closed/draining state through its state machine.
        p.now_nanos += 5 * std.time.ns_per_s;
        _ = try p.client_lifecycle.processPendingWork(harness.client_handle, p.client, p.now_nanos);
        try testing.expect(p.client.connectionState() != .active);
    }
}

test "keepalive stays active across multiple original idle deadlines" {
    const alloc = testing.allocator;
    // 500 ms idle deadline with a 20 ms keepalive: the connection must
    // survive 1.2 s — well past two original idle deadlines — and then
    // actually close once keepalives stop, proving the deadlines were
    // real all along.
    var opts = try randomPsk();
    opts.idle_timeout_ms = 500;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    var round: usize = 0;
    while (round < 60) : (round += 1) {
        p.now_nanos += 20 * std.time.ns_per_ms;
        try p.client.sendPing();
        try p.flushClientShort();
        try p.flushServerShort();
        try testing.expect(p.client.connectionState() == .active);
        try testing.expect(p.server.connectionState() == .active);
    }

    // Stop keeping alive: the (still-negotiated) idle deadline closes it.
    p.now_nanos += 1 * std.time.ns_per_s;
    _ = try p.client_lifecycle.processPendingWork(harness.client_handle, p.client, p.now_nanos);
    try testing.expect(p.client.connectionState() != .active);
}

test "streamSendProgress end-to-end across an ACK round trip" {
    const alloc = testing.allocator;
    var p = try Pair.create(alloc, try randomPsk());
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    const fresh = p.client.streamSendProgress(s).?;
    try testing.expectEqual(@as(u64, 0), fresh.accepted_offset);
    try testing.expectEqual(@as(u64, 0), fresh.contiguous_acked_offset);
    try testing.expect(fresh.last_ack_progress_nanos == null);
    try testing.expect(p.client.streamSendProgress(999_999) == null);

    const payload = "progress-across-the-wire";
    const got = try p.clientToServer(s, payload, false);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings(payload, got.?);

    // Server ACK return drains the logical offsets to zero.
    try p.flushServerShort();
    const progress = p.client.streamSendProgress(s).?;
    try testing.expectEqual(@as(u64, payload.len), progress.accepted_offset);
    try testing.expectEqual(@as(u64, payload.len), progress.contiguous_acked_offset);
    try testing.expectEqual(@as(u64, 0), progress.outstandingBytes());
    try testing.expect(progress.last_ack_progress_nanos != null);
}

test "fault matrix: loss, duplication, reordering, corruption, blackout" {
    const alloc = testing.allocator;

    // Loss of the first client Initial (handshake packet loss): the
    // handshake still completes after PTO retransmission.
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        p.wire.drop_first_client = 1;
        try p.completeHandshakeWithRecovery();
        try testing.expect(p.server.handshakeConfirmed());
        try testing.expect(p.wire.dropped >= 1);
        _ = try p.client.openStream();
    }

    // Deterministic reordering: the wire holds stream-a's datagram and
    // lets stream-b's overtake it. Both still arrive exactly once, in
    // order within each stream.
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();
        p.wire.reorder_swap_once = true;
        const a = try p.client.openStream();
        const b = try p.client.openStream();
        // stream-a's datagram is held by the wire.
        const ra0 = try p.clientToServer(a, "stream-a-payload", true);
        try testing.expect(ra0 == null);
        // stream-b's datagram overtakes it and is delivered first.
        const rb = try p.clientToServer(b, "stream-b-payload", true);
        defer if (rb) |x| alloc.free(x);
        try testing.expectEqualStrings("stream-b-payload", rb.?);
        // The overtaken stream-a datagram still arrives, exactly once.
        var buf: [128]u8 = undefined;
        const n = (try p.server.recvOnStream(a, &buf)) orelse return error.StreamALost;
        try testing.expectEqualStrings("stream-a-payload", buf[0..n]);
    }

    // Duplication: every delivered datagram is sent twice; packet-number
    // dedup delivers each stream byte exactly once.
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();
        p.wire.duplicate = true;
        const s = try p.client.openStream();
        const got = try p.clientToServer(s, "dup-payload", true);
        defer if (got) |x| alloc.free(x);
        try testing.expectEqualStrings("dup-payload", got.?);
        try testing.expect(p.wire.duplicated >= 1);
        var buf: [128]u8 = undefined;
        try testing.expect((try p.server.recvOnStream(s, &buf)) == null);
    }

    // Corruption: the AEAD-failed datagram is discarded without killing
    // the connection, and its bytes are still delivered exactly once —
    // the surviving traffic's ACKs reveal the lost packet and QUIC
    // retransmits it, in order before the later data.
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();
        // Flush any post-handshake stragglers first so the corruptor
        // deterministically hits the stream-data datagram itself.
        try p.flushClientShort();
        try p.flushServerShort();
        p.wire.corrupt_once = true;
        const s = try p.client.openStream();
        // First write is corrupted on the wire and dropped by the server.
        const lost = try p.clientToServer(s, "AAAA", false);
        try testing.expect(lost == null);
        try testing.expectEqual(@as(usize, 1), p.wire.corrupted);
        try testing.expect(p.client.connectionState() == .active);

        // A later write on the same stream survives; its ACK makes the
        // loss detector requeue the corrupted packet's stream data.
        const got_b = try p.clientToServer(s, "BBBB", true);
        defer if (got_b) |x| alloc.free(x);

        var assembled: std.ArrayList(u8) = .empty;
        defer assembled.deinit(alloc);
        var round: usize = 0;
        while (round < 12 and assembled.items.len < 8) : (round += 1) {
            try p.recoverBoth();
            try p.flushServerShort();
            var buf: [256]u8 = undefined;
            while (try p.server.recvOnStream(s, &buf)) |n| {
                try assembled.appendSlice(alloc, buf[0..n]);
            }
        }
        try testing.expectEqualStrings("AAAABBBB", assembled.items);
        try testing.expect(p.client.connectionState() == .active);
    }

    // Ten-second outage (scaled to 100 ms): nothing delivers during the
    // blackout; afterwards the connection recovers AND the bytes lost
    // inside the blackout are delivered exactly once.
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();
        p.wire.blackout_until_nanos = p.now_nanos + 100 * std.time.ns_per_ms;
        const s = try p.client.openStream();
        const none = try p.clientToServer(s, "lost-in-blackout", true);
        try testing.expect(none == null);
        try testing.expect(p.wire.dropped > 0);

        p.now_nanos += 150 * std.time.ns_per_ms;
        var got: ?[]u8 = null;
        var round: usize = 0;
        while (got == null and round < 8) : (round += 1) {
            try p.recoverBoth();
            var buf: [256]u8 = undefined;
            if (try p.server.recvOnStream(s, &buf)) |n| {
                got = try alloc.dupe(u8, buf[0..n]);
            }
        }
        defer if (got) |x| alloc.free(x);
        try testing.expectEqualStrings("lost-in-blackout", got.?);
        var buf: [256]u8 = undefined;
        try testing.expect((try p.server.recvOnStream(s, &buf)) == null);
    }

    // Delay: datagrams held for two pump cycles still deliver exactly
    // once; the connection stays healthy.
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();
        p.wire.delay_client_cycles = 2;
        const s = try p.client.openStream();
        const none = try p.clientToServer(s, "delayed-payload", true);
        try testing.expect(none == null);
        try testing.expect(p.wire.delayed >= 1);
        var got: ?[]u8 = null;
        var round: usize = 0;
        while (got == null and round < 6) : (round += 1) {
            try p.flushAged();
            var buf: [256]u8 = undefined;
            if (try p.server.recvOnStream(s, &buf)) |n| {
                got = try alloc.dupe(u8, buf[0..n]);
            }
            if (got == null) try p.recoverBoth();
        }
        defer if (got) |x| alloc.free(x);
        try testing.expectEqualStrings("delayed-payload", got.?);
        try testing.expect(p.client.connectionState() == .active);
    }
}

test "NAT rebinding: the route follows a new client source port" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.migration_disabled = false;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    const first = try p.clientToServer(s, "before-rebind", false);
    defer if (first) |x| alloc.free(x);
    try testing.expectEqualStrings("before-rebind", first.?);

    // The client rebinds to a new source port (NAT rebinding).
    p.client_path.local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40123);
    p.server_path.remote = p.client_path.local;

    // Data from the new path still routes by DCID; with migration enabled
    // the server accepts the path change and traffic continues.
    const second = try p.clientToServer(s, "after-rebind", true);
    defer if (second) |x| alloc.free(x);
    try testing.expectEqualStrings("after-rebind", second.?);
    try testing.expect(p.client.connectionState() == .active);

    // Data from the new path is ACCEPTED (routed by DCID, migration
    // enabled) but the committed route is not moved until the caller
    // validates the new path — the plan's path-validation-before-commit
    // discipline, enforced by the routing layer itself.
    const pre_commit = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(!pre_commit.remote.eql(p.client_path.local));

    // Completing validation commits the migration to the new path.
    _ = try p.server_lifecycle.updateRoutePathFromValidatedDatagramAndResetSpinBit(&harness.server_scid, p.server_path, p.server);
    const route_path = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(route_path.remote.eql(p.client_path.local));
}

test "slow reader: unread stream data bounds sender memory by flow control" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.max_stream_data = 256;
    opts.max_data = 4 * 1024;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const slow = try p.client.openStream();
    // The server never reads `slow`: the client can place at most the
    // 256-byte stream credit, then is blocked — memory bounded by the
    // negotiated credit, not by the peer's silence.
    var chunk: [128]u8 = undefined;
    @memset(&chunk, 'S');
    if (try p.clientToServer(slow, &chunk, false)) |x| alloc.free(x);
    if (try p.clientToServer(slow, &chunk, false)) |x| alloc.free(x);
    try testing.expectError(error.FlowControlBlocked, p.client.sendOnStream(slow, &chunk, false));

    const progress = p.client.streamSendProgress(slow).?;
    try testing.expect(progress.outstandingBytes() <= 256);

    // A healthy stream is unaffected by the slow one.
    const fast = try p.client.openStream();
    const got = try p.clientToServer(fast, "fast-wins", true);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings("fast-wins", got.?);
}

test "emitted datagrams respect the configured maximum size" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.max_data = 4 * 1024 * 1024;
    opts.max_stream_data = 64 * 1024;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    var big: [8192]u8 = undefined;
    @memset(&big, 'M');
    var sent: usize = 0;
    while (sent < big.len) {
        const got = try p.clientToServer(s, big[sent..@min(sent + 1024, big.len)], false);
        if (got) |x| alloc.free(x);
        sent += 1024;
    }
    // In-process the wire is unbounded, but quicz never emits a datagram
    // larger than the configured max_datagram_size (8192 here; the
    // real-socket proofs pin 1200/1350 against actual UDP payloads).
    try testing.expect(p.wire.max_datagram_seen <= 8192);
    try testing.expect(p.wire.max_datagram_seen >= 1200);
}
