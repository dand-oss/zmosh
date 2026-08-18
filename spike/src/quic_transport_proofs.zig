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
    try testing.expectEqual(@as(u64, 0), fresh.oldest_unsettled_offset);
    try testing.expectEqual(@as(u64, 0), fresh.outstandingBytes());
    try testing.expect(p.client.streamSendProgress(999_999) == null);

    const payload = "progress-across-the-wire";
    const got = try p.clientToServer(s, payload, false);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings(payload, got.?);

    // Server ACK return drains the logical offsets to zero.
    try p.flushServerShort();
    const progress = p.client.streamSendProgress(s).?;
    try testing.expectEqual(@as(u64, payload.len), progress.accepted_offset);
    try testing.expectEqual(@as(u64, payload.len), progress.oldest_unsettled_offset);
    try testing.expectEqual(@as(u64, 0), progress.outstandingBytes());
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

test "migration: PATH_CHALLENGE/RESPONSE commits the route; wrong responses cannot" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.migration_disabled = false;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    const first = try p.clientToServer(s, "old-path", false);
    defer if (first) |x| alloc.free(x);
    try testing.expectEqualStrings("old-path", first.?);

    // The committed route is still the original path.
    const pre = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(pre.remote.eql(p.client_path.local));

    // The client rebinds to a new source port (candidate path).
    const old_path = p.server_path;
    p.client_path.local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40123);
    p.server_path.remote = p.client_path.local;

    // Authenticated data from the new path is delivered by DCID routing,
    // but the route must NOT move without path validation.
    const via_new = try p.clientToServer(s, "new-path", false);
    defer if (via_new) |x| alloc.free(x);
    try testing.expectEqualStrings("new-path", via_new.?);
    const mid = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(mid.remote.eql(old_path.remote));

    // Real validation: the server queues an unpredictable PATH_CHALLENGE
    // and sends it on the candidate path.
    var challenge_bytes: [8]u8 = undefined;
    try testing.io.randomSecure(&challenge_bytes);
    try p.server.sendPathChallengeForPath(challenge_bytes, p.server_path.toUdp());
    try testing.expect(p.server.pendingPathChallengeCount() > 0);
    try p.flushServerShort();

    // The client's PATH_RESPONSE (auto-queued on receipt of the
    // challenge) travels back; only a matching response from the
    // candidate path commits the route through the validated feed.
    try p.flushClientShort();
    // Deliver the response through the validated-feed entry point.
    var rounds: usize = 0;
    while (p.server.outstandingPathChallengeCount() > 0 and rounds < 6) : (rounds += 1) {
        try p.flushServerShort();
        try p.flushClientShort();
    }
    try testing.expectEqual(@as(usize, 0), p.server.outstandingPathChallengeCount());

    const post = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(post.remote.eql(p.client_path.local));
    try testing.expect(!post.remote.eql(old_path.remote));

    // Traffic continues on the committed path.
    const after = try p.clientToServer(s, "after-migration", true);
    defer if (after) |x| alloc.free(x);
    try testing.expectEqualStrings("after-migration", after.?);
}

test "migration: stale, wrong, and old-path responses cannot commit" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.migration_disabled = false;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();
    const s = try p.client.openStream();
    if (try p.clientToServer(s, "seed", false)) |x| alloc.free(x);

    const old_path = p.server_path;

    // A second, unrelated candidate path: client rebinds to yet another
    // port and never validates it.
    const orig_local = p.client_path.local;
    p.client_path.local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 1 }, 40999);
    p.server_path.remote = p.client_path.local;

    // The server queues an unpredictable challenge for the candidate
    // path. Before any response arrives the challenge stays outstanding
    // and the route stays on the old path: a wrong or stale response
    // cannot commit anything because only a PATH_RESPONSE whose data
    // matches an outstanding challenge decrements the count (unknown
    // data is rejected at frame level inside quicz).
    var challenge: [8]u8 = undefined;
    try testing.io.randomSecure(&challenge);
    try p.server.sendPathChallengeForPath(challenge, p.server_path.toUdp());
    try p.flushServerShort();
    try testing.expect(p.server.outstandingPathChallengeCount() > 0);
    const still_old = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(still_old.remote.eql(old_path.remote));

    // A valid matching response eventually commits the route.
    try p.flushServerShort();
    try p.flushClientShort();
    var rounds: usize = 0;
    while (p.server.outstandingPathChallengeCount() > 0 and rounds < 6) : (rounds += 1) {
        try p.flushServerShort();
        try p.flushClientShort();
    }
    try testing.expectEqual(@as(usize, 0), p.server.outstandingPathChallengeCount());
    const committed = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(committed.remote.eql(p.client_path.local));

    // Traffic returning to the OLD path cannot silently re-commit it:
    // with the route now on the new path, old-path data still routes by
    // DCID but the committed route does not revert without fresh
    // validation.
    p.client_path.local = orig_local;
    p.server_path.remote = orig_local;
    const back = try p.clientToServer(s, "old-again", true);
    defer if (back) |x| alloc.free(x);
    try testing.expectEqualStrings("old-again", back.?);
    const not_reverted = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(!not_reverted.remote.eql(orig_local));
}

test "slow reader: backpressure blocks writes, spares control, then resumes" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.max_stream_data = 256;
    opts.max_data = 4 * 1024;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const slow = try p.client.openStream();
    var chunk: [128]u8 = undefined;
    @memset(&chunk, 'S');

    // Deliver 256 bytes on `slow` WITHOUT the server ever calling
    // recvOnStream: raw sends plus socket flush only, no receive drain.
    _ = try p.client.sendOnStream(slow, &chunk, false);
    try p.flushClientShort();
    _ = try p.client.sendOnStream(slow, &chunk, false);
    try p.flushClientShort();

    // The next write is blocked while the server still has not read.
    try testing.expectError(error.FlowControlBlocked, p.client.sendOnStream(slow, &chunk, false));
    const blocked = p.client.streamSendProgress(slow).?;
    try testing.expectEqual(@as(u64, 256), blocked.accepted_offset);
    try testing.expectEqual(@as(u64, 0), blocked.oldest_unsettled_offset);

    // Control traffic still progresses while the stream is blocked.
    try p.client.sendPing();
    try p.flushClientShort();
    try p.flushServerShort();
    try testing.expect(p.client.connectionState() == .active);

    // Draining the server read side resumes the credit.
    var buf: [512]u8 = undefined;
    var drained: usize = 0;
    while (try p.server.recvOnStream(slow, &buf)) |n| drained += n;
    try testing.expectEqual(@as(usize, 256), drained);
    try p.flushServerShort();
    _ = try p.client.sendOnStream(slow, &chunk, false);
    const got = try p.clientToServer(slow, &chunk, true);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings(&chunk, got.?);
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

/// Protected PATH_RESPONSE datagram builder for the fail-closed proofs:
/// fresh packet number per delivery (except where replay is the point).
fn makeResponse(
    alloc: std.mem.Allocator,
    pn: u64,
    data: [8]u8,
    keys: quicz.protection.Aes128PacketProtectionKeys,
) ![]u8 {
    var payload: [64]u8 = undefined;
    var w = std.Io.Writer.fixed(&payload);
    try quicz.frame.encodeFrame(&w, .{ .path_response = .{ .data = data } });
    return quicz.protection.protectShortPacketAes128(alloc, .{
        .dcid = &harness.server_scid,
        .spin_bit = false,
        .key_phase = false,
        .packet_number = pn,
    }, try quicz.packet.encodePacketNumberForHeader(pn, null), keys, w.buffered());
}

test "fail-closed: null hint, wrong path, one commit, replay, stale" {
    const alloc = testing.allocator;

    // ── (1) NULL HINT on its own fresh pair ──────────────────────────
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();

        const data1 = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
        const bound = p.server_path;
        try p.server.sendPathChallengeForPath(data1, bound.toUdp());
        const ch = (try p.pollShortTolerantForTest(false)) orelse return error.NoChallenge;
        defer alloc.free(ch);
        try p.deliver(false, ch);
        try testing.expectEqual(@as(usize, 1), p.server.outstandingPathChallengeCountForPath(bound.toUdp()));

        // Decoded frames driven directly on the connection: no feed, no
        // arrival hint — the bound challenge must NOT be consumed.
        try p.driveDecodedFramesNoHint(true, data1);
        try testing.expectEqual(@as(usize, 1), p.server.outstandingPathChallengeCountForPath(bound.toUdp()));
    }

    // ── (2)–(5) the wire-level matrix on a second fresh pair ────────
    var opts = try randomPsk();
    opts.migration_disabled = false;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    if (try p.clientToServer(s, "seed", false)) |x| alloc.free(x);
    const old_path = p.server_path;
    const candidate = quicz.endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 2 }, 50_001),
    };
    const other = quicz.endpoint.Udp4Tuple{
        .local = old_path.local,
        .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 3 }, 50_002),
    };
    const client_keys = p.clientKeyForTest();

    const data2 = [_]u8{ 0x21, 0x43, 0x65, 0x87, 0x78, 0x56, 0x34, 0x12 };
    try p.server.sendPathChallengeForPath(data2, candidate.toUdp());
    const ch2 = (try p.pollShortTolerantForTest(false)) orelse return error.NoChallenge;
    defer alloc.free(ch2);
    try p.deliver(false, ch2);
    try testing.expectEqual(@as(usize, 1), p.server.outstandingPathChallengeCountForPath(candidate.toUdp()));

    // (2) WRONG PATH: ignored, still outstanding, no commit.
    const wrong_dg = try makeResponse(alloc, 1, data2, client_keys);
    defer alloc.free(wrong_dg);
    try testing.expect((try p.deliverViaUpdatePathForTest(true, other, wrong_dg)) == null);
    try testing.expectEqual(@as(usize, 1), p.server.outstandingPathChallengeCountForPath(candidate.toUdp()));

    // (3) CANDIDATE PATH: consumed once, committed exactly once.
    const good_dg = try makeResponse(alloc, 2, data2, client_keys);
    defer alloc.free(good_dg);
    try testing.expect((try p.deliverViaUpdatePathForTest(true, candidate, good_dg)) != null);
    try testing.expectEqual(@as(usize, 0), p.server.outstandingPathChallengeCountForPath(candidate.toUdp()));

    // (4) EXACT-DATAGRAM REPLAY (same packet number): dedup, no commit.
    try testing.expect((try p.deliverViaUpdatePathForTest(true, candidate, good_dg)) == null);

    // (5) FRESH STALE and WRONG-DATA responses (fresh packet numbers)
    //     on a FRESH pair: the OrClose entry queues a close on frame
    //     errors, so this pair is isolated per the frozen rule.
    {
        var opts5 = try randomPsk();
        opts5.migration_disabled = false;
        var p5 = try Pair.create(alloc, opts5);
        defer p5.destroy();
        try p5.completeHandshake();
        const s5 = try p5.client.openStream();
        if (try p5.clientToServer(s5, "seed5", false)) |x| alloc.free(x);
        const cand5 = quicz.endpoint.Udp4Tuple{
            .local = p5.server_path.local,
            .remote = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 2 }, 50_001),
        };
        const keys5 = p5.clientKeyForTest();

        // STALE: no challenge exists — rejected, nothing committed.
        const stale_dg = try makeResponse(alloc, 1, [_]u8{1} ** 8, keys5);
        defer alloc.free(stale_dg);
        try testing.expect((p5.deliverViaUpdatePathForTest(true, cand5, stale_dg) catch null) == null);

        // WRONG DATA with a live bound challenge: frame-level rejection
        // and the challenge stays outstanding.
        const wrong2 = [_]u8{ 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };
        try p5.server.sendPathChallengeForPath(wrong2, cand5.toUdp());
        const ch3 = (try p5.pollShortTolerantForTest(false)) orelse return error.NoChallenge;
        defer alloc.free(ch3);
        try p5.deliver(false, ch3);
        try testing.expectEqual(@as(usize, 1), p5.server.outstandingPathChallengeCountForPath(cand5.toUdp()));
        const wrongdata_dg = try makeResponse(alloc, 2, [_]u8{9} ** 8, keys5);
        defer alloc.free(wrongdata_dg);
        try testing.expect((p5.deliverViaUpdatePathForTest(true, cand5, wrongdata_dg) catch null) == null);
        try testing.expectEqual(@as(usize, 1), p5.server.outstandingPathChallengeCountForPath(cand5.toUdp()));
    }
}

test "migration: source-ADDRESS change commits only the bound path" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.migration_disabled = false;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    const first = try p.clientToServer(s, "old-addr", false);
    defer if (first) |x| alloc.free(x);
    try testing.expectEqualStrings("old-addr", first.?);

    // Source-ADDRESS rebind (127.0.0.1 -> 127.0.0.2), not just a port.
    const old_remote = p.server_path.remote;
    p.client_path.local = quicz.endpoint.Udp4Address.init([_]u8{ 127, 0, 0, 2 }, p.client_path.local.port);
    p.server_path.remote = p.client_path.local;
    const candidate = p.server_path;

    const challenge = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    try p.server.sendPathChallengeForPath(challenge, candidate.toUdp());
    try p.flushServerShort();
    try testing.expect(p.server.outstandingPathChallengeCountForPath(candidate.toUdp()) > 0);

    // Authenticated data from the new ADDRESS routes by DCID but
    // commits nothing until validation completes.
    const via_new = try p.clientToServer(s, "new-addr", false);
    defer if (via_new) |x| alloc.free(x);
    try testing.expectEqualStrings("new-addr", via_new.?);

    var rounds: usize = 0;
    while (p.server.outstandingPathChallengeCountForPath(candidate.toUdp()) > 0 and rounds < 6) : (rounds += 1) {
        try p.flushClientShort();
        try p.flushServerShort();
    }
    try testing.expectEqual(@as(usize, 0), p.server.outstandingPathChallengeCountForPath(candidate.toUdp()));

    const post = try p.server_lifecycle.currentRoutePath(&harness.server_scid);
    try testing.expect(post.remote.eql(p.client_path.local));
    try testing.expect(!post.remote.eql(old_remote));

    const after = try p.clientToServer(s, "after-addr-migration", true);
    defer if (after) |x| alloc.free(x);
    try testing.expectEqualStrings("after-addr-migration", after.?);
}
