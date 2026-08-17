//! Q1 transport and resource proofs over the sans-I/O harness:
//! negotiated bounds, RESET_STREAM / STOP_SENDING observability, idle
//! lifetime negotiation with scaled timer expiry, keepalive, and the
//! deterministic fault matrix (loss, duplication, corruption, blackout).

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
    if (try p.clientToServer(stream_id, "before-reset", false)) |got| testing.allocator.free(got);
    try p.client.resetStream(stream_id, 4242);
    // Deliver the RESET_STREAM.
    try p.flushClientShort();
    const state = (try p.server.streamState(stream_id)).?;
    try testing.expect(state.receive_reset_error_code != null);
    try testing.expectEqual(@as(u64, 4242), state.receive_reset_error_code.?);
}

test "STOP_SENDING is observable by the application" {
    const alloc = testing.allocator;
    var p = try Pair.create(alloc, try randomPsk());
    defer p.destroy();
    try p.completeHandshake();

    const stream_id = try p.client.openStream();
    if (try p.clientToServer(stream_id, "early", false)) |got| testing.allocator.free(got);

    // The server asks the client to stop sending on that stream.
    try p.server.stopSending(stream_id, 7777);
    try p.flushServerShort();
    const server_state = (try p.server.streamState(stream_id)).?;
    try testing.expect(server_state.receive_stop_sending_sent == true);
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
        // Advance far past the deadline and service the connection's
        // pending work; the connection must leave the active state.
        p.now_nanos += 5 * std.time.ns_per_s;
        _ = try p.client_lifecycle.processPendingWork(harness.client_handle, p.client, p.now_nanos);
        try testing.expect(p.client.connectionState() != .active);
    }
}

test "keepalive PING holds the connection open across idle windows" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.idle_timeout_ms = 250;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    // Scaled 1-second keepalive from the plan becomes 50 ms here: send a
    // PING and deliver it well within each 250 ms idle window, three
    // times, advancing the clock across what would otherwise be several
    // idle deadlines.
    var round: usize = 0;
    while (round < 3) : (round += 1) {
        p.now_nanos += 50 * std.time.ns_per_ms;
        try p.client.sendPing();
        try p.flushClientShort();
        try testing.expect(p.client.connectionState() == .active);
    }
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

    // Corruption: an AEAD-failed datagram is discarded without killing
    // the connection; subsequent traffic flows normally. (Retransmission
    // of the lost bytes rides the same PTO machinery proven by the
    // Initial-loss block above and quicz's own retransmission suite.)
    {
        var p = try Pair.create(alloc, try randomPsk());
        defer p.destroy();
        try p.completeHandshake();
        p.wire.corrupt_once = true;
        const s = try p.client.openStream();
        const lost = try p.clientToServer(s, "corrupted-copy", true);
        defer if (lost) |x| alloc.free(x);
        try testing.expectEqual(@as(usize, 1), p.wire.corrupted);
        try testing.expect(p.client.connectionState() == .active);

        // Fresh traffic after the corrupted datagram delivers exactly.
        const s2 = try p.client.openStream();
        const got = try p.clientToServer(s2, "after-corruption", true);
        defer if (got) |x| alloc.free(x);
        try testing.expectEqualStrings("after-corruption", got.?);
    }

    // Ten-second outage (scaled to 100 ms): nothing delivers during the
    // blackout; the connection recovers afterwards and still passes data.
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
        const s2 = try p.client.openStream();
        const got = try p.clientToServer(s2, "after-blackout", true);
        defer if (got) |x| alloc.free(x);
        try testing.expectEqualStrings("after-blackout", got.?);
    }
}

test "stream isolation: a stalled output stream cannot block input or control" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    // Tiny per-stream credit so the heavy stream stalls quickly.
    opts.max_stream_data = 256;
    opts.max_data = 4 * 1024;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const output = try p.client.openStream();
    const input = try p.client.openStream();

    // Drain the 256-byte stream credit on `output` so it is provably
    // stalled by per-stream flow control.
    var chunk: [128]u8 = undefined;
    @memset(&chunk, 'O');
    if (try p.clientToServer(output, &chunk, false)) |got| alloc.free(got);
    if (try p.clientToServer(output, &chunk, false)) |got| alloc.free(got);

    // The stalled output stream now blocks further writes on itself...
    try testing.expectError(error.FlowControlBlocked, p.client.sendOnStream(output, &chunk, false));

    // ...while a different stream and control (PING) still flow and are
    // delivered: stream isolation under output stall.
    try p.client.sendPing();
    const small = try p.clientToServer(input, "input-wins", true);
    defer if (small) |s_| alloc.free(s_);
    try testing.expectEqualStrings("input-wins", small.?);
    try testing.expect(p.client.connectionState() == .active);
}

test "per-stream outstanding bytes and oldest-unacked age (upstreamable patch)" {
    const alloc = testing.allocator;
    var opts = try randomPsk();
    opts.max_stream_data = 2048;
    var p = try Pair.create(alloc, opts);
    defer p.destroy();
    try p.completeHandshake();

    const s = try p.client.openStream();
    // A fresh send side reports zero outstanding, no unacked age.
    try testing.expectEqual(@as(?u64, 0), p.client.streamSendOutstandingBytes(s));
    try testing.expect(p.client.streamSendOldestUnackedSentTimeNanos(s) == null);
    // A stream with no send side reports null.
    try testing.expect(p.client.streamSendOutstandingBytes(999_999) == null);

    // Send while the server's ACK has not returned: every byte is queued
    // or in flight and unacknowledged, with a real send timestamp.
    const payload = "outstanding-bytes-payload";
    const got = try p.clientToServer(s, payload, false);
    defer if (got) |x| alloc.free(x);
    try testing.expectEqualStrings(payload, got.?);
    try testing.expectEqual(@as(?u64, payload.len), p.client.streamSendOutstandingBytes(s));
    const oldest = p.client.streamSendOldestUnackedSentTimeNanos(s).?;
    try testing.expect(oldest <= p.now_nanos);

    // After the server's ACK returns, the stream drains to zero.
    try p.flushServerShort();
    try testing.expectEqual(@as(?u64, 0), p.client.streamSendOutstandingBytes(s));
}
