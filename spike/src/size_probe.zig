//! Size probe: one executable linking quicz through the same sans-I/O
//! surface the spike uses, so stripped-binary growth from the QUIC
//! dependency is measurable before production integration.

const std = @import("std");
const quicz = @import("quicz");

pub fn main(init: std.process.Init) !void {
    const alloc = init.gpa;
    var conn = try quicz.Connection.init(alloc, .client, .{
        .initial_max_data = 4 * 1024 * 1024,
        .initial_max_stream_data = 65536,
        .initial_max_streams_bidi = 4,
        .initial_max_streams_uni = 8,
        .max_idle_timeout_ms = 24 * 60 * 60 * 1000,
    });
    defer conn.deinit();
    var backend = quicz.tls13_backend.Tls13Backend.initClient(.{
        .alpn = &.{"zmosh/1"},
        .server_name = "zmosh",
    });
    var buf: [1200]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try backend.writeKeylog(&w);
    _ = conn.streamSendOutstandingBytes(0);
    _ = conn.streamSendOldestUnackedSentTimeNanos(0);
    std.debug.print("probe: {d} keylog bytes\n", .{w.buffered().len});
}
