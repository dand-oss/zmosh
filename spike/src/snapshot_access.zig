//! Q1 spike: prove native Zig access to Ghostty Snapshot v1 through the
//! required public `ghostty_vt.snapshot` re-export.
//!
//! This file mirrors zmosh's daemon-side terminal usage (`src/loop.zig`):
//! one `ghostty_vt.Terminal` plus one persistent `TerminalStream` with
//! continuation tracking enabled before the first PTY byte. It compiles
//! only against a Ghostty tree carrying the one-line re-export:
//!
//!     pub const snapshot = terminal.snapshot;
//!
//! The whole point of the gate: zmosh owns a native Zig Terminal, so the
//! Zig codecs must be reachable without the C TerminalWrapper.

const std = @import("std");
const testing = std.testing;

const ghostty_vt = @import("ghostty-vt");
const snapshot = ghostty_vt.snapshot;

const Terminal = ghostty_vt.Terminal;
const TerminalStream = ghostty_vt.TerminalStream;

const cols = 80;
const rows = 24;
const scrollback_lines = 1000;
const feed_lines = 300; // comfortably exceeds `rows`, forcing scrollback
const max_continuation_bytes = 64 * 1024 * 1024; // plan Phase Q4 bound

fn initTerm(alloc: std.mem.Allocator) !Terminal {
    return Terminal.init(testing.io, alloc, .{
        .cols = cols,
        .rows = rows,
        .max_scrollback_lines = scrollback_lines,
    });
}

fn streamFor(alloc: std.mem.Allocator, term: *Terminal) TerminalStream {
    return TerminalStream.init(.{
        .allocator = alloc,
        .handler = term.vtHandler(),
        .continuation_max_bytes = max_continuation_bytes,
    });
}

/// VT input up to the snapshot cut: scrollback-generating lines, a title,
/// and one deliberately unfinished CSI that must survive as continuation.
fn writeFeed(w: *std.Io.Writer) !void {
    var i: usize = 0;
    while (i < feed_lines) : (i += 1) {
        try w.print("scroll line {d:0>3}\r\n", .{i});
    }
    try w.writeAll("\x1b]2;spike title\x1b\\");
    try w.writeAll("\x1b[31"); // unfinished SGR -> continuation bytes
}

fn hasScrollback(term: *const Terminal) bool {
    const pages = &term.screens.active.pages;
    return !pages.getTopLeft(.screen).eql(pages.getTopLeft(.active));
}

fn expectTerminalsEqual(a: *Terminal, b: *Terminal) !void {
    const a_text = try a.plainString(testing.allocator);
    defer testing.allocator.free(a_text);
    const b_text = try b.plainString(testing.allocator);
    defer testing.allocator.free(b_text);
    try testing.expectEqualStrings(a_text, b_text);
    try testing.expectEqual(a.screens.active.cursor.x, b.screens.active.cursor.x);
    try testing.expectEqual(a.screens.active.cursor.y, b.screens.active.cursor.y);
    try testing.expectEqual(
        a.screens.active.cursor.style_id,
        b.screens.active.cursor.style_id,
    );
    try testing.expectEqualStrings(a.getTitle().?, b.getTitle().?);
}

test "encode/decode round trip through the public snapshot alias" {
    const alloc = testing.allocator;

    var term = try initTerm(alloc);
    defer term.deinit(alloc);
    var stream = streamFor(alloc, &term);
    defer stream.deinit();

    var feed: [64 * 1024]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&feed);
    try writeFeed(&fw);
    stream.nextSlice(fw.buffered());

    // The unfinished CSI is the only input needed to recreate stream state.
    var cont_buf: [64]u8 = undefined;
    var cw: std.Io.Writer = .fixed(&cont_buf);
    try stream.writeContinuation(&cw);
    const continuation = cw.buffered();
    try testing.expectEqualStrings("\x1b[31", continuation);

    // Encode through the public alias, into one contiguous buffer — the
    // same shape as the Q4 daemon export path.
    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    try snapshot.encode(alloc, &out.writer, &term, .{
        .continuation = if (continuation.len == 0)
            .ground
        else
            .{ .bytes = continuation },
    });
    const encoded = out.writer.buffered();
    try testing.expect(encoded.len > 0);

    // Spool-first decode: a fixed reader over the complete buffer, ready()
    // exactly once, continuation replayed exactly once, then history.
    var reader: std.Io.Reader = .fixed(encoded);
    var decoder: snapshot.Decoder = .init(&reader);
    var decoded = try decoder.ready(alloc, testing.io, .{
        .max_continuation_bytes = max_continuation_bytes,
    });
    defer decoded.deinit(alloc);
    try testing.expect((decoded.history_rows.get(.primary) orelse 0) > 0);

    var restored = decoded.toOwned();
    defer restored.deinit(alloc);

    var restored_stream = streamFor(alloc, &restored);
    defer restored_stream.deinit();
    restored_stream.nextSlice(continuation); // replay exactly once

    while (try decoder.next(alloc, &restored)) |_| {}
    // FINISH validated; no trailing bytes may remain in the spool.
    try testing.expectEqual(@as(usize, 0), reader.buffered().len);

    try testing.expect(hasScrollback(&term));
    try testing.expect(hasScrollback(&restored));
    try expectTerminalsEqual(&term, &restored);

    // Both terminals stay in lockstep after the cut.
    stream.nextSlice("mA");
    restored_stream.nextSlice("mA");
    try expectTerminalsEqual(&term, &restored);
}

test "post-cut output applied before history pages matches uninterrupted terminal" {
    const alloc = testing.allocator;
    const post_cut = "m post-cut text\r\n";

    var feed: [64 * 1024]u8 = undefined;
    var fw: std.Io.Writer = .fixed(&feed);
    try writeFeed(&fw);

    // Control: an uninterrupted terminal that never heard of snapshots.
    var control = try initTerm(alloc);
    defer control.deinit(alloc);
    var control_stream = streamFor(alloc, &control);
    defer control_stream.deinit();
    control_stream.nextSlice(fw.buffered());
    control_stream.nextSlice(post_cut);

    // Source at the cut.
    var term = try initTerm(alloc);
    defer term.deinit(alloc);
    var stream = streamFor(alloc, &term);
    defer stream.deinit();
    stream.nextSlice(fw.buffered());

    var cont_buf: [64]u8 = undefined;
    var cw: std.Io.Writer = .fixed(&cont_buf);
    try stream.writeContinuation(&cw);
    const continuation = cw.buffered();

    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    try snapshot.encode(alloc, &out.writer, &term, .{
        .continuation = .{ .bytes = continuation },
    });

    // Spool-first decode; post-cut output arrives after READY but before
    // any history page — the Q4/Q5 live-attach ordering.
    var reader: std.Io.Reader = .fixed(out.writer.buffered());
    var decoder: snapshot.Decoder = .init(&reader);
    var decoded = try decoder.ready(alloc, testing.io, .{
        .max_continuation_bytes = max_continuation_bytes,
    });
    defer decoded.deinit(alloc);
    var restored = decoded.toOwned();
    defer restored.deinit(alloc);

    var restored_stream = streamFor(alloc, &restored);
    defer restored_stream.deinit();
    restored_stream.nextSlice(continuation);
    restored_stream.nextSlice(post_cut); // before history completes

    while (try decoder.next(alloc, &restored)) |_| {}
    try testing.expectEqual(@as(usize, 0), reader.buffered().len);

    try expectTerminalsEqual(&control, &restored);
    try testing.expect(hasScrollback(&control));
    try testing.expect(hasScrollback(&restored));
}
