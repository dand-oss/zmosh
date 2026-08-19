const std = @import("std");
const lib_posix = @import("posix.zig");

/// Self-pipe woken by signal handlers. std.posix.poll loops on .INTR internally
/// (PollError has no Interrupted member), so a signal that lands during poll()
/// never surfaces; the handler writes a byte here and poll() wakes on POLLIN.
pub var sig_pipe: [2]lib_posix.fd_t = .{ -1, -1 };

pub fn wakeSignalPipe(_: lib_posix.SIG, _: *const lib_posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    const saved = std.c._errno().*;
    _ = std.c.write(sig_pipe[1], "x", 1);
    std.c._errno().* = saved;
}

// std.posix.poll retries EINTR internally, so SA_RESTART is moot -- neither
// setting wakes the loop. The handler writes to sig_pipe instead; poll()
// wakes on its read end.
pub fn installWakeHandler(sig: u6) void {
    const act: lib_posix.Sigaction = .{
        .handler = .{ .sigaction = wakeSignalPipe },
        .mask = lib_posix.sigemptyset(),
        .flags = lib_posix.SA.SIGINFO,
    };
    lib_posix.sigaction(@as(lib_posix.SIG, @enumFromInt(sig)), &act, null);
}

pub fn ignoreSigpipe() void {
    const act: lib_posix.Sigaction = .{
        .handler = .{ .handler = lib_posix.SIG.IGN },
        .mask = lib_posix.sigemptyset(),
        .flags = 0,
    };
    lib_posix.sigaction(lib_posix.SIG.PIPE, &act, null);
}

/// Idempotent, ownership-reporting pipe acquisition: true when THIS
/// call created the pipe, false when one is already open. Callers
/// close only pipes they opened, via `closeSignalPipe`.
pub fn acquireSignalPipe() !bool {
    if (sig_pipe[0] != -1) return false;
    sig_pipe = try lib_posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    return true;
}

pub fn openSignalPipe() !void {
    _ = try acquireSignalPipe();
}

/// Close the pipe and reset both descriptors so a later acquire
/// creates a fresh one. Only the owner of the current pipe calls this.
pub fn closeSignalPipe() void {
    if (sig_pipe[0] != -1) lib_posix.close(sig_pipe[0]);
    if (sig_pipe[1] != -1) lib_posix.close(sig_pipe[1]);
    sig_pipe = .{ -1, -1 };
}

pub fn drainSignalPipe() void {
    var b: [16]u8 = undefined;
    while (true) {
        const n = lib_posix.read(sig_pipe[0], &b) catch return;
        if (n == 0) return;
    }
}
