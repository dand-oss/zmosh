comptime {
    _ = @import("main.zig");
    _ = @import("util.zig");
    _ = @import("socket.zig");
    _ = @import("ipc.zig");
    _ = @import("label.zig");
    _ = @import("signal.zig");
    _ = @import("loop.zig");
    _ = @import("cfg.zig");
    _ = @import("daemonize.zig");
    _ = @import("crypto.zig");
    _ = @import("udp.zig");
    _ = @import("transport.zig");
    _ = @import("quic_transport.zig");
    _ = @import("quic_gateway.zig");
    // Re-added as each module is ported to 0.16 (stage 2 slices):
    _ = @import("serve.zig");
    _ = @import("remote.zig");
    _ = @import("lib.zig");
    _ = @import("remote_command.zig");
}
