//! Q1 spike build: proves Ghostty Snapshot v1 access through the required
//! public `ghostty_vt.snapshot` re-export, isolated from the zmosh build.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Same dependency options as zmosh's build.zig, plus an explicit
    // vt-features=+snapshot so a future default change cannot silently
    // remove snapshot support (plan Phase Q1 prerequisite).
    const ghostty = b.dependency("ghostty", .{
        .target = target,
        .optimize = optimize,
        .@"emit-lib-vt" = true,
        .@"emit-xcframework" = false,
        .@"emit-macos-app" = false,
        .@"vt-features" = "+snapshot",
    });

    const mod = b.addModule("spike", .{
        .root_source_file = b.path("src/snapshot_access.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("ghostty-vt", ghostty.module("ghostty-vt"));

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Q1 snapshot-access spike tests");
    test_step.dependOn(&run_tests.step);

    b.default_step = b.step("spike", "No-op default; use zig build test");
}
