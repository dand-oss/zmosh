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

    // Q1 hard gate: certificate-free external-PSK TLS 1.3 over the sans-I/O
    // layer, against the unmodified quicz pin.
    const quicz = b.dependency("quicz", .{
        .target = target,
        .optimize = optimize,
    });
    const psk_mod = b.addModule("spike-psk", .{
        .root_source_file = b.path("src/quic_psk_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    psk_mod.addImport("quicz", quicz.module("quicz"));

    const psk_tests = b.addTest(.{ .root_module = psk_mod });
    const run_psk_tests = b.addRunArtifact(psk_tests);

    // Q1 transport/resource proofs and the deterministic fault matrix,
    // sharing the sans-I/O harness module.
    const proofs_mod = b.addModule("spike-proofs", .{
        .root_source_file = b.path("src/quic_transport_proofs.zig"),
        .target = target,
        .optimize = optimize,
    });
    proofs_mod.addImport("quicz", quicz.module("quicz"));
    const proofs_tests = b.addTest(.{ .root_module = proofs_mod });
    const run_proofs_tests = b.addRunArtifact(proofs_tests);

    // quicz's build registers its own top-level "test" step; avoid the
    // name collision by giving every gate an explicit unique step.
    const spike_test = b.step("spike-test", "Run Q1 spike tests (snapshot access + PSK gate + transport proofs)");
    spike_test.dependOn(&run_tests.step);
    spike_test.dependOn(&run_psk_tests.step);
    spike_test.dependOn(&run_proofs_tests.step);

    // Stripped-size probe: one exe linking quicz the way zmosh would.
    const probe_mod = b.createModule(.{
        .root_source_file = b.path("src/size_probe.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });
    probe_mod.addImport("quicz", quicz.module("quicz"));
    const probe_exe = b.addExecutable(.{
        .name = "quicz-size-probe",
        .root_module = probe_mod,
    });
    const install_probe = b.addInstallArtifact(probe_exe, .{});
    const probe_step = b.step("size-probe", "Build the stripped quicz size-probe executable");
    probe_step.dependOn(&install_probe.step);

    const quicz_suite = b.step("quicz-suite", "Run the pinned quicz upstream test suite");
    if (quicz.builder.top_level_steps.get("test")) |dep_test| {
        quicz_suite.dependOn(&dep_test.step);
    } else {
        quicz_suite.dependOn(&b.addFail("quicz-test-step-missing").step);
    }

    b.default_step = b.step("spike", "No-op default; use zig build test");
}
