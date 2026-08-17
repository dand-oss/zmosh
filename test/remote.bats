#!/usr/bin/env bats
# Remote attach tests over the loopback encrypted-UDP path.
#
# ZMX_SSH points at test/ssh-shim.sh so the "SSH" bootstrap runs the
# gateway locally — no sshd, no network, deterministic. attach needs a
# tty (raw mode), so each attach runs under `script`, bounded by timeout.

load test_helper

setup() {
  REPO_DIR="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
  if [[ ! -x "$REPO_DIR/zig-out/bin/zmosh" ]]; then
    cd "$REPO_DIR" && zig build
  fi
  ZMX="$REPO_DIR/zig-out/bin/zmosh"
  export ZMX_DIR="$BATS_TEST_TMPDIR/zmx-sockets"
  mkdir -p "$ZMX_DIR"
  export ZMX_SSH="$REPO_DIR/test/ssh-shim.sh"
  export ZMX_SSH_SHIM_LOG="$BATS_TEST_TMPDIR/shim.pids"
  export PATH="$REPO_DIR/zig-out/bin:$PATH"
}

teardown() {
  "$ZMX" kill rt-output rt-prefix rt-args rt-new >/dev/null 2>&1 || true
}

@test "remote attach rehydrates session output over UDP" {
  run "$ZMX" run rt-output -d bash -c 'echo remote-attach-marker'
  [ "$status" -eq 0 ]
  sleep 1

  timeout 10 script -qec "$ZMX attach -r localhost rt-output" /dev/null \
    >"$BATS_TEST_TMPDIR/attach.out" 2>&1 || true

  grep -q remote-attach-marker "$BATS_TEST_TMPDIR/attach.out"
  # the shim actually ran (bootstrap went through ZMX_SSH)
  [ -s "$ZMX_SSH_SHIM_LOG" ]
}

@test "remote attach: -r without a host errors" {
  run "$ZMX" attach -r
  [ "$status" -ne 0 ]
  [[ "$output" == *"-r requires a host"* ]]
}

@test "session prefix is applied exactly once" {
  export ZMX_SESSION_PREFIX="pfx."
  run "$ZMX" run rt-prefix -d bash -c 'echo prefix-marker'
  [ "$status" -eq 0 ]
  sleep 1

  timeout 10 script -qec "$ZMX attach -r localhost rt-prefix" /dev/null \
    >"$BATS_TEST_TMPDIR/attach.out" 2>&1 || true

  grep -q prefix-marker "$BATS_TEST_TMPDIR/attach.out"
  run "$ZMX" list --short
  [[ "$output" == *"pfx.rt-prefix"* ]]
  [[ "$output" != *"pfx.pfx"* ]]
}

@test "args after the session name are not eaten as -r" {
  run "$ZMX" run rt-args -d bash -c 'echo args-marker'
  [ "$status" -eq 0 ]
  sleep 1

  # `-r trailing` after the session must forward as a command argument,
  # not trigger "-r requires a host".
  timeout 10 script -qec "$ZMX attach -r localhost rt-args -r trailing" /dev/null \
    >"$BATS_TEST_TMPDIR/attach.out" 2>&1 || true

  grep -q args-marker "$BATS_TEST_TMPDIR/attach.out"
  grep -q -- "-r requires a host" "$BATS_TEST_TMPDIR/attach.out" && return 1
  return 0
}

@test "attach -r creates a new remote session running the forwarded command" {
  run "$ZMX" list --short
  [[ "$output" != *"rt-new"* ]]

  # The command must outlive the attach so the session is still listed;
  # a command that exits instantly ends (and removes) the session.
  timeout 8 script -qec "$ZMX attach -r localhost rt-new bash -c 'echo forwarded-command-marker; sleep 15'" /dev/null \
    >"$BATS_TEST_TMPDIR/attach.out" 2>&1 || true

  grep -q forwarded-command-marker "$BATS_TEST_TMPDIR/attach.out"
  run "$ZMX" list --short
  [[ "$output" == *"rt-new"* ]]
}

@test "fish completion exposes both remote spellings" {
  run "$ZMX" completions fish
  [ "$status" -eq 0 ]
  [[ "$output" == *"-s r"* ]]
  [[ "$output" == *"-l remote"* ]]
}

@test "bootstrap failure is visible and exits 2" {
  run "$ZMX" run rt-output -d bash -c 'echo marker'
  sleep 1
  # bats' run captures output itself; assert on $output (script propagates
  # the child's exit code, 2 = bootstrap failure).
  run env ZMX_SSH=/bin/false timeout 10 script -qec "$ZMX attach -r localhost rt-output" /dev/null
  [ "$status" -eq 2 ]
  [[ "$output" == *"remote connect to localhost failed"* ]]
}
