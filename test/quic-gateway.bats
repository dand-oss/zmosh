#!/usr/bin/env bats
# QUIC gateway bootstrap tests: the ZMX_CONNECT quic line, visible
# mixed-binary failure (the pre-QUIC client rejects the quic token),
# and child reaping through the ZMX_SSH shim.

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
  "$ZMX" kill qg-line qg-mixed >/dev/null 2>&1 || true
}

@test "gateway emits the exact ZMX_CONNECT quic bootstrap line" {
  run "$ZMX" run qg-line -d bash -c 'echo quic-marker'
  [ "$status" -eq 0 ]
  sleep 1

  timeout 10 script -qec "$ZMX attach -r localhost qg-line" /dev/null \
    >"$BATS_TEST_TMPDIR/attach.out" 2>&1 || true

  # The pre-QUIC client cannot parse the line; its failure output
  # proves the line reached it (UnsupportedProtocol is preserved).
  [[ "$(<"$BATS_TEST_TMPDIR/attach.out")" == *"UnsupportedProtocol"* ]]
  # the shim actually ran (bootstrap went through ZMX_SSH)
  [ -s "$ZMX_SSH_SHIM_LOG" ]
  # no orphaned gateway process remains
  if [ -s "$ZMX_SSH_SHIM_LOG" ]; then
    while IFS= read -r pid || [ -n "$pid" ]; do
      if kill -0 "$pid" 2>/dev/null; then
        echo "orphaned gateway pid $pid"
        return 1
      fi
    done <"$ZMX_SSH_SHIM_LOG"
  fi
}

@test "mixed binaries fail visibly: old client rejects the quic token" {
  run "$ZMX" run qg-mixed -d bash -c 'echo mixed-marker'
  [ "$status" -eq 0 ]
  sleep 1

  run bash -c "timeout 10 $ZMX attach -r localhost qg-mixed; echo rc=\$?"
  [[ "$output" == *"UnsupportedProtocol"* ]]
  [[ "$output" == *"rc=2"* ]]
}
