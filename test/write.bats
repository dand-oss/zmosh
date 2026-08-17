#!/usr/bin/env bats
# Local write-command safety: shared 128 KiB limit, atomic rejection,
# shell-injection-proof path quoting (Phase 4A).

load test_helper

@test "write creates a file with the piped content" {
  run "$ZMX" run wt-basic -d bash
  [ "$status" -eq 0 ]
  sleep 1

  printf 'hello write\n' > "$BATS_TEST_TMPDIR/in.txt"
  # NB: piping into bats' run() executes it in a subshell and loses
  # $status/$output — feed stdin with a redirect instead.
  run "$ZMX" write wt-basic "$BATS_TEST_TMPDIR/wt-basic.txt" < "$BATS_TEST_TMPDIR/in.txt"
  [ "$status" -eq 0 ]
  [[ "$output" == *"file created"* ]]

  # The PTY command needs a moment to drain and execute.
  sleep 2
  [ -f "$BATS_TEST_TMPDIR/wt-basic.txt" ]
  grep -q "hello write" "$BATS_TEST_TMPDIR/wt-basic.txt"
}

@test "write rejects input over the shared 128 KiB limit atomically" {
  run "$ZMX" run wt-limit -d bash
  [ "$status" -eq 0 ]
  sleep 1

  # 200 KiB of input: the client must refuse before sending anything.
  head -c 204800 /dev/zero | tr '\0' 'a' > "$BATS_TEST_TMPDIR/big.txt"
  run "$ZMX" write wt-limit "$BATS_TEST_TMPDIR/wt-limit.txt" < "$BATS_TEST_TMPDIR/big.txt"
  [[ "$output" == *"exceeds the 128 KiB limit"* ]]
  [[ "$output" != *"file created"* ]]

  sleep 2
  # Atomic rejection: no file, and the session is still healthy.
  [ ! -f "$BATS_TEST_TMPDIR/wt-limit.txt" ]
  run "$ZMX" list --short
  [[ "$output" == *"wt-limit"* ]]
}

@test "write paths with shell metacharacters are quoted, not injected" {
  # Session cwd is where run executes; keep the probe local. The hostile
  # basename must stay slash-free — an embedded / would make the literal
  # target an impossible path (a directory component that never exists),
  # which would prove nothing about quoting.
  cd "$BATS_TEST_TMPDIR"
  run "$ZMX" run wt-inject -d bash
  [ "$status" -eq 0 ]
  sleep 1

  # Quote-break plus command injection: must stay one literal filename.
  local evil="x'; touch PWNED; '"
  printf 'payload\n' > "$BATS_TEST_TMPDIR/in2.txt"
  run "$ZMX" write wt-inject "$BATS_TEST_TMPDIR/$evil" < "$BATS_TEST_TMPDIR/in2.txt"
  [ "$status" -eq 0 ]
  [[ "$output" == *"file created"* ]]

  sleep 2
  [ ! -f "$BATS_TEST_TMPDIR/PWNED" ]
  [ -f "$BATS_TEST_TMPDIR/$evil" ]
}
