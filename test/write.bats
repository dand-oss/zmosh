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
  [ "$status" -eq 1 ]
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

@test "write accepts exactly 128 KiB and rejects one byte more" {
  cd "$BATS_TEST_TMPDIR"
  run "$ZMX" run wt-boundary -d bash
  [ "$status" -eq 0 ]
  sleep 1

  # Exactly at the cap: accepted, full content round-trips.
  head -c 131072 /dev/zero | tr '\0' 'b' > exact.bin
  run "$ZMX" write wt-boundary "$BATS_TEST_TMPDIR/exact.out" < exact.bin
  [ "$status" -eq 0 ]
  [[ "$output" == *"file created"* ]]

  # One byte over: rejected with exit 1 before anything is sent.
  head -c 131073 /dev/zero | tr '\0' 'c' > over.bin
  run "$ZMX" write wt-boundary "$BATS_TEST_TMPDIR/over.out" < over.bin
  [ "$status" -eq 1 ]
  [[ "$output" == *"exceeds the 128 KiB limit"* ]]

  # A capped write lands in three chunks (printf|base64 > then >>), so
  # poll on the final SIZE, not existence — under full-suite load the
  # chunks drain at very different speeds.
  local i=0 size=0
  while [ "$i" -lt 120 ]; do
    if [ -f "$BATS_TEST_TMPDIR/exact.out" ]; then
      size=$(wc -c < "$BATS_TEST_TMPDIR/exact.out")
    fi
    [ "$size" -eq 131072 ] && break
    sleep 0.5
    i=$((i + 1))
  done
  [ "$size" -eq 131072 ]
  [ ! -f "$BATS_TEST_TMPDIR/over.out" ]
}

@test "daemon rejects a write when the pty queue is full, with exit 1" {
  # A non-reading command fills the queue: the first capped write occupies
  # it, the second cannot fit and must be rejected atomically.
  cd "$BATS_TEST_TMPDIR"
  run "$ZMX" run wt-full -d bash -c 'sleep 300'
  [ "$status" -eq 0 ]
  sleep 1

  head -c 131072 /dev/zero | tr '\0' 'd' > one.bin
  run "$ZMX" write wt-full "$BATS_TEST_TMPDIR/full-one.out" < one.bin
  [ "$status" -eq 0 ]
  [[ "$output" == *"file created"* ]]

  run "$ZMX" write wt-full "$BATS_TEST_TMPDIR/full-two.out" < one.bin
  [ "$status" -eq 1 ]
  [[ "$output" == *"write rejected: session busy"* ]]
  [[ "$output" != *"file created"* ]]
}
