# Plan: Replant zmosh on zmx v0.7.0 with semantic remote parity

## Summary

Replant zmosh on the frozen zmx v0.7.0 base at cd88d1b. Preserve zmosh's
encrypted UDP attach layer, terminal attach behavior, all ZMX_* variables,
socket and log conventions, public C ABI, and existing local daemon protocol.
Add remote parity for send, print, write, labels, tail, and kill through a
separate encrypted command channel.

The four non-negotiable semantic corrections are:

- tail follows future output only and never sends .Init;
- only write may create a missing session;
- kill --force performs stale-socket cleanup even without a reachable daemon;
- command traffic uses a 16-sequence span measured from the oldest
  unacknowledged packet (below the transport ACK window of 32); a count-only
  in-flight limit cannot protect a lost early packet.

No merge or push to master is allowed until every gate passes and landing is
explicitly authorized.

## Current state

- Frozen upstream base: cd88d1b, zmx v0.7.0, Zig 0.16.0.
- Local branch: replant-zmx0.7.
- master remains at 6f39fe1 and is untouched.
- Stages 0, 1, and 2 are complete.
- Stage 3 framing is implemented and remains the active review gate.
- Stage 4 gateway and later command work remain locked until Stage 3 is accepted.

## Preserved invariants

- Binary and package name remain zmosh.
- serve keeps aliases serve and s; send uses send and se.
- Existing ZMX_* environment variables remain unchanged.
- Existing zmx socket and log-directory conventions remain unchanged.
- Successful attach bootstrap remains exactly ZMX_CONNECT udp PORT KEY.
- Existing attach wire framing and terminal behavior remain unchanged.
- The public C ABI, exported symbols, enum values, callbacks, and headers remain unchanged.
- The daemon event loop and Unix-socket IPC remain the source of truth for local behavior.
- Network features stay in gateway modules; no daemon threads are added.
- Runtime dependencies remain limited to Ghostty.

### Phase 0: Freeze inputs, ledger, and toolchain

Use exact upstream commit cd88d1b rather than a moving upstream branch. Confirm
the package is zmx 0.7.0 and Zig is 0.16.0. Record every commit in
58eb669..master in the replant ledger with a disposition of ported,
already-upstream, intentionally obsolete, or documentation/build-only.

Verify the starting worktree is clean and origin/master is the recovery point.
Install the official Zig 0.16.0 tarball with its published checksum under
~/.local/zig-0.16.0, link ~/.local/bin/zig, and install a pinned Bats release
if necessary.

The ledger must cover the network algorithms, SSH behavior, terminal fixes,
C-library targets, build additions, documentation, and regression tests.

### Phase 1: Frozen zmx base and local parity

Rename remotes so upstream points to neurosnap/zmx and mmonad remains the
reference remote. Create the replant branch from cd88d1b.

Preserve zmosh-owned README.md, docs, include, AGENTS.md, CLAUDE.md,
.claude/skills/zig, network modules, C headers, and build additions. Rebrand
the executable, package, help, logs, completions, release archives, flake
outputs, and metadata to zmosh. Set the package version to 0.6.0-dev and
regenerate the Zig 0.16 package fingerprint for .zmosh.

Keep all ZMX_* names and zmx socket/log paths. Make serve/s and send/se the
canonical aliases. Remove zmx-only release and Docker artifacts, including
brew.tmpl, gen-brew.sh, index.tmpl, pico.sh, Dockerfile variants,
.dockerignore, and the superseded zmx release webpage docs/index.html.
Preserve zmosh-authored documentation.

Reach a local-only checkpoint with zig build, zig build check, zig build test,
the upstream Bats suite using zmosh, zig fmt --check, and git diff --check.

### Phase 2: Encrypted remote attach

Reintroduce crypto.zig, udp.zig, transport.zig, remote.zig, serve.zig, and
lib.zig on the Zig 0.16 module structure without changing their algorithms or
timing behavior.

Retain IPC tags 0 through 18, add SessionEnd as tag 19, retain
roundTripForTag(), retain four-field Resize including xpixel and ypixel, and
update frozen-tag tests. Use zmx Cfg, Daemon.ensureSession,
socket.getSocketPath, socket.sessionConnect, and daemonize.spawnPty. Pass the
already initialized Cfg and std.Io into serveMain; do not duplicate
configuration or socket-path logic and do not modify loop.daemonLoop.

Resolve ZMX_SESSION_PREFIX exactly once on the initiating client. Pass the
already-prefixed name using hidden --exact-session. Recognize that hidden flag
only before the session name; every argument after the session name, including
literal --exact-session, -r, spaces, and shell metacharacters, is payload.
Existing sessions ignore creation commands; newly created sessions receive
daemon.command before ensureSession.

Port SSH spawning to Zig 0.16 with a bounded connect-line buffer, a
10-second bootstrap timeout, inherited visible stderr, stdin isolation, proper
child ownership, and reliable reaping. Quote TERM, COLORTERM, session names,
and forwarded arguments using the shared shell-quoting utility. Resolve SSH
aliases with ssh -G for the UDP destination and fall back to the supplied host
on failure. Document that ProxyJump still requires direct UDP reachability.

Reapply remote argument forwarding, visible connect/loss errors, session-end
propagation, Kitty restoration, and terminal pixel dimensions. Permit bounded
ZMX_ERROR CODE MESSAGE diagnostics without changing successful bootstrap
framing.

The remote-attach checkpoint must cover existing-session rehydration, new
session command forwarding, prefix-once behavior, literal payload flags,
completion output, reconnect/loss reporting, and absence of orphan processes.

### Phase 3: Frozen command framing

Add src/remote_command.zig and Channel.command = 4. Keep attach transport
behavior separate from command interpretation.

Freeze a 20-byte big-endian header:

0 version u8, initially 1
1 kind u8: request=1, response=2, cancel=3
2 opcode u8
3 status u8; zero for requests
4 flags u8: FIRST=1, LAST=2, STREAM=4
5..7 three reserved zero bytes
8..11 request_id u32
12..15 total_len u32
16..19 offset u32
20 onward payload

Freeze opcodes as send=1, print=2, write=3, label_get=4, label_set=5,
label_clear=6, tail=7, and kill=8.

Freeze statuses as ok=0, invalid_request=1, unsupported_version=2,
unsupported_opcode=3, session_not_found=4, session_unresponsive=5, timeout=6,
too_large=7, cancelled=8, backpressure=9, and internal_error=255.

Limit command payload per packet to transport.max_payload_len minus 20, which
is 1080 bytes. The generic envelope limit is 64 MiB; the write command's v1
semantic limit is a shared 128 KiB (local and remote), raised only if the
daemon grows streamed flow control. Validate version,
kind, status, opcode, flags, reserved bytes, alignment, total length, offset
overflow, FIRST/LAST placement, body shape, and maximum size before allocation.

Permit empty requests for tail and label_clear as one FIRST|LAST frame with
total_len zero. Request and cancel frames must have status ok and may not use
STREAM. kill accepts only a single byte with value 0 or 1.

Reassemble by offset. Ignore byte-identical duplicate payload and metadata.
Reject conflicting overlaps and conflicting metadata. Require the final frame's
LAST flag regardless of arrival order. Cache the completed response by exact
request_id and compare opcode and total length before serving a duplicate.
Allow only one request per command gateway.

Bound sending to a 16-sequence span from the oldest unacknowledged packet; queue later chunks until ACKs release
capacity, and continue ACK and heartbeat processing during command execution.
Never log command content, labels, keys, file data, or protocol secrets.

Unit coverage must include golden bytes, empty requests, invalid versions,
unsupported opcodes, malformed flags, reserved bytes, status errors, offset
overflow, truncation, oversized payloads, invalid kill values, out-of-order
chunks, duplicate chunks, conflicting overlaps, conflicting metadata, missing
LAST, actual packet loss and retransmission, more than 32 chunks, the 16-sequence-span
flow control, and duplicate request IDs without repeated execution.

This phase is a review gate. Do not begin gateway or CLI work until its tests
and implementation are accepted.

### Phase 4: Ephemeral command gateway (umbrella: zmosh-bu1)

Add hidden command mode:

zmosh serve --command --exact-session SESSION

Do not reuse the attach gateway's preconnected daemon socket. The command
gateway binds encrypted UDP, prints the normal connect line, authenticates
one request, applies local daemon semantics, sends a final response, waits
briefly for acknowledgement, and exits naturally so SSH can be reaped.

send requires an existing live session, forwards .Send, and succeeds after the
complete IPC write. print requires an existing live session, forwards .Output,
and preserves bytes exactly. write may create a session through the normal
ensure path, forwards .Write, and waits for .Ack.

label_get requires an existing session and waits for .LabelData. label_set and
label_clear require an existing session, use local validation, and wait for
.Ack. kill preserves session-not-found behavior; --force performs stale-socket
cleanup; a live kill succeeds only after socket EOF confirms shutdown.

tail requires an existing session, connects as an ordinary daemon client,
never sends .Init, and forwards future .Output only. It remains alive until
cancelled, the session ends, or permanent loss occurs. The gateway forwards
raw daemon output and never rewrites it; the CLIENT strips ANSI with the
existing zmx helper. Keep stdout clean, write reconnect diagnostics to stderr,
pause daemon reads when the output window is full, bound queued output, and
return backpressure instead of unbounded growth.

Handle SIGINT and SIGTERM by sending cancellation and closing the daemon
socket. Use a short graceful-shutdown deadline, then terminate and reap the
SSH child if necessary.

#### Phase 4A: shared local write safety

Depends on Phase 3. One limit for local and remote write (128 KiB v1),
complete encoded PTY input built before enqueue, atomic rejection when
queue space is insufficient, no ACK of partial or dropped data, path
quoting via util.shellQuote, redacted logging (lengths/counts only —
never paths, labels, keys, or file data).

#### Phase 4B: finite command executor and encrypted command gateway

Depends on 4A. The serve --command gateway and finite command execution
per the semantic matrix below. Redirect gateway stdout to /dev/null after
the bootstrap line instead of closing it, so post-bootstrap session
creation cannot die on BrokenPipe.

#### Phase 4C: ordered tail streaming, cancellation, backpressure

Depends on 4B. Stream frames in transport-sequence order, cancellation
state machine (idempotent), bounded output queues with backpressure.

#### Phase 4D: encrypted loopback, timeout and orphan-process tests

Depends on 4C. End-to-end encrypted loopback tests, timeout behavior,
and no-orphan-process verification. The Phase 4 umbrella completes with
4D; Phase 5 depends on it.

### Phase 5: Remote CLI parity

Use one parser for:

zmosh send -r HOST SESSION [TEXT...]
zmosh print -r HOST SESSION [TEXT...]
zmosh write -r HOST SESSION FILE
zmosh get -r HOST SESSION [KEY]
zmosh set -r HOST SESSION KEY=VALUE...
zmosh clear -r HOST SESSION
zmosh tail -r HOST SESSION
zmosh kill -r HOST SESSION [--force]

Recognize remote options before -- and treat everything after -- as payload.
Read one-shot stdin before spawning SSH. send joins operands like local zmx
and strips one trailing LF from piped stdin. print preserves piped bytes and
trailing newlines. Successful output matches local commands exactly. Failures
produce one concise stderr message.

Use exit code 0 for success or normal tail/session end, 1 for command or
session failure, 2 for SSH/bootstrap failure, and 3 for permanent UDP loss.
Finite commands use a 30-second response deadline. Attach and tail retain
roaming-oriented lifetimes.

Add ZMX_SSH with default ssh, ZMX_UDP_PORT_RANGE=START:END, and
ZMX_REMOTE_COMMAND_TIMEOUT_MS with default 30000. Update Bash, Zsh, Fish, and
Nu completions and document command limitations and ProxyJump behavior.

### Phase 6: Build and C ABI

Port the zmx Zig 0.16 build structure, then add branded host libzmosh.a,
macOS library, iOS library, xcframework, and release archive steps. Preserve
Ghostty's pinned revision and required build flags.

Rebrand flake.nix package and app outputs while retaining Zig 0.16. Host-gate
Apple-only build commands so Linux can evaluate every step without Xcode.

Keep every exported C symbol, enum value, callback signature, and header
declaration unchanged. Document the actual public header path:
include/zmosh/zmosh.h.

### Phase 7: Terminal and replant audit

Compare the replant ledger against the completed branch so every zmosh commit
has a disposition. Verify or port two-phase scrollback serialization,
visible-screen clearing without scrollback loss, nested serialization,
Kitty keyboard restoration, and session persistence after the final client
disconnects.

Retain zmx improvements for terminal titles, OSC 7, synchronized output,
pixel resize, and task markers. Add docs/upstream-sync.md recording the frozen
zmx SHA, overlay modules, IPC and command allocations, alias decisions, and
the future upstream-sync checklist.

### Phase 8: Tests and end-to-end verification

Preserve all zmx unit and Bats tests, rehome the session-persistence,
Kitty Ctrl-Backslash, and session-line tests, and keep network tests with
their modules.

Add protocol tests for framing, reassembly, flow control, duplicate handling,
timeouts, cancellation, SSH connect-line parsing, bootstrap timeout, shell
quoting, and exact prefix behavior.

Use a deterministic ZMX_SSH shim for Bats. Cover remote attach/reconnect,
missing-session semantics, write-created sessions, send versus print stdin,
labels and validation, binary and multi-packet writes, tail future-output-only
behavior, tail cancellation, live kill, force stale-socket cleanup, visible
bootstrap errors, permanent loss, dropped/delayed/reordered/duplicated
packets, and orphan-process detection. Use SIGSTOP/SIGCONT on the recorded
gateway PID for deterministic loss testing.

Build libzmosh.a, compile a C consumer against include/zmosh/zmosh.h, verify
symbols and enum constants, and run a loopback connect/send/resize/disconnect
smoke test. A real SSH smoke is optional in CI but required before release.

### Phase 9: Gates and authorized landing

Required automated gates:

- zig build;
- zig build check;
- zig build test;
- bats test;
- zig build lib;
- zig build release;
- zig fmt --check;
- git diff --check.

Manually verify local attach/detach/reattach, terminal restoration, history
VT/HTML output, local run/wait/new commands, remote attach, heartbeat expiry
and reconnect, every remote one-shot, large writes, tail interruption, kill
cleanup, C smoke, and process cleanup.

Commit every green checkpoint as an atomic logical change. Push only the
feature branch with fast-forward-only updates. Before history cleanup, create
a backup branch. Merge and push master only after explicit landing
authorization. The final report must include the frozen upstream SHA, gate
results, skipped platform checks, ledger summary, and remaining macOS work.

## Assumptions and non-goals

- Old zmosh/zmx gateway-client mixing is unsupported.
- There are no public C ABI changes.
- Successful attach framing does not change.
- There are no daemon threads and no daemon IPC redesign.
- Remote list, history, run, wait, switch, wildcard, and multi-session
  operations are out of scope.
- There is no Rust rewrite.
- No runtime dependency beyond Ghostty is added.
- ProxyJump does not remove the requirement for direct UDP reachability.
- Existing sessions ignore forwarded creation commands; only new sessions run
  daemon.command.

## Command-semantic matrix (frozen)

| opcode | creates session | IPC traffic | success signal | timeout | success output |
|---|---|---|---|---|---|
| send | no (session_not_found) | .Send | complete IPC write | 30 s | none (local parity) |
| print | no | .Output | write queued | 30 s | none |
| write | yes (daemon-ensure, then .Write) | .Write → .Ack | .Ack received | 30 s | `file created PATH` via the response payload, plus `session "NAME" created` when the session is new — gateway stdout is redirected, so parity travels through the response |
| label_get | no | .LabelGet → .LabelData | .LabelData | 30 s | matches local get |
| label_set | no | .LabelSet → .Ack | .Ack | 30 s | matches local set |
| label_clear | no | .LabelClear → .Ack | .Ack | 30 s | matches local clear |
| kill | no | .Kill | daemon socket EOF confirms shutdown; --force also unlinks stale socket | 30 s | matches local kill |
| tail | no | connect as ordinary client, forward future .Output only (never .Init) | stream until session end or cancel | streaming | raw daemon bytes, transport-sequence order |

Exit codes: 0 success or normal tail/session end (SIGINT/SIGTERM map to
cancel → 0); 1 command/session error; 2 SSH/bootstrap failure; 3
permanent UDP loss.

## Gateway event-loop constraint

ipc.roundTripForTag() must NEVER be called inside the gateway event
loop: it blocks on a single daemon round-trip for up to one second,
stalling UDP ACK and heartbeat processing. The gateway polls the daemon
socket alongside its UDP socket and completes command responses from
event-loop state.
