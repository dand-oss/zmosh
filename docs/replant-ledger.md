# Replant ledger — zmosh on zmx v0.7.0

Frozen base: `cd88d1b` (neurosnap/zmx `upstream/main`, 2026-08-14, zon `0.7.0` / Zig `0.16.0`).
Fork range classified: `58eb669..master` (28 commits, old upstream = mmonad/zmosh).
Dispositions: **ported** (carried in this branch), **port-pending** (scheduled stage below),
**already-upstream** (zmx 0.7 has the equivalent), **obsolete** (intentionally dropped).

| # | Commit | Subject | Disposition | Where / notes |
|---|--------|---------|-------------|---------------|
| 1 | `0ebe543` | writeSessionLine test fields | already-upstream | zmx 0.7 restructured its tests; re-verify Stage 7 |
| 2 | `7daae47` | XChaCha20-Poly1305 datagram encryption | ported | `src/crypto.zig` preserved (inert until Stage 2) |
| 3 | `18142cd` | UDP transport, Mosh-style roaming | ported | `src/udp.zig` preserved (final state incl. `86d478f`) |
| 4 | `113ddc0` | remote attach via encrypted UDP | ported | `src/remote.zig` + `src/serve.zig` preserved; dispatch wiring in Stage 2 |
| 5 | `10d946a` | rename binary zmx→zmosh | obsolete | redone by Stage 1 rebrand on the new base |
| 6 | `d20ac1e` | local project setup | ported | `AGENTS.md`, `CLAUDE.md`, `.claude/skills/zig`, `docs/` preserved |
| 7 | `a6f65f4` | SSH steals stdin during remote attach | ported | inside preserved `remote.zig`; re-verify in Stage 2.6 (0.16 `std.process` rewrite) |
| 8 | `5d16850` | propagate session end to remote client | ported | `SessionEnd` tag moves 11→**19** (zmx took 11 for `Switch`), Stage 2.2 |
| 9 | `c8518e7` | forward TERM/COLORTERM via SSH | ported | inside `remote.zig`; covered by Stage 2.6 quoting rules |
| 10 | `b47f2e0` | chunk large output vs UDP fragmentation | ported | inside `serve.zig`; Stage 3 flow control (16-packet window) builds on it |
| 11 | `ee292e6` | libzmosh C library + XCFramework targets | ported | `src/lib.zig`, `include/` preserved; build wiring in Stage 6 |
| 12 | `61f832b` | README rewrite (remote mode, comparisons) | ported | preserved; Stage 5 documents new commands |
| 13 | `fab8cd1` | README build-targets + libzmosh section | ported | preserved; Stage 5/6 doc pass pending |
| 14 | `1dbff97` | version 0.4.0 | obsolete | replant sets `0.6.0-dev` |
| 15 | `2b6ebf7` | README homebrew/AUR install | ported | preserved |
| 16 | `85eb0fd` | AGENTS.md rename | ported | preserved |
| 17 | `7a6dd36` | xcframework bundle packaging fix | ported | `include/zmosh/zmosh.h` + modulemap preserved; build detail in Stage 6 |
| 18 | `ea02b25` | MinimumOSVersion 17 for iOS | port-pending | Stage 6 Apple build step |
| 19 | `79bca01` | merge upstream/main (mmonad) | obsolete | history event only |
| 20 | `86d478f` | reliable UDP transport layer (v0.5.0) | ported | `src/transport.zig` preserved; `Channel.command = 4` added in Stage 3 |
| 21 | `1124610` | pop Kitty keyboard protocol on detach | port-pending | remote half in preserved `remote.zig`; main.zig half maps to zmx `util.zig` — Stage 7 audit |
| 22 | `c145d3e` | two-phase scrollback serialization | port-pending | same split — Stage 7 audit |
| 23 | `6c314ea` | preserve scrollback on ESC[2J | port-pending | same split — Stage 7 audit |
| 24 | `b87bef0` | version 0.5.2 | obsolete | `0.6.0-dev` |
| 25 | `71eba23` | SSH PATH fix (prefer $PATH, Homebrew) | ported | inside preserved `remote.zig` |
| 26 | `79da8df` | remote attach: forward command arguments | port-pending | Stage 2.8 hand-reapply |
| 27 | `b4c3055` | remote attach: visible connect/loss failures | port-pending | Stage 2.8 hand-reapply |
| 28 | `6f39fe1` | regression: session persists after last client | port-pending | Stage 8 rehome into new test structure |

## Stage-1 rebrand decisions (this checkpoint)

- Binary/package/help/completions/release tarballs → `zmosh`; version `0.6.0-dev`;
  package fingerprint regenerated as prescribed by Zig 0.16 (`0xb8fc6fefb3ea6e7c`).
- **Kept** `ZMX_*` env vars and `zmx` socket/log directory names (`/run/user/{uid}/zmx`,
  `~/.local/state/zmx/logs`, `zmx.log`) — backward compatible with existing sessions.
- Aliases: `send` now `se` (zmx's fish completions advertised a ghost `se set` that the
  dispatch never implemented — removed); `s` reserved for `serve` (arrives Stage 2).
- Dropped zmx release infra: `brew.tmpl`, `gen-brew.sh`, `index.tmpl`, `pico.sh`,
  `Dockerfile*`, `.dockerignore`, `docs/index.html`.
- Deferred: `flake.nix` rebrand + Zig 0.16 pin → Stage 6 (nix unavailable on this host;
  bundling avoids a half-updated state).
- Toolchain (Stage 0, not repo content): Zig 0.16.0 official tarball, sha256-verified
  (`70e49664…3d00`), at `~/.local/zig-0.16.0`; bats-core v1.14.0 at `~/.local/bats-core`.
