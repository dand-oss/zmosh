#!/bin/sh
# ssh-shim.sh — deterministic stand-in for `ssh` in tests and smokes.
#
# zmosh invokes:  $ZMX_SSH <host> -- '<remote command>'
# The shim drops the host (the loopback gateway runs locally), records its
# PID so tests can SIGSTOP/SIGCONT it, and executes the command in a shell.
# Requires no sshd and no network.

if [ -n "$ZMX_SSH_SHIM_LOG" ]; then
    echo "$$" >> "$ZMX_SSH_SHIM_LOG"
fi

shift # drop host
if [ "$1" = "--" ]; then
    shift
fi
exec sh -c "$1"
