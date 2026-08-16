const std = @import("std");

pub const Shell = enum {
    bash,
    zsh,
    fish,
    nu,

    pub fn fromString(s: []const u8) ?Shell {
        if (std.mem.eql(u8, s, "bash")) return .bash;
        if (std.mem.eql(u8, s, "zsh")) return .zsh;
        if (std.mem.eql(u8, s, "fish")) return .fish;
        if (std.mem.eql(u8, s, "nu")) return .nu;

        return null;
    }

    pub fn getCompletionScript(self: Shell) []const u8 {
        return switch (self) {
            .bash => bash_completions,
            .zsh => zsh_completions,
            .fish => fish_completions,
            .nu => nu_completions,
        };
    }
};

const bash_completions =
    \\_zmx_completions() {
    \\  local cur prev words cword
    \\  COMPREPLY=()
    \\  cur="${COMP_WORDS[COMP_CWORD]}"
    \\  prev="${COMP_WORDS[COMP_CWORD-1]}"
    \\
    \\  local commands="attach run send print write detach list kill history get set clear wait tail completions version help"
    \\
    \\  if [[ $COMP_CWORD -eq 1 ]]; then
    \\    COMPREPLY=($(compgen -W "$commands" -- "$cur"))
    \\    return 0
    \\  fi
    \\
    \\  case "$prev" in
    \\    attach|run|send|print|write|kill|history|get|set|clear|wait|tail)
    \\      local sessions=$(zmosh list --short 2>/dev/null | tr '\n' ' ')
    \\      COMPREPLY=($(compgen -W "$sessions" -- "$cur"))
    \\      ;;
    \\    completions)
    \\      COMPREPLY=($(compgen -W "bash zsh fish nu" -- "$cur"))
    \\      ;;
    \\    list)
    \\      COMPREPLY=($(compgen -W "--short" -- "$cur"))
    \\      ;;
    \\    *)
    \\      ;;
    \\  esac
    \\}
    \\
    \\complete -o bashdefault -o default -F _zmx_completions zmosh
;

const zsh_completions =
    \\#compdef zmosh
    \\_zmx() {
    \\  local context state state_descr line
    \\  typeset -A opt_args
    \\
    \\  _arguments -C \
    \\    '1: :->commands' \
    \\    '2: :->args' \
    \\    '*: :->trailing' \
    \\    && return 0
    \\
    \\  case $state in
    \\    commands)
    \\      local -a commands
    \\      commands=(
    \\        'attach:Attach to session, creating if needed'
    \\        'run:Send command without attaching'
    \\        'send:Send raw input to session PTY'
    \\        'print:Inject text into session display'
    \\        'write:Write stdin to file_path through the session'
    \\        'detach:Detach all clients from current session'
    \\        'list:List active sessions'
    \\        'kill:Kill a session'
    \\        'history:Output session scrollback'
    \\        'wait:Wait for session tasks to complete'
    \\        'tail:Follow session output'
    \\        'completions:Shell completion scripts'
    \\        'get:Get session labels'
    \\        'set:Set session labels'
    \\        'clear:Clear all session labels'
    \\        'version:Show version'
    \\        'help:Show help message'
    \\      )
    \\      _describe 'command' commands
    \\      ;;
    \\    args)
    \\      case $words[2] in
    \\        attach|a|kill|k|run|r|send|se|print|p|write|wr|history|get|g|set|clear|hi|wait|w|tail|t)
    \\          _zmx_sessions
    \\          ;;
    \\        completions|c)
    \\          _values 'shell' 'bash' 'zsh' 'fish' 'nu'
    \\          ;;
    \\        list|l)
    \\          _values 'options' '--short'
    \\          ;;
    \\      esac
    \\      ;;
    \\    trailing)
    \\      # Additional args for commands like 'attach' or 'run'
    \\      ;;
    \\  esac
    \\}
    \\
    \\_zmx_sessions() {
    \\  local -a sessions
    \\
    \\  local local_sessions=$(zmosh list --short 2>/dev/null)
    \\  if [[ -n "$local_sessions" ]]; then
    \\    sessions+=(${(f)local_sessions})
    \\  fi
    \\
    \\  _describe 'local session' sessions
    \\}
    \\
    \\compdef _zmx zmosh
;

const fish_completions =
    \\complete -c zmosh -f
    \\
    \\# zmosh flags
    \\complete -c zmosh -x -n '__fish_is_nth_token 1' -s v -l version -d 'Show version'
    \\complete -c zmosh -x -n '__fish_is_nth_token 1' -s h -d 'Show help message'
    \\
    \\# zmosh subcommands
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a attach -d 'Attach to session, creating if needed'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a run -d 'Send command without attaching'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a send -d 'Send raw input to session PTY'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a print -d 'Inject text into session display'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a write -d 'Write stdin to file_path through the session'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a detach -d 'Detach all clients (ctrl+\ for current client)'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a list -d 'List active sessions'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a kill -d 'Kill session and all attached clients'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a history -d 'Output session scrollback'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a wait -d 'Wait for session tasks to complete'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a tail -d 'Follow session output'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a completions -d 'Shell completions (bash, zsh, fish, nu)'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a version -d 'Show version'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a get -d 'Get session labels'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a set -d 'Set session labels'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a clear -d 'Clear all session labels'
    \\complete -c zmosh -n "__fish_is_nth_token 1" -a help -d 'Show help message'
    \\
    \\# Complete session names and shells
    \\complete -c zmosh -n "__fish_is_nth_token 2; and __fish_seen_subcommand_from a attach r run se send p print wr write hi history g get set clear" -a '(zmosh list --short 2>/dev/null)' -d 'Session name'
    \\complete -c zmosh -n "not __fish_is_nth_token 1; and __fish_seen_subcommand_from k kill w wait t tail" -a '(zmosh list --short 2>/dev/null)' -d 'Session name'
    \\
    \\complete -c zmosh -n "__fish_is_nth_token 2; and __fish_seen_subcommand_from c completions" -a 'bash zsh fish nu' -d Shell
    \\
    \\# Subcommand flags
    \\complete -c zmosh -n "__fish_seen_subcommand_from r run" -s d -d 'Detach from the calling terminal; use `wait` to track its status'
    \\complete -c zmosh -n "__fish_seen_subcommand_from r run" -l fish -d 'Required when the session runs fish shell'
    \\complete -c zmosh -n "__fish_seen_subcommand_from l list" -l short -d 'Short output'
    \\complete -c zmosh -n "__fish_seen_subcommand_from l list" -l where -d 'Filter by label (key=value)' -r
    \\complete -c zmosh -n "__fish_seen_subcommand_from k kill" -l force -d 'Force kill'
    \\complete -c zmosh -n "__fish_seen_subcommand_from hi history" -l vt -d 'History format for escape sequences'
    \\complete -c zmosh -n "__fish_seen_subcommand_from hi history" -l html -d 'History format for escape sequences'
;

const nu_completions =
    \\def "nu-complete zmosh sessions" [] {
    \\    zmosh list --short | lines
    \\}
    \\
    \\def "nu-complete zmosh complete" [] {
    \\    [bash fish nu zsh]
    \\}
    \\
    \\export extern "zmosh attach" [
    \\    name: string@"nu-complete zmosh sessions"
    \\    ...rest: string
    \\]
    \\
    \\export extern "zmosh run" [
    \\    name: string@"nu-complete zmosh sessions"
    \\    -d
    \\    --fish
    \\    ...rest: string
    \\]
    \\
    \\export extern "zmosh send" [
    \\    name: string@"nu-complete zmosh sessions"
    \\    text: string
    \\]
    \\
    \\export extern "zmosh print" [
    \\    name: string@"nu-complete zmosh sessions"
    \\    text: string
    \\]
    \\
    \\export extern "zmosh write" [
    \\    name: string@"nu-complete zmosh sessions"
    \\    path: path
    \\]
    \\
    \\export extern "zmosh kill" [
    \\    --force
    \\    name: string@"nu-complete zmosh sessions"
    \\]
    \\
    \\export extern "zmosh detach" []
    \\export extern "zmosh list" [--short]
    \\export extern "zmosh history" [name: string@"nu-complete zmosh sessions", --vt, --html]
    \\export extern "zmosh wait" [...sessions: string@"nu-complete zmosh sessions"]
    \\export extern "zmosh tail" [...sessions: string@"nu-complete zmosh sessions"]
    \\export extern "zmosh version" []
    \\export extern "completions" [shell: string@"nu-complete zmosh complete"]
    \\export extern "zmosh get" [
    \\    name?: string@"nu-complete zmosh sessions"
    \\]
    \\
    \\export extern "zmosh set" [
    \\    name?: string@"nu-complete zmosh sessions"
    \\    ...pairs: string
    \\]
    \\
    \\export extern "zmosh clear" [
    \\    name?: string@"nu-complete zmosh sessions"
    \\]
    \\
    \\export extern "zmosh help" []
;
