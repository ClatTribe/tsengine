#!/bin/sh
# read-env.sh — export a .env the way DOCKER COMPOSE reads it, not the way `sh` would.
#
# WHY THIS EXISTS. The obvious one-liner is `. ./.env`, and it is wrong in a way that fails
# silently on exactly the values that matter. Sourcing EVALUATES the file as shell, so
#
#     NEXT_PUBLIC_LEGAL_ENTITY=Acme Security Pvt Ltd
#
# sets the entity to "Acme" and then tries to run `Security` as a command. Measured: the variable
# comes out EMPTY, and the frontend build then publishes legal pages with no contracting entity —
# the precise failure passing these build args is supposed to prevent.
#
# docker compose does NOT shell-evaluate an env file: everything after the first `=` is the value,
# verbatim, with one layer of matching surrounding quotes removed. So the SAME .env worked under
# compose and broke under make, which is worse than either failing — the two halves of one product
# disagreeing about the same input.
#
# Usage:
#   . scripts/read-env.sh                    reads ./.env
#   TS_ENV_FILE=other.env . scripts/read-env.sh
#
# THE PATH COMES FROM AN ENV VAR, NOT A POSITIONAL ARG. POSIX `.` does not take arguments: bash and
# macOS's sh accept `. file arg` and set $1, dash — which is /bin/sh on Ubuntu, and therefore on CI —
# ignores it. So `. read-env.sh custom.env` read $1 as unset, fell back to ./.env, found nothing and
# exported nothing. Measured: same command, dash gives an empty variable where bash gives the value.
# $1 is still honoured where the shell provides it, but nothing depends on that.
_envfile="${TS_ENV_FILE:-${1:-.env}}"
[ -f "$_envfile" ] || return 0 2>/dev/null || exit 0

while IFS= read -r _line || [ -n "$_line" ]; do
    case "$_line" in
        ''|'#'*) continue ;;          # blank + comment
        *=*) ;;                        # a real assignment
        *) continue ;;                 # anything else is not ours to guess at
    esac
    _key=${_line%%=*}
    _val=${_line#*=}
    # `export FOO=...` in a .env is a common habit; accept it rather than creating a variable
    # literally named "export FOO".
    case "$_key" in 'export '*) _key=${_key#export } ;; esac
    # Trim surrounding whitespace on the KEY only. A value's whitespace is the value's business.
    _key=$(printf '%s' "$_key" | tr -d ' \t')
    [ -n "$_key" ] || continue
    # Strip ONE layer of matching quotes, as compose does.
    case "$_val" in
        \"*\") _val=${_val#\"}; _val=${_val%\"} ;;
        \'*\') _val=${_val#\'}; _val=${_val%\'} ;;
    esac
    export "$_key=$_val"
done < "$_envfile"
unset _envfile _line _key _val
