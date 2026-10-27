# stress_helpers.sh -- shared helpers for the stress_* scripts.  Sourced.

# count_log_errors <opensips.log> -> number of ERROR/CRITICAL/FATAL lines.
# The scripts run opensips with `ulimit -c 0`, which makes the core log
# "CRITICAL:core:set_core_dump: core limits increased only to 0" at every
# start; that is the harness's own doing, not an error in the run.
count_log_errors() {
    [ -f "$1" ] || { echo 0; return; }
    grep -E "ERROR|CRITICAL|FATAL" "$1" | grep -vc "core:set_core_dump:"
}

# count_log_warns <opensips.log> -> number of WARN lines.
count_log_warns() {
    [ -f "$1" ] || { echo 0; return; }
    grep -c "WARN" "$1"
}

# stop_driver PID -- stop a background load-driver loop together with the
# command it is running.  Killing only the loop orphans its in-flight
# child (a `nats pub`, a sipsak), which then outlives the run.  The loop
# is frozen first so it cannot start another child in between.
stop_driver() {
    local pid="$1" kids
    kill -0 "$pid" 2>/dev/null || return 0
    kill -STOP "$pid" 2>/dev/null
    kids=$(ps --no-headers -o pid --ppid "$pid" 2>/dev/null)
    # shellcheck disable=SC2086
    [ -n "$kids" ] && kill $kids 2>/dev/null
    kill "$pid" 2>/dev/null
    kill -CONT "$pid" 2>/dev/null
    return 0
}
