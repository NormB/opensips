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
