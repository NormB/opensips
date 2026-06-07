#!/usr/bin/env bash
#
# Integration test for the uac_registrant 423 / Min-Expires handling (gh #3910).
#
# A SIPp UAS plays the role of the registrar and answers the registrant's
# REGISTER with a crafted 423 (Interval Too Brief). A real OpenSIPS instance
# runs the uac_registrant module under test; the registrant is injected at
# runtime over the MI FIFO (reg_upsert), so a single config drives every case.
#
# Each case asserts two independent things:
#   1. SIPp verdict      - the on-the-wire behaviour (did the registrant retry,
#                          and with the right expires?). Positive cases enforce
#                          the retry's ";expires=" via an ereg check_it; negative
#                          cases pass iff no retry arrives within the window.
#   2. MI registrant state - the authoritative outcome of the state machine,
#                          read back with 'reg_list' (REGISTERED vs REGISTRAR_ERROR).
#
# Truth table exercised (W = requested expires = 60, M = Min-Expires):
#   A  M=120 > W            strict=1  -> retry@120 -> REGISTERED
#   B  M=30  <= W           strict=1  -> error, no retry -> REGISTRAR_ERROR
#   C  M=30  <= W           strict=0  -> retry@30  -> REGISTERED   (legacy/tolerant)
#   D  no Min-Expires       strict=1  -> error, no retry -> REGISTRAR_ERROR
#   E  M=60  == W (boundary) strict=1 -> error, no retry -> REGISTRAR_ERROR
#
# Usage:  ./run.sh [-v] [case ...]      (default: all cases; -v keeps logs)
#
set -u

# --------------------------------------------------------------------------
# Layout / configuration
# --------------------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"          # opensips source root
OPENSIPS="${OPENSIPS_BIN:-$ROOT/opensips}"
MPATH="${OPENSIPS_MPATH:-$ROOT/modules/}"
SIPP="${SIPP_BIN:-sipp}"

SIP_IP=127.0.0.1 ;  SIP_PORT=5060               # OpenSIPS SIP listener
REG_IP=127.0.0.1 ;  REG_PORT=5070               # SIPp registrar (UAS)
AOR="sip:alice@example.com"
CONTACT="sip:alice@$SIP_IP:$SIP_PORT"
REGISTRAR="sip:$REG_IP:$REG_PORT"
EXPIRY=60

KEEP=0
[ "${1:-}" = "-v" ] && { KEEP=1; shift; }

# case table: name|scenario|strict|expected_state
CASES=(
  "A_conformant|case_A_conformant.xml|1|REGISTERED_STATE"
  "B_low_strict|case_B_low_strict.xml|1|REGISTRAR_ERROR_STATE"
  "C_low_tolerant|case_C_low_tolerant.xml|0|REGISTERED_STATE"
  "D_missing|case_D_missing.xml|1|REGISTRAR_ERROR_STATE"
  "E_equal_strict|case_E_equal_strict.xml|1|REGISTRAR_ERROR_STATE"
)

# --------------------------------------------------------------------------
# Pre-flight
# --------------------------------------------------------------------------
[ -x "$OPENSIPS" ] || { echo "opensips binary not found/executable: $OPENSIPS" >&2; exit 2; }
command -v "$SIPP" >/dev/null   || { echo "sipp not found in PATH" >&2; exit 2; }
command -v jq >/dev/null        || { echo "jq not found in PATH" >&2; exit 2; }

WORK="$(mktemp -d /tmp/uacreg_sipp.XXXXXX)"
OPID=""
cleanup_run() { [ -n "$OPID" ] && kill "$OPID" 2>/dev/null; OPID=""; }
trap 'cleanup_run; [ "$KEEP" = 1 ] || rm -rf "$WORK"' EXIT

# --------------------------------------------------------------------------
# MI over the FIFO:  request = ":"reply_fifo":"jsonrpc
# --------------------------------------------------------------------------
RUN=""      # set per case
mi() {      # mi <method> [json-params]
  # reply-fifo name must not contain '.', '/' or '\' (mi_fifo forbids them)
  local method="$1" params="${2:-}" rf="mireply_${RANDOM}_${RANDOM}" out
  local rfpath="$RUN/$rf"
  rm -f "$rfpath"; mkfifo "$rfpath"
  ( timeout 5 cat "$rfpath" ) >"$RUN/.mi_out" &
  local reader=$!
  if [ -n "$params" ]; then
    printf ':%s:{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}\n' "$rf" "$method" "$params" >"$RUN/fifo"
  else
    printf ':%s:{"jsonrpc":"2.0","id":1,"method":"%s"}\n' "$rf" "$method" >"$RUN/fifo"
  fi
  wait $reader 2>/dev/null
  rm -f "$rfpath"
  cat "$RUN/.mi_out"
}

wait_mi_ready() {
  local i
  for i in $(seq 1 50); do
    [ -p "$RUN/fifo" ] && mi reg_list | jq -e . >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}

# state of our single registrant, parsed out of reg_list
reg_state() {
  mi reg_list | jq -r --arg aor "$AOR" \
    '.result.Records[]? | select(.AOR==$aor) | .state' 2>/dev/null | head -1
}

# --------------------------------------------------------------------------
# OpenSIPS lifecycle
# --------------------------------------------------------------------------
gen_cfg() {  # gen_cfg <strict>
  sed -e "s#@MPATH@#$MPATH#g" \
      -e "s#@SIP_SOCK@#udp:$SIP_IP:$SIP_PORT#g" \
      -e "s#@DBDIR@#$RUN#g" \
      -e "s#@FIFO@#$RUN/fifo#g" \
      -e "s#@REPLYDIR@#$RUN/#g" \
      -e "s#@STRICT@#$1#g" \
      "$HERE/opensips.cfg.template" >"$RUN/opensips.cfg"
}

start_opensips() {  # start_opensips <strict>
  cp "$HERE/db/version" "$HERE/db/registrant" "$RUN/"
  gen_cfg "$1"
  # -i : skip the module git-revision cross-check (local build tree may mix
  #      revisions; version + compile-flags are still verified).
  # -F : keep the main process in the foreground so $! is the killable PID.
  "$OPENSIPS" -i -F -f "$RUN/opensips.cfg" -w "$RUN" -P "$RUN/opensips.pid" \
      >"$RUN/opensips.log" 2>&1 &
  OPID=$!
}

upsert_registrant() {
  mi reg_upsert "$(jq -n \
      --arg aor "$AOR" --arg c "$CONTACT" --arg r "$REGISTRAR" \
      --arg u alice --arg p secret --argjson e "$EXPIRY" \
      '{aor:$aor, contact:$c, registrar:$r, proxy:"", third_party_registrant:"",
        username:$u, password:$p, binding_params:"", expiry:$e,
        forced_socket:"", cluster_shtag:"", state:0}')" >/dev/null
  # ensure it registers at the next timer tick rather than waiting a full cycle
  mi reg_force_register "$(jq -n --arg aor "$AOR" --arg c "$CONTACT" --arg r "$REGISTRAR" \
        '{aor:$aor, contact:$c, registrar:$r}')" >/dev/null
}

# --------------------------------------------------------------------------
# One test case
# --------------------------------------------------------------------------
run_case() {  # run_case name scenario strict expected_state
  local name="$1" scn="$2" strict="$3" want="$4"
  RUN="$WORK/$name"; mkdir -p "$RUN"

  start_opensips "$strict"
  if ! wait_mi_ready; then
    echo "FAIL  $name : OpenSIPS MI did not come up"; sed -n '1,40p' "$RUN/opensips.log"
    cleanup_run; return 1
  fi

  # SIPp UAS (registrar). -m 1: one call; exit 0 iff the call matched the script.
  timeout 40 "$SIPP" "$SIP_IP:$SIP_PORT" \
      -sf "$HERE/scenarios/$scn" -i "$REG_IP" -p "$REG_PORT" -m 1 \
      -trace_err -error_file "$RUN/sipp.err" \
      -trace_screen -screen_file "$RUN/sipp.screen" \
      >"$RUN/sipp.out" 2>&1 &
  local sipp_pid=$!

  sleep 0.5
  upsert_registrant

  wait "$sipp_pid"; local sipp_rc=$?

  sleep 1
  local got; got="$(reg_state)"
  cleanup_run

  local ok=1
  [ "$sipp_rc" -eq 0 ] || ok=0
  [ "$got" = "$want" ] || ok=0

  if [ "$ok" = 1 ]; then
    printf 'PASS  %-15s sipp=ok  state=%s\n' "$name" "$got"
    return 0
  else
    printf 'FAIL  %-15s sipp_rc=%s  state=%s (expected %s)\n' "$name" "$sipp_rc" "${got:-<none>}" "$want"
    echo "      --- opensips uac_registrant log (filtered) ---"
    grep -iE "min-expires|423|registrar error|bogus|non-conformant|REGISTER" "$RUN/opensips.log" | sed 's/^/      /' | tail -15
    echo "      --- sipp errors ---"; sed 's/^/      /' "$RUN/sipp.err" 2>/dev/null | tail -15
    return 1
  fi
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
select="${*:-all}"
pass=0; fail=0
echo "uac_registrant 423/Min-Expires SIPp integration test"
echo "opensips=$OPENSIPS  sipp=$($SIPP -v 2>&1 | grep -oE 'v[0-9.]+' | head -1)"
echo "------------------------------------------------------------"
for row in "${CASES[@]}"; do
  IFS='|' read -r name scn strict want <<<"$row"
  case "$select" in
    all) : ;;
    *) [[ " $select " == *" $name "* ]] || continue ;;
  esac
  if run_case "$name" "$scn" "$strict" "$want"; then pass=$((pass+1)); else fail=$((fail+1)); fi
done
echo "------------------------------------------------------------"
echo "result: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
