#!/bin/bash
#
# run.sh -- end-to-end test of the rtpengine subscribe / publish script
# functions against a live rtpengine (see pubsub_e2e.py).
#
# Needs a built tree (./opensips plus the sl, sipmsgops and rtpengine
# modules) and an rtpengine answering the ng protocol.
#
# Environment:
#   RTPENGINE_NG  rtpengine ng control socket   (default 127.0.0.1:2223)
#   SIP_PORT      local port OpenSIPS listens on (default 5098)
#
# Exit: 0 pass, 1 fail, 77 skipped (missing build or rtpengine).
#

set -u

here=$(cd "$(dirname "$0")" && pwd)
tree=$(cd "$here/../../../.." && pwd)
NG="${RTPENGINE_NG:-127.0.0.1:2223}"
PORT="${SIP_PORT:-5098}"

for f in opensips modules/sl/sl.so modules/sipmsgops/sipmsgops.so modules/rtpengine/rtpengine.so; do
	if [ ! -e "$tree/$f" ]; then
		echo "SKIP: $tree/$f not built"
		exit 77
	fi
done
# Config checks (no rtpengine needed): the flags of subscribe answer and
# unsubscribe carry the mandatory subscription tag, so they are required.
cfgfails=0
cfg_check() { # cfg_check <accepted|rejected> <statement>
	local f got
	f=$(mktemp)
	printf 'log_level=1\nstderror_enabled=yes\nsyslog_enabled=no\n' > "$f"
	printf 'socket=udp:127.0.0.1:%s\nmpath="%s/modules/"\n' "$PORT" "$tree" >> "$f"
	printf 'loadmodule "proto_udp.so"\nloadmodule "rtpengine.so"\n' >> "$f"
	printf 'modparam("rtpengine", "rtpengine_sock", "udp:%s")\n' "$NG" >> "$f"
	printf 'route {\n%s\n}\n' "$2" >> "$f"
	if "$tree/opensips" -C -f "$f" >/dev/null 2>&1; then got=accepted; else got=rejected; fi
	rm -f "$f"
	if [ "$got" = "$1" ]; then
		echo "  ok  : $1: $2"
	else
		echo "  FAIL: want $1, got $got: $2"
		cfgfails=$((cfgfails + 1))
	fi
}
echo "== config checks"
cfg_check rejected 'rtpengine_subscribe_answer();'
cfg_check rejected 'rtpengine_unsubscribe();'
cfg_check accepted 'rtpengine_subscribe_answer("to-tag=$var(t)");'
cfg_check accepted 'rtpengine_unsubscribe("to-tag=$var(t)", $var(sock));'
cfg_check accepted 'rtpengine_subscribe_request();'
cfg_check accepted 'rtpengine_publish();'
[ "$cfgfails" -eq 0 ] || exit 1

python3 "$here/pubsub_e2e.py" --ng "$NG" --ping || exit 77

work=$(mktemp -d)
pgid=""
cleanup() {
	[ -n "$pgid" ] && kill -TERM -- "-$pgid" 2>/dev/null
	sleep 0.5
	[ -n "$pgid" ] && kill -KILL -- "-$pgid" 2>/dev/null
	rm -rf "$work"
}
trap cleanup EXIT

sed -e "s|@TREE@|$tree|" -e "s|@NG@|$NG|" -e "s|@PORT@|$PORT|" \
	"$here/opensips.cfg.in" > "$work/opensips.cfg"

# no cores (small tmpfs hosts); its own process group for the teardown
ulimit -c 0
setsid "$tree/opensips" -F -m 64 -M 8 -f "$work/opensips.cfg" -w "$work" \
	> "$work/opensips.log" 2>&1 &
pgid=$!

for _ in $(seq 1 50); do
	ss -lun 2>/dev/null | grep -q "127.0.0.1:$PORT " && break
	if ! kill -0 "$pgid" 2>/dev/null; then
		echo "FAIL: opensips did not start"
		tail -30 "$work/opensips.log"
		exit 1
	fi
	sleep 0.2
done
sleep 0.5

rc=0
python3 "$here/pubsub_e2e.py" --ng "$NG" --sip "127.0.0.1:$PORT" || rc=$?
if [ "$rc" -ne 0 ]; then
	echo "--- opensips log (tail)"
	tail -40 "$work/opensips.log"
fi
exit "$rc"
