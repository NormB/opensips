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
