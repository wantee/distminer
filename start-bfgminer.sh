#!/bin/sh
BFGMINER_OPTS="-S dist:auto -o http://api.bitcoin.cz:8332 -u xxxx -p xxxx --storm-url http://drpc1v.safe.zzbc.qihoo.net:3775/drpc/DistMiner --task-num 100 --task-hash 3000000"
n="
"
startscreen() {
	name="$1"; shift
	cmd="$1"; shift
	if ! screen -ls | grep -q "^[[:space:]]\+[0-9]\+\.$name"; then
		screen -dmS "$name"
	else
		for i in 1 2 3; do
			screen -x "$name" -p 0 -X stuff $(echo 'x' | tr 'x' '\003')
		done
		screen -x "$name" -p 0 -X stuff "stty sane$n"
	fi
	screen -x "$name" -p 0 -X stuff "$cmd$n"
}
PROG=bfgminer
MYDIR="$(dirname "$0")"
WHICHPROG="$(which "$PROG" 2>/dev/null)"
#if test -f "$MYDIR/$PROG" && test "$(realpath "$WHICHPROG" 2>/dev/null)" != "$(realpath "$MYDIR/$PROG")"; then
#	PROG="cd $(realpath -s "$MYDIR")$n./$PROG"
#fi
if test -f "$MYDIR/$PROG" && test "$(readlink -e "$WHICHPROG" 2>/dev/null)" != "$(readlink -e "$MYDIR/$PROG")"; then
	PROG="cd $(readlink -e "$MYDIR")$n./$PROG"
fi
startscreen distminer "${PROG} ${BFGMINER_OPTS}"
