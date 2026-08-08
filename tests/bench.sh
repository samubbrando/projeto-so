#!/usr/bin/env bash
# One benchmark run. Usage: bench.sh <rules.conf> [RESULTS_DIR]
#
#   - builds the scheduler at the repository root (make) if missing
#   - brings the testbed up (cgroup + netns pair, see mkbed.sh)
#   - moves this shell into the cgroup, then launches the scheduler in TARGET_NS
#     attached to VETH_T with the given rules
#   - warmup, then runs both spammers: peer (comm "peer", DURATION+1 s) in
#     PEER_NS and tgt (comm "tgt", DURATION s) in TARGET_NS
#   - tears the scheduler down and writes a machine-readable stats file:
#       RESULTS_DIR/stats.txt  -> EGRESS_BPS/BYTES INGRESS_BPS/BYTES
#                                  OFFERED_BPS/BYTES CAP_BPS
#   - echoes a one-line human summary on stdout
#
# EGRESS  = what the PEER received (tgt's send direction, the one being limited)
# INGRESS = what the TARGET received
# OFFERED = what the TARGET tried to send
# CAP     = last full "Capacity: <n> bps" line in scheduler.log
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
. "$TESTS_DIR/.env"
set +a

PROJ_DIR="${PROJ_DIR:-$TESTS_DIR/..}"
SCHED="${SCHED_BIN:-$PROJ_DIR/scheduler}"
RULES="${1:-${RULES:-}}"
RESULTS_DIR="${2:-${RESULTS_DIR:-$TESTS_DIR/results}}"
[ -n "$RULES" ] || { echo "usage: $0 <rules.conf> [RESULTS_DIR]" >&2; exit 1; }
[ -f "$RULES" ] || { echo "[bench] rules file not found: $RULES" >&2; exit 1; }

human() {
    awk -v n="$1" 'BEGIN{
        if (n >= 1e9) printf "%.3g G", n/1e9;
        else if (n >= 1e6) printf "%.3g M", n/1e6;
        else if (n >= 1e3) printf "%.3g k", n/1e3;
        else printf "%d", n}'
}

mkdir -p "$RESULTS_DIR"
export RESULTS_DIR

# --- build the scheduler at the repository root if missing ---
if [ ! -x "$SCHED" ]; then
    echo "[bench] building scheduler -> $SCHED"
    ( cd "$PROJ_DIR" && make ) || { echo "[bench] scheduler build failed" >&2; exit 1; }
fi

# --- testbed up; teardown on any exit ---
"$TESTS_DIR/mkbed.sh" up
trap '"$TESTS_DIR/mkbed.sh" down' EXIT

# --- cgroup: migrate THIS shell in (children scheduler+spammers inherit) ---
CG_ROOT="${CG_ROOT:-/sys/fs/cgroup}"
CG_PATH="$CG_ROOT/$CG"
CG_OK=0
if [ "$(id -u)" -eq 0 ]; then
    if echo "$$" > "$CG_PATH/cgroup.procs"; then CG_OK=1; fi
else
    if sudo -n sh -c "echo '$$' > '$CG_PATH/cgroup.procs'" 2>/dev/null; then CG_OK=1; fi
fi
[ "$CG_OK" -eq 1 ] || echo "[bench] WARN: could not migrate shell ($$) into $CG_PATH - cgroup layer won't apply"

# --- scheduler (in TARGET_NS, attached to VETH_T) ---
PIDFILE="$RESULTS_DIR/scheduler.pid"
rm -f "$PIDFILE"
sudo -n env BPF_CGROUP_PATH="$CG_PATH" PIDFILE="$PIDFILE" SCHED="$SCHED" \
     VETH_T="$VETH_T" RULES="$RULES" CAPACITY_BPS="${CAPACITY_BPS:-}" \
     ip netns exec "$TARGET_NS" \
     bash -c 'echo $$ > "$PIDFILE"; exec "$SCHED" -i "$VETH_T" -c "$RULES"' \
     > "$RESULTS_DIR/scheduler.log" 2>&1 &
sleep "$SCHEDULER_WARMUP"
if [ ! -s "$PIDFILE" ] || ! sudo -n kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "[bench] scheduler FAILED to start; last log lines:" >&2
    tail -n 25 "$RESULTS_DIR/scheduler.log" >&2 || true
    exit 1
fi
echo "[bench] scheduler running (pid $(cat "$PIDFILE"))"

# --- spammers: peer first (1s longer), then tgt in the same 4-tuple ---
PEER_DUR=$((DURATION + 1))
sudo -n ip netns exec "$PEER_NS" python3 "$TESTS_DIR/spam.py" \
    --comm peer --local "$PEER_IP" --lport "$UDP_PORT" \
    --remote "$TARGET_IP" --rport "$UDP_PORT" \
    --dur "$PEER_DUR" --size "$PCKTSIZE" > "$RESULTS_DIR/peer.out" 2>&1 &
PEER_BG=$!
sleep 0.5
sudo -n ip netns exec "$TARGET_NS" python3 "$TESTS_DIR/spam.py" \
    --comm tgt --local "$TARGET_IP" --lport "$UDP_PORT" \
    --remote "$PEER_IP" --rport "$UDP_PORT" \
    --dur "$DURATION" --size "$PCKTSIZE" > "$RESULTS_DIR/tgt.out" 2>&1 || true
wait "$PEER_BG" 2>/dev/null || true

# --- tear the scheduler down ---
SID="$(cat "$PIDFILE" 2>/dev/null || true)"
if [ -n "$SID" ]; then
    sudo -n kill "$SID" 2>/dev/null || true
    sleep 0.5
    sudo -n kill -9 "$SID" 2>/dev/null || true
fi

# --- extract stats ---
field() { awk -v k="$2" '{for(i=1;i<=NF;i++) if($i==k) print $(i+1)}' "$1"; }
EGRESS_BPS="$(field "$RESULTS_DIR/peer.out" RECV_BPS)";    EGRESS_BPS="${EGRESS_BPS:-0}"
EGRESS_BYTES="$(field "$RESULTS_DIR/peer.out" RECV_BYTES)"; EGRESS_BYTES="${EGRESS_BYTES:-0}"
INGRESS_BPS="$(field "$RESULTS_DIR/tgt.out" RECV_BPS)";    INGRESS_BPS="${INGRESS_BPS:-0}"
INGRESS_BYTES="$(field "$RESULTS_DIR/tgt.out" RECV_BYTES)"; INGRESS_BYTES="${INGRESS_BYTES:-0}"
OFFERED_BPS="$(field "$RESULTS_DIR/tgt.out" SENT_BPS)";     OFFERED_BPS="${OFFERED_BPS:-0}"
OFFERED_BYTES="$(field "$RESULTS_DIR/tgt.out" SENT_BYTES)"; OFFERED_BYTES="${OFFERED_BYTES:-0}"
CAP="$(awk '/^Capacity:/ && / bps /{gsub(/[^0-9]/,"",$2); if ($2+0 > 0) val=$2+0} END{print val+0}' \
    "$RESULTS_DIR/scheduler.log")"
CAP="${CAP:-0}"

cat > "$RESULTS_DIR/stats.txt" <<EOF
EGRESS_BPS $EGRESS_BPS
EGRESS_BYTES $EGRESS_BYTES
INGRESS_BPS $INGRESS_BPS
INGRESS_BYTES $INGRESS_BYTES
OFFERED_BPS $OFFERED_BPS
OFFERED_BYTES $OFFERED_BYTES
CAP_BPS $CAP
EOF

echo "[bench] EGRESS=$(human "$EGRESS_BPS")  INGRESS=$(human "$INGRESS_BPS")  OFFERED=$(human "$OFFERED_BPS")  CAP=$(human "$CAP")"