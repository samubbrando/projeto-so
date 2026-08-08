#!/usr/bin/env bash
# Bring the isolated testbed up or down. Config comes from tests/.env.
#
#   mkbed.sh up    create the cgroup + netns TARGET_NS <-> PEER_NS via a veth
#                  pair, with addresses held from tests/.env.
#   mkbed.sh down  kill the scheduler (if running), remove netns/veth.
#
# (bench.sh migrates its own PID into the cgroup; this script only ensures the
# cgroup directory exists.)
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
. "$TESTS_DIR/.env"
set +a

CG_ROOT="${CG_ROOT:-/sys/fs/cgroup}"
CG_PATH="$CG_ROOT/$CG"
RESULTS_DIR="${RESULTS_DIR:-$TESTS_DIR/results}"

root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi; }

bed_up() {
    echo "[mkbed] cgroup $CG_PATH + netns $TARGET_NS <-> $PEER_NS"

    root mkdir -p "$CG_PATH"
    echo "[mkbed] cgroup $CG_PATH ready (bench.sh migrates its own PID in)"

    root ip netns del "$TARGET_NS" 2>/dev/null || true
    root ip netns del "$PEER_NS" 2>/dev/null || true
    root ip link del "$VETH_T" 2>/dev/null || true

    root ip netns add "$TARGET_NS"
    root ip netns add "$PEER_NS"
    root ip link add "$VETH_T" type veth peer name "$VETH_P"
    root ip link set "$VETH_P" netns "$PEER_NS"
    root ip link set "$VETH_T" netns "$TARGET_NS"

    root ip netns exec "$TARGET_NS" ip link set lo up
    root ip netns exec "$TARGET_NS" ip addr add "$TARGET_IP/$PREFIX" dev "$VETH_T"
    root ip netns exec "$TARGET_NS" ip link set "$VETH_T" up
    # default route so the scheduler's burst probe exits via the veth and its
    # tx bytes count; the peer just drops the probe packets.
    root ip netns exec "$TARGET_NS" ip route add default via "$PEER_IP" dev "$VETH_T" || true

    root ip netns exec "$PEER_NS" ip link set lo up
    root ip netns exec "$PEER_NS" ip addr add "$PEER_IP/$PREFIX" dev "$VETH_P"
    root ip netns exec "$PEER_NS" ip link set "$VETH_P" up

    mkdir -p "$RESULTS_DIR"
    sleep 1
    echo "[testbed] ready: $VETH_T=$TARGET_IP ($TARGET_NS) <-> $VETH_P=$PEER_IP ($PEER_NS)"
}

bed_down() {
    if [ -f "$RESULTS_DIR/scheduler.pid" ]; then
        root kill "$(cat "$RESULTS_DIR/scheduler.pid")" 2>/dev/null || true
        sleep 0.5
        root kill -9 "$(cat "$RESULTS_DIR/scheduler.pid")" 2>/dev/null || true
        rm -f "$RESULTS_DIR/scheduler.pid"
    fi
    root ip netns del "$TARGET_NS" 2>/dev/null || true
    root ip netns del "$PEER_NS" 2>/dev/null || true
    root ip link del "$VETH_T" 2>/dev/null || true
    echo "[testbed] down"
}

case "${1:-}" in
    up)   bed_up ;;
    down) bed_down ;;
    *) echo "usage: $0 up|down" >&2; exit 1 ;;
esac