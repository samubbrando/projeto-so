#!/usr/bin/env bash
# Run the whole test suite in sequence.
#
#   correctness   does the limiter block/pass each direction?   (cases.tab)
#   rate-limit    accuracy of the pct rule vs the measured ceiling
#
# Needs root: caches a sudo credential once, then hands each case off to
# bench.sh, which brings up/tears down the netns+veth testbed per run.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
set -a
. "$DIR/.env"
set +a
export TESTS_DIR="$DIR"
export PROJ_DIR="${PROJ_DIR:-$DIR/..}"
export RESULTS_ROOT="${RESULTS_ROOT:-$DIR/results}"

# --- read the stat keys bench.sh wrote ---
get() { awk -v k="$1" '{ for(i=1;i<=NF;i+=2) if ($i==k) print $(i+1) }' "$2"; }

# ---------------- correctness ----------------
run_correctness() {
    local summary="$RESULTS_ROOT/correctness/summary.txt"
    mkdir -p "$RESULTS_ROOT/correctness"
    printf '%-15s %-18s %-18s %s\n' case expected_egress expected_ingress result | tee "$summary"

    local fails=0
    while read -r name expect_eg expect_in; do
        [ -n "$name" ] && [ "${name#\#}" = "$name" ] || continue
        local run="$RESULTS_ROOT/correctness/$name"
        mkdir -p "$run"
        echo
        echo "===== correctness/$name ====="
        RESULTS_DIR="$run" "$DIR/bench.sh" "$DIR/cases/correctness/$name.conf" || true
        local eg in
        eg="$(get EGRESS_BPS "$run/stats.txt")"
        in="$(get INGRESS_BPS "$run/stats.txt")"
        local ok=1
        eg="${eg:-0}"
        in="${in:-0}"
        case_ok() {
            local want="$1" got="$2"
            [ "$want" = blocked ] && [ "$got" -lt   100 ] && return 0
            [ "$want" = flow ] && [ "$got" -ge 10000000 ] && return 0
            return 1
        }
        case_ok "$expect_eg" "$eg" || ok=0
        case_ok "$expect_in" "$in" || ok=0
        local result=PASS
        [ "$ok" -eq 1 ] || result=FAIL
        printf '%-15s %-18s %-18s %s\n' \
            "$name" "$expect_eg" "$expect_in" "$result" | tee -a "$summary"
        [ "$result" = PASS ] || fails=$((fails + 1))
    done < "$DIR/cases/correctness/cases.tab"

    echo
    echo "---- correctness summary ----"
    cat "$summary"
    return $(((fails > 0)))
}

# ---------------- rate-limit ----------------
run_rate_limit() {
    local out="$RESULTS_ROOT/rate-limit/summary.txt"
    mkdir -p "$RESULTS_ROOT/rate-limit"
    local sweep="${DURATION:-15}"

    echo
    echo "===== rate-limit: baseline ====="
    local base="$RESULTS_ROOT/rate-limit/baseline"
    mkdir -p "$base"
    cat > "$base/rules.conf" <<'EOF'
scheduler 100 allow drop drop
tgt 100 allow edt edt
EOF
    RESULTS_DIR="$base" "$DIR/bench.sh" "$base/rules.conf" || { echo "baseline FAILED"; return 1; }
    local ceil
    ceil="$(get EGRESS_BYTES "$base/stats.txt")"; ceil="${ceil:-0}"
    ceil=$(( ceil * 8 / sweep ))
    [ "$ceil" -gt 0 ] || { echo "WARN: baseline ceiling was 0; falling back to probe CAP"; }

    echo
    echo "===== rate-limit sweep ====="
    printf '%-4s %-12s %-12s %-12s %-12s %-12s %s\n' \
        pct achieved offered probe_cap ceiling target accuracy_pct | tee "$out"

    local fails=0
    local pct
    for pct in $PCTS; do
        local run="$RESULTS_ROOT/rate-limit/pct-$pct"
        mkdir -p "$run"
        echo
        echo "===== rate-limit/pct-$pct ====="
        sed "s/{PCT}/$pct/" "$DIR/cases/rate-limit/rules.template.conf" > "$run/rules.conf"
        RESULTS_DIR="$run" CAPACITY_BPS="$ceil" "$DIR/bench.sh" "$run/rules.conf" || true
        local stats="$run/stats.txt"
        local ach offered cap
        ach="$(get EGRESS_BYTES "$stats")"; ach="${ach:-0}"
        ach=$(( ach * 8 / sweep ))
        offered="$(get OFFERED_BPS "$stats")"; offered="${offered:-0}"
        cap="$(get CAP_BPS "$stats")"; cap="${cap:-0}"
        local target=$(( (ceil > 0 ? ceil : cap) * pct / 100 ))
        local acc="n/a"
        [ "$target" -gt 0 ] && acc=$(awk -v a="$ach" -v t="$target" 'BEGIN{printf "%.1f", a*100/t}')
        printf '%-4s %-12s %-12s %-12s %-12s %-12s %s\n' \
            "$pct" "$ach" "$offered" "$cap" "$ceil" "$target" "$acc" | tee -a "$out"
    done

    echo
    echo "---- rate-limit summary (accuracy ~100% = limiter exact) ----"
    cat "$out"
}

sudo -v || { echo "need a sudo credential for the testbed" >&2; exit 1; }

rc=0
run_correctness || rc=1
run_rate_limit || rc=1

# ---------------- diagnostics ----------------
if command -v python3 >/dev/null 2>&1; then
    echo
    echo "===== diagnostics report ====="
    "$DIR/diag/report.py" "$RESULTS_ROOT" || true
else
    echo "[diag] python3 not found; skipping report generation" >&2
fi

echo
echo "done. results in $RESULTS_ROOT/"
exit $rc