#!/bin/bash
# Stateless Validator Status Dashboard
# Usage: ./validator-status.sh [metrics_url]
set -e

METRICS_URL="${1:-http://localhost:9090/metrics}"
METRICS=$(curl -s "$METRICS_URL" 2>/dev/null) || { echo "Error: Could not fetch metrics from $METRICS_URL"; exit 1; }
[ -z "$METRICS" ] && { echo "Error: Empty response from $METRICS_URL"; exit 1; }

# Parse all metrics in single awk pass - outputs shell variable assignments
eval "$(echo "$METRICS" | awk '
/^#/ { next }
# Handle quantile metrics: metric{quantile="0.5"} value
/\{quantile=/ {
    name = $1
    sub(/\{.*/, "", name)
    q = $1
    sub(/.*quantile="/, "", q)
    sub(/".*/, "", q)
    gsub(/\./, "_", q)
    if (!seen[name"_q"q]++) print "M_Q_"name"_"q"=\""$2"\""
    next
}
# Handle histogram _sum (without labels) - use index() for BSD awk compatibility
/_sum / {
    if (index($0, "{") == 0) {
        name = $1
        sub(/_sum$/, "", name)
        if (!seen[name"_sum"]++) print "M_S_"name"=\""$2"\""
    }
    next
}
# Handle histogram _count (without labels)
/_count / {
    if (index($0, "{") == 0) {
        name = $1
        sub(/_count$/, "", name)
        if (!seen[name"_count"]++) print "M_C_"name"=\""$2"\""
    }
    next
}
# Handle plain metrics (no labels)
/^[a-zA-Z_][a-zA-Z0-9_]* / {
    if (index($0, "{") == 0 && index($0, "#") != 1) {
        if (!seen[$1]++) print "M_V_"$1"=\""$2"\""
    }
}
')"

# Fast lookups using parsed variables
metric()   { eval "v=\${M_V_$1:-}"; echo "${v%%.*}"; }
quantile() { local q="$2"; q="${q//./_}"; eval "echo \${M_Q_${1}_$q:-}"; }
hist_sum() { eval "echo \${M_S_$1:-}"; }
hist_count() { eval "echo \${M_C_$1:-}"; }
hist_avg() {
    eval "s=\${M_S_$1:-0}; c=\${M_C_$1:-0}"
    [ -n "$c" ] && [ "$c" != "0" ] && echo "scale=6; $s / $c" | bc 2>/dev/null || echo "0"
}

# Formatting helpers
fmt_ms() {
    [ -z "$1" ] || [ "$1" = "0" ] && { echo "N/A"; return; }
    printf "%.2f" "$(echo "scale=6; $1 * 1000" | bc 2>/dev/null)"
}
fmt_num() {
    [ -z "$1" ] && { echo "0"; return; }
    printf "%'d" "${1%.*}" 2>/dev/null || echo "0"
}
fmt_bytes() {
    [ -z "$1" ] && { echo "0 B"; return; }
    b="${1%.*}"
    [ "$b" -le 0 ] 2>/dev/null && { echo "0 B"; return; }
    if [ "$b" -ge 1048576 ]; then
        printf "%.2f MB" "$(echo "scale=2; $b / 1048576" | bc)"
    elif [ "$b" -ge 1024 ]; then
        printf "%.2f KB" "$(echo "scale=2; $b / 1024" | bc)"
    else
        printf "%d B" "$b"
    fi
}
# Compact count format with K/M/B/T suffix (for gas and other large cumulative counters).
fmt_bignum() {
    [ -z "$1" ] && { echo "0"; return; }
    n="${1%.*}"
    if [ "$n" -ge 1000000000000 ] 2>/dev/null; then
        printf "%.2fT" "$(echo "scale=2; $n / 1000000000000" | bc)"
    elif [ "$n" -ge 1000000000 ] 2>/dev/null; then
        printf "%.2fB" "$(echo "scale=2; $n / 1000000000" | bc)"
    elif [ "$n" -ge 1000000 ] 2>/dev/null; then
        printf "%.2fM" "$(echo "scale=2; $n / 1000000" | bc)"
    elif [ "$n" -ge 1000 ] 2>/dev/null; then
        printf "%.2fK" "$(echo "scale=2; $n / 1000" | bc)"
    else
        printf "%s" "$n"
    fi
}

# Header
LINE="═══════════════════════════════════════════════════════════════════════════════"
THIN="───────────────────────────────────────────────────────────────────────────────"
echo ""
echo "$LINE"
echo "                       STATELESS VALIDATOR STATUS"
echo "$LINE"
echo "  URL: $METRICS_URL | $(date '+%Y-%m-%d %H:%M:%S')"

# Chain Status
LOCAL=$(metric 'stateless_validator_local_chain_height')
REMOTE=$(metric 'stateless_validator_remote_chain_height')
GAP=$(metric 'stateless_validator_validation_lag')

echo ""
echo "  CHAIN"
echo "$THIN"
REORGS=$(metric 'stateless_validator_reorgs_detected_total')
GAP_INT="${GAP:-0}"
GAP_INT="${GAP_INT%%.*}"
GAP_SUFFIX=$( [ "$GAP_INT" -eq 0 ] 2>/dev/null && echo ' ✓' || echo ' blocks' )
printf "   Local: %s | Remote: %s | Gap: %s%s | Reorgs: %s\n" \
    "$(fmt_num "$LOCAL")" "$(fmt_num "$REMOTE")" \
    "$(fmt_num "$GAP_INT")" "$GAP_SUFFIX" "${REORGS:-0}"

# Performance
VAL_SUM=$(hist_sum 'stateless_validator_block_validation_time_seconds')
VAL_COUNT=$(hist_count 'stateless_validator_block_validation_time_seconds')
VAL_P50=$(quantile 'stateless_validator_block_validation_time_seconds' '0.5')
VAL_P95=$(quantile 'stateless_validator_block_validation_time_seconds' '0.95')
VAL_P99=$(quantile 'stateless_validator_block_validation_time_seconds' '0.99')
TOTAL_TX=$(metric 'stateless_validator_transactions_total')
TOTAL_GAS=$(metric 'stateless_validator_gas_used_total')

echo ""
echo "  PERFORMANCE"
echo "$THIN"
if [ -n "$VAL_COUNT" ] && [ "$VAL_COUNT" != "0" ]; then
    AVG=$(echo "scale=6; $VAL_SUM / $VAL_COUNT" | bc 2>/dev/null)
    # `grep -c` always prints a number to stdout, including "0" on no match
    # (and exits 1 in that case). Don't add `|| echo 1` — that would emit "0\n1".
    WORKER_COUNT=$(echo "$METRICS" | grep -c "^stateless_validator_worker_tasks_completed_total{")
    [ "$WORKER_COUNT" -eq 0 ] && WORKER_COUNT=1

    # Calculate throughput metrics:
    # - BPS (blocks per second) = WORKER_COUNT / AVG
    #   Since workers run in parallel, multiply single-worker throughput by worker count
    # - TX_PER_BLOCK = total transactions / total blocks validated
    # - TPS (transactions per second) = BPS * TX_PER_BLOCK
    #   This is the theoretical max TPS the validator can sustain
    BPS=$(echo "scale=2; $WORKER_COUNT / $AVG" | bc 2>/dev/null)
    B=${VAL_COUNT%.*}
    TX_PER_BLOCK=$(echo "scale=2; ${TOTAL_TX:-0} / $B" | bc 2>/dev/null)
    TPS=$(echo "scale=2; $BPS * $TX_PER_BLOCK" | bc 2>/dev/null)

    printf "   Validation: Avg: %s ms | P50: %s ms | P95: %s ms | P99: %s ms\n" \
        "$(fmt_ms "$AVG")" "$(fmt_ms "$VAL_P50")" "$(fmt_ms "$VAL_P95")" "$(fmt_ms "$VAL_P99")"
    printf "   Throughput: %s blocks/sec | %s TPS (with %d workers, %.2f tx/block)\n" "$BPS" "$TPS" "$WORKER_COUNT" "$TX_PER_BLOCK"
    printf "   Totals: %s blocks | %s tx | %s gas\n" \
        "$(fmt_num "$VAL_COUNT")" "$(fmt_num "$TOTAL_TX")" "$(fmt_bignum "$TOTAL_GAS")"

    # Validation phase breakdown (avg and p99 to surface tail outliers)
    WITNESS_VERIFY_AVG=$(hist_avg 'stateless_validator_witness_verification_time_seconds')
    WITNESS_VERIFY_P99=$(quantile 'stateless_validator_witness_verification_time_seconds' '0.99')
    BLOCK_REPLAY_AVG=$(hist_avg 'stateless_validator_block_replay_time_seconds')
    BLOCK_REPLAY_P99=$(quantile 'stateless_validator_block_replay_time_seconds' '0.99')
    SALT_UPDATE_AVG=$(hist_avg 'stateless_validator_salt_update_time_seconds')
    SALT_UPDATE_P99=$(quantile 'stateless_validator_salt_update_time_seconds' '0.99')
    printf "   Phases avg/p99 (ms): Verify %s/%s | Replay %s/%s | Salt Update %s/%s\n" \
        "$(fmt_ms "$WITNESS_VERIFY_AVG")" "$(fmt_ms "$WITNESS_VERIFY_P99")" \
        "$(fmt_ms "$BLOCK_REPLAY_AVG")" "$(fmt_ms "$BLOCK_REPLAY_P99")" \
        "$(fmt_ms "$SALT_UPDATE_AVG")" "$(fmt_ms "$SALT_UPDATE_P99")"
else
    echo "   No data yet"
fi

# RPC
echo ""
echo "  RPC"
echo "$THIN"
echo "$METRICS" | grep "^stateless_validator_rpc_requests_total{" | \
    sed 's/.*method="\([^"]*\)".* \([0-9.]*\)/\1 \2/' | sort | while read -r METHOD COUNT; do
    printf "   %-28s %s\n" "$METHOD:" "$(fmt_num "${COUNT%.*}")"
done

# RPC Errors with detail by method (final failures only)
ERROR_LINES=$(echo "$METRICS" | grep "^stateless_validator_rpc_errors_total{")
TOTAL_ERRORS=$(echo "$ERROR_LINES" | awk '{sum += $2} END {print int(sum)}')
if [ "${TOTAL_ERRORS:-0}" -gt 0 ]; then
    echo ""
    printf "   Errors (Total: %s):\n" "$(fmt_num "$TOTAL_ERRORS")"
    echo "$ERROR_LINES" | sed 's/.*method="\([^"]*\)".* \([0-9.]*\)/\1 \2/' | sort | \
        while read -r METHOD COUNT; do
        C=${COUNT%.*}
        [ "${C:-0}" -gt 0 ] && printf "      %-25s %s\n" "$METHOD:" "$(fmt_num "$C")"
    done
else
    echo ""
    echo "   Errors: None ✓"
fi

# RPC transient retries (attempts before final outcome; >0 indicates upstream backpressure
# like rate limits that were eventually absorbed by the backoff layer).
RETRY_LINES=$(echo "$METRICS" | grep "^stateless_validator_rpc_retry_attempts_total{")
TOTAL_RETRIES=$(echo "$RETRY_LINES" | awk '{sum += $2} END {print int(sum)}')
if [ "${TOTAL_RETRIES:-0}" -gt 0 ]; then
    echo ""
    printf "   Retries (Total: %s):\n" "$(fmt_num "$TOTAL_RETRIES")"
    echo "$RETRY_LINES" | sed 's/.*method="\([^"]*\)".* \([0-9.]*\)/\1 \2/' | sort | \
        while read -r METHOD COUNT; do
        C=${COUNT%.*}
        [ "${C:-0}" -gt 0 ] && printf "      %-25s %s\n" "$METHOD:" "$(fmt_num "$C")"
    done
fi

# Timing Breakdown
# Helper: use P50 if available, fallback to average if P50 is 0 but data exists
latency_ms() {
    local p50=$(quantile "$1" '0.5')
    if [ -n "$p50" ] && [ "$p50" != "0" ]; then
        fmt_ms "$p50"
    else
        # P50 is 0 or empty, try using average instead
        local avg=$(hist_avg "$1")
        if [ -n "$avg" ] && [ "$avg" != "0" ]; then
            fmt_ms "$avg"
        else
            echo "N/A"
        fi
    fi
}
echo ""
printf "   Fetch Latency (P50): Witness: %s ms | Block: %s ms | Code: %s ms\n" \
    "$(latency_ms 'stateless_validator_witness_fetch_rpc_time_seconds')" \
    "$(latency_ms 'stateless_validator_block_fetch_time_seconds')" \
    "$(latency_ms 'stateless_validator_code_fetch_time_seconds')"

# Cache
HITS=$(metric 'stateless_validator_contract_cache_hits_total')
MISSES=$(metric 'stateless_validator_contract_cache_misses_total')

echo ""
echo "  CONTRACT CACHE"
echo "$THIN"
TOTAL=$((${HITS:-0} + ${MISSES:-0}))
RATE=$( [ "$TOTAL" -gt 0 ] && echo "$(echo "scale=1; ${HITS:-0} * 100 / $TOTAL" | bc)%" || echo "N/A" )
printf "   Hits: %s | Misses: %s | Rate: %s\n" "$(fmt_num "$HITS")" "${MISSES:-0}" "$RATE"

# Witness Stats
SALT_SIZE=$(hist_avg 'stateless_validator_salt_witness_size_bytes')
SALT_KEYS=$(hist_avg 'stateless_validator_salt_witness_keys')
SALT_KVS_SIZE=$(hist_avg 'stateless_validator_salt_witness_kvs_size_bytes')
MPT_SIZE=$(hist_avg 'stateless_validator_mpt_witness_size_bytes')
STATE_READS=$(hist_avg 'stateless_validator_block_state_reads')
STATE_WRITES=$(hist_avg 'stateless_validator_block_state_writes')

echo ""
echo "  WITNESS (avg per block)"
echo "$THIN"
printf "   Salt: %s | Keys: %s | KVs: %s | MPT: %s\n" \
    "$(fmt_bytes "$SALT_SIZE")" "$(fmt_num "$SALT_KEYS")" "$(fmt_bytes "$SALT_KVS_SIZE")" "$(fmt_bytes "$MPT_SIZE")"
printf "   State Reads: %s | State Writes: %s\n" "$(fmt_num "$STATE_READS")" "$(fmt_num "$STATE_WRITES")"

# Workers
echo ""
echo "  WORKERS"
echo "$THIN"
WORKER_DATA=$(echo "$METRICS" | grep "^stateless_validator_worker_tasks_completed_total{" | \
    sed 's/.*worker_id="\([^"]*\)".* \([0-9.]*\)/\1 \2/' | sort -n)
FAILED_TOTAL=$(echo "$METRICS" | grep "^stateless_validator_worker_tasks_failed_total{" | \
    awk '{sum += $2} END {print int(sum)}')

if [ -n "$WORKER_DATA" ]; then
    TOTAL=0; COUNT=0; MAX=0
    while read -r _ TASKS; do
        T=${TASKS%.*}; TOTAL=$((TOTAL + T)); COUNT=$((COUNT + 1))
        [ "$T" -gt "$MAX" ] && MAX=$T
    done <<< "$WORKER_DATA"
    if [ "${FAILED_TOTAL:-0}" -gt 0 ]; then
        printf "   Workers: %d | Total Tasks: %s | Avg: %d | Failed: %s ⚠\n" \
            "$COUNT" "$(fmt_num "$TOTAL")" "$((TOTAL / COUNT))" "$(fmt_num "$FAILED_TOTAL")"
    else
        printf "   Workers: %d | Total Tasks: %s | Avg: %d | Failed: 0 ✓\n" \
            "$COUNT" "$(fmt_num "$TOTAL")" "$((TOTAL / COUNT))"
    fi
    echo "$WORKER_DATA" | while read -r WID TASKS; do
        T=${TASKS%.*}; BAR=$(printf '%*s' "$((T * 20 / MAX))" '' | tr ' ' '█')
        printf "      Worker %2s: %6d  %s\n" "$WID" "$T" "$BAR"
    done
else
    echo "   No worker data"
fi

# Reorg depth distribution (only if any reorg actually happened — histograms aren't
# emitted until first observation, and this context is noise in a healthy run).
REORG_COUNT=$(hist_count 'stateless_validator_reorg_depth')
if [ -n "$REORG_COUNT" ] && [ "$REORG_COUNT" != "0" ]; then
    echo ""
    echo "  REORGS"
    echo "$THIN"
    R_AVG=$(hist_avg 'stateless_validator_reorg_depth')
    R_P50=$(quantile 'stateless_validator_reorg_depth' '0.5')
    R_P99=$(quantile 'stateless_validator_reorg_depth' '0.99')
    R_MAX=$(quantile 'stateless_validator_reorg_depth' '1')
    printf "   Count: %s | Depth avg: %s | P50: %s | P99: %s | Max: %s\n" \
        "$(fmt_num "$REORG_COUNT")" "${R_AVG%.*}" "${R_P50%.*}" "${R_P99%.*}" "${R_MAX%.*}"
fi

echo ""
echo "$LINE"
echo ""
