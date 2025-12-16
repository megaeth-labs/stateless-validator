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

# Header
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "                  STATELESS VALIDATOR STATUS"
echo "═══════════════════════════════════════════════════════════════"
echo "  URL: $METRICS_URL | $(date '+%Y-%m-%d %H:%M:%S')"

# Chain Status
LOCAL=$(metric 'stateless_validator_local_chain_height')
REMOTE=$(metric 'stateless_validator_remote_chain_height')
GAP=$(metric 'stateless_validator_validation_lag')

echo ""
echo "  CHAIN"
echo "───────────────────────────────────────────────────────────────"
REORGS=$(metric 'stateless_validator_reorgs_detected_total')
printf "   %-20s %-15s %-20s %s\n" "Local: $(fmt_num "$LOCAL")" "Remote: $(fmt_num "$REMOTE")" \
    "Gap: ${GAP:-0}$( [ "${GAP:-0}" -eq 0 ] && echo ' ✓' || echo ' blocks')" "Reorgs: ${REORGS:-0}"

# Performance
VAL_SUM=$(hist_sum 'stateless_validator_block_validation_time_seconds')
VAL_COUNT=$(hist_count 'stateless_validator_block_validation_time_seconds')
VAL_P50=$(quantile 'stateless_validator_block_validation_time_seconds' '0.5')
VAL_P95=$(quantile 'stateless_validator_block_validation_time_seconds' '0.95')
VAL_P99=$(quantile 'stateless_validator_block_validation_time_seconds' '0.99')

echo ""
echo "  PERFORMANCE (Block Validation)"
echo "───────────────────────────────────────────────────────────────"
if [ -n "$VAL_COUNT" ] && [ "$VAL_COUNT" != "0" ]; then
    AVG=$(echo "scale=6; $VAL_SUM / $VAL_COUNT" | bc 2>/dev/null)
    BPS=$(echo "scale=2; 1 / $AVG" | bc 2>/dev/null)
    printf "   Avg: %s ms | P50: %s ms | P95: %s ms | P99: %s ms\n" \
        "$(fmt_ms "$AVG")" "$(fmt_ms "$VAL_P50")" "$(fmt_ms "$VAL_P95")" "$(fmt_ms "$VAL_P99")"
    printf "   Throughput: %s blocks/sec\n" "$BPS"

    # Validation phase breakdown
    WITNESS_VERIFY=$(hist_avg 'stateless_validator_witness_verification_time_seconds')
    BLOCK_REPLAY=$(hist_avg 'stateless_validator_block_replay_time_seconds')
    SALT_UPDATE=$(hist_avg 'stateless_validator_salt_update_time_seconds')
    printf "   Phases (avg): Verify: %s ms | Replay: %s ms | Salt Update: %s ms\n" \
        "$(fmt_ms "$WITNESS_VERIFY")" "$(fmt_ms "$BLOCK_REPLAY")" "$(fmt_ms "$SALT_UPDATE")"
else
    echo "   No data yet"
fi

# Throughput
BLOCKS=$(hist_count 'stateless_validator_block_validation_time_seconds')
TOTAL_TX=$(metric 'stateless_validator_transactions_total')
TOTAL_GAS=$(metric 'stateless_validator_gas_used_total')

echo ""
echo "  THROUGHPUT"
echo "───────────────────────────────────────────────────────────────"
printf "   Blocks: %s | TX: %s | Gas: %s\n" "$(fmt_num "$BLOCKS")" "$(fmt_num "$TOTAL_TX")" "$(fmt_num "$TOTAL_GAS")"
if [ -n "$BLOCKS" ] && [ "${BLOCKS%.*}" -gt 0 ]; then
    B=${BLOCKS%.*}
    [ "${TOTAL_TX:-0}" -gt 0 ] && printf "   Avg TX/Block: %.2f\n" "$(echo "scale=2; $TOTAL_TX / $B" | bc)"
fi

# Timing Breakdown
echo ""
echo "   Fetch Latency (P50): Witness: $(fmt_ms "$(quantile 'stateless_validator_witness_fetch_time_seconds' '0.5')") ms | " \
    "Block: $(fmt_ms "$(quantile 'stateless_validator_block_fetch_time_seconds' '0.5')") ms | " \
    "Code: $(fmt_ms "$(quantile 'stateless_validator_code_fetch_time_seconds' '0.5')") ms"

# Cache
HITS=$(metric 'stateless_validator_contract_cache_hits_total')
MISSES=$(metric 'stateless_validator_contract_cache_misses_total')

echo ""
echo "  CONTRACT CACHE"
echo "───────────────────────────────────────────────────────────────"
TOTAL=$((${HITS:-0} + ${MISSES:-0}))
RATE=$( [ "$TOTAL" -gt 0 ] && echo "$(echo "scale=1; ${HITS:-0} * 100 / $TOTAL" | bc)%" || echo "N/A" )
printf "   Hits: %s | Misses: %s | Rate: %s\n" "$(fmt_num "$HITS")" "${MISSES:-0}" "$RATE"

# Witness Stats
SALT_SIZE=$(hist_avg 'stateless_validator_witness_salt_size_bytes')
SALT_KEYS=$(hist_avg 'stateless_validator_witness_salt_keys')
SALT_KVS_SIZE=$(hist_avg 'stateless_validator_witness_salt_kvs_bytes')
MPT_SIZE=$(hist_avg 'stateless_validator_witness_mpt_size_bytes')

echo ""
echo "  WITNESS (avg per block)"
echo "───────────────────────────────────────────────────────────────"
printf "   Keys: %s | Salt: %s | KVs: %s | MPT: %s\n" \
    "$(fmt_num "$SALT_KEYS")" "$(fmt_bytes "$SALT_SIZE")" "$(fmt_bytes "$SALT_KVS_SIZE")" "$(fmt_bytes "$MPT_SIZE")"

# State Access
STATE_READS=$(hist_avg 'stateless_validator_block_state_reads')
STATE_WRITES=$(hist_avg 'stateless_validator_block_state_writes')

echo ""
echo "  STATE ACCESS (avg per block)"
echo "───────────────────────────────────────────────────────────────"
printf "   Reads: %s | Writes: %s\n" "$(fmt_num "$STATE_READS")" "$(fmt_num "$STATE_WRITES")"

# RPC
echo ""
echo "  RPC REQUESTS"
echo "───────────────────────────────────────────────────────────────"
echo "$METRICS" | grep "^stateless_validator_rpc_requests_total{" | while read -r line; do
    METHOD=$(echo "$line" | sed 's/.*method="\([^"]*\)".*/\1/')
    COUNT=$(echo "$line" | awk '{print $2}' | cut -d'.' -f1)
    printf "   %-28s %s\n" "$METHOD:" "$(fmt_num "$COUNT")"
done

# RPC Errors with detail by method
ERROR_LINES=$(echo "$METRICS" | grep "^stateless_validator_rpc_errors_total{")
TOTAL_ERRORS=$(echo "$ERROR_LINES" | awk '{sum += $2} END {print int(sum)}')
if [ "${TOTAL_ERRORS:-0}" -gt 0 ]; then
    echo ""
    echo "  RPC ERRORS (Total: $TOTAL_ERRORS)"
    echo "───────────────────────────────────────────────────────────────"
    echo "$ERROR_LINES" | while read -r line; do
        METHOD=$(echo "$line" | sed 's/.*method="\([^"]*\)".*/\1/')
        COUNT=$(echo "$line" | awk '{print $2}' | cut -d'.' -f1)
        [ "${COUNT:-0}" -gt 0 ] && printf "   %-28s %s\n" "$METHOD:" "$(fmt_num "$COUNT")"
    done
else
    echo "   Errors: None ✓"
fi

# Workers
echo ""
echo "  WORKERS"
echo "───────────────────────────────────────────────────────────────"
WORKER_DATA=$(echo "$METRICS" | grep "^stateless_validator_worker_tasks_completed_total{" | \
    sed 's/.*worker_id="\([^"]*\)".* \([0-9.]*\)/\1 \2/' | sort -n)

if [ -n "$WORKER_DATA" ]; then
    TOTAL=0; COUNT=0; MAX=0
    while read -r _ TASKS; do
        T=${TASKS%.*}; TOTAL=$((TOTAL + T)); COUNT=$((COUNT + 1))
        [ "$T" -gt "$MAX" ] && MAX=$T
    done <<< "$WORKER_DATA"
    printf "   Workers: %d | Total Tasks: %s | Avg: %d\n" "$COUNT" "$(fmt_num "$TOTAL")" "$((TOTAL / COUNT))"
    echo "$WORKER_DATA" | while read -r WID TASKS; do
        T=${TASKS%.*}; BAR=$(printf '%*s' "$((T * 20 / MAX))" '' | tr ' ' '█')
        printf "      Worker %2s: %6d  %s\n" "$WID" "$T" "$BAR"
    done
else
    echo "   No worker data"
fi

# Pruning (only if non-zero)
PRUNED=$(metric 'stateless_validator_blocks_pruned_total')
[ -n "$PRUNED" ] && [ "$PRUNED" != "0" ] && echo "" && echo "   Blocks Pruned: $(fmt_num "$PRUNED")"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
