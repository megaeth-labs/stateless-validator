#!/bin/bash
# Stateless Validator Status Dashboard
# Usage: ./validator-status.sh [metrics_url]
# Example: ./validator-status.sh http://localhost:9090/metrics

set -e

METRICS_URL="${1:-http://localhost:9090/metrics}"

# Fetch all metrics once
METRICS=$(curl -s "$METRICS_URL" 2>/dev/null)

if [ -z "$METRICS" ]; then
    echo "Error: Could not fetch metrics from $METRICS_URL"
    exit 1
fi

# Helper functions
fetch_metric() {
    echo "$METRICS" | grep "^$1" | grep -v quantile | head -1 | awk '{print $2}' | cut -d'.' -f1
}

fetch_metric_float() {
    echo "$METRICS" | grep "^$1" | grep -v quantile | head -1 | awk '{print $2}'
}

fetch_metric_with_label() {
    echo "$METRICS" | grep "^$1{$2}" | grep -v quantile | head -1 | awk '{print $2}'
}

fetch_quantile() {
    echo "$METRICS" | grep "^$1{quantile=\"$2\"}" | head -1 | awk '{print $2}'
}

fetch_quantile_with_label() {
    echo "$METRICS" | grep "^$1{.*$2.*quantile=\"$3\"}" | head -1 | awk '{print $2}'
}

fetch_sum() {
    echo "$METRICS" | grep "^${1}_sum" | grep -v "{" | head -1 | awk '{print $2}'
}

fetch_sum_with_label() {
    echo "$METRICS" | grep "^${1}_sum{$2}" | head -1 | awk '{print $2}'
}

fetch_count() {
    echo "$METRICS" | grep "^${1}_count" | grep -v "{" | head -1 | awk '{print $2}'
}

fetch_count_with_label() {
    echo "$METRICS" | grep "^${1}_count{$2}" | head -1 | awk '{print $2}'
}

format_duration_ms() {
    if [ -n "$1" ] && [ "$1" != "0" ]; then
        # Convert to ms and format to 2 decimal places
        RESULT=$(echo "scale=6; $1 * 1000" | bc 2>/dev/null)
        if [ -n "$RESULT" ]; then
            printf "%.2f" "$RESULT" 2>/dev/null || echo "$RESULT"
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

format_number() {
    if [ -n "$1" ]; then
        printf "%'d" "${1%.*}" 2>/dev/null || echo "$1"
    else
        echo "0"
    fi
}

# Header
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo "                    STATELESS VALIDATOR STATUS"
echo "══════════════════════════════════════════════════════════════════════"
echo "  Metrics URL: $METRICS_URL"
echo "  Timestamp:   $(date '+%Y-%m-%d %H:%M:%S')"
echo "══════════════════════════════════════════════════════════════════════"

# Chain Status
CANONICAL=$(fetch_metric 'stateless_validator_local_chain_height')
REMOTE=$(fetch_metric 'stateless_validator_remote_chain_height')
GAP=$(fetch_metric 'stateless_validator_validation_lag')

echo ""
echo "  CHAIN STATUS"
echo "──────────────────────────────────────────────────────────────────────"
printf "   %-24s %s\n" "Canonical Height:" "$(format_number "$CANONICAL")"
printf "   %-24s %s\n" "Remote Height:" "$(format_number "$REMOTE")"
if [ "${GAP:-0}" -eq 0 ]; then
    printf "   %-24s %s ✓\n" "Chain Gap:" "0 (synced)"
else
    printf "   %-24s %s blocks behind\n" "Chain Gap:" "$GAP"
fi

# Validation Stats
REORGS=$(fetch_metric 'stateless_validator_reorgs_detected_total')

echo ""
echo "  VALIDATION"
echo "──────────────────────────────────────────────────────────────────────"
printf "   %-24s %s\n" "Reorgs Detected:" "${REORGS:-0}"

# Performance Metrics
VAL_SUM=$(fetch_sum 'stateless_validator_block_validation_time_seconds')
VAL_COUNT=$(fetch_count 'stateless_validator_block_validation_time_seconds')
VAL_P50=$(fetch_quantile 'stateless_validator_block_validation_time_seconds' '0.5')
VAL_P95=$(fetch_quantile 'stateless_validator_block_validation_time_seconds' '0.95')
VAL_P99=$(fetch_quantile 'stateless_validator_block_validation_time_seconds' '0.99')

echo ""
echo "  PERFORMANCE"
echo "──────────────────────────────────────────────────────────────────────"
echo "   Block Validation Latency:"
if [ -n "$VAL_COUNT" ] && [ "$VAL_COUNT" != "0" ]; then
    AVG=$(echo "scale=6; $VAL_SUM / $VAL_COUNT" | bc 2>/dev/null)
    printf "      %-20s %s ms\n" "Average:" "$(format_duration_ms "$AVG")"
    printf "      %-20s %s ms\n" "P50 (median):" "$(format_duration_ms "$VAL_P50")"
    printf "      %-20s %s ms\n" "P95:" "$(format_duration_ms "$VAL_P95")"
    printf "      %-20s %s ms\n" "P99:" "$(format_duration_ms "$VAL_P99")"

    # Calculate blocks per second
    if [ -n "$AVG" ] && [ "$AVG" != "0" ]; then
        BPS=$(echo "scale=2; 1 / $AVG" | bc 2>/dev/null)
        printf "      %-20s %s blocks/sec\n" "Throughput:" "$BPS"
    fi
else
    echo "      No data yet"
fi


# Block Statistics
echo ""
echo "  THROUGHPUT"
echo "──────────────────────────────────────────────────────────────────────"

TOTAL_GAS=$(fetch_metric 'stateless_validator_gas_used_total')
TOTAL_TX=$(fetch_metric 'stateless_validator_transactions_total')
BLOCKS_VALIDATED=$(fetch_count 'stateless_validator_block_validation_time_seconds')

printf "   %-24s %s\n" "Blocks Validated:" "$(format_number "$BLOCKS_VALIDATED")"
printf "   %-24s %s\n" "Total Transactions:" "$(format_number "$TOTAL_TX")"
printf "   %-24s %s\n" "Total Gas Used:" "$(format_number "$TOTAL_GAS")"

# Calculate averages if we have blocks
if [ -n "$BLOCKS_VALIDATED" ] && [ "${BLOCKS_VALIDATED%.*}" -gt 0 ]; then
    BLOCKS_INT=${BLOCKS_VALIDATED%.*}
    if [ -n "$TOTAL_TX" ] && [ "${TOTAL_TX:-0}" -gt 0 ]; then
        AVG_TX=$(echo "scale=2; $TOTAL_TX / $BLOCKS_INT" | bc 2>/dev/null)
        printf "   %-24s %s\n" "Avg TX/Block:" "$AVG_TX"
    fi
    if [ -n "$TOTAL_GAS" ] && [ "${TOTAL_GAS:-0}" -gt 0 ]; then
        AVG_GAS=$(echo "scale=0; $TOTAL_GAS / $BLOCKS_INT" | bc 2>/dev/null)
        printf "   %-24s %s\n" "Avg Gas/Block:" "$(format_number "$AVG_GAS")"
    fi
fi

echo ""
echo "   Note: Use Prometheus rate() for TPS/Gas-per-second:"
echo "      rate(stateless_validator_transactions_total[1m])"
echo "      rate(stateless_validator_gas_used_total[1m])"

# Timing Breakdown
echo ""
echo "   Timing Breakdown (P50):"
WITNESS_P50=$(fetch_quantile 'stateless_validator_witness_fetch_time_seconds' '0.5')
BLOCK_FETCH_P50=$(fetch_quantile 'stateless_validator_block_fetch_time_seconds' '0.5')
CODE_FETCH_P50=$(fetch_quantile 'stateless_validator_code_fetch_time_seconds' '0.5')

printf "      %-20s %s ms\n" "Witness Fetch:" "$(format_duration_ms "$WITNESS_P50")"
printf "      %-20s %s ms\n" "Block Fetch:" "$(format_duration_ms "$BLOCK_FETCH_P50")"
printf "      %-20s %s ms\n" "Code Fetch:" "$(format_duration_ms "$CODE_FETCH_P50")"

# Cache Stats
HITS=$(fetch_metric 'stateless_validator_contract_cache_hits_total')
MISSES=$(fetch_metric 'stateless_validator_contract_cache_misses_total')

echo ""
echo "  CONTRACT CACHE"
echo "──────────────────────────────────────────────────────────────────────"
printf "   %-24s %s\n" "Cache Hits:" "$(format_number "$HITS")"
printf "   %-24s %s\n" "Cache Misses:" "${MISSES:-0}"
if [ -n "$HITS" ] && [ -n "$MISSES" ]; then
    TOTAL=$((${HITS:-0} + ${MISSES:-0}))
    if [ "$TOTAL" -gt 0 ]; then
        RATE=$(echo "scale=2; ${HITS:-0} * 100 / $TOTAL" | bc 2>/dev/null)
        printf "   %-24s %s%%\n" "Hit Rate:" "$RATE"
    fi
fi

# RPC Stats
echo ""
echo "  RPC REQUESTS"
echo "──────────────────────────────────────────────────────────────────────"

# Extract and display RPC request counts
echo "$METRICS" | grep "^stateless_validator_rpc_requests_total{" | while read -r line; do
    METHOD=$(echo "$line" | sed 's/.*method="\([^"]*\)".*/\1/')
    COUNT=$(echo "$line" | awk '{print $2}' | cut -d'.' -f1)
    printf "   %-32s %s\n" "$METHOD:" "$(format_number "$COUNT")"
done

# RPC Errors
echo ""
echo "   Errors:"
HAS_ERRORS=false
echo "$METRICS" | grep "^stateless_validator_rpc_errors_total{" | while read -r line; do
    METHOD=$(echo "$line" | sed 's/.*method="\([^"]*\)".*/\1/')
    COUNT=$(echo "$line" | awk '{print $2}' | cut -d'.' -f1)
    if [ "${COUNT:-0}" -gt 0 ]; then
        printf "      %-29s %s\n" "$METHOD:" "$COUNT"
        HAS_ERRORS=true
    fi
done
if [ "$HAS_ERRORS" = false ]; then
    TOTAL_ERRORS=$(echo "$METRICS" | grep "^stateless_validator_rpc_errors_total{" | awk '{sum += $2} END {print sum}')
    if [ -z "$TOTAL_ERRORS" ] || [ "${TOTAL_ERRORS%.*}" -eq 0 ]; then
        echo "      None ✓"
    fi
fi

# Worker Stats
echo ""
echo "  WORKERS"
echo "──────────────────────────────────────────────────────────────────────"

WORKER_DATA=$(echo "$METRICS" | grep "^stateless_validator_worker_tasks_completed_total{" | \
    sed 's/.*worker_id="\([^"]*\)".* \([0-9.]*\)/\1 \2/' | \
    sort -n)

if [ -n "$WORKER_DATA" ]; then
    TOTAL_TASKS=0
    WORKER_COUNT=0
    MIN_TASKS=999999999
    MAX_TASKS=0

    while read -r WORKER_ID TASKS; do
        TASKS_INT=${TASKS%.*}
        TOTAL_TASKS=$((TOTAL_TASKS + TASKS_INT))
        WORKER_COUNT=$((WORKER_COUNT + 1))
        if [ "$TASKS_INT" -lt "$MIN_TASKS" ]; then MIN_TASKS=$TASKS_INT; fi
        if [ "$TASKS_INT" -gt "$MAX_TASKS" ]; then MAX_TASKS=$TASKS_INT; fi
    done <<< "$WORKER_DATA"

    printf "   %-24s %s\n" "Active Workers:" "$WORKER_COUNT"
    printf "   %-24s %s\n" "Total Tasks:" "$(format_number "$TOTAL_TASKS")"

    if [ "$WORKER_COUNT" -gt 0 ]; then
        AVG_TASKS=$((TOTAL_TASKS / WORKER_COUNT))
        printf "   %-24s %s\n" "Avg Tasks/Worker:" "$AVG_TASKS"
        printf "   %-24s %s - %s\n" "Task Range:" "$MIN_TASKS" "$MAX_TASKS"
    fi

    echo ""
    echo "   Per-Worker Breakdown:"
    echo "$WORKER_DATA" | while read -r WORKER_ID TASKS; do
        TASKS_INT=${TASKS%.*}
        # Create a simple bar chart
        BAR_LEN=$((TASKS_INT * 20 / MAX_TASKS))
        BAR=$(printf '%*s' "$BAR_LEN" '' | tr ' ' '█')
        printf "      Worker %2s: %6s  %s\n" "$WORKER_ID" "$TASKS_INT" "$BAR"
    done
else
    echo "   No worker data available"
fi

# Pruning Stats
PRUNED=$(fetch_metric 'stateless_validator_blocks_pruned_total')
if [ -n "$PRUNED" ] && [ "$PRUNED" != "0" ]; then
    echo ""
    echo "   PRUNING"
    echo "──────────────────────────────────────────────────────────────────────"
    printf "   %-24s %s\n" "Blocks Pruned:" "$(format_number "$PRUNED")"
fi

# Footer
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo ""
