#!/usr/bin/env python3
"""
Verify debug/trace consistency using existing transactions from recent blocks.

This script:
1. Fetches recent blocks with transactions
2. Verifies consistency between mega-reth and debug-trace-server for multiple blocks/transactions
"""

import json
import sys
from typing import Optional, List, Tuple
import requests

# Configuration
MEGA_RETH_URL = "http://localhost:49945"
DEBUG_TRACE_SERVER_URL = "http://localhost:18545"


def rpc_call(url: str, method: str, params: list, timeout: int = 120) -> dict:
    """Make a JSON-RPC call."""
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    }
    try:
        response = requests.post(url, json=payload, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": {"message": str(e)}}


def normalize_json(obj):
    """Normalize JSON for comparison."""
    if isinstance(obj, dict):
        return {k: normalize_json(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [normalize_json(item) for item in obj]
    elif isinstance(obj, str):
        if obj.startswith("0x"):
            if obj == "0x":
                return ""
            return obj.lower()
        return obj
    return obj


def compare_responses(resp1: dict, resp2: dict, method: str) -> Tuple[bool, str]:
    """Compare two RPC responses."""
    if "error" in resp1 and "error" in resp2:
        return True, "Both returned errors"
    if "error" in resp1:
        return False, f"mega-reth returned error: {resp1['error']}"
    if "error" in resp2:
        return False, f"debug-trace-server returned error: {resp2['error']}"

    result1 = resp1.get("result")
    result2 = resp2.get("result")

    norm1 = normalize_json(result1)
    norm2 = normalize_json(result2)

    if norm1 == norm2:
        return True, "Results match"

    # Show diff details
    str1 = json.dumps(norm1, indent=2)
    str2 = json.dumps(norm2, indent=2)
    if len(str1) > 500:
        str1 = str1[:500] + "..."
    if len(str2) > 500:
        str2 = str2[:500] + "..."
    return False, f"Results differ:\nmega-reth: {str1}\ndebug-trace-server: {str2}"


def get_blocks_with_transactions(count: int = 10) -> List[Tuple[int, str, List[str]]]:
    """Get recent blocks that have transactions."""
    resp = rpc_call(MEGA_RETH_URL, "eth_blockNumber", [])
    if "error" in resp:
        print(f"Error getting block number: {resp['error']}")
        return []

    latest = int(resp["result"], 16)
    blocks = []

    # Search backwards for blocks with transactions
    for block_num in range(latest - 5, max(0, latest - 200), -1):
        resp = rpc_call(MEGA_RETH_URL, "eth_getBlockByNumber", [hex(block_num), True])
        if "error" in resp or not resp.get("result"):
            continue

        block = resp["result"]
        txs = block.get("transactions", [])
        if txs and isinstance(txs[0], dict):
            tx_hashes = [tx["hash"] for tx in txs]
            blocks.append((block_num, block["hash"], tx_hashes))
            if len(blocks) >= count:
                break

    return blocks


def verify_transaction(tx_hash: str, description: str) -> Tuple[int, int]:
    """Verify a transaction's traces match between servers. Returns (passed, failed)."""
    print(f"\n  Transaction: {tx_hash[:18]}... ({description})")

    passed = 0
    failed = 0

    # Test debug_traceTransaction (default)
    resp1 = rpc_call(MEGA_RETH_URL, "debug_traceTransaction", [tx_hash, {}])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "debug_traceTransaction", [tx_hash, {}])
    ok, msg = compare_responses(resp1, resp2, "debug_traceTransaction")
    print(f"    debug_traceTransaction (default): {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    # Test debug_traceTransaction (callTracer)
    resp1 = rpc_call(MEGA_RETH_URL, "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "debug_traceTransaction", [tx_hash, {"tracer": "callTracer"}])
    ok, msg = compare_responses(resp1, resp2, "debug_traceTransaction (callTracer)")
    print(f"    debug_traceTransaction (callTracer): {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    # Test trace_transaction
    resp1 = rpc_call(MEGA_RETH_URL, "trace_transaction", [tx_hash])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "trace_transaction", [tx_hash])
    ok, msg = compare_responses(resp1, resp2, "trace_transaction")
    print(f"    trace_transaction: {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    return passed, failed


def verify_block(block_number: int, block_hash: str) -> Tuple[int, int]:
    """Verify a block's traces match between servers. Returns (passed, failed)."""
    passed = 0
    failed = 0
    block_hex = hex(block_number)

    # Test debug_traceBlockByNumber (default)
    resp1 = rpc_call(MEGA_RETH_URL, "debug_traceBlockByNumber", [block_hex, {}])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "debug_traceBlockByNumber", [block_hex, {}])
    ok, msg = compare_responses(resp1, resp2, "debug_traceBlockByNumber")
    print(f"    debug_traceBlockByNumber (default): {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    # Test debug_traceBlockByNumber (callTracer)
    resp1 = rpc_call(MEGA_RETH_URL, "debug_traceBlockByNumber", [block_hex, {"tracer": "callTracer"}])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "debug_traceBlockByNumber", [block_hex, {"tracer": "callTracer"}])
    ok, msg = compare_responses(resp1, resp2, "debug_traceBlockByNumber (callTracer)")
    print(f"    debug_traceBlockByNumber (callTracer): {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    # Test debug_traceBlockByHash
    resp1 = rpc_call(MEGA_RETH_URL, "debug_traceBlockByHash", [block_hash, {}])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "debug_traceBlockByHash", [block_hash, {}])
    ok, msg = compare_responses(resp1, resp2, "debug_traceBlockByHash")
    print(f"    debug_traceBlockByHash: {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    # Test trace_block
    resp1 = rpc_call(MEGA_RETH_URL, "trace_block", [block_hex])
    resp2 = rpc_call(DEBUG_TRACE_SERVER_URL, "trace_block", [block_hex])
    ok, msg = compare_responses(resp1, resp2, "trace_block")
    print(f"    trace_block: {'✓' if ok else '✗'}")
    if ok:
        passed += 1
    else:
        failed += 1
        print(f"      {msg[:200]}")

    return passed, failed


def main():
    print("=" * 70)
    print("Extended Debug/Trace Consistency Verification")
    print("=" * 70)
    print(f"mega-reth URL: {MEGA_RETH_URL}")
    print(f"debug-trace-server URL: {DEBUG_TRACE_SERVER_URL}")

    # Get blocks with transactions
    print("\nFetching recent blocks with transactions...")
    blocks = get_blocks_with_transactions(count=5)

    if not blocks:
        print("ERROR: No blocks with transactions found!")
        sys.exit(1)

    print(f"Found {len(blocks)} blocks with transactions")

    total_passed = 0
    total_failed = 0

    # Verify each block and its transactions
    for block_num, block_hash, tx_hashes in blocks:
        print(f"\n{'='*70}")
        print(f"Block {block_num} (hash: {block_hash[:18]}...)")
        print(f"{'='*70}")

        # Verify block-level methods
        print("\n  Block-level methods:")
        p, f = verify_block(block_num, block_hash)
        total_passed += p
        total_failed += f

        # Verify transaction-level methods (limit to first 3 transactions per block)
        print(f"\n  Transaction-level methods ({min(len(tx_hashes), 3)} transactions):")
        for i, tx_hash in enumerate(tx_hashes[:3]):
            p, f = verify_transaction(tx_hash, f"tx {i+1}/{len(tx_hashes)}")
            total_passed += p
            total_failed += f

    # Print summary
    print("\n" + "=" * 70)
    print("FINAL SUMMARY")
    print("=" * 70)
    print(f"Total tests: {total_passed + total_failed}")
    print(f"Passed: {total_passed}")
    print(f"Failed: {total_failed}")
    print("=" * 70)

    if total_failed > 0:
        print("\n✗ Some tests failed!")
        sys.exit(1)
    else:
        print("\n✓ All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
