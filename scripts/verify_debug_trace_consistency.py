#!/usr/bin/env python3
"""
Verify consistency between mega-reth and debug-trace-server RPC responses.

This script:
1. Starts the debug-trace-server
2. Calls the same RPC methods on both mega-reth and debug-trace-server
3. Compares the responses for consistency
"""

import argparse
import json
import subprocess
import sys
import time
from typing import Any, Optional
import requests


# Default configuration
DEFAULT_MEGA_RETH_PORT = 49945
DEFAULT_DEBUG_TRACE_SERVER_PORT = 18545
DEFAULT_WITNESS_ENDPOINT = "http://localhost:8080"  # Adjust as needed


def rpc_call(url: str, method: str, params: list, timeout: int = 120) -> dict:
    """Make a JSON-RPC call and return the result."""
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


def wait_for_server(url: str, max_retries: int = 30, delay: float = 1.0) -> bool:
    """Wait for a server to become available."""
    for i in range(max_retries):
        try:
            response = requests.post(
                url,
                json={"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1},
                timeout=5,
            )
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass
        time.sleep(delay)
        print(f"Waiting for server at {url}... ({i + 1}/{max_retries})")
    return False


def normalize_json(obj: Any) -> Any:
    """Normalize JSON for comparison (sort keys, handle numeric differences)."""
    if isinstance(obj, dict):
        return {k: normalize_json(v) for k, v in sorted(obj.items())}
    elif isinstance(obj, list):
        return [normalize_json(item) for item in obj]
    elif isinstance(obj, str):
        # Normalize hex strings to lowercase
        if obj.startswith("0x"):
            # Treat "0x" as equivalent to empty string for returnValue
            if obj == "0x":
                return ""
            return obj.lower()
        return obj
    return obj


def compare_responses(resp1: dict, resp2: dict, method: str) -> tuple[bool, str]:
    """Compare two RPC responses and return (is_equal, diff_message)."""
    # Check for errors
    if "error" in resp1 and "error" in resp2:
        return True, "Both returned errors"
    if "error" in resp1:
        return False, f"mega-reth returned error: {resp1['error']}"
    if "error" in resp2:
        return False, f"debug-trace-server returned error: {resp2['error']}"

    result1 = resp1.get("result")
    result2 = resp2.get("result")

    # Normalize for comparison
    norm1 = normalize_json(result1)
    norm2 = normalize_json(result2)

    if norm1 == norm2:
        return True, "Results match"

    # Generate diff for debugging
    diff_msg = f"Results differ for {method}\n"
    diff_msg += f"mega-reth result type: {type(result1).__name__}\n"
    diff_msg += f"debug-trace-server result type: {type(result2).__name__}\n"

    # For large results, just show a summary
    str1 = json.dumps(norm1, indent=2)
    str2 = json.dumps(norm2, indent=2)
    if len(str1) > 1000 or len(str2) > 1000:
        diff_msg += f"mega-reth result length: {len(str1)}\n"
        diff_msg += f"debug-trace-server result length: {len(str2)}\n"
        diff_msg += "Results are too large to display in full\n"
    else:
        diff_msg += f"mega-reth result:\n{str1}\n"
        diff_msg += f"debug-trace-server result:\n{str2}\n"

    return False, diff_msg


def get_test_block_number(mega_reth_url: str) -> Optional[int]:
    """Get a recent block number for testing."""
    resp = rpc_call(mega_reth_url, "eth_blockNumber", [])
    if "result" in resp:
        latest = int(resp["result"], 16)
        # Use a block that's a few blocks behind latest to ensure it's finalized
        return max(1, latest - 5)
    return None


def get_test_tx_hash(mega_reth_url: str, block_number: int) -> Optional[str]:
    """Get a transaction hash from a block for testing."""
    resp = rpc_call(mega_reth_url, "eth_getBlockByNumber", [hex(block_number), True])
    if "result" in resp and resp["result"]:
        txs = resp["result"].get("transactions", [])
        if txs and isinstance(txs[0], dict):
            return txs[0].get("hash")
    return None


def get_block_hash(mega_reth_url: str, block_number: int) -> Optional[str]:
    """Get the block hash for a given block number."""
    resp = rpc_call(mega_reth_url, "eth_getBlockByNumber", [hex(block_number), False])
    if "result" in resp and resp["result"]:
        return resp["result"].get("hash")
    return None


class DebugTraceVerifier:
    """Verifier for debug/trace RPC consistency."""

    def __init__(
        self,
        mega_reth_url: str,
        debug_trace_server_url: str,
        verbose: bool = False,
    ):
        self.mega_reth_url = mega_reth_url
        self.debug_trace_server_url = debug_trace_server_url
        self.verbose = verbose
        self.results = {"passed": 0, "failed": 0, "skipped": 0}

    def log(self, msg: str):
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(msg)

    def test_method(
        self,
        method: str,
        params: list,
        description: str,
    ) -> bool:
        """Test a single RPC method for consistency."""
        print(f"\n{'='*60}")
        print(f"Testing: {description}")
        print(f"Method: {method}")
        print(f"Params: {json.dumps(params)}")
        print(f"{'='*60}")

        # Call mega-reth
        print("Calling mega-reth...")
        resp1 = rpc_call(self.mega_reth_url, method, params)
        self.log(f"mega-reth response: {json.dumps(resp1)[:500]}...")

        # Call debug-trace-server
        print("Calling debug-trace-server...")
        resp2 = rpc_call(self.debug_trace_server_url, method, params)
        self.log(f"debug-trace-server response: {json.dumps(resp2)[:500]}...")

        # Compare
        is_equal, msg = compare_responses(resp1, resp2, method)

        if is_equal:
            print(f"✓ PASSED: {msg}")
            self.results["passed"] += 1
        else:
            print(f"✗ FAILED: {msg}")
            self.results["failed"] += 1

        return is_equal

    def run_all_tests(self, block_number: int, block_hash: str, tx_hash: Optional[str]):
        """Run all consistency tests."""
        print("\n" + "=" * 60)
        print("Starting Debug/Trace RPC Consistency Tests")
        print("=" * 60)
        print(f"mega-reth URL: {self.mega_reth_url}")
        print(f"debug-trace-server URL: {self.debug_trace_server_url}")
        print(f"Test block number: {block_number}")
        print(f"Test block hash: {block_hash}")
        print(f"Test tx hash: {tx_hash}")
        print("=" * 60)

        # Test debug_traceBlockByNumber
        self.test_method(
            "debug_traceBlockByNumber",
            [hex(block_number), {}],
            f"debug_traceBlockByNumber with block {block_number}",
        )

        # Test debug_traceBlockByNumber with tracer options
        self.test_method(
            "debug_traceBlockByNumber",
            [hex(block_number), {"tracer": "callTracer"}],
            f"debug_traceBlockByNumber with callTracer",
        )

        # Test debug_traceBlockByHash
        self.test_method(
            "debug_traceBlockByHash",
            [block_hash, {}],
            f"debug_traceBlockByHash with hash {block_hash[:18]}...",
        )

        # Test trace_block
        self.test_method(
            "trace_block",
            [hex(block_number)],
            f"trace_block with block {block_number}",
        )

        # Test transaction-level methods if we have a tx hash
        if tx_hash:
            # Test debug_traceTransaction
            self.test_method(
                "debug_traceTransaction",
                [tx_hash, {}],
                f"debug_traceTransaction with tx {tx_hash[:18]}...",
            )

            # Test debug_traceTransaction with callTracer
            self.test_method(
                "debug_traceTransaction",
                [tx_hash, {"tracer": "callTracer"}],
                f"debug_traceTransaction with callTracer",
            )

            # Test trace_transaction
            self.test_method(
                "trace_transaction",
                [tx_hash],
                f"trace_transaction with tx {tx_hash[:18]}...",
            )
        else:
            print("\nSkipping transaction-level tests (no transactions in test block)")
            self.results["skipped"] += 3

        # Print summary
        print("\n" + "=" * 60)
        print("Test Summary")
        print("=" * 60)
        print(f"Passed: {self.results['passed']}")
        print(f"Failed: {self.results['failed']}")
        print(f"Skipped: {self.results['skipped']}")
        print("=" * 60)

        return self.results["failed"] == 0


def start_debug_trace_server(
    binary_path: str,
    addr: str,
    rpc_endpoint: str,
    witness_endpoint: str,
    data_dir: str = "./data",
    genesis_file: Optional[str] = None,
) -> subprocess.Popen:
    """Start the debug-trace-server as a subprocess."""
    cmd = [
        binary_path,
        "--addr", addr,
        "--rpc-endpoint", rpc_endpoint,
        "--witness-endpoint", witness_endpoint,
        "--data-dir", data_dir,
    ]
    if genesis_file:
        cmd.extend(["--genesis-file", genesis_file])
    print(f"Starting debug-trace-server: {' '.join(cmd)}")
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return process


def main():
    parser = argparse.ArgumentParser(
        description="Verify consistency between mega-reth and debug-trace-server"
    )
    parser.add_argument(
        "--mega-reth-port",
        type=int,
        default=DEFAULT_MEGA_RETH_PORT,
        help=f"mega-reth RPC port (default: {DEFAULT_MEGA_RETH_PORT})",
    )
    parser.add_argument(
        "--debug-trace-server-port",
        type=int,
        default=DEFAULT_DEBUG_TRACE_SERVER_PORT,
        help=f"debug-trace-server RPC port (default: {DEFAULT_DEBUG_TRACE_SERVER_PORT})",
    )
    parser.add_argument(
        "--witness-endpoint",
        type=str,
        default=DEFAULT_WITNESS_ENDPOINT,
        help=f"Witness endpoint URL (default: {DEFAULT_WITNESS_ENDPOINT})",
    )
    parser.add_argument(
        "--binary-path",
        type=str,
        default="./target/release/debug-trace-server",
        help="Path to debug-trace-server binary",
    )
    parser.add_argument(
        "--block-number",
        type=int,
        default=None,
        help="Specific block number to test (default: auto-detect recent block)",
    )
    parser.add_argument(
        "--tx-hash",
        type=str,
        default=None,
        help="Specific transaction hash to test (default: auto-detect from block)",
    )
    parser.add_argument(
        "--skip-server-start",
        action="store_true",
        help="Skip starting debug-trace-server (assume it's already running)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default="./data",
        help="Data directory for debug-trace-server",
    )
    parser.add_argument(
        "--genesis-file",
        type=str,
        default=None,
        help="Path to genesis JSON file for debug-trace-server",
    )

    args = parser.parse_args()

    mega_reth_url = f"http://localhost:{args.mega_reth_port}"
    debug_trace_server_url = f"http://localhost:{args.debug_trace_server_port}"

    # Check mega-reth is available
    print(f"Checking mega-reth at {mega_reth_url}...")
    if not wait_for_server(mega_reth_url, max_retries=5, delay=1.0):
        print(f"ERROR: mega-reth not available at {mega_reth_url}")
        sys.exit(1)
    print("mega-reth is available")

    # Start debug-trace-server if needed
    server_process = None
    if not args.skip_server_start:
        server_process = start_debug_trace_server(
            binary_path=args.binary_path,
            addr=f"0.0.0.0:{args.debug_trace_server_port}",
            rpc_endpoint=mega_reth_url,
            witness_endpoint=args.witness_endpoint,
            data_dir=args.data_dir,
            genesis_file=args.genesis_file,
        )
        print(f"Waiting for debug-trace-server at {debug_trace_server_url}...")
        if not wait_for_server(debug_trace_server_url, max_retries=30, delay=1.0):
            print(f"ERROR: debug-trace-server failed to start")
            if server_process:
                server_process.terminate()
            sys.exit(1)
        print("debug-trace-server is available")
    else:
        print(f"Checking debug-trace-server at {debug_trace_server_url}...")
        if not wait_for_server(debug_trace_server_url, max_retries=5, delay=1.0):
            print(f"ERROR: debug-trace-server not available at {debug_trace_server_url}")
            sys.exit(1)
        print("debug-trace-server is available")

    try:
        # Get test parameters
        block_number = args.block_number
        if block_number is None:
            block_number = get_test_block_number(mega_reth_url)
            if block_number is None:
                print("ERROR: Could not get block number from mega-reth")
                sys.exit(1)

        block_hash = get_block_hash(mega_reth_url, block_number)
        if block_hash is None:
            print(f"ERROR: Could not get block hash for block {block_number}")
            sys.exit(1)

        tx_hash = args.tx_hash
        if tx_hash is None:
            tx_hash = get_test_tx_hash(mega_reth_url, block_number)
            if tx_hash is None:
                print(f"WARNING: No transactions found in block {block_number}")

        # Run tests
        verifier = DebugTraceVerifier(
            mega_reth_url=mega_reth_url,
            debug_trace_server_url=debug_trace_server_url,
            verbose=args.verbose,
        )
        success = verifier.run_all_tests(block_number, block_hash, tx_hash)

        sys.exit(0 if success else 1)

    finally:
        if server_process:
            print("\nStopping debug-trace-server...")
            server_process.terminate()
            server_process.wait(timeout=5)


if __name__ == "__main__":
    main()
