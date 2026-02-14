#!/usr/bin/env python3
"""Generate Grafana dashboard JSON for Debug-Trace-Server metrics.

NOTE: metrics-exporter-prometheus v0.18 exports Histogram as Prometheus
summaries. For duration panels we show avg = rate(sum)/rate(count)."""
import json

DS = {"type": "prometheus", "uid": "aez57j8oocoowe"}

def _base_custom():
    return {
        "axisBorderShow": False,
        "axisCenteredZero": False,
        "axisColorMode": "text",
        "axisLabel": "",
        "axisPlacement": "auto",
        "barAlignment": 0,
        "barWidthFactor": 0.6,
        "drawStyle": "line",
        "fillOpacity": 0,
        "gradientMode": "none",
        "hideFrom": {"legend": False, "tooltip": False, "viz": False},
        "insertNulls": False,
        "lineInterpolation": "linear",
        "lineWidth": 1,
        "pointSize": 5,
        "scaleDistribution": {"type": "linear"},
        "showPoints": "auto",
        "showValues": False,
        "spanNulls": False,
        "stacking": {"group": "A", "mode": "none"},
        "thresholdsStyle": {"mode": "off"},
    }

def ts(title, targets, unit="", pid=0, gp=None):
    fc = {
        "defaults": {
            "color": {"mode": "palette-classic"},
            "custom": _base_custom(),
            "mappings": [],
            "thresholds": {"mode": "absolute", "steps": [
                {"color": "green", "value": 0},
                {"color": "red", "value": 80},
            ]},
        },
        "overrides": [],
    }
    if unit:
        fc["defaults"]["unit"] = unit
    return {
        "datasource": DS,
        "fieldConfig": fc,
        "gridPos": gp or {"h": 8, "w": 12, "x": 0, "y": 0},
        "id": pid,
        "options": {
            "legend": {
                "calcs": ["mean", "max", "lastNotNull"],
                "displayMode": "table",
                "placement": "right",
                "showLegend": True,
            },
            "tooltip": {"hideZeros": False, "mode": "multi", "sort": "desc"},
        },
        "pluginVersion": "12.2.0",
        "targets": targets,
        "title": title,
        "type": "timeseries",
    }

def t(expr, legend="__auto", ref="A"):
    return {"datasource": DS, "editorMode": "code", "expr": expr,
            "legendFormat": legend, "range": True, "refId": ref}

def row(title, pid, y):
    return {"collapsed": False, "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
            "id": pid, "panels": [], "title": title, "type": "row"}

def L(y): return {"h": 8, "w": 12, "x": 0, "y": y}
def R(y): return {"h": 8, "w": 12, "x": 12, "y": y}
def W8(y): return {"h": 8, "w": 8, "x": 0, "y": y}
def W8M(y): return {"h": 8, "w": 8, "x": 8, "y": y}
def W8R(y): return {"h": 8, "w": 8, "x": 16, "y": y}
def Q1(y): return {"h": 8, "w": 6, "x": 0, "y": y}
def Q2(y): return {"h": 8, "w": 6, "x": 6, "y": y}
def Q3(y): return {"h": 8, "w": 6, "x": 12, "y": y}
def Q4(y): return {"h": 8, "w": 6, "x": 18, "y": y}

H = '$host'
I = '$interval'

def avg_expr(metric):
    return (f'rate({metric}_sum{{server_role="{H}"}}[{I}])'
            f' / rate({metric}_count{{server_role="{H}"}}[{I}])')

panels = []
pid = 1; y = 0

# ==================== Row 1: RPC Overview ====================
panels.append(row("RPC Overview", pid, y)); pid += 1; y += 1

panels.append(ts("RPC QPS",
    [t(f'sum(rate(debug_trace_rpc_requests_total{{server_role="{H}"}}[{I}])) by (method)', "{{method}}")],
    unit="reqps", pid=pid, gp=L(y))); pid += 1
panels.append(ts("RPC Success Rate",
    [t(f'1 - (sum(rate(debug_trace_rpc_errors_total{{server_role="{H}"}}[{I}])) by (method) / sum(rate(debug_trace_rpc_requests_total{{server_role="{H}"}}[{I}])) by (method))', "{{method}}")],
    unit="percentunit", pid=pid, gp=R(y))); pid += 1
y += 8

panels.append(ts("Inflight Requests",
    [t(f'debug_trace_inflight_requests{{server_role="{H}", scope="global"}}', "inflight")],
    pid=pid, gp=L(y))); pid += 1
panels.append(ts("Request Duration",
    [t(avg_expr("debug_trace_request_duration_seconds"), "{{method}}")],
    unit="s", pid=pid, gp=R(y))); pid += 1
y += 8

panels.append(ts("Response Size",
    [t(avg_expr("debug_trace_response_size_bytes"), "{{method}}")],
    unit="bytes", pid=pid, gp=L(y))); pid += 1
panels.append(ts("CPU Time",
    [t(avg_expr("debug_trace_cpu_time_seconds"), "avg")],
    unit="s", pid=pid, gp=R(y))); pid += 1
y += 8

# ==================== Row 2: Response Cache ====================
panels.append(row("Response Cache", pid, y)); pid += 1; y += 1

panels.append(ts("Cache Hit Rate",
    [t(f'sum(rate(debug_trace_cache_hits_total{{server_role="{H}"}}[{I}])) by (type) / (sum(rate(debug_trace_cache_hits_total{{server_role="{H}"}}[{I}])) by (type) + sum(rate(debug_trace_cache_misses_total{{server_role="{H}"}}[{I}])) by (type))', "{{type}}")],
    unit="percentunit", pid=pid, gp=L(y))); pid += 1
panels.append(ts("Cache Hit / Miss QPS",
    [t(f'sum(rate(debug_trace_cache_hits_total{{server_role="{H}"}}[{I}])) by (type)', "{{type}} hits", "A"),
     t(f'sum(rate(debug_trace_cache_misses_total{{server_role="{H}"}}[{I}])) by (type)', "{{type}} misses", "B")],
    unit="reqps", pid=pid, gp=R(y))); pid += 1
y += 8

panels.append(ts("Cache Entries",
    [t(f'debug_trace_cache_entries{{server_role="{H}"}}', "{{type}}")],
    pid=pid, gp=L(y))); pid += 1
panels.append(ts("Cache Size",
    [t(f'debug_trace_cache_bytes{{server_role="{H}"}}', "{{type}}")],
    unit="bytes", pid=pid, gp=R(y))); pid += 1
y += 8

# ==================== Row 3: Data Fetch ====================
panels.append(row("Data Fetch", pid, y)); pid += 1; y += 1

panels.append(ts("Block Data Source QPS",
    [t(f'sum(rate(debug_trace_block_data_fetches_total{{server_role="{H}"}}[{I}])) by (source)', "{{source}}")],
    unit="reqps", pid=pid, gp=L(y))); pid += 1
panels.append(ts("Single-Flight Events QPS",
    [t(f'sum(rate(debug_trace_single_flight_total{{server_role="{H}"}}[{I}])) by (type)', "{{type}}")],
    unit="reqps", pid=pid, gp=R(y))); pid += 1
y += 8

# ==================== Row 4: Upstream RPC ====================
panels.append(row("Upstream RPC", pid, y)); pid += 1; y += 1

panels.append(ts("Upstream QPS",
    [t(f'sum(rate(debug_trace_upstream_requests_total{{server_role="{H}"}}[{I}])) by (method)', "{{method}}")],
    unit="reqps", pid=pid, gp=W8(y))); pid += 1
panels.append(ts("Upstream Success Rate",
    [t(f'1 - (sum(rate(debug_trace_upstream_errors_total{{server_role="{H}"}}[{I}])) by (method) / sum(rate(debug_trace_upstream_requests_total{{server_role="{H}"}}[{I}])) by (method))', "{{method}}")],
    unit="percentunit", pid=pid, gp=W8M(y))); pid += 1
panels.append(ts("Upstream Duration",
    [t(avg_expr("debug_trace_upstream_duration_seconds"), "{{method}}")],
    unit="s", pid=pid, gp=W8R(y))); pid += 1
y += 8

# ==================== Row 5: Witness Fetch ====================
panels.append(row("Witness Fetch", pid, y)); pid += 1; y += 1

panels.append(ts("Witness QPS",
    [t(f'sum(rate(debug_trace_witness_requests_total{{server_role="{H}"}}[{I}])) by (source)', "{{source}}")],
    unit="reqps", pid=pid, gp=Q1(y))); pid += 1
panels.append(ts("Witness Success Rate",
    [t(f'1 - (sum(rate(debug_trace_witness_errors_total{{server_role="{H}"}}[{I}])) by (source) / sum(rate(debug_trace_witness_requests_total{{server_role="{H}"}}[{I}])) by (source))', "{{source}}")],
    unit="percentunit", pid=pid, gp=Q2(y))); pid += 1
panels.append(ts("Witness Duration",
    [t(avg_expr("debug_trace_witness_duration_seconds"), "{{source}}")],
    unit="s", pid=pid, gp=Q3(y))); pid += 1
panels.append(ts("Witness Size",
    [t(avg_expr("debug_trace_witness_bytes"), "{{source}}")],
    unit="bytes", pid=pid, gp=Q4(y))); pid += 1
y += 8

# ==================== Row 6: EVM Execution ====================
panels.append(row("EVM Execution", pid, y)); pid += 1; y += 1

panels.append(ts("EVM Execution Duration",
    [t(avg_expr("debug_trace_evm_execution_seconds"), "{{method}}")],
    unit="s", pid=pid, gp=L(y))); pid += 1
panels.append(ts("Block Tx Count",
    [t(avg_expr("debug_trace_evm_block_tx_count"), "{{method}}")],
    pid=pid, gp=R(y))); pid += 1
y += 8

# ==================== Row 7: Chain Sync & Database ====================
panels.append(row("Chain Sync & Database", pid, y)); pid += 1; y += 1

panels.append(ts("Chain Height & DB Range",
    [t(f'debug_trace_remote_chain_height{{server_role="{H}"}}', "Remote Height", "A"),
     t(f'debug_trace_db_latest_block{{server_role="{H}"}}', "DB Latest", "B"),
     t(f'debug_trace_db_earliest_block{{server_role="{H}"}}', "DB Earliest", "C")],
    pid=pid, gp=L(y))); pid += 1
panels.append(ts("DB Block Range",
    [t(f'debug_trace_db_latest_block{{server_role="{H}"}} - debug_trace_db_earliest_block{{server_role="{H}"}}', "range")],
    pid=pid, gp=R(y))); pid += 1
y += 8

panels.append(ts("Block Distance from Tip",
    [t(avg_expr("debug_trace_block_distance_from_tip"), "avg distance")],
    pid=pid, gp=W8(y))); pid += 1
panels.append(ts("Reorg Depth",
    [t(avg_expr("debug_trace_reorg_depth"), "avg depth")],
    pid=pid, gp=W8M(y))); pid += 1
panels.append(ts("DB Read Duration",
    [t(avg_expr("debug_trace_db_read_duration_seconds"), "avg")],
    unit="s", pid=pid, gp=W8R(y))); pid += 1
y += 8

panels.append(ts("DB Size",
    [t(f'debug_trace_db_size_bytes{{server_role="{H}"}}', "size")],
    unit="bytes", pid=pid, gp=L(y))); pid += 1
y += 8

# ==================== Assemble Dashboard ====================
dashboard = {
    "annotations": {
        "list": [{
            "builtIn": 1,
            "datasource": {"type": "grafana", "uid": "-- Grafana --"},
            "enable": True, "hide": True,
            "iconColor": "rgba(0, 211, 255, 1)",
            "name": "Annotations & Alerts",
            "type": "dashboard",
        }]
    },
    "editable": True,
    "fiscalYearStartMonth": 0,
    "graphTooltip": 0,
    "id": 0,
    "links": [],
    "panels": panels,
    "preload": False,
    "schemaVersion": 42,
    "tags": [],
    "templating": {
        "list": [
            {
                "current": {"text": "mnet-ash-compute-4", "value": "mnet-ash-compute-4"},
                "definition": 'label_values(reth_info{env="mnet", server_role=~"mnet-ash-compute-4|mnet-ash-compute-5"},server_role)',
                "label": "host",
                "name": "host",
                "options": [],
                "query": {
                    "qryType": 1,
                    "query": 'label_values(reth_info{env="mnet", server_role=~"mnet-ash-compute-4|mnet-ash-compute-5"},server_role)',
                    "refId": "PrometheusVariableQueryEditor-VariableQuery",
                },
                "refresh": 1,
                "regex": "",
                "type": "query",
            },
            {
                "current": {"selected": True, "text": "1m", "value": "1m"},
                "label": "Interval",
                "name": "interval",
                "options": [
                    {"selected": False, "text": "1s",  "value": "1s"},
                    {"selected": False, "text": "5s",  "value": "5s"},
                    {"selected": False, "text": "10s", "value": "10s"},
                    {"selected": False, "text": "30s", "value": "30s"},
                    {"selected": True,  "text": "1m",  "value": "1m"},
                    {"selected": False, "text": "5m",  "value": "5m"},
                ],
                "query": "1s,5s,10s,30s,1m,5m",
                "type": "custom",
            },
        ]
    },
    "time": {"from": "now-6h", "to": "now"},
    "timepicker": {},
    "timezone": "browser",
    "title": "Stateless RPC Server",
    "uid": "deznm79",
    "version": 2,
}

with open("/home/krabat/workspace/stateless-validator/grafana/init.json", "w") as f:
    json.dump(dashboard, f, indent=2, ensure_ascii=False)

rows = sum(1 for p in panels if p["type"] == "row")
data = sum(1 for p in panels if p["type"] != "row")
print(f"Done: {len(panels)} panels ({rows} rows, {data} data panels)")
