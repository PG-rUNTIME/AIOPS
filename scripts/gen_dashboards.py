"""Generate Grafana dashboards as code (config/grafana/dashboards/*.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parents[1] / "config" / "grafana" / "dashboards"
VM = {"type": "prometheus", "uid": "vm"}
# Cassava series palette (brand/tokens.json "chartSeries"), readable on Grafana's dark theme
SERIES = ["#00F19C", "#5B8DEF", "#C9D2E3", "#00B377", "#F5B841", "#FF7A85"]
LOKI = {"type": "loki", "uid": "loki"}


def panel(
    pid: int,
    title: str,
    exprs: list[tuple[str, str]],
    x: int,
    y: int,
    w: int = 12,
    h: int = 8,
    kind: str = "timeseries",
    unit: str = "short",
    ds: dict[str, str] = VM,
) -> dict[str, Any]:
    overrides = [
        {
            "matcher": {"id": "byFrameRefID", "options": chr(65 + i)},
            "properties": [
                {"id": "color", "value": {"mode": "fixed", "fixedColor": SERIES[i % len(SERIES)]}}
            ],
        }
        for i in range(len(exprs))
    ]
    defaults: dict[str, Any] = {"unit": unit, "color": {"mode": "palette-classic"}}
    if kind == "timeseries":
        defaults["custom"] = {
            "lineWidth": 2,
            "fillOpacity": 8,
            "gradientMode": "opacity",
            "showPoints": "never",
        }
    return {
        "id": pid,
        "title": title,
        "type": kind,
        "datasource": ds,
        "gridPos": {"x": x, "y": y + 3, "w": w, "h": h},
        "fieldConfig": {"defaults": defaults, "overrides": overrides},
        "targets": [
            {"refId": chr(65 + i), "expr": e, "legendFormat": lg, "datasource": ds}
            for i, (e, lg) in enumerate(exprs)
        ],
    }


def header(title: str, subtitle: str) -> dict[str, Any]:
    """Branded header: Cassava logo (served from public/img/cassava) + dashboard purpose."""
    logo = '<img src="public/img/cassava/cassava-logo-white.png" alt="Cassava Technologies" height="30">'
    html = (
        '<div style="display:flex;align-items:center;gap:18px;height:100%">'
        f'{logo}<div style="border-left:1px solid #3a4a72;padding-left:18px">'
        f'<div style="font:700 18px Montserrat,Arial,sans-serif;color:#fff">{title}</div>'
        f'<div style="font:13px Arial,sans-serif;color:#C9D2E3">{subtitle}</div></div></div>'
    )
    return {
        "id": 99,
        "type": "text",
        "title": "",
        "transparent": True,
        "gridPos": {"x": 0, "y": 0, "w": 24, "h": 3},
        "options": {"mode": "html", "content": html},
    }


def dash(
    uid: str, title: str, panels: list[dict[str, Any]], variables: list[dict[str, Any]]
) -> dict[str, Any]:
    panels = [header(title.split(" / ", 1)[-1], SUBTITLES[uid]), *panels]
    return {
        "uid": uid,
        "title": title,
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "time": {"from": "now-1h", "to": "now"},
        "refresh": "30s",
        "tags": ["aiops"],
        "templating": {"list": variables},
        "panels": panels,
    }


def var(name: str, query: str) -> dict[str, Any]:
    return {
        "name": name,
        "type": "query",
        "datasource": VM,
        "query": {"query": query, "refId": name},
        "refresh": 2,
        "includeAll": False,
    }


SUBTITLES = {
    "aiops-ci-overview": "One configuration item: observed values, 15-minute predictions and logs",
    "aiops-platform": "Health of the AIOps services themselves (rate, errors, duration)",
    "aiops-kpis": "Were warnings real, were failures caught, and how much notice did teams get",
}
CI = 'ci_id="$ci_id"'
ci_overview = dash(
    "aiops-ci-overview",
    "AIOps / CI overview",
    [
        panel(
            1,
            "Disk used ratio (+15m predict_linear)",
            [
                (
                    f"1 - node_filesystem_avail_bytes{{{CI}}} / node_filesystem_size_bytes{{{CI}}}",
                    "used {{mountpoint}}",
                ),
                (
                    f"1 - aiops:disk_avail_bytes:predict_15m{{{CI}}} / node_filesystem_size_bytes{{{CI}}}",
                    "predicted +15m",
                ),
            ],
            0,
            0,
            unit="percentunit",
        ),
        panel(
            2,
            "Memory used ratio",
            [(f"aiops:memory_used_ratio{{{CI}}}", "used")],
            12,
            0,
            unit="percentunit",
        ),
        panel(
            3,
            "CPU utilisation",
            [(f"node_cpu_utilisation{{{CI}}}", "cpu")],
            0,
            8,
            unit="percentunit",
        ),
        panel(
            4,
            "DB pool in use / max",
            [(f"db_pool_connections_in_use{{{CI}}} / db_pool_connections_max{{{CI}}}", "pool")],
            12,
            8,
            unit="percentunit",
        ),
        panel(5, "Logs", [(f"{{{CI}}}", "")], 0, 16, w=24, h=10, kind="logs", ds=LOKI),
    ],
    [
        var("tenant", "label_values(node_cpu_utilisation, tenant_id)"),
        var("ci_id", 'label_values(node_cpu_utilisation{tenant_id="$tenant"}, ci_id)'),
    ],
)

SVC = 'service=~"$service"'
platform = dash(
    "aiops-platform",
    "AIOps / Platform services (RED)",
    [
        panel(
            1,
            "Messages handled /s",
            [
                (
                    f"sum by (service, outcome) (rate(aiops_messages_total{{{SVC}}}[1m]))",
                    "{{service}} {{outcome}}",
                )
            ],
            0,
            0,
        ),
        panel(
            2,
            "Handler p95 latency",
            [
                (
                    f"histogram_quantile(0.95, sum by (le, service) (rate(aiops_handler_duration_seconds_bucket{{{SVC}}}[5m])))",
                    "{{service}}",
                )
            ],
            12,
            0,
            unit="s",
        ),
        panel(
            3,
            "Signals / candidates per minute",
            [
                (
                    "sum by (detector) (rate(aiops_signals_emitted_total[5m])) * 60",
                    "signals {{detector}}",
                ),
                (
                    "sum by (kind) (rate(aiops_candidates_emitted_total[5m])) * 60",
                    "candidates {{kind}}",
                ),
                ("sum(rate(aiops_signals_suppressed_total[5m])) * 60", "suppressed"),
            ],
            0,
            8,
        ),
        panel(
            4,
            "Verdicts by status",
            [("sum by (status) (rate(aiops_verdicts_total[5m])) * 60", "{{status}}")],
            12,
            8,
        ),
        panel(
            5,
            "Candidate → verdict p95",
            [
                (
                    "histogram_quantile(0.95, sum by (le) (rate(aiops_verdict_latency_seconds_bucket[10m])))",
                    "p95",
                )
            ],
            0,
            16,
            unit="s",
        ),
        panel(
            6,
            "Deliveries & outbox",
            [
                (
                    "sum by (channel, outcome) (rate(aiops_router_delivered_total[5m])) * 60",
                    "{{channel}} {{outcome}}",
                ),
                ("aiops_router_outbox_pending", "pending"),
            ],
            12,
            16,
        ),
        panel(
            7,
            "LLM tokens today / in-flight",
            [
                ("aiops_agent_tokens_used_today", "tokens {{tenant}}"),
                ("aiops_agent_inflight", "inflight {{tenant}}"),
            ],
            0,
            24,
        ),
        panel(
            8,
            "Detector lag & scoring interval",
            [
                ("aiops_detector_event_lag_seconds", "lag"),
                ("aiops_detector_score_interval_seconds", "interval"),
            ],
            12,
            24,
            unit="s",
        ),
    ],
    [
        {
            "name": "service",
            "type": "custom",
            "query": "ingest-gateway,detector-workers,correlator,agent-gateway,router,feedback-service",
            "includeAll": True,
            "multi": True,
            "current": {"text": "All", "value": "$__all"},
        }
    ],
)

kpis = dash(
    "aiops-kpis",
    "AIOps / Prediction quality (KPIs)",
    [
        panel(
            1,
            "Precision by failure type",
            [("aiops_kpi_precision", "{{tenant}} {{failure_type}}")],
            0,
            0,
            unit="percentunit",
        ),
        panel(
            2,
            "Recall by failure type",
            [("aiops_kpi_recall", "{{tenant}} {{failure_type}}")],
            12,
            0,
            unit="percentunit",
        ),
        panel(
            3,
            "Median lead time (minutes)",
            [("aiops_kpi_median_lead_time_minutes", "{{tenant}} {{failure_type}}")],
            0,
            8,
        ),
        panel(
            4,
            "Labelled outcomes",
            [("aiops_kpi_labelled_total", "{{failure_type}} {{outcome}}")],
            12,
            8,
            kind="bargauge",
        ),
    ],
    [],
)

for d in (ci_overview, platform, kpis):
    (OUT / f"{d['uid']}.json").write_text(json.dumps(d, indent=2) + "\n")
print("ok")
