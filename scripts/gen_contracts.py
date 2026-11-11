"""Generate contracts/: JSON Schemas (from Pydantic), AsyncAPI 3 and OpenAPI 3.1 specs.

uv run python scripts/gen_contracts.py           # write
uv run python scripts/gen_contracts.py --check   # CI: fail if committed files drift
"""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.ext.asyncio import create_async_engine

from aiops_common.bus import InMemoryBus
from aiops_common.contracts.registry import EVENT_TYPES, Topics
from aiops_common.contracts.schemas import generate_all

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "contracts"


def asyncapi() -> dict[str, Any]:
    producers = {
        Topics.METRICS: ["ingest-gateway"],
        Topics.LOGS: ["ingest-gateway"],
        Topics.CHANGES: ["change-collectors"],
        Topics.SIGNALS: ["detector-workers"],
        Topics.CANDIDATES: ["correlator"],
        Topics.VERDICTS: ["agent-gateway"],
        Topics.OUTBOX: ["router"],
        Topics.FEEDBACK: ["feedback-service"],
    }
    consumers = {
        Topics.METRICS: ["detector-workers"],
        Topics.LOGS: ["detector-workers"],
        Topics.CHANGES: ["correlator"],
        Topics.SIGNALS: ["correlator"],
        Topics.CANDIDATES: ["agent-gateway"],
        Topics.VERDICTS: ["router", "feedback-service"],
        Topics.OUTBOX: ["audit/analytics"],
        Topics.FEEDBACK: ["threshold-tuning"],
    }
    channels: dict[str, Any] = {}
    messages: dict[str, Any] = {}
    operations: dict[str, Any] = {}
    for et in EVENT_TYPES:
        cid = et.topic.replace(".", "_")
        mname = et.name.replace("-", "_")
        messages[mname] = {
            "name": et.ce_type,
            "contentType": "application/cloudevents+json",
            "headers": {"$ref": "./jsonschema/cloudevent/v1.json"},
            "payload": {"$ref": f"./jsonschema/{et.name}/v{et.version}.json"},
            "bindings": {
                "kafka": {"key": {"type": "string", "description": "partition key tenant_id:ci_id"}}
            },
        }
        channels[cid] = {
            "address": et.topic,
            "description": f"Produced by {', '.join(producers[et.topic])}; "
            f"consumed by {', '.join(consumers[et.topic])}. "
            f"Dead letters go to {Topics.dlq(et.topic)}.",
            "messages": {mname: {"$ref": f"#/components/messages/{mname}"}},
            "bindings": {
                "kafka": {
                    "topic": et.topic,
                    "partitions": 24,
                    "replicas": 3,
                    "topicConfiguration": {"cleanup.policy": ["delete"], "retention.ms": 604800000},
                }
            },
        }
        channels[f"{cid}_dlq"] = {
            "address": Topics.dlq(et.topic),
            "description": "Dead letters with x-error / x-attempts headers.",
            "messages": {mname: {"$ref": f"#/components/messages/{mname}"}},
        }
        operations[f"publish_{cid}"] = {"action": "send", "channel": {"$ref": f"#/channels/{cid}"}}
        operations[f"consume_{cid}"] = {
            "action": "receive",
            "channel": {"$ref": f"#/channels/{cid}"},
        }
    return {
        "asyncapi": "3.0.0",
        "info": {
            "title": "AIOps platform event bus",
            "version": "1.0.0",
            "description": "Every message is a CloudEvents 1.0 structured JSON envelope "
            "(tenantid + partitionkey extensions) whose data validates "
            "against the versioned JSON Schema. Schemas evolve backward-"
            "compatibly only; breaking changes get a new major version.",
        },
        "defaultContentType": "application/cloudevents+json",
        "servers": {
            "dev": {"host": "kafka:9092", "protocol": "kafka"},
            "prod": {
                "host": "kafka-bootstrap.aiops.svc:9093",
                "protocol": "kafka-secure",
                "security": [{"$ref": "#/components/securitySchemes/scram"}],
            },
        },
        "channels": channels,
        "operations": operations,
        "components": {"messages": messages, "securitySchemes": {"scram": {"type": "scramSha512"}}},
    }


def openapis() -> dict[str, dict[str, Any]]:
    from pydantic import SecretStr

    from control_plane.app import create_app as cp
    from control_plane.auth import Authenticator, AuthSettings
    from control_plane.remediation import DryRunExecutor
    from feedback_service.app import FeedbackService
    from feedback_service.app import create_app as fb
    from ingest_gateway.app import Ingest
    from ingest_gateway.app import create_app as ig

    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    return {
        "control-plane-api": cp(
            eng,
            Authenticator(AuthSettings(mode="dev", dev_secret=SecretStr("x" * 32)), "dev"),
            DryRunExecutor(),
            set(),
        ).openapi(),
        "feedback-service": fb(FeedbackService(eng, None, {})).openapi(),
        "ingest-gateway": ig(Ingest(InMemoryBus(), {})).openapi(),
    }


def render() -> dict[Path, str]:
    files: dict[Path, str] = {}
    for rel, doc in generate_all().items():
        files[OUT / "jsonschema" / rel] = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    files[OUT / "asyncapi.yaml"] = yaml.safe_dump(asyncapi(), sort_keys=False, width=100)
    for name, doc in openapis().items():
        files[OUT / "openapi" / f"{name}.json"] = json.dumps(doc, indent=2, sort_keys=True) + "\n"
    return files


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    drift = 0
    for path, text in render().items():
        if args.check:
            old = path.read_text() if path.exists() else ""
            if old != text:
                drift += 1
                sys.stdout.writelines(
                    difflib.unified_diff(
                        old.splitlines(True), text.splitlines(True), str(path), "generated", n=1
                    )
                )
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    if drift:
        print(f"\n{drift} contract file(s) out of date: run `make contracts`", file=sys.stderr)
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
