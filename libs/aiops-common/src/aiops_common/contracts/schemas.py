"""Generate and validate against the versioned JSON Schemas in ``contracts/jsonschema``."""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from aiops_common.contracts.registry import BY_CE_TYPE, EVENT_TYPES, EventType

CLOUDEVENT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://schemas.aiops.local/cloudevent/v1.json",
    "title": "AIOps CloudEvent envelope (CloudEvents 1.0, structured JSON)",
    "type": "object",
    "required": [
        "specversion",
        "id",
        "source",
        "type",
        "time",
        "dataschema",
        "tenantid",
        "partitionkey",
        "data",
    ],
    "properties": {
        "specversion": {"const": "1.0"},
        "id": {"type": "string", "minLength": 1},
        "source": {"type": "string", "minLength": 1},
        "type": {"type": "string", "enum": sorted(BY_CE_TYPE)},
        "time": {"type": "string", "format": "date-time"},
        "datacontenttype": {"const": "application/json"},
        "dataschema": {"type": "string", "format": "uri"},
        "tenantid": {"type": "string", "minLength": 1},
        "partitionkey": {"type": "string", "pattern": "^[^:]+:.+$"},
        "traceparent": {"type": "string"},
        "data": {"type": "object"},
    },
}


def schema_for(et: EventType) -> dict[str, Any]:
    schema = et.model.model_json_schema(mode="serialization")
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": et.dataschema,
        "x-cloudevents-type": et.ce_type,
        "x-topic": et.topic,
        **schema,
    }


def generate_all() -> dict[str, dict[str, Any]]:
    """Map of relative path -> schema document."""
    out = {f"{et.name}/v{et.version}.json": schema_for(et) for et in EVENT_TYPES}
    out["cloudevent/v1.json"] = CLOUDEVENT_SCHEMA
    return out


def write_all(root: Path) -> list[Path]:
    written = []
    for rel, doc in generate_all().items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        written.append(p)
    return written


@cache
def _validator(ce_type: str) -> Draft202012Validator:
    return Draft202012Validator(schema_for(BY_CE_TYPE[ce_type]))


_ENVELOPE = Draft202012Validator(CLOUDEVENT_SCHEMA)


def validate_event(doc: dict[str, Any]) -> None:
    """Validate a CloudEvent dict (envelope + data) against the JSON Schemas.

    Raises ``jsonschema.ValidationError`` on the first problem.
    """
    _ENVELOPE.validate(doc)
    _validator(doc["type"]).validate(doc["data"])
