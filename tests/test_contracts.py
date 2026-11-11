"""Contract tests: committed schemas match the models, and evolution stays backward compatible."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from aiops_common.contracts.registry import EVENT_TYPES
from aiops_common.contracts.schemas import generate_all

ROOT = Path(__file__).resolve().parents[1]


def test_committed_schemas_are_up_to_date() -> None:
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_contracts.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stdout[-3000:]


def test_v1_required_fields_are_frozen() -> None:
    """A v1 schema may only add optional fields; required sets must never grow."""
    frozen = json.loads((ROOT / "contracts" / "required-fields.v1.json").read_text())
    docs = generate_all()
    for et in EVENT_TYPES:
        required = set(docs[f"{et.name}/v1.json"].get("required", []))
        assert required <= set(frozen[et.name]), (et.name, required - set(frozen[et.name]))
        assert set(frozen[et.name]) <= required, f"{et.name}: required field removed (breaking)"
