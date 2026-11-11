"""Remediation executors. Only allow-listed playbooks; nothing runs without approval.

``AnsibleRunnerExecutor`` uses the ``ansible-runner`` Python API
(``ansible_runner.run(private_data_dir=..., playbook=..., extravars=...)``) and
is only importable where the ``remediation`` extra is installed.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class ExecutionResult:
    ok: bool
    output: str


class Executor(Protocol):
    async def run(self, playbook: str, params: dict[str, Any]) -> ExecutionResult: ...


@dataclass
class DryRunExecutor:
    """Default in dev/tests: records what would have run."""

    runs: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    async def run(self, playbook: str, params: dict[str, Any]) -> ExecutionResult:
        self.runs.append((playbook, params))
        return ExecutionResult(True, f"dry-run: would run {playbook} with {sorted(params)}")


@dataclass
class AnsibleRunnerExecutor:  # pragma: no cover - needs ansible-runner + inventory
    private_data_dir: str

    async def run(self, playbook: str, params: dict[str, Any]) -> ExecutionResult:
        import ansible_runner

        r = await asyncio.to_thread(
            ansible_runner.run,
            private_data_dir=self.private_data_dir,
            playbook=playbook,
            extravars=params,
            quiet=True,
        )
        return ExecutionResult(r.status == "successful", f"status={r.status} rc={r.rc}")


def allowed_playbooks(directory: str | Path) -> set[str]:
    return {p.name for p in Path(directory).glob("*.yml")}
