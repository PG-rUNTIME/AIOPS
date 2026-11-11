"""Runbook registry and retrieval (RAG).

Runbooks are Markdown files with YAML front matter in ``config/runbooks``:

    ---
    id: RB-DISK-001
    title: Filesystem filling up
    failure_types: [disk_full]
    ---

``KeywordRetriever`` ranks runbooks + past incidents by token overlap (no
infrastructure needed). ``PgVectorRetriever`` uses pgvector cosine distance
over embeddings from any OpenAI-compatible ``/embeddings`` endpoint.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx
import yaml


@dataclass(frozen=True)
class Runbook:
    id: str
    title: str
    failure_types: tuple[str, ...]
    body: str


@dataclass(frozen=True)
class PastIncident:
    ref: str  # e.g. INC0045211
    failure_type: str
    summary: str
    root_cause: str
    fix: str


def load_runbooks(directory: str | Path) -> dict[str, Runbook]:
    out: dict[str, Runbook] = {}
    for p in sorted(Path(directory).glob("*.md")):
        text = p.read_text()
        m = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
        if not m:
            continue
        meta = yaml.safe_load(m.group(1)) or {}
        rb = Runbook(
            str(meta["id"]),
            str(meta.get("title", p.stem)),
            tuple(meta.get("failure_types", [])),
            m.group(2).strip(),
        )
        out[rb.id] = rb
    return out


def load_past_incidents(path: str | Path | None) -> list[PastIncident]:
    if not path or not Path(path).exists():
        return []
    docs = yaml.safe_load(Path(path).read_text()) or []
    return [PastIncident(**d) for d in docs]


_TOK = re.compile(r"[a-z0-9_]{3,}")


def _toks(s: str) -> Counter[str]:
    return Counter(_TOK.findall(s.lower()))


def _cos(a: Counter[str], b: Counter[str]) -> float:
    common = set(a) & set(b)
    num = sum(a[t] * b[t] for t in common)
    den = math.sqrt(sum(v * v for v in a.values())) * math.sqrt(sum(v * v for v in b.values()))
    return num / den if den else 0.0


class Retriever(Protocol):
    async def runbooks_for(self, failure_type: str, text: str, k: int = 2) -> list[Runbook]: ...
    async def similar_incidents(
        self, failure_type: str, text: str, k: int = 3
    ) -> list[PastIncident]: ...


class KeywordRetriever:
    def __init__(self, runbooks: dict[str, Runbook], incidents: list[PastIncident]) -> None:
        self.runbooks = runbooks
        self.incidents = incidents

    async def runbooks_for(self, failure_type: str, text: str, k: int = 2) -> list[Runbook]:
        q = _toks(text + " " + failure_type)
        scored = sorted(
            self.runbooks.values(),
            key=lambda r: (failure_type in r.failure_types, _cos(q, _toks(r.title + r.body))),
            reverse=True,
        )
        return scored[:k]

    async def similar_incidents(
        self, failure_type: str, text: str, k: int = 3
    ) -> list[PastIncident]:
        q = _toks(text)
        pool = [i for i in self.incidents if i.failure_type == failure_type] or self.incidents
        return sorted(pool, key=lambda i: _cos(q, _toks(i.summary + i.root_cause)), reverse=True)[
            :k
        ]


class PgVectorRetriever:  # pragma: no cover - needs Postgres + pgvector + embeddings endpoint
    """SQL: ``SELECT ... ORDER BY embedding <=> :q LIMIT :k`` on tables
    ``rag_runbooks(id, title, failure_types text[], body, embedding vector)`` and
    ``rag_incidents(ref, failure_type, summary, root_cause, fix, embedding vector)``
    (created by deploy/compose/postgres/init/02-rag.sql)."""

    def __init__(self, dsn: str, embed_url: str, embed_model: str, api_key: str | None) -> None:
        self.dsn, self.embed_url, self.embed_model, self.api_key = (
            dsn,
            embed_url,
            embed_model,
            api_key,
        )

    async def _embed(self, text: str) -> list[float]:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{self.embed_url.rstrip('/')}/embeddings",
                headers=headers,
                json={"model": self.embed_model, "input": text},
            )
            r.raise_for_status()
            vec: list[float] = r.json()["data"][0]["embedding"]
            return vec

    async def _query(self, sql: str, text: str, k: int) -> list[dict[str, object]]:
        import asyncpg

        vec = "[" + ",".join(f"{x:.6f}" for x in await self._embed(text)) + "]"
        conn = await asyncpg.connect(self.dsn)
        try:
            rows = await conn.fetch(sql, vec, k)
            return [dict(r) for r in rows]
        finally:
            await conn.close()

    async def runbooks_for(self, failure_type: str, text: str, k: int = 2) -> list[Runbook]:
        rows = await self._query(
            "SELECT id, title, failure_types, body FROM rag_runbooks "
            "ORDER BY embedding <=> $1::vector LIMIT $2",
            f"{failure_type} {text}",
            k,
        )
        return [
            Runbook(
                str(r["id"]),
                str(r["title"]),
                tuple(r["failure_types"]),  # type: ignore[arg-type]
                str(r["body"]),
            )
            for r in rows
        ]

    async def similar_incidents(
        self, failure_type: str, text: str, k: int = 3
    ) -> list[PastIncident]:
        rows = await self._query(
            "SELECT ref, failure_type, summary, root_cause, fix FROM rag_incidents "
            "ORDER BY embedding <=> $1::vector LIMIT $2",
            text,
            k,
        )
        return [PastIncident(**{k2: str(v) for k2, v in r.items()}) for r in rows]
