"""Data-source connections (tenant-scoped, with row-level security on Postgres).

Revision ID: 0003
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from control_plane.db import Connection

revision = "0003"
down_revision = "0002"
T = "cp_connections"


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table(T):  # fresh install: 0001 already created it with its policy
        return
    Connection.__table__.create(bind)  # type: ignore[attr-defined]
    if bind.dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {T} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {T} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {T} "
            f"USING (tenant_id = current_setting('app.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )


def downgrade() -> None:
    Connection.__table__.drop(op.get_bind(), checkfirst=True)  # type: ignore[attr-defined]
