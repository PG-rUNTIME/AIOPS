"""Incident workflow activity (tenant-scoped, with row-level security on Postgres).

Revision ID: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

from control_plane.db import IncidentActivity

revision = "0004"
down_revision = "0003"
T = "cp_incident_activity"


def upgrade() -> None:
    bind = op.get_bind()
    if sa.inspect(bind).has_table(T):  # fresh install: 0001 already created it with its policy
        return
    IncidentActivity.__table__.create(bind)  # type: ignore[attr-defined]
    if bind.dialect.name == "postgresql":
        op.execute(f"ALTER TABLE {T} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {T} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {T} "
            f"USING (tenant_id = current_setting('app.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )
        op.execute(f"REVOKE UPDATE, DELETE ON {T} FROM PUBLIC")


def downgrade() -> None:
    IncidentActivity.__table__.drop(op.get_bind(), checkfirst=True)  # type: ignore[attr-defined]
