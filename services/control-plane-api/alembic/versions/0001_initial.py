"""Initial control-plane schema with Postgres row-level security.

Revision ID: 0001
"""

from __future__ import annotations

from alembic import op

from control_plane.db import TENANT_TABLES, Base

revision = "0001"
down_revision = None


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind)
    if bind.dialect.name != "postgresql":
        return
    for t in TENANT_TABLES:
        op.execute(f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {t} "
            f"USING (tenant_id = current_setting('app.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        )
    # Audit log is append-only for the application role.
    op.execute("REVOKE UPDATE, DELETE ON cp_audit_log FROM PUBLIC")


def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind())
