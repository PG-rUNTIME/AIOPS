"""Initial schema.

Revision ID: 0001
"""

from __future__ import annotations

from alembic import op

from router.db import Base

revision = "0001"
down_revision = None


def upgrade() -> None:
    Base.metadata.create_all(op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(op.get_bind())
