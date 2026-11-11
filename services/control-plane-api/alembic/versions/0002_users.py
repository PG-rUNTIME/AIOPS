"""Local console users.

Revision ID: 0002
"""

from __future__ import annotations

from alembic import op

from control_plane.db import User

revision = "0002"
down_revision = "0001"


def upgrade() -> None:
    User.__table__.create(op.get_bind(), checkfirst=True)  # type: ignore[attr-defined]


def downgrade() -> None:
    User.__table__.drop(op.get_bind(), checkfirst=True)  # type: ignore[attr-defined]
