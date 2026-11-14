"""Revocable sessions, audit trail, blocking, safety reports and auth throttles."""
from alembic import op
import sqlalchemy as sa
revision = "jade_0002"
down_revision = "jade_0001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("auth_sessions", sa.Column("token_hash", sa.String(64), primary_key=True),
                    sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("expires_at", sa.Integer(), nullable=False), sa.Column("revoked", sa.Boolean(), nullable=False))
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_table("audit_events", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("actor_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
                    sa.Column("action", sa.String(60), nullable=False), sa.Column("subject", sa.String(100), nullable=False),
                    sa.Column("details", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("member_blocks", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("blocker_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("blocked_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
                    sa.UniqueConstraint("blocker_id", "blocked_id", name="uq_block"))
    op.create_table("safety_reports", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("reporter_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("reported_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("category", sa.String(40), nullable=False), sa.Column("description", sa.Text(), nullable=False),
                    sa.Column("status", sa.String(20), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("auth_throttles", sa.Column("key", sa.String(64), primary_key=True),
                    sa.Column("window_start", sa.Integer(), nullable=False), sa.Column("count", sa.Integer(), nullable=False))


def downgrade():
    for table in ("auth_throttles", "safety_reports", "member_blocks", "audit_events"):
        op.drop_table(table)
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
