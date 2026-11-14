"""Frozen v0.1 domain schema. Do not import mutable application metadata here."""
from alembic import op
import sqlalchemy as sa
revision = "jade_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("users", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("email", sa.String(254), nullable=False), sa.Column("password_digest", sa.String(300), nullable=False),
                    sa.Column("role", sa.String(20), nullable=False), sa.Column("active", sa.Boolean(), nullable=False))
    op.create_index("ix_users_email", "users", ["email"], unique=True)
    op.create_table("profiles", sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), primary_key=True),
                    sa.Column("display_name", sa.String(90), nullable=False), sa.Column("birth_date", sa.Date(), nullable=False),
                    sa.Column("country", sa.String(2), nullable=False), sa.Column("looking_in", sa.String(2), nullable=False),
                    sa.Column("marriage_intent", sa.Boolean(), nullable=False), sa.Column("verified", sa.Boolean(), nullable=False),
                    sa.Column("discoverable", sa.Boolean(), nullable=False))
    op.create_table("consents", sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), primary_key=True),
                    sa.Column("matchmaking", sa.Boolean(), nullable=False), sa.Column("profile_sharing", sa.Boolean(), nullable=False),
                    sa.Column("version", sa.String(20), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))
    op.create_table("introductions", sa.Column("id", sa.Integer(), primary_key=True),
                    sa.Column("first_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("second_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
                    sa.Column("status", sa.String(20), nullable=False), sa.Column("first_accepts", sa.Boolean(), nullable=True),
                    sa.Column("second_accepts", sa.Boolean(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
                    sa.UniqueConstraint("first_id", "second_id", name="uq_pair"))


def downgrade():
    for table in ("introductions", "consents", "profiles"):
        op.drop_table(table)
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
