from io import StringIO
from alembic import command
from sqlalchemy import create_engine, inspect, text
from app.manage import migration_config
from app.models import Base


def test_upgrade_baseline_preserves_member_and_downgrade_roundtrip(tmp_path):
    url = "sqlite:///" + str(tmp_path / "migration.db")
    config = migration_config(url)
    command.upgrade(config, "jade_0001")
    engine = create_engine(url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (id,email,password_digest,role,active) VALUES (1,'legacy@example.test','legacy-test-only','member',1)"))
    command.upgrade(config, "head")
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT email FROM users WHERE id=1")) == "legacy@example.test"
        assert conn.scalar(text("SELECT version_num FROM alembic_version")) == "jade_0002"
    inspector = inspect(engine)
    for table in Base.metadata.sorted_tables:
        assert set(table.columns.keys()) == {c["name"] for c in inspector.get_columns(table.name)}
    command.downgrade(config, "jade_0001")
    assert "auth_sessions" not in inspect(engine).get_table_names()
    with engine.connect() as conn:
        assert conn.scalar(text("SELECT COUNT(*) FROM users")) == 1
    command.upgrade(config, "head")
    command.downgrade(config, "base")
    assert inspect(engine).get_table_names() == ["alembic_version"]
    engine.dispose()


def test_postgres_offline_migration_compiles():
    config = migration_config("postgresql+psycopg://offline@localhost/jade")
    output = StringIO()
    config.output_buffer = output
    command.upgrade(config, "head", sql=True)
    sql = output.getvalue()
    assert "CREATE TABLE users" in sql and "CREATE TABLE auth_sessions" in sql
    assert "uq_pair" in sql and "COMMIT" in sql
