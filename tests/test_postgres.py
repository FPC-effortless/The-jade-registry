"""Optional live PostgreSQL tests. Only use a disposable database named *_test."""
import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import MetaData
from sqlalchemy.engine import make_url
from app.api import create_app
from app.config import Settings
from app.manage import migration_config
from conftest import approve, introduce, member, staff

URL = os.getenv("JADE_TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not URL, reason="JADE_TEST_DATABASE_URL not configured; live PostgreSQL not executed")


@pytest.fixture
def pg_client():
    if not make_url(URL).database.endswith("_test"):
        raise RuntimeError("Refusing destructive setup: use a disposable PostgreSQL database ending in _test")
    app = create_app(Settings(URL, "postgres-test-only-" + "x" * 40, "test", "http://testserver"))
    # Explicitly disposable test database only. Never set this URL to customer data.
    meta = MetaData()
    meta.reflect(bind=app.state.engine)
    meta.drop_all(bind=app.state.engine)
    command.upgrade(migration_config(URL), "head")
    with TestClient(app) as client:
        yield client
    app.state.engine.dispose()


def pg_pair(client):
    a, ah = member(client)
    b, bh = member(client, "two@example.test", "JP", "SG")
    s, sh = staff(client)
    approve(client, a, sh)
    approve(client, b, sh)
    return a, ah, b, bh, s, sh


def test_postgres_migrations_and_mutual_introduction(pg_client):
    pair = pg_pair(pg_client)
    iid = introduce(pg_client, pair)
    for h in (pair[1], pair[3]):
        r = pg_client.post(f"/me/introductions/{iid}/decision", headers=h, json={"accept": True})
        assert r.status_code == 200
    assert r.json()["status"] == "mutual"
    assert pg_client.get("/health/ready").status_code == 200


def test_postgres_concurrent_acceptance_preserves_both_decisions(pg_client):
    pair = pg_pair(pg_client)
    iid = introduce(pg_client, pair)
    barrier = Barrier(2)
    def accept(headers):
        with TestClient(pg_client.app) as c:
            barrier.wait(timeout=10)
            return c.post(f"/me/introductions/{iid}/decision", headers=headers, json={"accept": True})
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(accept, (pair[1], pair[3])))
    assert all(r.status_code == 200 for r in results)
    assert pg_client.get("/me/introductions", headers=pair[1]).json()["introductions"][0]["status"] == "mutual"


def test_postgres_duplicate_creation_has_one_winner(pg_client):
    pair = pg_pair(pg_client)
    barrier = Barrier(2)
    def create(_):
        with TestClient(pg_client.app) as c:
            barrier.wait(timeout=10)
            return c.post("/staff/introductions", headers=pair[-1], json={"first_id": pair[0], "second_id": pair[2]}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(create, range(2)))
    assert sorted(statuses) == [201, 409]
