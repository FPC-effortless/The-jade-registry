from alembic import command
from fastapi.testclient import TestClient
import pytest
from app.api import create_app
from app.config import Settings
from app.manage import migration_config, provision_staff

PASSWORD = "synthetic-test-passphrase-832"


@pytest.fixture
def application(tmp_path):
    url = "sqlite:///" + str(tmp_path / "registry.db")
    command.upgrade(migration_config(url), "head")
    app = create_app(Settings(url, "t" * 48, "test", "http://testserver"))
    yield app
    app.state.engine.dispose()


@pytest.fixture
def client(application):
    with TestClient(application) as client:
        yield client


def account(client, email):
    r = client.post("/auth/register", json={"email": email, "password": PASSWORD})
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    client.cookies.clear()  # Model a different browser for each synthetic account.
    result = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert result.status_code == 200, result.text
    return uid, {"Authorization": "Bearer " + result.json()["access_token"]}


def member(client, email="one@example.test", country="SG", looking="JP"):
    uid, headers = account(client, email)
    r = client.put("/me/profile", headers=headers, json={"display_name": email.split("@")[0], "birth_date": "1993-06-02",
        "country": country, "looking_in": looking, "marriage_intent": True, "discoverable": True})
    assert r.status_code == 200, r.text
    assert client.put("/me/consent", headers=headers, json={"matchmaking": True, "profile_sharing": True}).status_code == 200
    return uid, headers


def staff(client, role="matchmaker", email="staff@example.test"):
    with client.app.state.session_factory() as db:
        uid = provision_staff(db, email, PASSWORD, role)
    client.cookies.clear()
    response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return uid, {"Authorization": "Bearer " + response.json()["access_token"]}


def approve(client, uid, headers, approved=True):
    return client.post(f"/staff/members/{uid}/verify", headers=headers,
                       json={"approved": approved, "evidence_reference": "SYNTHETIC-REVIEW-001"})


@pytest.fixture
def pair(client):
    a, ah = member(client)
    b, bh = member(client, "two@example.test", "JP", "SG")
    s, sh = staff(client)
    assert approve(client, a, sh).status_code == 200
    assert approve(client, b, sh).status_code == 200
    return a, ah, b, bh, s, sh


def introduce(client, pair):
    a, ah, b, bh, s, sh = pair
    response = client.post("/staff/introductions", headers=sh, json={"first_id": a, "second_id": b})
    assert response.status_code == 201, response.text
    return response.json()["id"]
