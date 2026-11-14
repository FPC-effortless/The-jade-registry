import hashlib
import json
import time
from datetime import date
import pytest
from sqlalchemy import select
from app.config import Settings
from app.domain import eligible
from app.manage import provision_staff
from app.models import AuditEvent, AuthSession, Consent, Introduction, Profile, User
from app.security import check_password, hash_password
from conftest import PASSWORD, account, approve, introduce, member, staff


@pytest.mark.parametrize("path", ["/me", "/matches", "/me/introductions", "/staff/review-queue", "/staff/candidates?member_id=1", "/staff/introductions", "/staff/reports", "/staff/audit"])
def test_anonymous_denied(client, path):
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("path", ["/staff/review-queue", "/staff/candidates?member_id=1", "/staff/introductions", "/staff/reports", "/staff/audit"])
def test_member_cannot_access_staff(client, path):
    uid, headers = account(client, "member@example.test")
    assert client.get(path, headers=headers).status_code == 403


def test_self_verification_and_public_role_injection_denied(client):
    response = client.post("/auth/register", json={"email": "attacker@example.test", "password": PASSWORD, "role": "admin"})
    assert response.status_code == 422
    uid, headers = member(client)
    assert approve(client, uid, headers).status_code == 403
    assert client.get("/me", headers=headers).json()["role"] == "member"


@pytest.mark.parametrize("birth", ["2020-01-01", "2999-01-01", "1800-01-01"])
def test_invalid_age_rejected(client, birth):
    uid, headers = account(client, "birth@example.test")
    r = client.put("/me/profile", headers=headers, json={"display_name": "Example", "birth_date": birth, "country": "SG", "looking_in": "JP"})
    assert r.status_code == 422
    assert client.get("/me", headers=headers).json()["profile"] is None


def test_exact_eighteenth_birthday_is_valid(client):
    today = date.today()
    birth = today.replace(year=today.year - 18)
    uid, headers = account(client, "adult@example.test")
    assert client.put("/me/profile", headers=headers, json={"display_name": "Adult", "birth_date": str(birth), "country": "SG", "looking_in": "JP"}).status_code == 200


@pytest.mark.parametrize("email", ["missing-at", "x@", "x@y", "space @example.test"])
def test_email_validation(client, email):
    r = client.post("/auth/register", json={"email": email, "password": PASSWORD})
    assert r.status_code == 422
    assert PASSWORD not in r.text


def test_duplicate_email_casefold_and_no_password_echo(client):
    account(client, "EXAMPLE@example.test")
    assert client.post("/auth/register", json={"email": "example@example.test", "password": PASSWORD}).status_code == 409
    r = client.post("/auth/register", json={"email": "second@example.test", "password": "short"})
    assert r.status_code == 422
    assert '"input"' not in r.text


def test_consent_defaults_and_no_unreviewed_directory(client, pair):
    a, ah, b, bh, s, sh = pair
    assert client.get("/matches", headers=ah).json() == {"candidates": []}
    candidates = client.get(f"/staff/candidates?member_id={a}", headers=sh).json()["candidates"]
    assert [c["id"] for c in candidates] == [b]
    assert "email" not in candidates[0] and "birth_date" not in candidates[0]
    fresh, fh = account(client, "fresh@example.test")
    assert client.get("/me", headers=fh).json()["consent"] is None
    assert client.get("/matches", headers=fh).status_code == 403


def test_supervised_mutual_introduction_and_no_contacts(client, pair):
    a, ah, b, bh, s, sh = pair
    iid = introduce(client, pair)
    matches = client.get("/matches", headers=ah).json()["candidates"]
    assert [c["id"] for c in matches] == [b]
    r = client.post(f"/me/introductions/{iid}/decision", headers=ah, json={"accept": True})
    assert r.json()["status"] == "pending"
    r = client.post(f"/me/introductions/{iid}/decision", headers=bh, json={"accept": True})
    assert r.json()["status"] == "mutual"
    data = client.get("/me/introductions", headers=ah).json()
    assert data["introductions"][0]["partner"]["id"] == b
    assert "email" not in json.dumps(data) and "birth_date" not in json.dumps(data)
    assert client.post("/staff/introductions", headers=sh, json={"first_id": b, "second_id": a}).status_code == 409
    assert client.post(f"/me/introductions/{iid}/decision", headers=ah, json={"accept": True}).status_code == 409


def test_outsider_cannot_read_or_decide_introduction(client, pair):
    iid = introduce(client, pair)
    outsider, oh = member(client, "outsider@example.test")
    assert client.get("/me/introductions", headers=oh).json()["introductions"] == []
    assert client.post(f"/me/introductions/{iid}/decision", headers=oh, json={"accept": True}).status_code == 404


@pytest.mark.parametrize("become_mutual", [False, True])
def test_withdrawal_cancels_redacts_and_does_not_revive(client, pair, become_mutual):
    a, ah, b, bh, s, sh = pair
    iid = introduce(client, pair)
    client.post(f"/me/introductions/{iid}/decision", headers=ah, json={"accept": True})
    if become_mutual:
        client.post(f"/me/introductions/{iid}/decision", headers=bh, json={"accept": True})
    assert client.put("/me/consent", headers=bh, json={"matchmaking": True, "profile_sharing": False}).status_code == 200
    intro = client.get("/me/introductions", headers=ah).json()["introductions"][0]
    assert intro["status"] == "cancelled" and intro["partner"] is None and intro["my_decision"] is None
    assert client.get("/matches", headers=bh).status_code == 403
    client.put("/me/consent", headers=bh, json={"matchmaking": True, "profile_sharing": True})
    assert client.get("/matches", headers=ah).json()["candidates"] == []
    assert client.post(f"/me/introductions/{iid}/decision", headers=bh, json={"accept": True}).status_code == 409


def test_profile_edit_revokes_review_and_cancels(client, pair):
    a, ah, b, bh, s, sh = pair
    iid = introduce(client, pair)
    p = client.get("/me", headers=ah).json()["profile"]
    p.pop("verified")
    p["display_name"] = "Changed"
    assert client.put("/me/profile", headers=ah, json=p).status_code == 200
    me = client.get("/me", headers=ah).json()
    assert not me["profile"]["verified"] and not me["matching_enabled"]
    assert client.get("/me/introductions", headers=bh).json()["introductions"][0]["partner"] is None


def test_disabled_user_never_matches_or_logs_in(client, pair):
    a, ah, b, bh, s, sh = pair
    iid = introduce(client, pair)
    with client.app.state.session_factory() as db:
        db.get(User, b).active = False
        db.commit()
        assert not eligible(db, b)
    assert client.get("/me", headers=bh).status_code == 401
    assert client.post("/auth/login", json={"email": "two@example.test", "password": PASSWORD}).status_code == 401
    assert client.get("/matches", headers=ah).json()["candidates"] == []
    assert client.post(f"/me/introductions/{iid}/decision", headers=ah, json={"accept": True}).status_code == 403


def test_block_cancels_and_prevents_rematching(client, pair):
    a, ah, b, bh, s, sh = pair
    iid = introduce(client, pair)
    assert client.post(f"/me/blocks/{b}", headers=ah).status_code == 200
    assert client.post(f"/me/blocks/{b}", headers=ah).status_code == 200
    assert client.get("/matches", headers=ah).json()["candidates"] == []
    assert client.get(f"/staff/candidates?member_id={a}", headers=sh).json()["candidates"] == []
    assert client.get("/me/introductions", headers=bh).json()["introductions"][0]["status"] == "cancelled"
    assert client.post("/staff/introductions", headers=sh, json={"first_id": a, "second_id": b}).status_code == 403


def test_reports_private_and_audited_even_after_withdrawal(client, pair):
    a, ah, b, bh, s, sh = pair
    introduce(client, pair)
    client.put("/me/consent", headers=bh, json={"matchmaking": False, "profile_sharing": False})
    r = client.post("/me/reports", headers=ah, json={"member_id": b, "category": "other", "description": "Synthetic concern for a test case."})
    assert r.status_code == 201
    report_id = r.json()["id"]
    assert client.get("/staff/reports", headers=bh).status_code == 403
    reports = client.get("/staff/reports", headers=sh).json()["reports"]
    assert reports[0]["id"] == report_id
    assert client.post(f"/staff/reports/{report_id}/status", headers=sh, json={"status": "reviewing"}).json()["status"] == "reviewing"
    with client.app.state.session_factory() as db:
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "safety.queue_accessed"))


def test_unintroduced_reports_and_blocks_denied(client, pair):
    a, ah, b, bh, s, sh = pair
    assert client.post(f"/me/blocks/{b}", headers=ah).status_code == 404
    assert client.post("/me/reports", headers=ah, json={"member_id": b, "category": "fraud", "description": "Synthetic concern only."}).status_code == 404


def test_review_requires_consent_reference_and_can_revoke(client, pair):
    a, ah, b, bh, s, sh = pair
    iid = introduce(client, pair)
    assert client.post(f"/staff/members/{a}/verify", headers=sh).status_code == 422
    result = approve(client, a, sh, False)
    assert result.json()["identity_provider_verified"] is False
    assert not client.get("/me", headers=ah).json()["matching_enabled"]
    assert client.get("/me/introductions", headers=bh).json()["introductions"][0]["status"] == "cancelled"
    client.put("/me/consent", headers=ah, json={"matchmaking": False, "profile_sharing": False})
    assert approve(client, a, sh).status_code == 404


def test_decline_terminal_and_no_same_person_intro(client, pair):
    a, ah, b, bh, s, sh = pair
    assert client.post("/staff/introductions", headers=sh, json={"first_id": a, "second_id": a}).status_code == 422
    iid = introduce(client, pair)
    assert client.post(f"/me/introductions/{iid}/decision", headers=ah, json={"accept": False}).json()["status"] == "declined"
    assert client.post(f"/me/introductions/{iid}/decision", headers=bh, json={"accept": True}).status_code == 409


def test_mutual_country_preferences_required(client):
    a, ah = member(client, "a@example.test", "SG", "JP")
    b, bh = member(client, "b@example.test", "JP", "IN")
    s, sh = staff(client)
    approve(client, a, sh)
    approve(client, b, sh)
    assert client.get(f"/staff/candidates?member_id={a}", headers=sh).json()["candidates"] == []
    assert client.post("/staff/introductions", headers=sh, json={"first_id": a, "second_id": b}).status_code == 403


def test_cookie_csrf_origin_logout_and_no_raw_session_storage(client):
    uid, headers = member(client)
    token = headers["Authorization"].split()[1]
    csrf = client.get("/auth/session").json()["csrf_token"]
    assert client.put("/me/consent", json={"matchmaking": False, "profile_sharing": False}).status_code == 403
    assert client.put("/me/consent", headers={"X-CSRF-Token": csrf, "Origin": "https://bad.example"}, json={"matchmaking": False, "profile_sharing": False}).status_code == 403
    with client.app.state.session_factory() as db:
        session = db.scalar(select(AuthSession).where(AuthSession.user_id == uid))
        assert session.token_hash != token and len(session.token_hash) == 64
    assert client.post("/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 200
    assert client.get("/me", headers=headers).status_code == 401
    assert client.get("/me").status_code == 401


def test_cookie_flags_and_rotation(client):
    uid, headers = account(client, "cookies@example.test")
    r = client.post("/auth/login", json={"email": "cookies@example.test", "password": PASSWORD})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert client.get("/me", headers=headers).status_code == 401
    assert client.get("/me").status_code == 200


def test_session_expiry_and_logout_all(client):
    uid, headers = account(client, "expiry@example.test")
    with client.app.state.session_factory() as db:
        s = db.scalar(select(AuthSession).where(AuthSession.user_id == uid))
        s.expires_at = int(time.time()) - 1
        db.commit()
    assert client.get("/me", headers=headers).status_code == 401
    r = client.post("/auth/login", json={"email": "expiry@example.test", "password": PASSWORD})
    headers = {"Authorization": "Bearer " + r.json()["access_token"]}
    assert client.post("/auth/logout-all", headers=headers).status_code == 200
    assert client.get("/me", headers=headers).status_code == 401


def test_rate_limit_persists_across_clients(client):
    for _ in range(10):
        assert client.post("/auth/login", json={"email": "notfound@example.test", "password": PASSWORD}).status_code == 401
    from fastapi.testclient import TestClient
    with TestClient(client.app) as other:
        response = other.post("/auth/login", json={"email": "notfound@example.test", "password": PASSWORD})
        assert response.status_code == 429 and "retry-after" in response.headers


def test_login_cross_origin_and_short_password_validation_redacted(client):
    assert client.post("/auth/login", headers={"Origin": "https://wrong.example"}, json={"email": "x@example.test", "password": PASSWORD}).status_code == 403
    r = client.post("/auth/login", json={"email": "x@example.test", "password": "leakme"})
    assert r.status_code == 422 and "leakme" not in r.text


def test_legacy_password_upgrades(client):
    salt = bytes(range(16))
    legacy = salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, 260000).hex()
    with client.app.state.session_factory() as db:
        db.add(User(email="legacy@example.test", password_digest=legacy, role="member", active=True))
        db.commit()
    assert client.post("/auth/login", json={"email": "legacy@example.test", "password": PASSWORD}).status_code == 200
    with client.app.state.session_factory() as db:
        u = db.scalar(select(User).where(User.email == "legacy@example.test"))
        assert u.password_digest.startswith("$argon2id$") and check_password(PASSWORD, u.password_digest)


def test_audit_admin_only_without_secrets(client, pair):
    a, ah, b, bh, s, sh = pair
    introduce(client, pair)
    assert client.get("/staff/audit", headers=sh).status_code == 403
    uid, admin_headers = staff(client, "admin", "admin@example.test")
    r = client.get("/staff/audit", headers=admin_headers)
    assert r.status_code == 200
    assert "introduction.created" in r.text and "profile.reviewed" in r.text
    assert PASSWORD not in r.text and ah["Authorization"].split()[1] not in r.text and "one@example.test" not in r.text


def test_staff_provisioning_refuses_overwrite_or_promotion(client):
    uid, headers = account(client, "existing@example.test")
    with client.app.state.session_factory() as db:
        with pytest.raises(ValueError, match="will not promote"):
            provision_staff(db, "existing@example.test", PASSWORD, "admin")
    assert client.get("/me", headers=headers).json()["role"] == "member"


@pytest.mark.parametrize("key", ["", "short", "development-only-replace-before-production", "REPLACE_WITH_RANDOM_SECRET" * 2])
def test_missing_or_placeholder_secret_rejected(key):
    with pytest.raises(ValueError):
        Settings("sqlite://", key)


def test_production_config_fails_closed():
    with pytest.raises(ValueError, match="PostgreSQL"):
        Settings("sqlite://", "x" * 48, "production", "https://jade.example")
    with pytest.raises(ValueError, match="HTTPS"):
        Settings("postgresql+psycopg://user:pass@localhost/jade", "x" * 48, "production", "http://jade.example")
    assert Settings("postgresql+psycopg://user:pass@localhost/jade", "x" * 48, "production", "https://jade.example").secure_cookies


@pytest.mark.parametrize("path", ["/", "/member", "/staff", "/static/styles.css", "/static/app.js", "/openapi.json"])
def test_static_routes_security_headers_and_no_placeholder_old_brand(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["cache-control"] == "no-store"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert "cadenza" not in r.text.lower()


def test_health_readiness_and_pagination_bounds(client, pair):
    assert client.get("/health/ready").json()["schema"] == "jade_0002"
    assert client.get("/health").json()["version"] == "0.2.0"
    assert client.get("/staff/review-queue?limit=10001", headers=pair[-1]).status_code == 422


def test_hostile_profile_is_data_not_html(client):
    uid, headers = member(client)
    p = client.get("/me", headers=headers).json()["profile"]
    p.pop("verified")
    p["display_name"] = "<img src=x onerror=alert(1)>"
    assert client.put("/me/profile", headers=headers, json=p).status_code == 200
    assert client.get("/me", headers=headers).json()["profile"]["display_name"] == p["display_name"]
    js = client.get("/static/app.js").text
    assert "innerHTML" not in js and "localStorage" not in js and "sessionStorage" not in js
