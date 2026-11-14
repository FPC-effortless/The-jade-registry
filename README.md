# The Jade Registry — Engineering Foundation v0.1

**The Jade Registry** is a premium, marriage-focused matchmaking service (previously called Cadenza).

This repository is the canonical codebase: https://github.com/FPC-effortless/The-jade-registry

This is an initial runnable **FastAPI backend vertical slice**, not a production matchmaking application.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export JADE_REGISTRY_SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
python -m app.init_db
uvicorn app.main:app --reload
```

API documentation: http://localhost:8000/docs

Tests: `pytest -q`

## Routes

- `POST /auth/register`, `POST /auth/login`
- `PUT /me/profile`, `PUT /me/consent`, `GET /me`
- `GET /matches`, `GET /me/introductions`, `POST /me/introductions/{id}/decision`
- `GET /staff/candidates`, `POST /staff/members/{id}/verify`, `POST /staff/introductions`

## Requirements and safety

Enrollment is for adults only. Member profiles must be opted into matching and sharing; matching requires manual verification; staff review introductions and both members must accept. All editing of a profile revokes verification.

**Not production-ready:** manual verification is not independent identity verification. Staff roles require secure provisioning. There is no email verification, MFA, rate limiting, audit logging, data retention workflow, full abuse management, PCI-compliant billing integration, or production migration system. SQLite is strictly for local development. Do not use real customer information.

## Delivery sequence

1. PostgreSQL and Alembic, audit logs, CI, harden staff provisioning and auth.
2. Verification-provider integration, document handling, abuse reporting and safety workflows.
3. Member questionnaire, mutual deal-breakers and measured ranking.
4. Member portal and matchmaker dashboard.
5. Private introductions, mutual consent, internal messaging.
6. Commerce, concierge, locale support and privacy-preserving analytics.
7. Independent security, privacy and operational readiness review.
