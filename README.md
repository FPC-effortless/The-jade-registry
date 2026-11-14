# The Jade Registry — v0.2

A runnable, human-supervised matchmaking engineering pilot: member portal, matchmaker workspace, API, migrations, and safety controls.

Canonical repository: https://github.com/FPC-effortless/The-jade-registry

**Not a live or production-approved service. Use synthetic data only.** This release is an incremental engineering delivery, not completion of the commissioned business.

## Quick start (Python 3.13)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# Put the generated value into JADE_REGISTRY_SECRET_KEY in .env.
python -m app.manage migrate
python -m app.manage create-staff --email concierge@example.test --role admin
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/**. Use this exact origin, not `localhost`, unless you also change `JADE_REGISTRY_ORIGIN`.

The staff command prompts for a password without echoing it. It refuses to overwrite or promote an existing account. Public registration only creates members.

On a **fresh development database**, `python -m app.manage seed-demo` creates three fictional members and a staff account. It prints a newly generated temporary password. Do not run the create-staff command before seed-demo: seeding refuses a nonempty users table.

## A complete test journey

1. Register two synthetic member accounts in separate browser sessions. Give them reciprocal country preferences, adult birth dates, and marriage intent. Enable discoverability and both consent choices.
2. Sign into a provisioned staff account. Record a manual review for each member with an internal case reference. Do not put identity documents or document numbers in that field.
3. In Matchmaking, select one eligible member and approve an introduction to the other. There is no public member directory.
4. Each member can accept or decline independently. Only two acceptances produce `mutual` status. Contact details are never automatically released.
5. Withdraw consent or block a member: active introductions are cancelled, decisions cleared, and profile cards redacted. Re-enabling consent does not resurrect old decisions.

## Delivered in v0.2

- Responsive, same-origin member and staff interfaces (plain HTML/CSS/JavaScript, served by FastAPI).
- Member registration, sign-in, profile editing, consent management, introductions, blocking and reporting.
- Staff review queue with evidence references, mutual-country eligibility filtering, introductions, safety-report triage, administrator audit view.
- Argon2id passwords; successful legacy PBKDF2 logins are upgraded automatically.
- Opaque server-side sessions, hashed token storage, logout/revocation, HTTP-only cookies, CSRF and origin checks.
- PostgreSQL-compatible SQLAlchemy models, two frozen Alembic revisions, CLI staff provisioning, health/readiness endpoints.
- Database-backed auth throttles, security headers, least-privilege public registration, request-validation redaction.
- Docker/Compose configuration and a CI workflow including optional live PostgreSQL concurrency tests.

**Matching is eligibility filtering, not AI compatibility prediction.** The present hard criteria are consent, age, active member status, manual review, discoverability, reciprocal country preference, and absence of blocking. More complete preference/values modeling is still required.

## Verification status

| Check | Result in this build environment |
|---|---|
| Original v0.1 regression suite | 5 passed before changes |
| v0.2 API, security, schema and migration tests | 59 passed |
| Live PostgreSQL tests | 3 skipped; no live server/driver available |
| PostgreSQL migration SQL generation | Passed; not a live database execution |
| JavaScript syntax (`node --check`) | Passed |
| Python bytecode compilation | Passed |
| Browser interaction / visual inspection | Blocked by browser administrator policy; not verified |
| Docker build / Compose startup | Not executed here |
| Public hosting | Not deployed |

Raw results are in `evidence/`. Do not interpret an unrun check as a pass.

```bash
python -m pytest -q
node --check app/static/app.js
# Optional PostgreSQL path, on a disposable database named *_test:
pip install -r requirements-postgres.txt
JADE_TEST_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST/jade_test' python -m pytest -q
```

The PostgreSQL fixture deletes tables in the supplied **disposable** test database. Never point it at customer data.

## Local PostgreSQL integration

Add a random URL-safe `POSTGRES_PASSWORD` to `.env`, then:

```bash
docker compose up --build -d
docker compose exec web python -m app.manage create-staff --email concierge@example.test --role admin
```

Compose binds the web service to loopback and does not publish the database port. It is a local integration configuration, not a complete production deployment. Production mode requires a PostgreSQL URL and an HTTPS origin, but those checks alone do not make this release ready for real customers.

## API and upgrade notes

The development OpenAPI contract is at `/openapi.json`. Interactive third-party-hosted documentation is disabled. Browser interfaces use cookies and CSRF headers; programmatic clients may use the opaque bearer token returned by login.

v0.1 signed tokens are intentionally invalidated. The original four tables and password digests can be retained; follow the guarded migration instructions in `docs/ENGINEERING.md` for existing unversioned databases. Do **not** blindly stamp an unknown schema.

Changes to API behavior: `/matches` returns only staff-approved introductions, not an unreviewed directory; `/staff/candidates` requires `member_id`; manual verification requires a review JSON body; profile edits and consent withdrawal cancel active introductions.

## Remaining launch blockers

Independent identity verification, email verification/recovery, staff MFA, richer reciprocal preferences, secure messaging, payments/refunds, concierge scheduling, family permissions, retention/deletion/export workflows, staff assignment boundaries, managed backups/restore drills, observability, load/concurrency validation, independent security/accessibility review, and client-approved operating/privacy policies remain outstanding. No real identity documents, payments, or external notifications are processed in this release.

See `docs/ENGINEERING.md` for boundaries, operations, data migration, and the next engineering sequence. This release adds no open-source license grant or client IP-transfer terms.
