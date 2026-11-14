# Engineering handover — 14 November 2026

## Architecture decision

Keep the initial deployable unit small: FastAPI serves a same-origin browser application and a JSON API, with SQLAlchemy storage and Alembic migrations. The first functional interfaces use HTML/CSS/JavaScript rather than introducing a second Node/Next.js deployment now. This is an explicit implementation choice for the pilot, not a claim that the originally proposed Next.js architecture was delivered. The API boundary supports a later replacement frontend.

`config.py` validates environment settings. `database.py` creates connections and enables SQLite foreign keys. `models.py` contains nine tables. `security.py` owns password and token primitives. `domain.py` centralizes eligibility and consent invariants. `api.py` enforces role, resource and session boundaries. `manage.py` is an operator-only CLI. `static/` contains the member and matchmaker experiences. `migrations/` freezes schema revisions without importing mutable model metadata into revision scripts.

## Data and access boundaries

- Users contain login identifiers, password digests, role and active status. Public input rejects unknown fields such as `role` and `active`.
- Profiles contain a display name, birth date, residence and preferred partner country, marriage intention, discoverability and manual review flag.
- Consent records separate matchmaking and profile sharing. Every update produces an audit event with consent version and flags.
- Introductions have a unique normalized pair, independent decisions, and pending/mutual/declined/cancelled status. Closed pairs cannot be silently recreated or reopened.
- Auth sessions store an HMAC digest of an unpredictable token, expiry and revocation, never the raw token. Changing the application secret invalidates all sessions.
- Blocks suppress the pair in both directions. Reports are restricted to previously introduced members; reporting is still possible after consent withdrawal, using a durable member ID without recovering the private profile.
- Audit events capture actor, action, subject and limited metadata. Passwords, sessions, date of birth and report descriptions are not copied into audit details. Review references must not contain identity-document content.
- Auth throttles use keyed digests of account/IP scopes. A 15-minute fixed window is enforced in the database, not per worker memory.

Staff access is role-based, not yet limited to assigned client portfolios. All matchmaker/admin accounts can view the consenting review queue and safety reports. Administrator-only audit access is narrower. A dedicated safeguarding role and assignment-level permissions are launch requirements.

## Session and browser behavior

Sessions expire after eight hours by default (configurable from 5 minutes to 24 hours). Logout revokes the current session; `/auth/logout-all` revokes all of the member's sessions. Successful sign-in rotates the current browser session. Existing v0.1 signed tokens are not accepted.

Browser credentials use an HTTP-only, SameSite=Strict cookie; HTTPS/production sets Secure. Unsafe cookie-authenticated requests require a session-bound CSRF header. Unsafe requests carrying a foreign Origin or cross-site Fetch Metadata are rejected, including login. No credential is saved in localStorage or sessionStorage. Native bearer clients do not require cookie CSRF headers.

The UI inserts untrusted text through `textContent`; there is no dynamic HTML interpolation. CSP limits scripts/styles/connections to the same origin. Static responses and personalized responses use no-store. The public `/member` and `/staff` pages are only empty shells; data endpoints enforce the role boundary.

Remaining auth requirements: email ownership checks, password recovery, staff MFA, reauthentication for privileged operations, reviewed password policy, session management UI, adaptive anti-abuse controls, idle-session limits, complete brute-force/DoS analysis, and dependency vulnerability review. Current auth throttles can be used to cause temporary denial of sign-in; mitigation must be evaluated before launch.

## Consent and concurrency semantics

An eligible member must be active, have member role, be 18–120 years old at query time, have marriage intent, be manually reviewed and discoverable, and grant both current consents. Reciprocal country preferences and absence of either-direction blocks are checked for each proposed introduction.

Members never browse unapproved candidate profiles. An introduction card shows only display name, age, residence country and the manual-review label. No email, full date of birth, contact details or evidence reference is released. Read paths recheck current eligibility.

Profile edits reset manual review and cancel active introductions. Turning either consent off, revoking review or blocking a counterpart cancels pending/mutual introductions and clears stored decisions. Re-enabling permission does not reactivate them. Declines are terminal. Reporting is distinct from blocking.

Mutations lock member rows in ascending ID order before introduction decisions or writes. Decision rows are locked and refreshed; the pair constraint handles duplicate creation. These PostgreSQL concurrency properties have test cases but were **not executed against a live PostgreSQL server in this build environment**. SQLite is only a local development substitute and does not establish PostgreSQL behavior. Concurrent deactivation, consent and decisions require further live stress tests.

## Database migration and legacy data

Fresh databases:

```bash
python -m app.manage migrate
# or: alembic upgrade head
```

Revision `jade_0001` recreates the original users/profiles/consents/introductions schema. `jade_0002` adds sessions, audit, blocks, reports and throttles. Tests verify baseline member data survives upgrade, downgrade to the baseline, and re-upgrade. Downgrading removes operational/audit/session data; it is **not** a data-preserving production rollback strategy.

Existing unversioned v0.1 databases must not run a fresh create-table migration blindly. An authorized operator must:

1. Stop all writers, make an encrypted backup and demonstrate a restore into an isolated database.
2. Compare the actual schema, constraints and indexes with `0001_v01_baseline.py`. Check for duplicate pairs/emails, orphan foreign keys, inappropriate staff roles and invalid adult profiles. Resolve differences in an explicit migration; do not guess.
3. Only after that comparison, on a tested copy, run `alembic stamp jade_0001` and then `alembic upgrade head`.
4. Verify row counts, sample profiles and consent flags; test existing PBKDF2 sign-in (which upgrades the digest), and require every existing user to sign in again.
5. Approve a controlled cutover and a backup-based rollback. Do not run SQLite and PostgreSQL as independently writable sources.

A SQLite-to-PostgreSQL data-transfer job has **not** been implemented. Alembic schema support is not data migration between engines. An import must preserve IDs, reconcile sequences, verify constraints and compare exports before cutover.

## Operations and deployment

No service has been provisioned or publicly deployed. No external subscription or API purchase was made. Docker/Compose is supplied but was not run here. Image tags and direct package pins are not a complete supply-chain lock; pin image/action digests and generate a vulnerability-checked dependency lock before production.

`/health` checks process availability. `/health/ready` checks that the database reports the expected Alembic revision. Neither proves end-to-end health or a successful backup.

Production needs TLS termination with validated forwarded-header trust, an explicit hostname allowlist, managed secrets, encrypted storage, a separate least-privileged database application role and migration role, backup retention and restore drills, resource limits, monitoring, private document storage and restricted operator access. Request Content-Length is checked in the API, but full streamed-body limits/timeouts must be enforced at ingress. Do not enable proxy-header trust for arbitrary sources.

Use `python -m app.manage prune-auth` for expired session and old throttle records. Schedule it in the deployment platform after operational ownership is assigned. Audit/report retention is intentionally not silently purged: an approved retention and subject-rights process is still required.

No identity documents are uploaded. The review endpoint's `identity_provider_verified` field is always false. Billing, messaging, outbound notifications, scheduling and family workspace are not connected. Real-time updates are not implemented; workspace refresh reloads state. Queues have bounded backend pagination; this UI currently displays the first 50 records without a next-page control.

## Verification evidence and limitations

`evidence/pytest.txt` and `pytest.xml` record 59 passing local checks and 3 skipped live PostgreSQL checks. `evidence/browser-results.json` records the actual browser-policy failure, not a successful UI test. JavaScript syntax and HTTP route tests passed, but layout, keyboard/screen-reader accessibility and browser interaction remain unverified here.

The supplied GitHub workflow is intended to run the SQLite suite and three live PostgreSQL tests in an isolated service. A committed workflow is not evidence of a successful CI run. Inspect the actual workflow result before merging/releasing.

## Next engineering sequence

1. Execute browser/mobile/accessibility tests and live PostgreSQL concurrent-write tests; resolve findings, implement queue pagination, and set a staging environment.
2. Add email verification/recovery, staff MFA, assignments and scoped safety roles before onboarding real operators.
3. Add complete reciprocal preferences and explainable ranking, then integrate consented independent identity checks and private evidence storage.
4. Deliver controlled messaging, notification delivery/opt-outs, support tools and deactivation/session-revocation workflows.
5. Implement memberships/payments/refunds, concierge scheduling and consent-scoped family participation; finish retention/export/deletion and operational approval gates.

## Primary implementation references

- Alembic tutorial: https://alembic.sqlalchemy.org/en/latest/tutorial.html
- OWASP session management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP password storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Psycopg installation: https://www.psycopg.org/psycopg3/docs/basic/install.html

These references informed implementation choices; they are not a security certification.
