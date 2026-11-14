"""Same-origin member/staff application and API. v0.2 engineering pilot only."""
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import case, delete, func, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from .config import Settings
from .database import make_engine
from .domain import age, audit, blocked, cancel_introductions, card, compatible, eligible, intro_view, lock_users, pair_filter
from .models import AuthSession, AuthThrottle, AuditEvent, Consent, Introduction, MemberBlock, Profile, SafetyReport, User
from .schemas import ConsentIn, Decision, IntroductionIn, Login, ProfileIn, ReportDecision, ReportIn, Review
from .security import check_password, csrf_for, hash_password, keyed_digest, needs_rehash

COOKIE = "jade_session"
STATIC = Path(__file__).parent / "static"


def session(request: Request):
    with request.app.state.session_factory() as db:
        yield db


DB = Annotated[Session, Depends(session)]


def current_user(request: Request, db: DB) -> User:
    authorization = request.headers.get("authorization")
    cookie_auth = not authorization
    if authorization:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(401, "Authentication required")
        token = parts[1]
    else:
        token = request.cookies.get(COOKIE, "")
    if not token or len(token) > 256:
        raise HTTPException(401, "Authentication required")
    settings = request.app.state.settings
    auth = db.get(AuthSession, keyed_digest(settings.secret_key, token))
    if not auth or auth.revoked or auth.expires_at <= int(time.time()):
        raise HTTPException(401, "Session expired or revoked")
    user = db.get(User, auth.user_id)
    if not user or not user.active:
        raise HTTPException(401, "Account unavailable")
    if cookie_auth and request.method not in {"GET", "HEAD", "OPTIONS"}:
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), csrf_for(settings.secret_key, token)):
            raise HTTPException(403, "CSRF validation failed")
    request.state.auth_session = auth
    request.state.session_token = token
    return user


Current = Annotated[User, Depends(current_user)]


def member(user: Current):
    if user.role != "member":
        raise HTTPException(403, "Member account required")
    return user


def staff(user: Current):
    if user.role not in {"matchmaker", "admin"}:
        raise HTTPException(403, "Staff access required")
    return user


def admin(user: Current):
    if user.role != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


Member = Annotated[User, Depends(member)]
Staff = Annotated[User, Depends(staff)]
Admin = Annotated[User, Depends(admin)]


def throttle(db: Session, secret: str, scopes: list[tuple[str, int]]):
    """Database-backed fixed-window limiter, with atomic increments across workers."""
    from sqlalchemy.dialects.sqlite import insert as sqlite_insert
    from sqlalchemy.dialects.postgresql import insert as postgres_insert
    insert = sqlite_insert if db.bind.dialect.name == "sqlite" else postgres_insert
    start = int(time.time()) // 900 * 900
    limited = False
    for scope, limit in sorted(scopes):
        key = keyed_digest(secret, "limit:" + scope)
        stmt = insert(AuthThrottle).values(key=key, window_start=start, count=1)
        stmt = stmt.on_conflict_do_update(index_elements=[AuthThrottle.key], set_={
            "window_start": start,
            "count": case((AuthThrottle.window_start == start, AuthThrottle.count + 1), else_=1),
        }).returning(AuthThrottle.count)
        limited = db.scalar(stmt) > limit or limited
    db.commit()  # Record attempts even when authentication later fails.
    if limited:
        raise HTTPException(429, "Too many attempts. Try again later.", headers={"Retry-After": str(start + 900 - int(time.time()))})


def create_app(settings: Settings | None = None):
    settings = settings or Settings.from_env()
    app = FastAPI(title="The Jade Registry", version="0.2.0", docs_url=None, redoc_url=None,
                  openapi_url="/openapi.json" if settings.environment != "production" else None)
    app.state.settings = settings
    app.state.engine = make_engine(settings.database_url)
    app.state.session_factory = sessionmaker(bind=app.state.engine, expire_on_commit=False)

    @app.middleware("http")
    async def boundary(request: Request, call_next):
        origin = request.headers.get("origin")
        unsafe = request.method not in {"GET", "HEAD", "OPTIONS"}
        if unsafe and ((origin is not None and origin != settings.origin) or request.headers.get("sec-fetch-site") == "cross-site"):
            response = JSONResponse({"detail": "Cross-origin request denied"}, status_code=403)
        else:
            try:
                too_large = int(request.headers.get("content-length", "0")) > 65536
            except ValueError:
                too_large = True
            if too_large:
                response = JSONResponse({"detail": "Request too large"}, status_code=413)
            else:
                response = await call_next(request)
        response.headers.update({
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
        })
        if settings.secure_cookies:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(_, error):
        # Pydantic's input value may contain a password: never echo it.
        return JSONResponse(status_code=422, content={"detail": [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in error.errors()]})

    @app.get("/health")
    def health():
        return {"status": "ok", "version": "0.2.0"}

    @app.get("/health/ready")
    def ready(db: DB):
        try:
            revision = db.scalar(text("SELECT version_num FROM alembic_version"))
        except SQLAlchemyError:
            raise HTTPException(503, "Database migration required")
        if revision != "jade_0002":
            raise HTTPException(503, "Database migration required")
        return {"status": "ready", "schema": revision}

    @app.post("/auth/register", status_code=201)
    def register(payload: Login, request: Request, db: DB):
        ip = request.client.host if request.client else "unknown"
        throttle(db, settings.secret_key, [("register-ip:" + ip, 20)])
        user = User(email=payload.email, password_digest=hash_password(payload.password), role="member", active=True)
        db.add(user)
        try:
            db.flush()
            audit(db, user.id, "account.created", f"member:{user.id}")
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Account already exists")
        return {"id": user.id}

    @app.post("/auth/login")
    def login(payload: Login, request: Request, response: Response, db: DB):
        ip = request.client.host if request.client else "unknown"
        throttle(db, settings.secret_key, [("login-ip:" + ip, 60), ("login-email:" + payload.email, 10)])
        user = db.scalar(select(User).where(User.email == payload.email))
        valid = check_password(payload.password, user.password_digest if user else None)
        if not valid or not user or not user.active:
            raise HTTPException(401, "Incorrect credentials")
        if needs_rehash(user.password_digest):
            user.password_digest = hash_password(payload.password)
        old = request.cookies.get(COOKIE)
        if old:
            db.execute(update(AuthSession).where(AuthSession.token_hash == keyed_digest(settings.secret_key, old)).values(revoked=True))
        token = secrets.token_urlsafe(48)
        db.add(AuthSession(token_hash=keyed_digest(settings.secret_key, token), user_id=user.id,
                           expires_at=int(time.time()) + settings.session_seconds, revoked=False))
        audit(db, user.id, "session.created", f"member:{user.id}")
        db.commit()
        response.set_cookie(COOKIE, token, max_age=settings.session_seconds, httponly=True,
                            secure=settings.secure_cookies, samesite="strict", path="/")
        return {"access_token": token, "token_type": "bearer", "expires_in": settings.session_seconds,
                "csrf_token": csrf_for(settings.secret_key, token), "role": user.role}

    @app.get("/auth/session")
    def auth_session(request: Request, user: Current):
        return {"id": user.id, "role": user.role, "csrf_token": csrf_for(settings.secret_key, request.state.session_token)}

    @app.post("/auth/logout")
    def logout(request: Request, response: Response, db: DB, user: Current):
        request.state.auth_session.revoked = True
        audit(db, user.id, "session.revoked", f"member:{user.id}")
        db.commit()
        response.delete_cookie(COOKIE, path="/", secure=settings.secure_cookies, httponly=True, samesite="strict")
        return {"logged_out": True}

    @app.post("/auth/logout-all")
    def logout_all(response: Response, db: DB, user: Current):
        db.execute(update(AuthSession).where(AuthSession.user_id == user.id).values(revoked=True))
        audit(db, user.id, "sessions.revoked_all", f"member:{user.id}")
        db.commit()
        response.delete_cookie(COOKIE, path="/", secure=settings.secure_cookies, httponly=True, samesite="strict")
        return {"logged_out": True}

    @app.get("/me")
    def me(db: DB, user: Current):
        p, c = db.get(Profile, user.id), db.get(Consent, user.id)
        return {"id": user.id, "email": user.email, "role": user.role,
                "profile": {"display_name": p.display_name, "birth_date": p.birth_date.isoformat(), "country": p.country,
                            "looking_in": p.looking_in, "marriage_intent": p.marriage_intent,
                            "discoverable": p.discoverable, "verified": p.verified} if p else None,
                "consent": {"matchmaking": c.matchmaking, "profile_sharing": c.profile_sharing, "version": c.version} if c else None,
                "matching_enabled": eligible(db, user.id)}

    @app.put("/me/profile")
    def profile(payload: ProfileIn, db: DB, user: Member):
        if not 18 <= age(payload.birth_date) <= 120:
            raise HTTPException(422, "A member profile requires an adult birth date (18–120 years)")
        lock_users(db, user.id)
        p = db.get(Profile, user.id)
        if p is None:
            p = Profile(user_id=user.id)
            db.add(p)
        for name, value in payload.model_dump().items():
            setattr(p, name, value)
        p.verified = False
        cancel_introductions(db, user.id, user.id, "profile_changed")
        audit(db, user.id, "profile.updated", f"member:{user.id}")
        db.commit()
        return {"profile_saved": True, "verification_status": "pending"}

    @app.put("/me/consent")
    def consent(payload: ConsentIn, db: DB, user: Member):
        lock_users(db, user.id)
        c = db.get(Consent, user.id)
        if c is None:
            c = Consent(user_id=user.id)
            db.add(c)
        c.matchmaking, c.profile_sharing, c.version = payload.matchmaking, payload.profile_sharing, "v1"
        from .models import utcnow
        c.updated_at = utcnow()
        if not payload.matchmaking or not payload.profile_sharing:
            cancel_introductions(db, user.id, user.id, "consent_withdrawn")
        audit(db, user.id, "consent.updated", f"member:{user.id}", **payload.model_dump(), version="v1")
        db.commit()
        return {"updated": True, "matching_enabled": eligible(db, user.id)}

    @app.get("/me/introductions")
    def introductions(db: DB, user: Member, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = db.scalars(select(Introduction).where(or_(Introduction.first_id == user.id, Introduction.second_id == user.id))
                          .order_by(Introduction.id.desc()).offset(offset).limit(limit)).all()
        return {"introductions": [intro_view(db, i, user.id) for i in rows]}

    @app.get("/matches")
    def matches(db: DB, user: Member):
        if not eligible(db, user.id):
            raise HTTPException(403, "Review, discoverability and both consents are required")
        # Unlike v0.1, this is NOT a browseable member directory.
        rows = db.scalars(select(Introduction).where(or_(Introduction.first_id == user.id, Introduction.second_id == user.id),
                          Introduction.status.in_(["pending", "mutual"])).order_by(Introduction.id.desc()).limit(100)).all()
        return {"candidates": [v["partner"] for i in rows if (v := intro_view(db, i, user.id))["partner"]]}

    @app.post("/me/introductions/{intro_id}/decision")
    def decide(intro_id: int, payload: Decision, db: DB, user: Member):
        intro = db.get(Introduction, intro_id)
        if intro is None or user.id not in (intro.first_id, intro.second_id):
            raise HTTPException(404, "Introduction not found")
        lock_users(db, intro.first_id, intro.second_id)
        intro = db.scalar(select(Introduction).where(Introduction.id == intro_id).with_for_update().execution_options(populate_existing=True))
        if intro.status != "pending":
            raise HTTPException(409, "Introduction is closed")
        if payload.accept and not compatible(db, intro.first_id, intro.second_id):
            raise HTTPException(403, "Introduction is no longer eligible")
        if user.id == intro.first_id:
            intro.first_accepts = payload.accept
        else:
            intro.second_accepts = payload.accept
        if payload.accept is False:
            intro.status = "declined"
        elif intro.first_accepts is True and intro.second_accepts is True:
            intro.status = "mutual"
        audit(db, user.id, "introduction.decision", f"introduction:{intro.id}", accept=payload.accept, status=intro.status)
        db.commit()
        return {"id": intro.id, "status": intro.status}

    @app.post("/me/blocks/{other_id}")
    def block(other_id: int, db: DB, user: Member):
        if other_id == user.id or not db.scalar(select(Introduction.id).where(pair_filter(user.id, other_id))):
            raise HTTPException(404, "Introduced member not found")
        lock_users(db, user.id, other_id)
        if not db.scalar(select(MemberBlock.id).where(MemberBlock.blocker_id == user.id, MemberBlock.blocked_id == other_id)):
            db.add(MemberBlock(blocker_id=user.id, blocked_id=other_id))
        cancel_introductions(db, user.id, user.id, "member_block", other_id)
        audit(db, user.id, "member.blocked", f"member:{other_id}")
        db.commit()
        return {"blocked": True}

    @app.post("/me/reports", status_code=201)
    def report(payload: ReportIn, db: DB, user: Member):
        if payload.member_id == user.id or not db.scalar(select(Introduction.id).where(pair_filter(user.id, payload.member_id))):
            raise HTTPException(404, "Introduced member not found")
        throttle(db, settings.secret_key, [(f"report:{user.id}", 5)])
        report = SafetyReport(reporter_id=user.id, reported_id=payload.member_id, category=payload.category, description=payload.description)
        db.add(report)
        db.flush()
        audit(db, user.id, "safety.reported", f"report:{report.id}", category=payload.category)
        db.commit()
        return {"id": report.id, "status": report.status}

    @app.get("/staff/review-queue")
    def review_queue(db: DB, actor: Staff, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = db.scalars(select(Profile).join(User).join(Consent, Consent.user_id == Profile.user_id)
                          .where(User.active.is_(True), User.role == "member", Consent.matchmaking.is_(True))
                          .order_by(Profile.verified, Profile.user_id).offset(offset).limit(limit)).all()
        return {"members": [{"id": p.user_id, "display_name": p.display_name, "age": age(p.birth_date),
                             "country": p.country, "looking_in": p.looking_in, "verified": p.verified,
                             "matching_enabled": eligible(db, p.user_id)} for p in rows]}

    @app.post("/staff/members/{member_id}/verify")
    def verify(member_id: int, payload: Review, db: DB, actor: Staff):
        lock_users(db, member_id)
        u, p, c = db.get(User, member_id), db.get(Profile, member_id), db.get(Consent, member_id)
        if not u or not u.active or u.role != "member" or not p or not c or not c.matchmaking:
            raise HTTPException(404, "Consenting member profile not found")
        if actor.id == member_id or not 18 <= age(p.birth_date) <= 120:
            raise HTTPException(403, "Review not permitted")
        p.verified = payload.approved
        if not payload.approved:
            cancel_introductions(db, member_id, actor.id, "review_revoked")
        audit(db, actor.id, "profile.reviewed", f"member:{member_id}", approved=payload.approved, evidence_reference=payload.evidence_reference)
        db.commit()
        return {"verified": p.verified, "verification_method": "manual_staff_review", "identity_provider_verified": False}

    @app.get("/staff/candidates")
    def candidates(db: DB, actor: Staff, member_id: int = Query(gt=0), limit: int = Query(50, ge=1, le=100)):
        if not eligible(db, member_id):
            raise HTTPException(403, "Selected member is not eligible")
        p = db.get(Profile, member_id)
        # Apply privacy, account, consent, block and already-introduced filters in SQL before pagination.
        existing = select(Introduction.id).where(or_(
            (Introduction.first_id == member_id) & (Introduction.second_id == Profile.user_id),
            (Introduction.second_id == member_id) & (Introduction.first_id == Profile.user_id))).exists()
        block_exists = select(MemberBlock.id).where(or_(
            (MemberBlock.blocker_id == member_id) & (MemberBlock.blocked_id == Profile.user_id),
            (MemberBlock.blocked_id == member_id) & (MemberBlock.blocker_id == Profile.user_id))).exists()
        rows = db.scalars(select(Profile).join(User).join(Consent, Consent.user_id == Profile.user_id).where(
            Profile.user_id != member_id, Profile.country == p.looking_in, Profile.looking_in == p.country,
            Profile.verified.is_(True), Profile.discoverable.is_(True), Profile.marriage_intent.is_(True),
            User.active.is_(True), User.role == "member", Consent.matchmaking.is_(True), Consent.profile_sharing.is_(True),
            ~existing, ~block_exists).order_by(Profile.user_id).limit(limit)).all()
        return {"candidates": [{**card(q), "reasons": ["Mutual country preferences", "Both opted in", "Both staff reviewed"]}
                               for q in rows if compatible(db, member_id, q.user_id)]}

    @app.post("/staff/introductions", status_code=201)
    def create_intro(payload: IntroductionIn, db: DB, actor: Staff):
        a, b = sorted((payload.first_id, payload.second_id))
        if a == b:
            raise HTTPException(422, "Choose two different members")
        lock_users(db, a, b)
        if not compatible(db, a, b):
            raise HTTPException(403, "Members are not mutually eligible")
        intro = Introduction(first_id=a, second_id=b, created_by=actor.id)
        db.add(intro)
        try:
            db.flush()
            audit(db, actor.id, "introduction.created", f"introduction:{intro.id}", first_id=a, second_id=b)
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "This pair has already been introduced")
        return {"id": intro.id, "status": intro.status}

    @app.get("/staff/introductions")
    def staff_intros(db: DB, actor: Staff, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = db.scalars(select(Introduction).order_by(Introduction.id.desc()).offset(offset).limit(limit)).all()
        return {"introductions": [{"id": i.id, "first_id": i.first_id, "second_id": i.second_id,
                                  "status": i.status, "created_at": i.created_at.isoformat()} for i in rows]}

    @app.get("/staff/reports")
    def reports(db: DB, actor: Staff, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = db.scalars(select(SafetyReport).order_by(SafetyReport.id.desc()).offset(offset).limit(limit)).all()
        audit(db, actor.id, "safety.queue_accessed", "safety_reports", count=len(rows))
        db.commit()
        return {"reports": [{"id": r.id, "reporter_id": r.reporter_id, "reported_id": r.reported_id,
                             "category": r.category, "description": r.description, "status": r.status} for r in rows]}

    @app.post("/staff/reports/{report_id}/status")
    def report_status(report_id: int, payload: ReportDecision, db: DB, actor: Staff):
        r = db.get(SafetyReport, report_id)
        if r is None:
            raise HTTPException(404, "Report not found")
        r.status = payload.status
        audit(db, actor.id, "safety.report_status", f"report:{r.id}", status=r.status)
        db.commit()
        return {"id": r.id, "status": r.status}

    @app.get("/staff/audit")
    def audit_events(db: DB, actor: Admin, limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
        rows = db.scalars(select(AuditEvent).order_by(AuditEvent.id.desc()).offset(offset).limit(limit)).all()
        return {"events": [{"id": r.id, "actor_id": r.actor_id, "action": r.action, "subject": r.subject,
                           "details": json.loads(r.details), "created_at": r.created_at.isoformat()} for r in rows]}

    @app.get("/", include_in_schema=False)
    @app.get("/member", include_in_schema=False)
    @app.get("/staff", include_in_schema=False)
    def index():
        # Public shell has no member data. Every data endpoint enforces authentication/role.
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app
