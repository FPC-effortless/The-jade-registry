"""Consent and introduction invariants shared by every entry point."""
import json
from datetime import date
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session
from .models import AuditEvent, Consent, Introduction, MemberBlock, Profile, User


def age(birth: date) -> int:
    today = date.today()
    return today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))


def audit(db: Session, actor: int | None, action: str, subject: str, **details):
    db.add(AuditEvent(actor_id=actor, action=action, subject=subject, details=json.dumps(details, sort_keys=True)))


def lock_users(db: Session, *ids: int):
    # One lock order for creation, blocking and decisions. PostgreSQL enforces row locks.
    return db.scalars(select(User).where(User.id.in_(set(ids))).order_by(User.id).with_for_update().execution_options(populate_existing=True)).all()


def eligible(db: Session, uid: int) -> bool:
    u, p, c = db.get(User, uid), db.get(Profile, uid), db.get(Consent, uid)
    return bool(u and u.active and u.role == "member" and p and c and 18 <= age(p.birth_date) <= 120
                and p.marriage_intent and p.verified and p.discoverable and c.matchmaking and c.profile_sharing)


def pair_filter(a: int, b: int):
    a, b = sorted((a, b))
    return and_(Introduction.first_id == a, Introduction.second_id == b)


def blocked(db: Session, a: int, b: int) -> bool:
    return db.scalar(select(MemberBlock.id).where(or_(
        and_(MemberBlock.blocker_id == a, MemberBlock.blocked_id == b),
        and_(MemberBlock.blocker_id == b, MemberBlock.blocked_id == a)))) is not None


def compatible(db: Session, a: int, b: int) -> bool:
    if a == b or not eligible(db, a) or not eligible(db, b) or blocked(db, a, b):
        return False
    ap, bp = db.get(Profile, a), db.get(Profile, b)
    return ap.looking_in == bp.country and bp.looking_in == ap.country


def card(profile: Profile):
    # Intentionally excludes email, full birth date, contacts and verification evidence.
    return {"id": profile.user_id, "display_name": profile.display_name,
            "country": profile.country, "age": age(profile.birth_date), "review_status": "staff_reviewed"}


def cancel_introductions(db: Session, uid: int, actor: int, reason: str, other_id: int | None = None):
    condition = pair_filter(uid, other_id) if other_id is not None else or_(Introduction.first_id == uid, Introduction.second_id == uid)
    result = db.execute(update(Introduction).where(condition, Introduction.status.in_(["pending", "mutual"]))
                        .values(status="cancelled", first_accepts=None, second_accepts=None))
    if result.rowcount:
        audit(db, actor, "introductions.cancelled", f"member:{uid}", reason=reason, count=result.rowcount)


def intro_view(db: Session, intro: Introduction, uid: int):
    other = intro.second_id if uid == intro.first_id else intro.first_id
    visible = intro.status in {"pending", "mutual"} and compatible(db, uid, other)
    return {"id": intro.id, "status": intro.status, "partner_id": other,
            "my_decision": intro.first_accepts if uid == intro.first_id else intro.second_accepts,
            "partner": card(db.get(Profile, other)) if visible else None,
            "created_at": intro.created_at.isoformat()}
