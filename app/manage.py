"""Administrative commands run by an authorized host operator, never exposed over HTTP."""
import argparse
import getpass
import secrets
import time
from datetime import date
from pathlib import Path
from alembic import command
from alembic.config import Config
from sqlalchemy import delete, select
from sqlalchemy.orm import Session
from .config import Settings
from .database import make_engine
from .domain import audit
from .models import AuthSession, AuthThrottle, Consent, Profile, User
from .schemas import Login
from .security import hash_password


def migration_config(url: str):
    config = Config(str(Path(__file__).resolve().parent.parent / "alembic.ini"))
    config.attributes["database_url"] = url
    return config


def provision_staff(db: Session, email: str, password: str, role: str):
    payload = Login(email=email, password=password)
    if role not in {"admin", "matchmaker"}:
        raise ValueError("Invalid staff role")
    if db.scalar(select(User.id).where(User.email == payload.email)):
        raise ValueError("Account already exists. This command will not promote or overwrite an account.")
    user = User(email=payload.email, password_digest=hash_password(password), role=role, active=True)
    db.add(user)
    db.flush()
    audit(db, None, "staff.provisioned_cli", f"member:{user.id}", role=role)
    db.commit()
    return user.id


def main():
    parser = argparse.ArgumentParser(description="The Jade Registry administration")
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("migrate")
    create = subs.add_parser("create-staff")
    create.add_argument("--email", required=True)
    create.add_argument("--role", choices=["matchmaker", "admin"], default="matchmaker")
    subs.add_parser("seed-demo")
    subs.add_parser("prune-auth")
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.command == "migrate":
        command.upgrade(migration_config(settings.database_url), "head")
        print("Schema upgraded to head.")
        return
    engine = make_engine(settings.database_url)
    with Session(engine) as db:
        if args.command == "create-staff":
            password = getpass.getpass("Staff password (12+ characters): ")
            if password != getpass.getpass("Confirm password: "):
                parser.error("Passwords do not match")
            try:
                uid = provision_staff(db, args.email, password, args.role)
            except ValueError as error:
                parser.error(str(error))
            print(f"Created {args.role} account #{uid}. No public promotion endpoint exists.")
        elif args.command == "seed-demo":
            if settings.environment != "development" or db.scalar(select(User.id).limit(1)):
                parser.error("Demo seeding requires development mode and an empty users table")
            password = secrets.token_urlsafe(24)
            provision_staff(db, "concierge@example.test", password, "admin")
            for name, country, looking in [("Alex", "SG", "JP"), ("Ren", "JP", "SG"), ("Morgan", "SG", "JP")]:
                u = User(email=name.lower() + "@example.test", password_digest=hash_password(password), role="member", active=True)
                db.add(u)
                db.flush()
                db.add(Profile(user_id=u.id, display_name=name + " (demo)", birth_date=date(1994, 6, 2), country=country, looking_in=looking,
                               discoverable=True, verified=False, marriage_intent=True))
                db.add(Consent(user_id=u.id, matchmaking=True, profile_sharing=True, version="v1"))
            audit(db, None, "demo.seeded", "development_only")
            db.commit()
            print("Synthetic demo accounts: concierge@example.test, alex@example.test, ren@example.test, morgan@example.test")
            print("Temporary demo password (local development only):", password)
        else:
            now = int(time.time())
            db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
            db.execute(delete(AuthThrottle).where(AuthThrottle.window_start < now - 86400))
            db.commit()
            print("Expired session and throttle records removed; audit records retained.")
    engine.dispose()


if __name__ == "__main__":
    main()
