"""Environment configuration. There is deliberately no default signing key."""
import os
from dataclasses import dataclass
from urllib.parse import urlsplit
from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    database_url: str
    secret_key: str
    environment: str = "development"
    origin: str = "http://127.0.0.1:8000"
    session_seconds: int = 28800

    def __post_init__(self):
        if len(self.secret_key) < 32 or any(x in self.secret_key.lower() for x in ("replace", "development-only", "changeme")):
            raise ValueError("Set JADE_REGISTRY_SECRET_KEY to a randomly generated value of at least 32 characters")
        if self.environment not in {"development", "test", "production"}:
            raise ValueError("Invalid JADE_REGISTRY_ENV")
        parsed = urlsplit(self.origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username:
            raise ValueError("JADE_REGISTRY_ORIGIN must be a single http(s) origin without a path")
        if not 300 <= self.session_seconds <= 86400:
            raise ValueError("Session lifetime must be between 300 and 86400 seconds")
        if self.environment == "production":
            if not self.database_url.startswith("postgresql+psycopg://"):
                raise ValueError("Production requires PostgreSQL with the psycopg driver")
            if parsed.scheme != "https":
                raise ValueError("Production requires an HTTPS origin")

    @property
    def secure_cookies(self) -> bool:
        return self.environment == "production" or self.origin.startswith("https://")

    @classmethod
    def from_env(cls):
        load_dotenv(override=False)
        return cls(
            database_url=os.getenv("JADE_REGISTRY_DATABASE_URL", "sqlite:///./jade_registry.db"),
            secret_key=os.getenv("JADE_REGISTRY_SECRET_KEY", ""),
            environment=os.getenv("JADE_REGISTRY_ENV", "development"),
            origin=os.getenv("JADE_REGISTRY_ORIGIN", "http://127.0.0.1:8000").rstrip("/"),
            session_seconds=int(os.getenv("JADE_REGISTRY_SESSION_SECONDS", "28800")),
        )
