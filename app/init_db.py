"""Compatibility entry point: execute migrations rather than create_all."""
from alembic import command
from .config import Settings
from .manage import migration_config
if __name__ == "__main__":
    command.upgrade(migration_config(Settings.from_env().database_url), "head")
    print("The Jade Registry schema is up to date.")
