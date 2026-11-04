# SPDX-FileCopyrightText: 2026 田中晴康
# SPDX-License-Identifier: Apache-2.0

"""Create all database tables for the configured environment.

Run this idempotent command from the repository root before the app starts:

    python -m scripts.init_db
"""

from sqlalchemy.engine import Engine

from app import models
from app.db import get_engine


def create_tables(engine: Engine | None = None) -> None:
    """Create every table registered on the application's metadata."""
    models.Base.metadata.create_all(bind=engine or get_engine())


if __name__ == "__main__":
    create_tables()
    print("Database tables are ready.")
