from sqlalchemy import inspect

from app import models
from scripts.init_db import create_tables


def test_create_tables_builds_the_complete_schema_and_is_idempotent(tmp_path):
    engine = models.create_db_engine(f"sqlite:///{tmp_path / 'attendance.db'}")

    create_tables(engine)
    create_tables(engine)

    assert set(inspect(engine).get_table_names()) == set(models.Base.metadata.tables)
