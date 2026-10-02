import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import engine.db as db_mod
from engine.config import settings

@pytest.fixture(autouse=True)
def isolate_test_db(tmp_path, monkeypatch):
    """
    Ensures all tests run against a temporary isolated SQLite database
    and temporary folders, never contaminating production data/scanner.db.
    """
    test_db_file = tmp_path / "test_scanner.db"
    test_engine = create_engine(
        f"sqlite:///{test_db_file.resolve()}", 
        connect_args={"check_same_thread": False}
    )
    db_mod.Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    
    orig_session = db_mod.SessionLocal
    orig_engine = db_mod._engine
    db_mod.SessionLocal = TestSessionLocal
    db_mod._engine = test_engine
    
    # Also redirect settings data_dir
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    
    try:
        yield test_engine
    finally:
        db_mod.SessionLocal = orig_session
        db_mod._engine = orig_engine
