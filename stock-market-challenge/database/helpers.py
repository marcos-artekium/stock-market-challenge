from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


engine = create_engine("sqlite:///users_db.db")
Session = sessionmaker(bind=engine)


# Context manager
@contextmanager
def session_scope():
    """Context manager for session"""
    session = Session()
    try:
        yield session
    except:
        session.rollback()
        raise
    finally:
        session.close()
