from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from models import RegisteredUser, Base
from helpers import session_scope

engine = create_engine("sqlite:///users_db.db")
Session = sessionmaker(bind=engine)

# Generate database schema
Base.metadata.create_all(engine)

# Create some User instances
users = [
    ("JuanPerez", "Juan", "Perez", "juan.p@mail.com", "pass1"),
    ("BautiLopez", "Bautista", "Lopez", "bl_2012p@mail.com", "pass2"),
    ("AnaMeir", "Ana", "Meir", "laani.11@mail.com", "pass3"),
]

with session_scope() as session:
    for user in users:
        session.add(RegisteredUser(*user))
    session.commit()
