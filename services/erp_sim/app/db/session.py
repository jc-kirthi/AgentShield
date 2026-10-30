"""Database engine and session factory for Mock S/4HANA."""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from services.erp_sim.app.db.models import Base


DB_URL = os.environ.get("ERP_DB_URL", "sqlite:///./erp_sim.db")

connect_args = {}
if DB_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DB_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
