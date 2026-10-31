"""AgentShield settings and environment configurations."""

import os
from pydantic import BaseModel


class Settings(BaseModel):
    jwt_secret: str = os.environ.get("JWT_SECRET", "agentshield-dev-secret-key-2026-signing")
    sandbox: bool = os.environ.get("SANDBOX", "1").lower() in ("1", "true", "yes")
    erp_db_url: str = os.environ.get("ERP_DB_URL", "sqlite:///./erp_sim.db")
    oracle_db_url: str = os.environ.get("ORACLE_DB_URL", "sqlite:///./oracles.db")
    lab_db_url: str = os.environ.get("LAB_DB_URL", "sqlite:///./attacklab.db")
    gateway_url: str = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8000")
    erp_url: str = os.environ.get("ERP_URL", "http://127.0.0.1:8001")
    oracles_url: str = os.environ.get("ORACLES_URL", "http://127.0.0.1:8002")
    attacklab_url: str = os.environ.get("ATTACKLAB_URL", "http://127.0.0.1:8004")
    erp_read_backend: str = os.environ.get("ERP_READ_BACKEND", "sim")


settings = Settings()
