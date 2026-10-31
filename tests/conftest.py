"""Shared fixtures: deterministic ERP reset and optional live HTTP stack."""

import os
import threading
import time
from typing import Dict

import httpx
import pytest
import uvicorn

from services.erp_sim.app.db.models import Base
from services.erp_sim.app.db.seed import reset_and_seed
from services.erp_sim.app.db.session import SessionLocal, engine
from services.erp_sim.app.main import app as erp_app
from services.oracles.app.main import AIS_PORTS
from services.oracles.app.main import app as oracles_app
from tests.support.gateway_stub import app as gateway_stub_app
from tests.support.gateway_stub import reset_stub_state


ERP_PORT = 18001
ORACLE_PORT = 18002
GATEWAY_PORT = 18000


class _UvicornThread(threading.Thread):
    def __init__(self, app, port: int):
        super().__init__(daemon=True)
        self.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
        )

    def run(self):
        self.server.run()


@pytest.fixture(scope="session", autouse=True)
def _schema():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture(autouse=True)
def isolate_state():
    db = SessionLocal()
    try:
        reset_and_seed(db)
    finally:
        db.close()
    AIS_PORTS["JNPT"] = {"berthed_today": 14, "status": "NORMAL"}
    AIS_PORTS["MUMBAI"] = {"berthed_today": 18, "status": "NORMAL"}
    AIS_PORTS["CHENNAI"] = {"berthed_today": 12, "status": "NORMAL"}
    os.environ.pop("SIM_FORCE_TIMEOUT", None)
    os.environ.pop("SIM_FORCE_UNAVAILABLE", None)
    os.environ.pop("SIM_LATENCY_MS", None)
    reset_stub_state()
    yield
    AIS_PORTS["JNPT"] = {"berthed_today": 14, "status": "NORMAL"}
    os.environ.pop("SIM_FORCE_TIMEOUT", None)
    os.environ.pop("SIM_FORCE_UNAVAILABLE", None)
    os.environ.pop("SIM_LATENCY_MS", None)


@pytest.fixture(scope="session")
def live_stack():
    os.environ["ERP_URL"] = f"http://127.0.0.1:{ERP_PORT}"
    os.environ["ORACLES_URL"] = f"http://127.0.0.1:{ORACLE_PORT}"
    os.environ["GATEWAY_URL"] = f"http://127.0.0.1:{GATEWAY_PORT}"

    from libs.common.settings import settings

    settings.erp_url = os.environ["ERP_URL"]
    settings.oracles_url = os.environ["ORACLES_URL"]
    settings.gateway_url = os.environ["GATEWAY_URL"]

    threads = [
        _UvicornThread(erp_app, ERP_PORT),
        _UvicornThread(oracles_app, ORACLE_PORT),
        _UvicornThread(gateway_stub_app, GATEWAY_PORT),
    ]
    for t in threads:
        t.start()

    deadline = time.time() + 15
    last_error = None
    while time.time() < deadline:
        try:
            httpx.get(f"http://127.0.0.1:{ERP_PORT}/health", timeout=0.5)
            httpx.get(f"http://127.0.0.1:{ORACLE_PORT}/health", timeout=0.5)
            httpx.get(f"http://127.0.0.1:{GATEWAY_PORT}/health", timeout=0.5)
            break
        except Exception as exc:
            last_error = exc
            time.sleep(0.1)
    else:
        raise RuntimeError(f"live stack failed to start: {last_error}")

    yield {
        "erp_url": settings.erp_url,
        "oracles_url": settings.oracles_url,
        "gateway_url": settings.gateway_url,
    }


@pytest.fixture
def stack_urls(live_stack) -> Dict[str, str]:
    from libs.common.settings import settings

    settings.erp_url = live_stack["erp_url"]
    settings.oracles_url = live_stack["oracles_url"]
    settings.gateway_url = live_stack["gateway_url"]
    httpx.post(f"{live_stack['erp_url']}/sim/v1/admin/reset", timeout=5.0)
    httpx.post(f"{live_stack['gateway_url']}/v1/test/reset", timeout=5.0)
    httpx.post(
        f"{live_stack['oracles_url']}/v1/ais/port/override",
        json={"port": "JNPT", "berthed_today": 14, "status": "NORMAL"},
        timeout=5.0,
    )
    return live_stack
