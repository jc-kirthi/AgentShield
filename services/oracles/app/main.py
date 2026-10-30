"""AgentShield Out-of-Band Oracle Simulators (Port 8002).

Independent out-of-band verification services:
1. Penny-Drop Verification (Bank Account -> Account Holder Name)
2. GSTIN Verification (GSTIN -> Legal Name, Trade Name, Status)
3. AIS Port Tracking (Port -> Berthed Vessels, Disruption Status)
4. Disruption Signals Oracle (Authoritative vs Unverified Signals)
"""

import asyncio
import os
from typing import Dict, List, Optional
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field


app = FastAPI(
    title="AgentShield Out-of-Band Oracles",
    version="2.0.0",
    description="Out-of-band oracle simulators for bank penny-drop, GSTIN identity, and AIS maritime tracking.",
)

# Seeds for Penny-Drop
PENNY_DROP_REGISTRY = {
    ("91001004417", "HDFC0000123"): "ULTRA BEARINGS PRIVATE LIMITED",
    ("XXXXXX4417", "HDFC0000123"): "ULTRA BEARINGS PRIVATE LIMITED",
    ("4417", "HDFC0000123"): "ULTRA BEARINGS PRIVATE LIMITED",
    ("9988", "ICIC0004521"): "RAVI TRADERS",
    ("XXXXXX9988", "ICIC0004521"): "RAVI TRADERS",
    ("91001009988", "ICIC0004521"): "RAVI TRADERS",
    ("91001008812", "ICIC0000045"): "SHAKTI CASTINGS PRIVATE LIMITED",
    ("XXXXXX8812", "ICIC0000045"): "SHAKTI CASTINGS PRIVATE LIMITED",
    ("8812", "ICIC0000045"): "SHAKTI CASTINGS PRIVATE LIMITED",
}

# Seeds for GSTIN
GSTIN_REGISTRY = {
    "27AABCU9603R1ZM": {
        "legal_name": "ULTRA BEARINGS PRIVATE LIMITED",
        "trade_name": "ULTRA BEARINGS",
        "status": "ACTIVE",
    },
    "29AAECS1234F1Z5": {
        "legal_name": "SHAKTI CASTINGS PRIVATE LIMITED",
        "trade_name": "SHAKTI CASTINGS",
        "status": "ACTIVE",
    },
}

# State for AIS Port Tracker
AIS_PORTS = {
    "JNPT": {"berthed_today": 14, "status": "NORMAL"},
    "MUMBAI": {"berthed_today": 18, "status": "NORMAL"},
    "CHENNAI": {"berthed_today": 12, "status": "NORMAL"},
}


class PennyDropRequest(BaseModel):
    bank_account: str
    ifsc: str


class PennyDropResponse(BaseModel):
    holder_name: str
    bank_account: str
    ifsc: str
    status: str = "VERIFIED"


class GSTINRequest(BaseModel):
    gstin: str


class GSTINResponse(BaseModel):
    gstin: str
    legal_name: str
    trade_name: str
    status: str


class AISPortRequest(BaseModel):
    port: str


class AISPortResponse(BaseModel):
    port: str
    berthed_today: int
    status: str


class AISPortOverrideRequest(BaseModel):
    port: str
    berthed_today: int
    status: str = "DISRUPTED"


async def check_simulated_delays_and_errors():
    """Support SIM_LATENCY_MS and SIM_FORCE_TIMEOUT for testing HOLD_ORACLE_UNAVAILABLE."""
    force_timeout = os.environ.get("SIM_FORCE_TIMEOUT", "0").lower() in ("1", "true")
    if force_timeout:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Simulated Oracle Gateway Timeout",
        )

    latency_ms = int(os.environ.get("SIM_LATENCY_MS", "0"))
    if latency_ms > 0:
        await asyncio.sleep(latency_ms / 1000.0)


@app.get("/health")
def health():
    return {"status": "ok", "service": "oracles", "port": 8002}


@app.post("/v1/penny-drop", response_model=PennyDropResponse)
async def penny_drop(req: PennyDropRequest):
    """Execute penny-drop bank verification to discover authoritative account holder name."""
    await check_simulated_delays_and_errors()

    account = req.bank_account.strip()
    ifsc = req.ifsc.strip().upper()

    # Direct match
    holder = PENNY_DROP_REGISTRY.get((account, ifsc))
    # Suffix match if full account or masked account was queried
    if not holder:
        for (reg_acc, reg_ifsc), reg_holder in PENNY_DROP_REGISTRY.items():
            if reg_ifsc == ifsc and (account.endswith(reg_acc) or reg_acc.endswith(account)):
                holder = reg_holder
                break

    if not holder:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "ACCOUNT_NOT_FOUND", "message": f"Bank account {account} with IFSC {ifsc} not found in penny-drop registry"},
        )

    return PennyDropResponse(
        holder_name=holder,
        bank_account=account,
        ifsc=ifsc,
        status="VERIFIED",
    )


@app.post("/v1/gstin", response_model=GSTINResponse)
async def verify_gstin(req: GSTINRequest):
    """Query authoritative GSTIN registry for legal and trade name."""
    await check_simulated_delays_and_errors()

    clean_gstin = req.gstin.strip().upper()
    info = GSTIN_REGISTRY.get(clean_gstin)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "GSTIN_NOT_FOUND", "message": f"GSTIN {clean_gstin} not found"},
        )

    return GSTINResponse(
        gstin=clean_gstin,
        legal_name=info["legal_name"],
        trade_name=info["trade_name"],
        status=info["status"],
    )


@app.post("/v1/ais/port", response_model=AISPortResponse)
async def ais_port(req: AISPortRequest):
    """Query AIS maritime registry for port activity and berth numbers."""
    await check_simulated_delays_and_errors()

    port_name = req.port.strip().upper()
    port_info = AIS_PORTS.get(port_name)
    if not port_info:
        # Default fallback
        return AISPortResponse(port=port_name, berthed_today=12, status="NORMAL")

    return AISPortResponse(
        port=port_name,
        berthed_today=port_info["berthed_today"],
        status=port_info["status"],
    )


@app.post("/v1/ais/port/override")
async def override_ais_port(req: AISPortOverrideRequest):
    """Set AIS port status for testing disrupted or normal conditions."""
    port_name = req.port.strip().upper()
    AIS_PORTS[port_name] = {
        "berthed_today": req.berthed_today,
        "status": req.status,
    }
    return {"status": "UPDATED", "port": port_name, "details": AIS_PORTS[port_name]}


@app.get("/v1/signals")
async def get_disruption_signals(region: Optional[str] = "IN-WEST", since: Optional[str] = None):
    """Disruption Signals Oracle (Finale v2.1 Section 13.4 & 13.5).
    Provides dual-channel signals:
    1. AUTHORITATIVE (AIS / Port telemetry)
    2. UNVERIFIED (News feeds, emails, notices)
    """
    await check_simulated_delays_and_errors()

    jnpt_info = AIS_PORTS.get("JNPT", {"berthed_today": 14, "status": "NORMAL"})
    signals = [
        {
            "signal_id": "SIG-AIS-JNPT-01",
            "channel": "AUTHORITATIVE",
            "source": "AIS_PORT_FEED",
            "region": "IN-WEST",
            "port": "JNPT",
            "berthed_today": jnpt_info["berthed_today"],
            "disruption": jnpt_info["berthed_today"] < 3,
            "evidence": f"AIS tracker reports {jnpt_info['berthed_today']} berthed vessels at JNPT.",
            "timestamp": "2026-10-29T08:00:00Z",
        },
        {
            "signal_id": "SIG-UNV-LOGISTICS-02",
            "channel": "UNVERIFIED",
            "source": "EXTERNAL_EMAIL_OR_NEWS",
            "region": "IN-WEST",
            "port": "JNPT",
            "headline": "Unconfirmed report of maritime labor strike at JNPT",
            "evidence": "Email newsletter claims 7-day berth shutdown.",
            "timestamp": "2026-10-29T08:15:00Z",
        },
    ]
    return {"signals": signals}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("services.oracles.app.main:app", host="0.0.0.0", port=8002, reload=True)
