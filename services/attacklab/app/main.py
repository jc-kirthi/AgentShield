"""AgentShield AttackLab Service (Port 8004).

Controlled adversarial attack runner and red-team blast-radius measurement engine.
Only functional when SANDBOX=1.
"""

from typing import List, Optional
from fastapi import FastAPI, Header, HTTPException, Query, status
import httpx
from pydantic import BaseModel
from libs.common.auth import require_role
from libs.common.settings import settings
from services.attacklab.app.redteam import (
    execute_redteam_suite,
    generate_blast_radius_report,
)
from services.attacklab.app.scenarios import (
    SCENARIO_RUNNERS,
    SCENARIOS_CATALOG,
)


app = FastAPI(
    title="AgentShield AttackLab & Red-Team Runner",
    version="2.0.0",
    description="Controlled adversarial attack execution lab and blast-radius benchmark runner.",
)


def verify_sandbox_active():
    """Ensure AttackLab is only functional when SANDBOX=1."""
    if not settings.sandbox:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AttackLab is only available in SANDBOX mode (SANDBOX=1)",
        )


class RedTeamRunRequest(BaseModel):
    profiles: List[str] = ["VULNERABLE", "PROTECTED"]
    runs_per_scenario: int = 5


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "attacklab",
        "port": 8004,
        "sandbox_active": settings.sandbox,
    }


@app.get("/v1/scenarios")
def list_scenarios(authorization: Optional[str] = Header(None)):
    """List all available attack scenarios with target rules and financial exposure."""
    verify_sandbox_active()
    # Permit attacker_sandbox or admin role
    require_role(authorization, ["attacker_sandbox", "admin", "business_operator", "defender"])
    return {"scenarios": SCENARIOS_CATALOG}


@app.post("/v1/scenarios/{scenario_id}/run")
async def run_scenario(
    scenario_id: str,
    profile: str = Query("PROTECTED"),
    authorization: Optional[str] = Header(None),
):
    """Execute a single controlled attack scenario and capture real HTTP traces."""
    verify_sandbox_active()
    require_role(authorization, ["attacker_sandbox", "admin"])

    runner = SCENARIO_RUNNERS.get(scenario_id)
    if not runner:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown attack scenario '{scenario_id}'. Available: {list(SCENARIO_RUNNERS.keys())}",
        )

    async with httpx.AsyncClient(timeout=10.0) as client:
        result = await runner(
            http_client=client,
            erp_url=settings.erp_url,
            gateway_url=settings.gateway_url,
            profile=profile,
        )

    return result


@app.post("/v1/redteam/run")
async def run_redteam_benchmark(
    req: RedTeamRunRequest,
    authorization: Optional[str] = Header(None),
):
    """Execute full red-team benchmark across profiles and record financial damage delta."""
    verify_sandbox_active()
    require_role(authorization, ["admin", "attacker_sandbox"])

    suite_res = await execute_redteam_suite(
        erp_url=settings.erp_url,
        gateway_url=settings.gateway_url,
        profiles=req.profiles,
        runs_per_scenario=req.runs_per_scenario,
    )
    # Automatically compute updated blast radius report
    report = generate_blast_radius_report()

    return {
        "status": "COMPLETED",
        "suite": suite_res,
        "blast_radius_summary": {
            "total_saved_inr": report["total_saved_inr"],
            "total_vulnerable_loss_inr": report["total_vulnerable_loss_inr"],
            "total_protected_loss_inr": report["total_protected_loss_inr"],
        },
    }


@app.get("/v1/redteam/report")
def get_redteam_report(
    model_name: str = Query("Qwen3.5 (Local Ollama)"),
    authorization: Optional[str] = Header(None),
):
    """Generate and retrieve the blast-radius damage prevention report."""
    verify_sandbox_active()
    require_role(authorization, ["admin", "attacker_sandbox", "defender", "business_operator"])
    return generate_blast_radius_report(model_name=model_name)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("services.attacklab.app.main:app", host="0.0.0.0", port=8004, reload=True)
