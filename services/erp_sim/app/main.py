"""Mock S/4HANA (erp_sim) FastAPI application."""

from fastapi import FastAPI
from services.erp_sim.app.api.odata import router as odata_router
from services.erp_sim.app.api.sim import router as sim_router
from services.erp_sim.app.db.models import Supplier
from services.erp_sim.app.db.seed import reset_and_seed
from services.erp_sim.app.db.session import SessionLocal, init_db


def startup_init():
    # Initialize DB schema
    init_db()
    # Check if seeded, if not seed it
    db = SessionLocal()
    try:
        if db.query(Supplier).count() == 0:
            reset_and_seed(db)
    finally:
        db.close()


app = FastAPI(
    title="AgentShield Mock S/4HANA ERP Simulator",
    version="2.0.0",
    description="Authoritative ERP simulator providing SAP OData V2 APIs, strict constraints, ETags, and state digests.",
)

# Run initialization
startup_init()

app.include_router(odata_router)
app.include_router(sim_router)



@app.get("/health")
def health():
    return {"status": "ok", "service": "erp_sim", "port": 8001}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("services.erp_sim.app.main:app", host="0.0.0.0", port=8001, reload=True)
