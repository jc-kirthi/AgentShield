import pytest
from fastapi.testclient import TestClient
from services.erp_sim.app.main import app as erp_app
from libs.common.auth import create_token
from services.erp_sim.app.db.session import SessionLocal
from services.erp_sim.app.core.digest import compute_state_digest

@pytest.fixture
def client():
    return TestClient(erp_app)

@pytest.fixture
def writer_token():
    return create_token("svc:gateway", ["erp_writer"])

@pytest.fixture
def reset_and_digest(client, writer_token):
    # reset DB to golden state
    res = client.post("/sim/v1/admin/reset", headers={"Authorization": f"Bearer {writer_token}"})
    assert res.status_code == 200
    # compute digest
    db = SessionLocal()
    d = compute_state_digest(db)
    db.close()
    return d

def test_payment_idempotent_same_payload(client, writer_token):
    payload = {"SupplierInvoice": "5105600021", "FiscalYear": "2026", "AmountInr": 4850000}
    headers = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "pay-key-1"}
    r1 = client.post("/sim/v1/payments", json=payload, headers=headers)
    assert r1.status_code == 201
    resp1 = r1.json()
    r2 = client.post("/sim/v1/payments", json=payload, headers=headers)
    assert r2.status_code == 201
    resp2 = r2.json()
    assert resp2.get("idempotent_replay") is True
    assert resp2["PaymentId"] == resp1["PaymentId"]

def test_payment_idempotent_altered_payload(client, writer_token):
    payload = {"SupplierInvoice": "5105600021", "FiscalYear": "2026", "AmountInr": 4850000}
    headers = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "pay-key-2"}
    r1 = client.post("/sim/v1/payments", json=payload, headers=headers)
    assert r1.status_code == 201
    altered = {"SupplierInvoice": "5105600021", "FiscalYear": "2026", "AmountInr": 4000000}
    r2 = client.post("/sim/v1/payments", json=altered, headers=headers)
    assert r2.status_code == 409

def test_payment_duplicate_new_key_fails_when_paid(client, writer_token):
    payload = {"SupplierInvoice": "5105600021", "FiscalYear": "2026", "AmountInr": 4850000}
    headers1 = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "pay-key-3"}
    r1 = client.post("/sim/v1/payments", json=payload, headers=headers1)
    assert r1.status_code == 201
    headers2 = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "pay-key-4"}
    r2 = client.post("/sim/v1/payments", json=payload, headers=headers2)
    assert r2.status_code == 409

def test_freight_booking_validation(client, writer_token):
    # valid booking
    payload = {"PurchaseOrder": "4500030", "Mode": "AIR", "CostInr": 1200000, "Reason": "expedite"}
    headers = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "frt-1"}
    r = client.post("/sim/v1/freight-bookings", json=payload, headers=headers)
    assert r.status_code == 201
    # invalid mode
    payload_bad = {"PurchaseOrder": "4500030", "Mode": "RAIL", "CostInr": 1200000}
    headers_bad = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "frt-2"}
    r2 = client.post("/sim/v1/freight-bookings", json=payload_bad, headers=headers_bad)
    assert r2.status_code == 400
    # negative cost
    payload_neg = {"PurchaseOrder": "4500030", "Mode": "SEA", "CostInr": -1000}
    headers_neg = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "frt-3"}
    r3 = client.post("/sim/v1/freight-bookings", json=payload_neg, headers=headers_neg)
    assert r3.status_code == 400
    # unknown PO
    payload_unknown = {"PurchaseOrder": "9999999", "Mode": "SEA", "CostInr": 5000}
    headers_unknown = {"Authorization": f"Bearer {writer_token}", "Idempotency-Key": "frt-4"}
    r4 = client.post("/sim/v1/freight-bookings", json=payload_unknown, headers=headers_unknown)
    assert r4.status_code == 404

def test_unauthorized_write_attempts(client):
    payload = {"SupplierInvoice": "5105600021", "FiscalYear": "2026", "AmountInr": 4850000}
    # no token
    r = client.post("/sim/v1/payments", json=payload)
    assert r.status_code == 401
    # token with insufficient role
    bad_token = create_token("user:foo", ["business_operator"])
    r2 = client.post("/sim/v1/payments", json=payload, headers={"Authorization": f"Bearer {bad_token}"})
    assert r2.status_code == 403

def test_duplicate_invoice_creation(client, writer_token):
    # create a new invoice for a new PO
    payload = {
        "supplier": "100045",
        "purchase_order": "4500030",
        "supplier_invoice_ref": "INV-NEW-01",
        "invoice_date": "2026-10-30",
        "items": [{"purchase_order_item": "10", "quantity": 100, "unit_price_inr": 50000}],
        "gross_amount_inr": 5000000,
        "source_document_id": "DOC-NEW"
    }
    headers = {"Authorization": f"Bearer {writer_token}"}
    r = client.post("/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice", json=payload, headers=headers)
    assert r.status_code == 201
    # duplicate creation should conflict
    r2 = client.post("/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice", json=payload, headers=headers)
    assert r2.status_code == 409

def test_invalid_invoice_references(client, writer_token):
    # missing required fields
    payload = {"supplier": "100045"}
    headers = {"Authorization": f"Bearer {writer_token}"}
    r = client.post("/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice", json=payload, headers=headers)
    assert r.status_code == 400
    # invalid supplier
    payload_bad = {
        "supplier": "999999",
        "purchase_order": "4500017",
        "supplier_invoice_ref": "INV-BAD",
        "invoice_date": "2026-10-30",
        "items": [{"purchase_order_item": "10", "quantity": 100, "unit_price_inr": 50000}],
        "gross_amount_inr": 5000000,
        "source_document_id": "DOC-BAD"
    }
    r2 = client.post("/sim/v1/invoices", json=payload_bad, headers=headers)
    assert r2.status_code == 404

def test_reset_and_state_digest_consistency(client, writer_token, reset_and_digest):
    # After reset, digest should match recorded golden digest
    golden_path = "scripts/golden_digest.txt"
    with open(golden_path, encoding="utf-8") as f:
        recorded = f.read().strip()
    assert reset_and_digest["digest"] == recorded
