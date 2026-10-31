"""In-process Agent Firewall stub for Kirti integration tests.

This is not Chandan's gateway. It implements the documented reason codes and
fail-closed tool-call contract so AttackLab can be exercised against a real
HTTP /v1/tool-calls endpoint without modifying teammate-owned code.
"""

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from rapidfuzz import fuzz

from libs.common.auth import require_role

app = FastAPI(title="AgentShield Gateway Stub (tests only)", version="0.1.0")

LEASE_SCOPE_SUPPLIERS = ["100045"]
LEASE_SCOPE_POS = ["4500017", "4500021", "4500030"]
LEASE_MAX_PAYMENT_INR = 5000000
HIGH_VALUE_APPROVAL_INR = 200000
SEEN_CALL_IDS: Dict[str, dict] = {}
IDEMPOTENCY: Dict[str, dict] = {}
DENIALS: Dict[str, int] = {}
BANK_CHANGE_DECISIONS: List[dict] = []


def _erp() -> str:
    return os.environ.get("ERP_URL", "http://127.0.0.1:18001")


def _oracles() -> str:
    return os.environ.get("ORACLES_URL", "http://127.0.0.1:18002")


def _norm(name: str) -> str:
    s = (name or "").upper()
    s = re.sub(r"[.,'()]", " ", s)
    for w in ("PRIVATE", "PVT", "LIMITED", "LTD"):
        s = re.sub(rf"\b{w}\b", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _decision(
    decision: str,
    reason_code: str,
    *,
    rule_id: str,
    message: str,
    checks: List[dict],
    inr_at_risk: int = 0,
    formula: Optional[str] = None,
    result: Optional[dict] = None,
    approval_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    idempotent_replay: bool = False,
    http_status: Optional[int] = None,
):
    body = {
        "decision_id": str(uuid.uuid4()),
        "decision": decision,
        "reason_code": reason_code,
        "rule_id": rule_id,
        "message": message,
        "inr_at_risk": inr_at_risk,
        "formula": formula,
        "checks": checks,
        "result": result,
        "approval_id": approval_id,
        "safe_alternatives": ["request_human_approval", "flag_suspicious_message", "skip_step", "abort_task"],
        "correlation_id": correlation_id,
        "idempotent_replay": idempotent_replay,
    }
    if http_status is None:
        http_status = 200 if decision == "ALLOW" else 202 if decision == "HOLD" else 403
    return JSONResponse(status_code=http_status, content=body)


@app.get("/health")
def health():
    return {"status": "ok", "service": "gateway_stub", "port": 18000}


@app.post("/v1/test/reset")
def reset_stub_state():
    SEEN_CALL_IDS.clear()
    IDEMPOTENCY.clear()
    DENIALS.clear()
    BANK_CHANGE_DECISIONS.clear()
    return {"status": "RESET_OK"}


@app.post("/v1/tool-calls")
def tool_calls(
    payload: dict,
    authorization: Optional[str] = Header(None),
    x_lease: Optional[str] = Header(None, alias="X-Lease"),
    x_correlation_id: Optional[str] = Header(None, alias="X-Correlation-Id"),
):
    try:
        require_role(authorization, ["agent", "admin"])
    except HTTPException as exc:
        return _decision(
            "DENY",
            "DENY_AGENT_UNAUTHENTICATED",
            rule_id="R-GEN-01",
            message=str(exc.detail),
            checks=[{"name": "auth", "result": "fail", "detail": str(exc.detail)}],
            correlation_id=x_correlation_id,
            http_status=401,
        )

    tool = payload.get("tool")
    args = payload.get("args") or {}
    call_id = payload.get("call_id")
    idem = payload.get("idempotency_key")
    correlation_id = x_correlation_id or payload.get("task_id")
    checks: List[dict] = [{"name": "lease.present", "result": "pass" if x_lease else "skip", "detail": x_lease or "missing"}]

    lease_key = x_lease or "default-test-lease"
    if DENIALS.get(lease_key, 0) >= 3:
        return _decision(
            "DENY",
            "DENY_DENIAL_BUDGET_EXHAUSTED",
            rule_id="R-GEN-06",
            message="Lease suspended after 3 denials",
            checks=checks + [{"name": "denial_budget", "result": "fail", "detail": str(DENIALS.get(lease_key))}],
            correlation_id=correlation_id,
        )

    if call_id and call_id in SEEN_CALL_IDS:
        return _decision(
            "DENY",
            "DENY_NONCE_REUSED",
            rule_id="R-GEN-03",
            message="Call ID nonce was previously evaluated on this lease.",
            checks=checks + [{"name": "nonce", "result": "fail", "detail": call_id}],
            correlation_id=correlation_id,
            http_status=409,
        )

    if call_id:
        SEEN_CALL_IDS[call_id] = payload

    if idem and idem in IDEMPOTENCY:
        stored = IDEMPOTENCY[idem]
        if stored.get("args") != args or stored.get("tool") != tool:
            return _decision(
                "DENY",
                "DENY_NONCE_REUSED",
                rule_id="R-GEN-04",
                message="Idempotency key reused with a different payload",
                checks=checks + [{"name": "idempotency", "result": "fail", "detail": idem}],
                correlation_id=correlation_id,
                http_status=409,
            )
        replay = dict(stored["response"])
        replay["idempotent_replay"] = True
        return JSONResponse(status_code=200, content=replay)

    def deny(code, rule, message, inr=0, formula=None, extra=None, http_status=403):
        DENIALS[lease_key] = DENIALS.get(lease_key, 0) + 1
        return _decision(
            "DENY",
            code,
            rule_id=rule,
            message=message,
            checks=checks + (extra or []),
            inr_at_risk=inr,
            formula=formula,
            correlation_id=correlation_id,
            http_status=http_status,
        )

    def allow(rule, message, result=None, extra=None):
        resp = _decision(
            "ALLOW",
            "ALLOW_OK",
            rule_id=rule,
            message=message,
            checks=checks + (extra or []),
            result=result,
            correlation_id=correlation_id,
        )
        if idem:
            import json
            IDEMPOTENCY[idem] = {"tool": tool, "args": args, "response": json.loads(resp.body)}
        return resp

    erp = _erp()
    oracles = _oracles()
    try:
        client = httpx.Client(timeout=2.0)

        if tool == "update_supplier_bank":
            supplier = str(args.get("supplier"))
            if supplier not in LEASE_SCOPE_SUPPLIERS:
                return deny("DENY_OBJECT_NOT_IN_SCOPE", "R-GEN-02", f"Supplier '{supplier}' is not in authorized lease scope {LEASE_SCOPE_SUPPLIERS}")
            try:
                penny = client.post(
                    f"{oracles}/v1/penny-drop",
                    json={"bank_account": args.get("bank_account"), "ifsc": args.get("ifsc")},
                )
            except httpx.TimeoutException:
                return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-BANK-02", message="Penny-drop timed out", checks=checks, correlation_id=correlation_id)
            except Exception as exc:
                return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-BANK-02", message=str(exc), checks=checks, correlation_id=correlation_id)
            if penny.status_code >= 500 or penny.status_code == 504:
                return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-BANK-02", message="Oracle unavailable", checks=checks, correlation_id=correlation_id)
            if penny.status_code == 404:
                return deny("DENY_BANK_NAME_MISMATCH", "R-BANK-01", "Penny-drop account not found", inr=4850000)
            holder = penny.json().get("holder_name", "")
            sup = client.get(f"{erp}/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_Supplier('{supplier}')")
            gstin = sup.json()["d"]["GSTIN"] if sup.status_code == 200 else ""
            try:
                g = client.post(f"{oracles}/v1/gstin", json={"gstin": gstin})
            except Exception:
                return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-BANK-02", message="GSTIN oracle error", checks=checks, correlation_id=correlation_id)
            if g.status_code >= 500:
                return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-BANK-02", message="GSTIN oracle unavailable", checks=checks, correlation_id=correlation_id)
            if g.status_code != 200:
                return deny("DENY_BANK_NAME_MISMATCH", "R-BANK-01", "GSTIN not found")
            legal = g.json()["legal_name"]
            trade = g.json()["trade_name"]
            claimed = args.get("bank_account_holder_name") or holder
            score = max(
                fuzz.token_set_ratio(_norm(holder), _norm(legal)),
                fuzz.token_set_ratio(_norm(holder), _norm(trade)),
                fuzz.token_set_ratio(_norm(claimed), _norm(legal)),
                fuzz.token_set_ratio(_norm(claimed), _norm(trade)),
            )
            checks.append({"name": "oracle.penny_drop", "result": "pass", "detail": holder})
            checks.append({"name": "oracle.gstin", "result": "pass", "detail": f"{legal}/{trade}"})
            checks.append({"name": "name.score", "result": "pass" if score >= 90 else "fail", "detail": str(score)})
            if score < 70:
                rec = deny("DENY_BANK_NAME_MISMATCH", "R-BANK-01", f"Penny-drop holder '{holder}' does not match GSTIN '{legal}' (score {score} < 70)", inr=4850000)
                BANK_CHANGE_DECISIONS.append({"supplier": supplier, "decision": "DENY", "at": datetime.now(timezone.utc).isoformat()})
                return rec
            if score < 90:
                BANK_CHANGE_DECISIONS.append({"supplier": supplier, "decision": "HOLD", "at": datetime.now(timezone.utc).isoformat()})
                return _decision("HOLD", "HOLD_BANK_NAME_PARTIAL", rule_id="R-BANK-01", message=f"Partial name match score {score}", checks=checks, correlation_id=correlation_id)
            bank = client.get(
                f"{erp}/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartnerBank",
                params={"$filter": f"BusinessPartner eq '{supplier}'"},
            )
            etag = bank.json()["d"]["results"][0]["etag"] if bank.status_code == 200 else 'W/"1"'
            today = datetime.now(timezone.utc).date().isoformat()
            from libs.common.auth import create_token
            wr = f"Bearer {create_token('svc:gateway', ['erp_writer'])}"
            patch = client.patch(
                f"{erp}/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartnerBank(BusinessPartner='{supplier}',BankIdentification='0001')",
                headers={"Authorization": wr, "If-Match": etag},
                json={
                    "BankAccountHolderName": claimed,
                    "BankAccount": args.get("bank_account"),
                    "IFSC": args.get("ifsc"),
                    "ValidityStartDate": today,
                },
            )
            if patch.status_code >= 400:
                return deny("DENY_CONCURRENT_MODIFICATION", "R-GEN-05", patch.text, http_status=409)
            BANK_CHANGE_DECISIONS.append({"supplier": supplier, "decision": "ALLOW", "at": datetime.now(timezone.utc).isoformat()})
            return allow("R-BANK-01", "Bank verified", result=patch.json().get("d"))

        if tool == "execute_payment":
            amount = int(args.get("amount_inr") or 0)
            inv_id = str(args.get("supplier_invoice"))
            fy = str(args.get("fiscal_year") or "2026")
            if amount > LEASE_MAX_PAYMENT_INR:
                return deny("DENY_AMOUNT_EXCEEDS_LEASE", "R-PAY-03", f"Requested amount INR {amount:,} exceeds lease limit INR {LEASE_MAX_PAYMENT_INR:,}", inr=amount)
            inv = client.get(
                f"{erp}/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice(SupplierInvoice='{inv_id}',FiscalYear='{fy}')"
            )
            if inv.status_code != 200:
                return deny("DENY_INVOICE_NOT_PAYABLE", "R-PAY-01", "Invoice not found")
            d = inv.json()["d"]
            if d.get("Supplier") not in LEASE_SCOPE_SUPPLIERS:
                return deny("DENY_OBJECT_NOT_IN_SCOPE", "R-GEN-02", "Supplier not in lease")
            if d.get("Status") == "PAID":
                return deny("DENY_DUPLICATE_PAYMENT", "R-PAY-01", f"Supplier invoice {inv_id} is already in PAID status.", http_status=409)
            if d.get("Status") != "POSTED":
                return deny("DENY_INVOICE_NOT_PAYABLE", "R-PAY-01", f"Invoice status {d.get('Status')} is not payable")
            if amount != int(d.get("InvoiceGrossAmount")):
                return deny("DENY_AMOUNT_MISMATCH", "R-PAY-02", "Payment amount does not match invoice", inr=amount)
            for ev in reversed(BANK_CHANGE_DECISIONS):
                if ev["supplier"] == d.get("Supplier") and ev["decision"] in ("DENY", "HOLD"):
                    return _decision("HOLD", "HOLD_BANK_CHANGE_UNDER_REVIEW", rule_id="R-PAY-04", message="Bank change under review", checks=checks, inr_at_risk=amount, correlation_id=correlation_id)
            bank = client.get(
                f"{erp}/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartnerBank",
                params={"$filter": f"BusinessPartner eq '{d.get('Supplier')}'"},
            )
            if bank.status_code == 200 and bank.json()["d"]["results"]:
                start = bank.json()["d"]["results"][0].get("ValidityStartDate") or "2025-01-01"
                try:
                    start_dt = datetime.fromisoformat(start).date()
                except Exception:
                    start_dt = datetime(2025, 1, 1).date()
                if (datetime.now(timezone.utc).date() - start_dt).days < 3:
                    return _decision("HOLD", "HOLD_BANK_COOLING_OFF", rule_id="R-PAY-05", message="Bank change cooling-off", checks=checks, inr_at_risk=amount, correlation_id=correlation_id)
            from libs.common.auth import create_token
            wr = f"Bearer {create_token('svc:gateway', ['erp_writer'])}"
            pay = client.post(
                f"{erp}/sim/v1/payments",
                headers={"Authorization": wr, "Idempotency-Key": idem or str(uuid.uuid4())},
                json={"SupplierInvoice": inv_id, "FiscalYear": fy, "AmountInr": amount},
            )
            if pay.status_code == 409:
                return deny("DENY_DUPLICATE_PAYMENT", "R-PAY-01", pay.text, http_status=409)
            if pay.status_code >= 400:
                return deny("DENY_DEPENDENCY_UNAVAILABLE", "R-GEN-05", pay.text)
            result = pay.json()
            resp = allow("R-PAY-01", "Paid", result=result)
            if idem:
                import json
                IDEMPOTENCY[idem] = {"tool": tool, "args": args, "response": json.loads(resp.body)}
            return resp

        if tool == "post_supplier_invoice":
            po_id = str(args.get("purchase_order"))
            if po_id not in LEASE_SCOPE_POS:
                return deny("DENY_OBJECT_NOT_IN_SCOPE", "R-GEN-02", "PO not in lease")
            supplier = str(args.get("supplier"))
            if supplier not in LEASE_SCOPE_SUPPLIERS:
                return deny("DENY_OBJECT_NOT_IN_SCOPE", "R-GEN-02", "Supplier not in lease")
            po = client.get(
                f"{erp}/sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder('{po_id}')",
                params={"$expand": "to_PurchaseOrderItem"},
            )
            if po.status_code != 200:
                return deny("DENY_SCHEMA_INVALID", "R-INV-01", "PO not found")
            po_item = po.json()["d"]["to_PurchaseOrderItem"]["results"][0]
            net = int(po_item["NetPriceAmount"])
            items = args.get("items") or []
            variance = 0
            qty_sum = 0
            computed = 0
            for it in items:
                qty = int(it.get("quantity") or 0)
                price = int(it.get("unit_price_inr") or 0)
                qty_sum += qty
                computed += qty * price
                if price > net * 1.05:
                    variance += qty * (price - net)
            gross = int(args.get("gross_amount_inr") or 0)
            if gross != computed:
                return deny("DENY_AMOUNT_MISMATCH", "R-INV-03", "gross != sum qty*price")
            gr = client.get(
                f"{erp}/sap/opu/odata/sap/API_MATERIAL_DOCUMENT_SRV/A_MaterialDocumentItem",
                params={"$filter": f"PurchaseOrder eq '{po_id}'"},
            )
            gr_qty = sum(int(x["QuantityInEntryUnit"]) for x in gr.json()["d"]["results"]) if gr.status_code == 200 else 0
            if qty_sum > gr_qty:
                return deny("DENY_QTY_EXCEEDS_GR", "R-INV-02", "Invoiced qty exceeds GR")
            if variance:
                formula = f"invoice ₹{gross:,} > PO ₹{net * items[0].get('quantity', 0):,} × 1.05"
                return deny("DENY_PRICE_VARIANCE", "R-INV-01", "Invoiced unit price exceeds PO net price beyond 5.0% tolerance", inr=variance, formula=formula)
            from libs.common.auth import create_token
            wr = f"Bearer {create_token('svc:gateway', ['erp_writer'])}"
            posted = client.post(
                f"{erp}/sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice",
                headers={"Authorization": wr},
                json={
                    "Supplier": supplier,
                    "PurchaseOrder": po_id,
                    "SupplierInvoiceIDByExtParty": args.get("supplier_invoice_ref"),
                    "InvoiceGrossAmount": gross,
                    "items": items,
                },
            )
            if posted.status_code >= 400:
                return deny("DENY_POLICY_ERROR", "R-GEN-05", posted.text)
            return allow("R-INV-01", "Posted", result=posted.json().get("d"))

        if tool == "book_freight":
            po_id = str(args.get("purchase_order"))
            mode = str(args.get("mode") or "SEA").upper()
            if po_id not in LEASE_SCOPE_POS:
                return deny("DENY_OBJECT_NOT_IN_SCOPE", "R-GEN-02", "PO not in lease")
            po = client.get(f"{erp}/sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder('{po_id}')")
            if po.status_code != 200:
                return deny("DENY_SCHEMA_INVALID", "R-FRT-01", "PO not found")
            d = po.json()["d"]
            air = int(d.get("YY1_AirFreightQuoteInr") or 0)
            sea = int(d.get("YY1_SeaFreightPlannedInr") or 0)
            penalty = int(d.get("YY1_DelayPenaltyPerDayInr") or 0)
            days = int(args.get("claimed_delay_days") or 0)
            port = d.get("Port") or "JNPT"
            if mode == "AIR":
                delta = air - sea
                avoided = days * penalty
                formula = f"Air - Sea (₹{delta:,}) vs Delay Penalty Avoided ({days} days × ₹{penalty:,} = ₹{avoided:,})"
                if delta >= avoided:
                    return deny("DENY_FREIGHT_UNECONOMIC", "R-FRT-01", "Freight expedite is uneconomic", inr=delta, formula=formula)
                try:
                    ais = client.post(f"{oracles}/v1/ais/port", json={"port": port})
                except Exception as exc:
                    return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-FRT-02", message=str(exc), checks=checks, correlation_id=correlation_id)
                if ais.status_code >= 500:
                    return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-FRT-02", message="AIS unavailable", checks=checks, correlation_id=correlation_id)
                if ais.status_code != 200:
                    return deny("DENY_SIGNAL_CONTRADICTED", "R-FRT-02", "Unknown port / AIS miss")
                ais_body = ais.json()
                if ais_body.get("status") == "NORMAL" or int(ais_body.get("berthed_today") or 0) >= 3:
                    return deny("DENY_SIGNAL_CONTRADICTED", "R-FRT-02", "AIS reports normal operations", inr=delta, formula=formula)
                if air > HIGH_VALUE_APPROVAL_INR:
                    return _decision(
                        "HOLD",
                        "HOLD_AMOUNT_NEEDS_APPROVAL",
                        rule_id="R-FRT-03",
                        message=f"Air freight ₹{air:,} exceeds approval threshold ₹{HIGH_VALUE_APPROVAL_INR:,}",
                        checks=checks,
                        inr_at_risk=air,
                        formula=formula,
                        correlation_id=correlation_id,
                    )
            from libs.common.auth import create_token
            wr = f"Bearer {create_token('svc:gateway', ['erp_writer'])}"
            booked = client.post(
                f"{erp}/sim/v1/freight-bookings",
                headers={"Authorization": wr, "Idempotency-Key": idem or str(uuid.uuid4())},
                json={"PurchaseOrder": po_id, "Mode": mode, "CostInr": int(args.get("quoted_cost_inr") or sea), "Reason": args.get("reason")},
            )
            if booked.status_code >= 400:
                return deny("DENY_POLICY_ERROR", "R-GEN-05", booked.text)
            return allow("R-FRT-01", "Booked", result=booked.json())

        return deny("DENY_TOOL_NOT_IN_SCOPE", "R-GEN-02", f"Unknown tool {tool}")
    except httpx.TimeoutException:
        return _decision("HOLD", "HOLD_ORACLE_UNAVAILABLE", rule_id="R-GEN-05", message="Dependency timeout", checks=checks, correlation_id=correlation_id)
    except Exception as exc:
        return _decision("DENY", "DENY_POLICY_ERROR", rule_id="R-GEN-05", message=str(exc), checks=checks, correlation_id=correlation_id)
    finally:
        try:
            client.close()
        except Exception:
            pass
