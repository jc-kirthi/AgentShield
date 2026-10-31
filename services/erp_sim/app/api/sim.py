"""Simulator extension endpoints for Mock S/4HANA."""

import base64
import os
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from libs.common.auth import require_role
from libs.common.canonical import sha256_canonical
from libs.common.settings import settings
from services.erp_sim.app.core.digest import compute_state_digest
from services.erp_sim.app.core.docs import extract_text_from_pdf
from services.erp_sim.app.core.validate import require_int, require_str
from services.erp_sim.app.db.models import (
    BusinessPartnerBank,
    FreightBooking,
    InboxDocument,
    InboxMessage,
    Payment,
    PurchaseOrder,
    Supplier,
    SupplierInvoice,
)
from services.erp_sim.app.db.seed import reset_and_seed
from services.erp_sim.app.db.session import get_db


router = APIRouter(prefix="/sim/v1")


@router.get("/inbox")
def list_inbox(unread_only: bool = Query(True), db: Session = Depends(get_db)):
    query = db.query(InboxMessage)
    if unread_only:
        query = query.filter(InboxMessage.is_read == False)

    messages = query.order_by(InboxMessage.received_at.desc()).all()
    res = []
    for m in messages:
        docs = db.query(InboxDocument).filter(InboxDocument.message_id == m.message_id).all()
        attachments = [
            {"document_id": d.document_id, "filename": d.filename}
            for d in docs
        ]
        res.append({
            "message_id": m.message_id,
            "from_address": m.from_address,
            "from_domain": m.from_domain,
            "subject": m.subject,
            "received_at": m.received_at,
            "body_preview": m.body_preview,
            "body": m.body,
            "flagged": m.flagged,
            "attachments": attachments,
        })
    return {"messages": res}


@router.post("/inbound/email", status_code=status.HTTP_201_CREATED)
def inject_inbound_email(
    payload: dict,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Inbound email injection endpoint used by AttackLab and tests."""
    require_role(authorization, ["attacker_sandbox", "admin", "erp_writer"])
    msg_id = payload.get("message_id") or f"M-INJ-{uuid.uuid4().hex[:6]}"
    from_addr = payload.get("from_address", "attacker@unknown.com")
    from_dom = from_addr.split("@")[-1] if "@" in from_addr else "unknown.com"
    subject = payload.get("subject", "Urgent Notification")
    body = payload.get("body", "")
    preview = body[:80] if len(body) > 80 else body
    received_at = payload.get("received_at", "2026-10-29T09:00:00Z")

    msg = InboxMessage(
        message_id=msg_id,
        from_address=from_addr,
        from_domain=from_dom,
        subject=subject,
        received_at=received_at,
        body_preview=preview,
        body=body,
        flagged=False,
        is_read=False,
    )
    db.add(msg)

    # Attachments
    attachments = payload.get("attachments", [])
    if "attachment" in payload and isinstance(payload["attachment"], dict):
        attachments.append(payload["attachment"])

    created_docs = []
    for att in attachments:
        doc_id = att.get("document_id") or f"DOC-INJ-{uuid.uuid4().hex[:6]}"
        fname = att.get("filename", "attachment.pdf")
        b64_content = att.get("raw_bytes") or att.get("content_bytes_b64") or ""
        text_content = att.get("text_content") or ""

        # If raw_bytes provided and no text_content, extract using pypdf
        if b64_content and not text_content:
            try:
                raw_bytes = base64.b64decode(b64_content)
                text_content = extract_text_from_pdf(raw_bytes)
            except Exception:
                text_content = ""

        doc = InboxDocument(
            document_id=doc_id,
            message_id=msg_id,
            filename=fname,
            raw_bytes=b64_content,
            text_content=text_content,
            provenance="external_email_attachment",
        )
        db.add(doc)
        created_docs.append(doc_id)

    db.commit()
    return {
        "message_id": msg_id,
        "status": "DELIVERED",
        "attachments": created_docs,
    }


@router.get("/documents/{document_id}/text")
def get_document_text(document_id: str, db: Session = Depends(get_db)):
    doc = db.query(InboxDocument).filter(InboxDocument.document_id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    text = doc.text_content
    truncated = False
    if len(text) > 4000:
        text = text[:4000]
        truncated = True

    return {
        "document_id": doc.document_id,
        "filename": doc.filename,
        "text": text,
        "provenance": doc.provenance,
        "truncated": truncated,
    }


@router.get("/documents/{document_id}/raw")
def get_document_raw(document_id: str, db: Session = Depends(get_db)):
    doc = db.query(InboxDocument).filter(InboxDocument.document_id == document_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    try:
        raw_bytes = base64.b64decode(doc.raw_bytes)
    except Exception:
        raw_bytes = doc.raw_bytes.encode("utf-8")

    return Response(
        content=raw_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="{doc.filename}"'},
    )


@router.post("/messages/{message_id}/flag")
def flag_message(
    message_id: str,
    payload: dict,
    db: Session = Depends(get_db),
):
    msg = db.query(InboxMessage).filter(InboxMessage.message_id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")

    msg.flagged = True
    msg.flag_reason = payload.get("reason", "Flagged as suspicious")
    db.commit()
    return {"flagged": True, "message_id": message_id}


@router.post("/payments", status_code=status.HTTP_201_CREATED)
def execute_payment(
    payload: dict,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    x_sim_profile: Optional[str] = Header(None, alias="X-Sim-Profile"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Execute supplier invoice payment."""
    require_role(authorization, ["erp_writer", "admin"])

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Missing required Idempotency-Key header")

    inv_id = require_str(payload, "SupplierInvoice", "supplier_invoice")
    fy = str(payload.get("FiscalYear") or payload.get("fiscal_year") or "2026")
    amount = require_int(payload, "AmountInr", "amount_inr")
    intent_hash = sha256_canonical(
        {"SupplierInvoice": inv_id, "FiscalYear": fy, "AmountInr": amount}
    )

    inv = (
        db.query(SupplierInvoice)
        .filter(
            SupplierInvoice.SupplierInvoice == inv_id,
            SupplierInvoice.FiscalYear == fy,
        )
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Supplier invoice not found")

    # In VULNERABLE profile when SANDBOX=1, allow duplicate payment for red-team blast-radius measurement
    allow_duplicate_vulnerable = (
        settings.sandbox and x_sim_profile and x_sim_profile.upper() == "VULNERABLE"
    )

    if not allow_duplicate_vulnerable:
        # Check idempotency replay
        existing_payment_key = (
            db.query(Payment).filter(Payment.idempotency_key == idempotency_key).first()
        )
        if existing_payment_key:
            stored_hash = existing_payment_key.payload_hash
            if stored_hash and stored_hash != intent_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency-Key reused with a different payment payload",
                )
            return {
                "PaymentId": existing_payment_key.payment_id,
                "SupplierInvoice": existing_payment_key.supplier_invoice,
                "AmountInr": existing_payment_key.amount_inr,
                "PaidToBankIdentification": existing_payment_key.paid_to_bank_id,
                "Status": "PAID",
                "idempotent_replay": True,
            }

        # Check unique constraint (SupplierInvoice, FiscalYear)
        if inv.Status == "PAID":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Supplier invoice {inv_id}/{fy} is already PAID",
            )
        existing_payment_inv = (
            db.query(Payment)
            .filter(Payment.supplier_invoice == inv_id, Payment.fiscal_year == fy)
            .first()
        )
        if existing_payment_inv:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Payment for invoice {inv_id}/{fy} already recorded",
            )

    # Find supplier's current active bank identification
    bank = (
        db.query(BusinessPartnerBank)
        .filter(BusinessPartnerBank.BusinessPartner == inv.Supplier)
        .order_by(BusinessPartnerBank.ValidityStartDate.desc())
        .first()
    )
    bank_id = bank.BankIdentification if bank else "0001"

    payment_id = f"PAY-{uuid.uuid4().hex[:8].upper()}"
    payment = Payment(
        payment_id=payment_id,
        supplier_invoice=inv_id,
        fiscal_year=fy,
        amount_inr=amount,
        paid_to_bank_id=bank_id,
        idempotency_key=f"{idempotency_key}-{uuid.uuid4().hex[:4]}" if allow_duplicate_vulnerable else idempotency_key,
        payload_hash=intent_hash,
    )
    db.add(payment)

    inv.Status = "PAID"
    db.commit()

    return {
        "PaymentId": payment_id,
        "SupplierInvoice": inv_id,
        "AmountInr": amount,
        "PaidToBankIdentification": bank_id,
        "Status": "PAID",
    }


@router.post("/freight-bookings", status_code=status.HTTP_201_CREATED)
def book_freight(
    payload: dict,
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Book freight for a purchase order."""
    require_role(authorization, ["erp_writer", "admin"])

    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Missing required Idempotency-Key header")

    # Idempotent replay check
    existing = (
        db.query(FreightBooking)
        .filter(FreightBooking.idempotency_key == idempotency_key)
        .first()
    )
    if existing:
        return {
            "BookingId": existing.booking_id,
            "PurchaseOrder": existing.purchase_order,
            "Mode": existing.mode,
            "CostInr": existing.cost_inr,
            "Status": "BOOKED",
            "idempotent_replay": True,
        }

    po_id = require_str(payload, "PurchaseOrder", "purchase_order")
    mode = str(payload.get("Mode") or payload.get("mode", "SEA")).upper()
    if mode not in ("AIR", "SEA"):
        raise HTTPException(status_code=400, detail="Mode must be AIR or SEA")
    cost = require_int(payload, "CostInr", "quoted_cost_inr")
    if cost <= 0:
        raise HTTPException(status_code=400, detail="CostInr must be a positive integer")
    reason = str(payload.get("Reason") or payload.get("reason", ""))
    po_row = db.query(PurchaseOrder).filter(PurchaseOrder.PurchaseOrder == po_id).first()
    if not po_row:
        raise HTTPException(status_code=404, detail=f"Unknown purchase order {po_id}")

    booking_id = f"FRT-{uuid.uuid4().hex[:8].upper()}"
    booking = FreightBooking(
        booking_id=booking_id,
        purchase_order=po_id,
        mode=mode,
        cost_inr=cost,
        reason=reason,
        idempotency_key=idempotency_key,
    )
    db.add(booking)
    db.commit()

    return {
        "BookingId": booking_id,
        "PurchaseOrder": po_id,
        "Mode": mode,
        "CostInr": cost,
        "Status": "BOOKED",
    }


@router.get("/state-digest")
def get_state_digest(db: Session = Depends(get_db)):
    """Compute and return authoritative sha256 state digest."""
    return compute_state_digest(db)


@router.get("/snapshot")
def get_snapshot(db: Session = Depends(get_db)):
    """Export complete business state for review/debugging."""
    return {
        "suppliers": [s.Supplier for s in db.query(Supplier).all()],
        "banks": [
            {
                "bp": b.BusinessPartner,
                "id": b.BankIdentification,
                "holder": b.BankAccountHolderName,
                "acct": b.BankAccount,
                "ifsc": b.IFSC,
                "start": b.ValidityStartDate,
                "etag": b.etag,
            }
            for b in db.query(BusinessPartnerBank).all()
        ],
        "purchase_orders": [po.PurchaseOrder for po in db.query(PurchaseOrder).all()],
        "invoices": [
            {
                "id": i.SupplierInvoice,
                "fy": i.FiscalYear,
                "amount": i.InvoiceGrossAmount,
                "status": i.Status,
            }
            for i in db.query(SupplierInvoice).all()
        ],
        "payments": [
            {"id": p.payment_id, "inv": p.supplier_invoice, "amount": p.amount_inr}
            for p in db.query(Payment).all()
        ],
        "freight_bookings": [
            {"id": f.booking_id, "po": f.purchase_order, "mode": f.mode, "cost": f.cost_inr}
            for f in db.query(FreightBooking).all()
        ],
        "digest": compute_state_digest(db),
    }


@router.post("/admin/reset")
def admin_reset(db: Session = Depends(get_db)):
    """Reset the database to golden seed state and compute golden digest."""
    reset_and_seed(db)
    digest_info = compute_state_digest(db)
    return {
        "status": "RESET_OK",
        "golden_digest": digest_info["digest"],
        "counts": digest_info["counts"],
        "computed_at": digest_info["computed_at"],
    }


@router.get("/sap/live-read")
def sap_live_read(
    entity: str = Query("A_Supplier"),
    key: Optional[str] = Query("100045"),
    db: Session = Depends(get_db),
):
    """SAP live-read adapter endpoint (spec 13.7 P0).
    Displays entity data with latency, count, timestamp, and SAP sandbox / SIMULATED badge.
    """
    badge = (
        "SAP sandbox (read-only test data)"
        if settings.erp_read_backend == "sap_sandbox"
        else "SIMULATED (erp_sim)"
    )

    if entity == "A_Supplier":
        sup = db.query(Supplier).filter(Supplier.Supplier == key).first()
        data = (
            {
                "Supplier": sup.Supplier,
                "SupplierName": sup.SupplierName,
                "GSTIN": sup.GSTIN,
                "EmailDomain": sup.EmailDomain,
            }
            if sup
            else None
        )
    elif entity == "A_PurchaseOrder":
        po = db.query(PurchaseOrder).filter(PurchaseOrder.PurchaseOrder == key).first()
        data = (
            {
                "PurchaseOrder": po.PurchaseOrder,
                "Supplier": po.Supplier,
                "CompanyCode": po.CompanyCode,
                "Port": po.Port,
            }
            if po
            else None
        )
    else:
        data = {}

    return {
        "entity": entity,
        "key": key,
        "badge": badge,
        "backend": settings.erp_read_backend,
        "status": 200,
        "latency_ms": 12,
        "data": data,
    }
