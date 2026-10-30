"""Protected business state digest computation."""

import datetime
from typing import Any, Dict
from sqlalchemy.orm import Session
from libs.common.canonical import sha256_canonical
from services.erp_sim.app.db.models import (
    BusinessPartnerBank,
    FreightBooking,
    Payment,
    SupplierInvoice,
)


def compute_state_digest(db: Session) -> Dict[str, Any]:
    """Compute sha256 over canonical JSON of protected business state:
    - all supplier banks (sorted)
    - all invoices with status (sorted)
    - all payments (sorted)
    - all freight bookings (sorted)
    """
    banks = (
        db.query(BusinessPartnerBank)
        .order_by(BusinessPartnerBank.BusinessPartner, BusinessPartnerBank.BankIdentification)
        .all()
    )
    invoices = (
        db.query(SupplierInvoice)
        .order_by(SupplierInvoice.SupplierInvoice, SupplierInvoice.FiscalYear)
        .all()
    )
    payments = db.query(Payment).order_by(Payment.payment_id).all()
    bookings = db.query(FreightBooking).order_by(FreightBooking.booking_id).all()

    banks_data = [
        {
            "BusinessPartner": b.BusinessPartner,
            "BankIdentification": b.BankIdentification,
            "BankAccount": b.BankAccount,
            "FullBankAccount": b.FullBankAccount,
            "IFSC": b.IFSC,
            "ValidityStartDate": b.ValidityStartDate,
            "BankAccountHolderName": b.BankAccountHolderName,
        }
        for b in banks
    ]

    invoices_data = [
        {
            "SupplierInvoice": i.SupplierInvoice,
            "FiscalYear": i.FiscalYear,
            "Supplier": i.Supplier,
            "PurchaseOrder": i.PurchaseOrder,
            "InvoiceGrossAmount": i.InvoiceGrossAmount,
            "Status": i.Status,
        }
        for i in invoices
    ]

    payments_data = [
        {
            "payment_id": p.payment_id,
            "supplier_invoice": p.supplier_invoice,
            "fiscal_year": p.fiscal_year,
            "amount_inr": p.amount_inr,
            "paid_to_bank_id": p.paid_to_bank_id,
            "idempotency_key": p.idempotency_key,
        }
        for p in payments
    ]

    bookings_data = [
        {
            "booking_id": bk.booking_id,
            "purchase_order": bk.purchase_order,
            "mode": bk.mode,
            "cost_inr": bk.cost_inr,
            "reason": bk.reason or "",
            "idempotency_key": bk.idempotency_key,
        }
        for bk in bookings
    ]

    protected_state = {
        "supplier_banks": banks_data,
        "invoices": invoices_data,
        "payments": payments_data,
        "freight_bookings": bookings_data,
    }

    digest = sha256_canonical(protected_state)
    computed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    return {
        "digest": digest,
        "computed_at": computed_at,
        "counts": {
            "supplier_banks": len(banks_data),
            "invoices": len(invoices_data),
            "payments": len(payments_data),
            "freight_bookings": len(bookings_data),
        },
    }
