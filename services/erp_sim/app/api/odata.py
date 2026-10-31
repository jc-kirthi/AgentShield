"""OData V2 SAP-style API endpoints for Mock S/4HANA."""

import re
import urllib.parse
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from libs.common.auth import require_role
from libs.common.settings import settings
from services.erp_sim.app.core.validate import require_int, require_str
from services.erp_sim.app.db.models import (
    BusinessPartnerBank,
    MaterialDocumentItem,
    PurchaseOrder,
    PurchaseOrderItem,
    Supplier,
    SupplierInvoice,
)
from services.erp_sim.app.db.session import get_db


router = APIRouter(prefix="/sap/opu/odata/sap")


def parse_odata_key(path_val: str) -> str:
    """Extract string value from OData key syntax like '100045'."""
    val = path_val.strip()
    if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
        return val[1:-1]
    return val


def parse_composite_key(path_val: str) -> dict:
    """Extract key-value pairs from composite key like (BusinessPartner='100045',BankIdentification='0001')."""
    # Remove outer parentheses if present
    s = path_val.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1]
    parts = s.split(",")
    res = {}
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            res[k.strip()] = parse_odata_key(v.strip())
    return res


# ============================================================================
# API_BUSINESS_PARTNER
# ============================================================================

@router.get("/API_BUSINESS_PARTNER/A_Supplier({supplier_id})")
def get_supplier(supplier_id: str, response: Response, db: Session = Depends(get_db)):
    clean_id = parse_odata_key(supplier_id)
    sup = db.query(Supplier).filter(Supplier.Supplier == clean_id).first()
    if not sup:
        raise HTTPException(status_code=404, detail={"error": "Supplier not found"})

    response.headers["ETag"] = sup.etag
    return {
        "d": {
            "__metadata": {
                "id": f"A_Supplier('{sup.Supplier}')",
                "uri": f"/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_Supplier('{sup.Supplier}')",
                "type": "API_BUSINESS_PARTNER.A_SupplierType",
                "etag": sup.etag,
            },
            "Supplier": sup.Supplier,
            "SupplierName": sup.SupplierName,
            "GSTIN": sup.GSTIN,
            "EmailDomain": sup.EmailDomain,
            "etag": sup.etag,
        }
    }


@router.get("/API_BUSINESS_PARTNER/A_BusinessPartnerBank")
def list_business_partner_banks(
    filter_expr: Optional[str] = Query(None, alias="$filter"),
    db: Session = Depends(get_db),
):
    query = db.query(BusinessPartnerBank)
    if filter_expr:
        # e.g. BusinessPartner eq '100045'
        match = re.search(r"BusinessPartner\s+eq\s+['\"]?([^'\"]+)['\"]?", filter_expr, re.IGNORECASE)
        if match:
            bp_id = match.group(1)
            query = query.filter(BusinessPartnerBank.BusinessPartner == bp_id)

    banks = query.all()
    results = []
    for b in banks:
        results.append({
            "__metadata": {
                "id": f"A_BusinessPartnerBank(BusinessPartner='{b.BusinessPartner}',BankIdentification='{b.BankIdentification}')",
                "type": "API_BUSINESS_PARTNER.A_BusinessPartnerBankType",
                "etag": b.etag,
            },
            "BusinessPartner": b.BusinessPartner,
            "Supplier": b.BusinessPartner,
            "BankIdentification": b.BankIdentification,
            "BankAccountHolderName": b.BankAccountHolderName,
            "BankAccountMasked": b.BankAccount,
            "BankAccount": b.BankAccount,
            "FullBankAccount": b.FullBankAccount,
            "IFSC": b.IFSC,
            "ValidityStartDate": b.ValidityStartDate,
            "etag": b.etag,
        })
    return {"d": {"results": results}}


@router.patch("/API_BUSINESS_PARTNER/A_BusinessPartnerBank({key})")
def update_business_partner_bank(
    key: str,
    payload: dict,
    response: Response,
    if_match: Optional[str] = Header(None, alias="If-Match"),
    x_sim_profile: Optional[str] = Header(None, alias="X-Sim-Profile"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    # Verify erp_writer authorization
    require_role(authorization, ["erp_writer", "admin"])

    keys = parse_composite_key(key)
    bp = keys.get("BusinessPartner")
    bank_id = keys.get("BankIdentification")

    bank = (
        db.query(BusinessPartnerBank)
        .filter(
            BusinessPartnerBank.BusinessPartner == bp,
            BusinessPartnerBank.BankIdentification == bank_id,
        )
        .first()
    )
    if not bank:
        raise HTTPException(status_code=404, detail="Bank record not found")

    # 428 Precondition Required if missing If-Match
    if not if_match:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="If-Match header is required for bank modification",
        )

    # Spec: If-Match must equal the current ETag. Wildcard "*" is only
    # accepted on the SANDBOX vulnerable-profile path used by AttackLab.
    allow_wildcard = (
        if_match.strip() == "*"
        and settings.sandbox
        and (x_sim_profile or "").upper() == "VULNERABLE"
    )
    if if_match.strip() != bank.etag.strip() and not allow_wildcard:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=f"ETag mismatch. Current: {bank.etag}, provided: {if_match}",
        )

    # Update fields
    if "BankAccountHolderName" in payload:
        bank.BankAccountHolderName = payload["BankAccountHolderName"]
    if "BankAccount" in payload:
        raw_acct = str(payload["BankAccount"])
        bank.FullBankAccount = raw_acct
        bank.BankAccount = f"XXXXXX{raw_acct[-4:]}" if len(raw_acct) >= 4 else raw_acct
    if "FullBankAccount" in payload:
        bank.FullBankAccount = str(payload["FullBankAccount"])
    if "IFSC" in payload:
        bank.IFSC = payload["IFSC"]
    if "ValidityStartDate" in payload:
        bank.ValidityStartDate = payload["ValidityStartDate"]

    # Bump ETag version
    try:
        curr_ver = int(bank.etag.replace('W/"', "").replace('"', ""))
        bank.etag = f'W/"{curr_ver + 1}"'
    except Exception:
        bank.etag = 'W/"2"'

    db.commit()
    db.refresh(bank)

    response.headers["ETag"] = bank.etag
    return {
        "d": {
            "Supplier": bank.BusinessPartner,
            "BusinessPartner": bank.BusinessPartner,
            "BankIdentification": bank.BankIdentification,
            "BankAccountHolderName": bank.BankAccountHolderName,
            "BankAccountMasked": bank.BankAccount,
            "IFSC": bank.IFSC,
            "ValidityStartDate": bank.ValidityStartDate,
            "Status": "UPDATED",
            "etag": bank.etag,
        }
    }


# ============================================================================
# API_PURCHASEORDER_PROCESS_SRV
# ============================================================================

@router.get("/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder({po_id})")
def get_purchase_order(
    po_id: str,
    response: Response,
    expand: Optional[str] = Query(None, alias="$expand"),
    db: Session = Depends(get_db),
):
    clean_id = parse_odata_key(po_id)
    po = db.query(PurchaseOrder).filter(PurchaseOrder.PurchaseOrder == clean_id).first()
    if not po:
        raise HTTPException(status_code=404, detail="Purchase Order not found")

    response.headers["ETag"] = po.etag

    items_result = []
    if expand and "to_PurchaseOrderItem" in expand:
        items = db.query(PurchaseOrderItem).filter(PurchaseOrderItem.PurchaseOrder == clean_id).all()
        for it in items:
            items_result.append({
                "PurchaseOrder": it.PurchaseOrder,
                "PurchaseOrderItem": it.PurchaseOrderItem,
                "Material": it.Material,
                "OrderQuantity": it.OrderQuantity,
                "NetPriceAmount": it.NetPriceAmount,
                "Currency": it.Currency,
            })

    d = {
        "PurchaseOrder": po.PurchaseOrder,
        "Supplier": po.Supplier,
        "CompanyCode": po.CompanyCode,
        "Port": po.Port,
        "YY1_SeaFreightPlannedInr": po.YY1_SeaFreightPlannedInr,
        "YY1_AirFreightQuoteInr": po.YY1_AirFreightQuoteInr,
        "YY1_DelayPenaltyPerDayInr": po.YY1_DelayPenaltyPerDayInr,
        "etag": po.etag,
        "items": items_result,
    }
    if items_result:
        d["to_PurchaseOrderItem"] = {"results": items_result}

    return {"d": d}


# ============================================================================
# API_MATERIAL_DOCUMENT_SRV (Goods Receipts)
# ============================================================================

@router.get("/API_MATERIAL_DOCUMENT_SRV/A_MaterialDocumentItem")
def list_material_document_items(
    filter_expr: Optional[str] = Query(None, alias="$filter"),
    db: Session = Depends(get_db),
):
    query = db.query(MaterialDocumentItem)
    if filter_expr:
        match = re.search(r"PurchaseOrder\s+eq\s+['\"]?([^'\"]+)['\"]?", filter_expr, re.IGNORECASE)
        if match:
            po_id = match.group(1)
            query = query.filter(MaterialDocumentItem.PurchaseOrder == po_id)

    grs = query.all()
    results = [
        {
            "MaterialDocument": g.MaterialDocument,
            "PurchaseOrder": g.PurchaseOrder,
            "PurchaseOrderItem": g.PurchaseOrderItem,
            "QuantityInEntryUnit": g.QuantityInEntryUnit,
            "PostingDate": g.PostingDate,
        }
        for g in grs
    ]
    return {"d": {"results": results}}


# ============================================================================
# API_SUPPLIERINVOICE_PROCESS_SRV
# ============================================================================

@router.get("/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice")
def list_supplier_invoices(
    filter_expr: Optional[str] = Query(None, alias="$filter"),
    db: Session = Depends(get_db),
):
    query = db.query(SupplierInvoice)
    if filter_expr:
        match_ref = re.search(r"SupplierInvoiceIDByExtParty\s+eq\s+['\"]?([^'\"]+)['\"]?", filter_expr, re.IGNORECASE)
        if match_ref:
            query = query.filter(SupplierInvoice.SupplierInvoiceIDByExtParty == match_ref.group(1))

        match_sup = re.search(r"Supplier\s+eq\s+['\"]?([^'\"]+)['\"]?", filter_expr, re.IGNORECASE)
        if match_sup:
            query = query.filter(SupplierInvoice.Supplier == match_sup.group(1))

    invoices = query.all()
    results = [
        {
            "SupplierInvoice": inv.SupplierInvoice,
            "FiscalYear": inv.FiscalYear,
            "SupplierInvoiceIDByExtParty": inv.SupplierInvoiceIDByExtParty,
            "Supplier": inv.Supplier,
            "PurchaseOrder": inv.PurchaseOrder,
            "InvoiceGrossAmount": inv.InvoiceGrossAmount,
            "Status": inv.Status,
            "DueDate": inv.DueDate,
            "DocumentDate": inv.DocumentDate,
            "etag": inv.etag,
        }
        for inv in invoices
    ]
    return {"d": {"results": results}}


@router.get("/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice({key})")
def get_supplier_invoice(key: str, response: Response, db: Session = Depends(get_db)):
    keys = parse_composite_key(key)
    inv_id = keys.get("SupplierInvoice")
    fy = keys.get("FiscalYear")

    inv = (
        db.query(SupplierInvoice)
        .filter(
            SupplierInvoice.SupplierInvoice == inv_id,
            SupplierInvoice.FiscalYear == fy,
        )
        .first()
    )
    if not inv:
        raise HTTPException(status_code=404, detail="Supplier Invoice not found")

    response.headers["ETag"] = inv.etag
    return {
        "d": {
            "SupplierInvoice": inv.SupplierInvoice,
            "FiscalYear": inv.FiscalYear,
            "SupplierInvoiceIDByExtParty": inv.SupplierInvoiceIDByExtParty,
            "Supplier": inv.Supplier,
            "PurchaseOrder": inv.PurchaseOrder,
            "InvoiceGrossAmount": inv.InvoiceGrossAmount,
            "Status": inv.Status,
            "DueDate": inv.DueDate,
            "DocumentDate": inv.DocumentDate,
            "etag": inv.etag,
        }
    }


@router.post(
    "/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice",
    status_code=status.HTTP_201_CREATED,
)
def create_supplier_invoice(
    payload: dict,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    # Verify erp_writer authorization
    require_role(authorization, ["erp_writer", "admin"])

    supplier = require_str(payload, "Supplier", "supplier")
    po = require_str(payload, "PurchaseOrder", "purchase_order")
    ext_ref = require_str(payload, "SupplierInvoiceIDByExtParty", "supplier_invoice_ref")
    gross_amount = require_int(payload, "InvoiceGrossAmount", "gross_amount_inr")
    fiscal_year = str(payload.get("FiscalYear") or "2026")
    doc_date = str(payload.get("DocumentDate") or payload.get("invoice_date") or "2026-10-29")

    sup = db.query(Supplier).filter(Supplier.Supplier == supplier).first()
    if not sup:
        raise HTTPException(status_code=404, detail=f"Unknown supplier {supplier}")
    po_row = db.query(PurchaseOrder).filter(PurchaseOrder.PurchaseOrder == po).first()
    if not po_row:
        raise HTTPException(status_code=404, detail=f"Unknown purchase order {po}")
    if po_row.Supplier != supplier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Purchase order {po} does not belong to supplier {supplier}",
        )

    items = payload.get("items")
    if items is not None:
        if not isinstance(items, list) or not items:
            raise HTTPException(status_code=400, detail="items must be a non-empty list when provided")
        computed = 0
        for item in items:
            qty = require_int(item, "quantity", "Quantity", field="quantity")
            price = require_int(item, "unit_price_inr", "NetPriceAmount", field="unit_price_inr")
            computed += qty * price
        if computed != gross_amount:
            raise HTTPException(
                status_code=400,
                detail=f"gross_amount_inr {gross_amount} != sum(qty*price) {computed}",
            )

    dup = (
        db.query(SupplierInvoice)
        .filter(SupplierInvoice.SupplierInvoiceIDByExtParty == ext_ref)
        .first()
    )
    if dup:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Duplicate supplier invoice reference {ext_ref}",
        )

    # Generate sequential invoice ID
    count = db.query(SupplierInvoice).count()
    inv_id = f"510560{1000 + count + 1}"

    inv = SupplierInvoice(
        SupplierInvoice=inv_id,
        FiscalYear=fiscal_year,
        SupplierInvoiceIDByExtParty=ext_ref,
        Supplier=supplier,
        PurchaseOrder=po,
        InvoiceGrossAmount=gross_amount,
        Status="POSTED",
        DueDate="2026-11-28",
        DocumentDate=doc_date,
        etag='W/"1"',
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)

    return {
        "d": {
            "SupplierInvoice": inv.SupplierInvoice,
            "FiscalYear": inv.FiscalYear,
            "Status": inv.Status,
            "SupplierInvoiceIDByExtParty": inv.SupplierInvoiceIDByExtParty,
            "InvoiceGrossAmount": inv.InvoiceGrossAmount,
        }
    }
