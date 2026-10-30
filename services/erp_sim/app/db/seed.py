"""Golden Seed initialization for Mock S/4HANA (erp_sim)."""

import base64
from sqlalchemy.orm import Session
from services.erp_sim.app.core.docs import generate_legit_invoice_pdf
from services.erp_sim.app.db.models import (
    Base,
    BusinessPartnerBank,
    FreightBooking,
    InboxDocument,
    InboxMessage,
    MaterialDocumentItem,
    Payment,
    PurchaseOrder,
    PurchaseOrderItem,
    Supplier,
    SupplierInvoice,
)
from services.erp_sim.app.db.session import engine


def reset_and_seed(db: Session):
    """Drop all tables, recreate schemas, and populate with exact Golden Seed data."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # 1. Suppliers
    s1 = Supplier(
        Supplier="100045",
        SupplierName="Ultra Bearings Pvt Ltd",
        GSTIN="27AABCU9603R1ZM",
        EmailDomain="ultra-bearings.com",
        etag='W/"1"',
    )
    s2 = Supplier(
        Supplier="100099",
        SupplierName="Shakti Castings Pvt Ltd",
        GSTIN="29AAECS1234F1Z5",
        EmailDomain="shakti-castings.com",
        etag='W/"1"',
    )
    db.add_all([s1, s2])
    db.flush()

    # 2. Banks
    b1 = BusinessPartnerBank(
        BusinessPartner="100045",
        BankIdentification="0001",
        BankAccountHolderName="ULTRA BEARINGS PRIVATE LIMITED",
        BankAccount="XXXXXX4417",
        FullBankAccount="91001004417",
        IFSC="HDFC0000123",
        ValidityStartDate="2025-04-01",
        etag='W/"1"',
    )
    b2 = BusinessPartnerBank(
        BusinessPartner="100099",
        BankIdentification="0001",
        BankAccountHolderName="SHAKTI CASTINGS PRIVATE LIMITED",
        BankAccount="XXXXXX8812",
        FullBankAccount="91001008812",
        IFSC="ICIC0000045",
        ValidityStartDate="2025-01-01",
        etag='W/"1"',
    )
    db.add_all([b1, b2])

    # 3. Purchase Orders & Items
    # PO 4500017
    po1 = PurchaseOrder(
        PurchaseOrder="4500017",
        Supplier="100045",
        CompanyCode="1000",
        Port="JNPT",
        YY1_SeaFreightPlannedInr=400000,
        YY1_AirFreightQuoteInr=1200000,
        YY1_DelayPenaltyPerDayInr=50000,
        etag='W/"1"',
    )
    po1_item = PurchaseOrderItem(
        PurchaseOrder="4500017",
        PurchaseOrderItem="10",
        Material="BRG-6205ZZ",
        OrderQuantity=1000,
        NetPriceAmount=980,
        Currency="INR",
    )
    gr1 = MaterialDocumentItem(
        MaterialDocument="5000017001",
        PurchaseOrder="4500017",
        PurchaseOrderItem="10",
        QuantityInEntryUnit=1000,
        PostingDate="2026-10-25",
    )

    # PO 4500021
    po2 = PurchaseOrder(
        PurchaseOrder="4500021",
        Supplier="100045",
        CompanyCode="1000",
        Port="JNPT",
        YY1_SeaFreightPlannedInr=400000,
        YY1_AirFreightQuoteInr=1200000,
        YY1_DelayPenaltyPerDayInr=50000,
        etag='W/"1"',
    )
    po2_item = PurchaseOrderItem(
        PurchaseOrder="4500021",
        PurchaseOrderItem="10",
        Material="BRG-7309B",
        OrderQuantity=500,
        NetPriceAmount=9700,
        Currency="INR",
    )
    gr2 = MaterialDocumentItem(
        MaterialDocument="5000021001",
        PurchaseOrder="4500021",
        PurchaseOrderItem="10",
        QuantityInEntryUnit=500,
        PostingDate="2026-10-20",
    )
    inv2 = SupplierInvoice(
        SupplierInvoice="5105600021",
        FiscalYear="2026",
        SupplierInvoiceIDByExtParty="INV-UB-2280",
        Supplier="100045",
        PurchaseOrder="4500021",
        InvoiceGrossAmount=4850000,
        Status="POSTED",
        DueDate="2026-10-29",
        DocumentDate="2026-10-20",
        etag='W/"1"',
    )

    # PO 4500030
    po3 = PurchaseOrder(
        PurchaseOrder="4500030",
        Supplier="100045",
        CompanyCode="1000",
        Port="JNPT",
        YY1_SeaFreightPlannedInr=400000,
        YY1_AirFreightQuoteInr=1200000,
        YY1_DelayPenaltyPerDayInr=50000,
        etag='W/"1"',
    )
    po3_item = PurchaseOrderItem(
        PurchaseOrder="4500030",
        PurchaseOrderItem="10",
        Material="BRG-SPECIAL",
        OrderQuantity=100,
        NetPriceAmount=50000,
        Currency="INR",
    )

    db.add_all([po1, po1_item, gr1, po2, po2_item, gr2, inv2, po3, po3_item])

    # 4. Inbox message M-1001 and DOC-2291 PDF
    pdf_bytes, pdf_text = generate_legit_invoice_pdf()
    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

    msg = InboxMessage(
        message_id="M-1001",
        from_address="billing@ultra-bearings.com",
        from_domain="ultra-bearings.com",
        subject="Invoice INV-UB-2291 for PO 4500017",
        received_at="2026-10-29T08:30:00Z",
        body_preview="Please find attached invoice for PO 4500017.",
        body="Dear Accounts Team,\n\nPlease find attached tax invoice INV-UB-2291 for PO 4500017.\nTotal amount: INR 9,80,000 for 1000 units of BRG-6205ZZ.\n\nBest regards,\nBilling Dept\nUltra Bearings Pvt Ltd",
        flagged=False,
        is_read=False,
    )
    doc = InboxDocument(
        document_id="DOC-2291",
        message_id="M-1001",
        filename="INV-UB-2291.pdf",
        raw_bytes=pdf_b64,
        text_content=pdf_text,
        provenance="external_email_attachment",
    )
    db.add_all([msg, doc])

    db.commit()
