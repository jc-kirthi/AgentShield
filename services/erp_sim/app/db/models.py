"""SQLAlchemy database models for Mock S/4HANA (erp_sim)."""

import datetime
from typing import Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker


Base = declarative_base()


class Supplier(Base):
    """SAP A_Supplier entity."""
    __tablename__ = "erp_suppliers"

    Supplier = Column(String(32), primary_key=True)
    SupplierName = Column(String(255), nullable=False)
    GSTIN = Column(String(32), nullable=False)
    EmailDomain = Column(String(128), nullable=False)
    etag = Column(String(64), nullable=False, default="W/\"1\"")

    banks = relationship("BusinessPartnerBank", back_populates="supplier_rel")


class BusinessPartnerBank(Base):
    """SAP A_BusinessPartnerBank entity."""
    __tablename__ = "erp_business_partner_banks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    BusinessPartner = Column(String(32), ForeignKey("erp_suppliers.Supplier"), nullable=False)
    BankIdentification = Column(String(16), nullable=False)
    BankAccountHolderName = Column(String(255), nullable=False)
    BankAccount = Column(String(64), nullable=False)  # Masked
    FullBankAccount = Column(String(64), nullable=False)
    IFSC = Column(String(32), nullable=False)
    ValidityStartDate = Column(String(32), nullable=False)
    etag = Column(String(64), nullable=False, default="W/\"1\"")

    supplier_rel = relationship("Supplier", back_populates="banks")

    __table_args__ = (
        UniqueConstraint("BusinessPartner", "BankIdentification", name="uq_bp_bank"),
    )


class PurchaseOrder(Base):
    """SAP A_PurchaseOrder entity."""
    __tablename__ = "erp_purchase_orders"

    PurchaseOrder = Column(String(32), primary_key=True)
    Supplier = Column(String(32), nullable=False)
    CompanyCode = Column(String(16), nullable=False, default="1000")
    Port = Column(String(32), nullable=True, default="JNPT")
    YY1_SeaFreightPlannedInr = Column(Integer, nullable=False, default=400000)
    YY1_AirFreightQuoteInr = Column(Integer, nullable=False, default=1200000)
    YY1_DelayPenaltyPerDayInr = Column(Integer, nullable=False, default=50000)
    etag = Column(String(64), nullable=False, default="W/\"1\"")

    items = relationship("PurchaseOrderItem", back_populates="po_rel")


class PurchaseOrderItem(Base):
    """SAP to_PurchaseOrderItem entity."""
    __tablename__ = "erp_purchase_order_items"

    id = Column(Integer, primary_key=True, autoincrement=True)
    PurchaseOrder = Column(String(32), ForeignKey("erp_purchase_orders.PurchaseOrder"), nullable=False)
    PurchaseOrderItem = Column(String(16), nullable=False, default="10")
    Material = Column(String(64), nullable=False)
    OrderQuantity = Column(Integer, nullable=False)
    NetPriceAmount = Column(Integer, nullable=False)  # Integer INR
    Currency = Column(String(8), nullable=False, default="INR")

    po_rel = relationship("PurchaseOrder", back_populates="items")


class MaterialDocumentItem(Base):
    """SAP A_MaterialDocumentItem (Goods Receipt)."""
    __tablename__ = "erp_material_document_items"

    MaterialDocument = Column(String(32), primary_key=True)
    PurchaseOrder = Column(String(32), nullable=False)
    PurchaseOrderItem = Column(String(16), nullable=False, default="10")
    QuantityInEntryUnit = Column(Integer, nullable=False)
    PostingDate = Column(String(32), nullable=False)


class SupplierInvoice(Base):
    """SAP A_SupplierInvoice entity."""
    __tablename__ = "erp_supplier_invoices"

    SupplierInvoice = Column(String(32), primary_key=True)
    FiscalYear = Column(String(8), primary_key=True)
    SupplierInvoiceIDByExtParty = Column(String(64), nullable=False)
    Supplier = Column(String(32), nullable=False)
    PurchaseOrder = Column(String(32), nullable=False)
    InvoiceGrossAmount = Column(Integer, nullable=False)
    Status = Column(String(16), nullable=False, default="POSTED")  # POSTED, PAID
    DueDate = Column(String(32), nullable=False)
    DocumentDate = Column(String(32), nullable=False)
    etag = Column(String(64), nullable=False, default="W/\"1\"")


class Payment(Base):
    """Payment record."""
    __tablename__ = "erp_payments"

    payment_id = Column(String(64), primary_key=True)
    supplier_invoice = Column(String(32), nullable=False)
    fiscal_year = Column(String(8), nullable=False)
    amount_inr = Column(Integer, nullable=False)
    paid_to_bank_id = Column(String(16), nullable=False)
    idempotency_key = Column(String(128), unique=True, nullable=False)
    payload_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    __table_args__ = (
        UniqueConstraint("supplier_invoice", "fiscal_year", name="uq_invoice_payment"),
    )


class FreightBooking(Base):
    """Freight booking record."""
    __tablename__ = "erp_freight_bookings"

    booking_id = Column(String(64), primary_key=True)
    purchase_order = Column(String(32), nullable=False)
    mode = Column(String(16), nullable=False)  # AIR, SEA
    cost_inr = Column(Integer, nullable=False)
    reason = Column(Text, nullable=True)
    idempotency_key = Column(String(128), unique=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))


class InboxMessage(Base):
    """Inbox message."""
    __tablename__ = "erp_inbox_messages"

    message_id = Column(String(64), primary_key=True)
    from_address = Column(String(255), nullable=False)
    from_domain = Column(String(128), nullable=False)
    subject = Column(String(255), nullable=False)
    received_at = Column(String(64), nullable=False)
    body_preview = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    flagged = Column(Boolean, default=False)
    flag_reason = Column(Text, nullable=True)
    is_read = Column(Boolean, default=False)


class InboxDocument(Base):
    """Attached document/PDF."""
    __tablename__ = "erp_inbox_documents"

    document_id = Column(String(64), primary_key=True)
    message_id = Column(String(64), nullable=False)
    filename = Column(String(255), nullable=False)
    raw_bytes = Column(Text, nullable=False)  # Base64 encoded or hex
    text_content = Column(Text, nullable=False)
    provenance = Column(String(64), default="external_email_attachment")
