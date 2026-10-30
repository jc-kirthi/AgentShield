# PROMPT 1 · A-TO-Z MASTER SPECIFICATION · AgentShield v2

> Copy this whole file into the repo as `docs/MASTER_SPEC.md`. It is the single source of truth. If any other prompt, code comment or chat message conflicts with this file, this file wins until it is changed by a reviewed PR (owner: Pavan, approver: Chandan).
>
> You are an AI coding assistant working on one module of a five-person team. Read this entire document before writing code. Do not change any shared contract (Sections 7 to 11) on your own. If a contract is wrong, write the proposed change in `docs/contract-change-requests.md` and continue with the current contract.

---

## 0. Context

- Event: SAP Hackfest 2026, Bengaluru Region (SAP + NHCE + LTM). Theme: Resilient Supply Chains. Finale: Wed 4 Nov 2026 at NHCE. Judged through Domain, Tech and Business lenses. Round 2 expects a functional prototype of at least one real agent.
- Team: No Idea. Members: Chandan, Harshita, Kirti, Yogesh, Pavan.
- Baseline: "Agent Firewall" v1.0 (Round 1). v1 claims that must stay true: we guard actions not words; deterministic ₹ rules (invoice ≤ PO × 1.05; air freight only if (air − sea) < delay penalty avoided; any bank change → verify/HOLD); out-of-band oracles (AIS feed, ₹1 penny-drop vs GSTIN legal/trade name, canary for pre-go-live testing); ₹ receipt with a formula per line; three attacks (fake port closure ₹8,00,000; BEC bank change ₹48,50,000; poisoned supplier PDF ₹2,70,000; total ₹59,20,000 scenario exposure); ALLOW / HOLD / BLOCK decisions; mock S/4HANA with SAP entity names; clean core, plug in at API layer.
- v2 name: **AgentShield**. The enforcement component inside it keeps the name **Agent Firewall gateway** for continuity with Round 1.
- Build window: Day 1 Wed 28 Oct to Day 7 Tue 3 Nov 2026. Feature freeze Day 7 12:00 IST.

## 1. Product in one paragraph

AgentShield is an independent security and control layer for AI agents that execute supply-chain and finance workflows on SAP-style ERP APIs. An operator starts a task; AgentShield mints a short-lived, signed **capability lease** limited to the tools, business objects, ₹ ceiling and call count that task needs. A real local AI agent (open-weight model on Ollama) plans and calls typed tools. Every call passes the Agent Firewall gateway, which verifies the lease, revalidates against authoritative ERP state, applies deterministic ₹ rules and out-of-band oracle checks, and executes allowed calls with optimistic concurrency (ETag If-Match) and idempotency. Denials return structured reasons and safe alternatives so the agent replans safely (escalate, flag, skip, abort). Every step is a correlated event and a hash-chained audit entry, visible live in Attacker, Defender and Business views.

## 2. Non-negotiable principles

1. The model is never a security boundary. All authorization happens in the gateway (trusted code) and in ERP constraints.
2. The agent holds no ERP credentials. Its only route to ERP is the gateway.
3. Rules read authoritative ERP state, never amounts or IDs claimed by the agent or a document.
4. Fail closed for state-changing actions: any error, timeout or unknown → HOLD or DENY, never ALLOW.
5. Rejected operations never mutate protected ERP state. Prove it with the state digest.
6. Exactly-once business effect for payments: nonce + idempotency + ERP unique constraint, all three.
7. No fake traffic, no fabricated events, no prerecorded results presented as live. The only replay allowed is model-output replay (L3), always labeled.
8. Synthetic data only. No real personal data, no real bank accounts, no real credentials.
9. Same code path for 3-laptop and 1-laptop modes. No mock-only UI implementation.
10. Never claim: SAP certified, compliant, production ready, trained our own model.

## 3. Scope (vertical slice)

Workflow: **AP inbox processing and supplier payment** for a manufacturer, plus **freight expedite on logistics alerts**.

In scope (must ship):
- Live agent processing a supplier inbox: read emails, read attached invoice PDFs, three-way match, post supplier invoice, execute payment, update supplier bank (gated), book freight (gated), flag suspicious messages, request human approval.
- Attacks live: BEC bank change (model-mediated), replay of captured payment (credential-level), out-of-scope object with stolen lease (credential-level).
- Attacks in batch report: poisoned PDF price inflation, fake port closure → air freight, plus the three above.
- Blast-radius report: vulnerable profile vs protected profile, measured.
- Views: Attacker, Defender, Business, Stage (three-in-one).
- Reset to golden state; health; preflight.

Out of scope this week: real SAP writes, real bank/GST APIs, multi-agent systems, Kubernetes, message brokers, TLS (stretch only), SSO.

## 4. Repository layout

```
agentshield/
  README.md
  Makefile
  docs/
    MASTER_SPEC.md            (this file)
    adr/0001-*.md ...
    threat-model.md
    compliance-map.md
    runbook-demo.md
    contract-change-requests.md
  contracts/                  (Pavan)
    openapi/gateway.yaml  openapi/erp_sim.yaml  openapi/agent.yaml  openapi/attacklab.yaml
    schemas/event.schema.json  schemas/decision.schema.json  schemas/lease.schema.json
    schemas/tools/*.json
    python/agentshield_contracts/   (pydantic models, enums, reason codes)
    ts/                              (generated TS types for web)
  libs/common/                (Pavan) auth (JWT verify/issue for dev), settings, structlog JSON logging, event client, http client with retries, canonical JSON + sha256
  services/
    gateway/      (Chandan)  FastAPI :8000
    agent/        (Harshita) FastAPI :8003
    erp_sim/      (Kirti)    FastAPI :8001
    oracles/      (Kirti)    FastAPI :8002
    attacklab/    (Kirti)    FastAPI :8004
  web/            (Yogesh)   React + Vite + TS
  deploy/         (Pavan)    compose.yaml, Caddyfile, .env.example, postgres/init.sql
  scripts/        (Pavan)    preflight.py, reset.sh, golden_digest.txt, record_trace.sh
  tests/
    e2e/          (Pavan)
    adversarial/  (Kirti owns scenarios, Chandan owns gateway assertions)
  .github/workflows/ci.yml   (Pavan)
```

Each service: `app/main.py`, `app/api/`, `app/core/`, `app/db/` (SQLAlchemy models + Alembic), `tests/`, `Dockerfile`, `pyproject.toml`. Python 3.12, ruff, pytest.

## 5. Technology stack (fixed)

Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, psycopg 3, Alembic, httpx, PyJWT, cryptography (Ed25519), rapidfuzz, reportlab, pypdf, structlog, sse-starlette. PostgreSQL 16 in Docker. Ollama native on host. Model: Qwen3.5 (9B if host VRAM ≥ 8 GB, else 4B; final pick from Day 2 eval). React 18 + Vite + TypeScript, `@ui5/webcomponents-react` (Business view), plain CSS modules. Caddy 2. Playwright. GitHub Actions.

## 6. Runtime topology and ports

| Service | Internal port | Public path via Caddy :8080 | Notes |
|---|---|---|---|
| web (static) | n/a | `/` routes `/business` `/defender` `/attacker` `/stage` `/login` | built by Vite, served by Caddy |
| gateway | 8000 | `/api/gw/*` → strip prefix | event hub + SSE + auth login |
| erp_sim | 8001 | `/api/erp/*` (read only for UI roles) | writes only from gateway service token |
| oracles | 8002 | not exposed | gateway only |
| agent | 8003 | `/api/agent/*` | task start, status, traces |
| attacklab | 8004 | `/api/attack/*` | attacker_sandbox role only |
| ollama | 11434 | not exposed | host 127.0.0.1 |
| postgres | 5432 | not exposed | Docker network only |

From inside Docker, services reach Ollama at `http://host.docker.internal:11434` (compose adds `extra_hosts: ["host.docker.internal:host-gateway"]`).

Postgres: one database `agentshield`, schemas `gw`, `agent`, `erp`, `lab`, `oracle`. Roles `gw_svc`, `agent_svc`, `erp_svc`, `lab_svc`, `oracle_svc`, each with privileges only on its own schema. No service reads another service's schema.

## 7. Identities and auth

Demo user and service tokens: JWT HS256, secret `JWT_SECRET` from `.env`, issuer `agentshield-demo`, 8 h expiry for users, 24 h for services. Claims: `sub`, `roles` (array), `iat`, `exp`, `iss`.

| Principal | sub | roles | How obtained |
|---|---|---|---|
| AP operator | `ops.meera` | `business_operator` | `POST /api/gw/v1/auth/login` |
| Approver | `approver.arjun` | `business_approver` | login |
| SOC analyst | `soc.kavya` | `defender` | login |
| Red team | `redteam` | `attacker_sandbox` | login |
| Presenter (stage) | `presenter` | `business_operator, business_approver, defender, attacker_sandbox` | login, only when `SANDBOX=1` |
| Admin | `admin` | `admin` | login |
| Agent runtime | `agent:ap-agent-01` | `agent` | service token in agent `.env` |
| Gateway → ERP | `svc:gateway` | `erp_writer` | service token in gateway `.env` |
| Services → event ingest | `svc:<name>` | `event_emitter` | service tokens |

Passwords for demo users come from `.env` (`DEMO_PASSWORD_*`). Login endpoint is in the gateway. All services verify JWTs with `libs/common/auth.py`.

## 8. Capability lease (shared contract)

### 8.1 Token format
`lease_token = base64url(payload_json_canonical) + "." + base64url(ed25519_signature)`; signing key `LEASE_SIGNING_KEY` (gateway only), public key `LEASE_PUBLIC_KEY` (may be shared). Canonical JSON: UTF-8, sorted keys, no whitespace.

Payload:
```json
{
  "v": 1,
  "kid": "lease-key-2026-11",
  "lease_id": "uuid",
  "task_id": "uuid",
  "agent_id": "agent:ap-agent-01",
  "issued_by": "ops.meera",
  "template": "AP_INBOX_V1",
  "iat": 1762240000,
  "nbf": 1762240000,
  "exp": 1762240900,
  "scope": {
    "tools": ["read_inbox","get_document_text","get_purchase_order","get_goods_receipts","get_supplier","get_supplier_bank","list_open_invoices","post_supplier_invoice","execute_payment","update_supplier_bank","book_freight","flag_suspicious_message","request_human_approval","complete_task"],
    "suppliers": ["100045"],
    "purchase_orders": ["4500017","4500021","4500030"],
    "max_payment_inr": 5000000,
    "max_calls": 25
  }
}
```

### 8.2 Templates (gateway config `policy/templates.yaml`)
- `AP_INBOX_V1`: tools as above, exp 15 min, max_calls 25, max_payment_inr 50,00,000. Object scope = suppliers and POs referenced by open inbox messages from **known supplier domains on file**, intersected with operator's allowed set. Messages from unknown domains do not widen scope.
- `READ_ONLY_V1`: read tools only.
Lease scope is always the intersection of template, operator permissions and requested objects. The agent cannot mint or widen leases.

### 8.3 Lease DB state (authoritative; signature is integrity only)
`gw.leases(lease_id pk, task_id, agent_id, issued_by, template, scope jsonb, iat, exp, status enum[ACTIVE,SUSPENDED,REVOKED,EXPIRED], calls_used int, denials int, created_at)`.
Denial budget: 3 DENY decisions on one lease → status SUSPENDED → all further calls `DENY_LEASE_SUSPENDED`.

## 9. Tool contracts (shared)

All tools are called by the agent through `POST /api/gw/v1/tool-calls` (internally `http://gateway:8000/v1/tool-calls`). Amounts are **integer INR rupees** in v2. IDs are strings.

| Tool | Kind | Args (all required unless marked) | Result on ALLOW |
|---|---|---|---|
| `read_inbox` | read | `{ "unread_only": bool (opt, default true) }` | `{ "messages": [ {message_id, from_address, from_domain, subject, received_at, body_preview, attachments:[{document_id, filename}]} ] }` |
| `get_document_text` | read | `{ "document_id": str }` | `{ document_id, filename, text, provenance:"external_email_attachment", truncated: bool }` (max 4000 chars) |
| `get_purchase_order` | read | `{ "purchase_order": str }` | `{ PurchaseOrder, Supplier, CompanyCode, items:[{PurchaseOrderItem, Material, OrderQuantity, NetPriceAmount, Currency}] , etag }` |
| `get_goods_receipts` | read | `{ "purchase_order": str }` | `{ receipts:[{MaterialDocument, PurchaseOrderItem, QuantityInEntryUnit, PostingDate}] }` |
| `get_supplier` | read | `{ "supplier": str }` | `{ Supplier, SupplierName, GSTIN, EmailDomain, etag }` |
| `get_supplier_bank` | read | `{ "supplier": str }` | `{ Supplier, BankIdentification, BankAccountMasked, IFSC, BankAccountHolderName, ValidityStartDate, etag }` |
| `list_open_invoices` | read | `{ "supplier": str (opt) }` | `{ invoices:[{SupplierInvoice, FiscalYear, Supplier, PurchaseOrder, InvoiceGrossAmount, Status, DueDate}] }` |
| `post_supplier_invoice` | write | `{ supplier, purchase_order, supplier_invoice_ref, invoice_date (YYYY-MM-DD), items:[{purchase_order_item, quantity:int, unit_price_inr:int}], gross_amount_inr:int, source_document_id }` | `{ SupplierInvoice, FiscalYear, Status:"POSTED" }` |
| `execute_payment` | write | `{ supplier_invoice, fiscal_year, amount_inr:int }` | `{ PaymentId, SupplierInvoice, AmountInr, PaidToBankIdentification, Status:"PAID" }` |
| `update_supplier_bank` | write | `{ supplier, bank_account_holder_name, bank_account, ifsc, reason, source_message_id }` | `{ Supplier, BankIdentification, Status:"UPDATED" }` |
| `book_freight` | write | `{ purchase_order, mode: "AIR"|"SEA", quoted_cost_inr:int, claimed_delay_days:int, reason, source_message_id }` | `{ BookingId, Mode, CostInr }` |
| `flag_suspicious_message` | control | `{ message_id, reason }` | `{ flagged:true }` |
| `request_human_approval` | control | `{ action_summary, reason, related_decision_id (opt) }` | `{ approval_id, status:"PENDING" }` |
| `complete_task` | control | `{ summary }` | `{ task_status:"COMPLETED" }` |

JSON Schemas for each live in `contracts/schemas/tools/<tool>.json` and Pydantic models in `agentshield_contracts.tools`. Agent and gateway both validate. `additionalProperties: false` everywhere.

## 10. Gateway API (shared)

### 10.1 Tool call
`POST /v1/tool-calls`
Headers: `Authorization: Bearer <agent JWT>`, `X-Lease: <lease_token>`
Body:
```json
{ "call_id": "uuid (new per attempt)", "idempotency_key": "string (required for write tools; stable per business intent, e.g. pay:5105600031:2026)",
  "task_id": "uuid", "step_id": "string", "tool": "execute_payment", "args": { }, "issued_at": "RFC3339" }
```
Response (all cases, `application/json`):
```json
{ "decision_id": "uuid", "decision": "ALLOW|HOLD|DENY", "reason_code": "ALLOW_OK", "rule_id": "R-PAY-01",
  "message": "plain English reason", "inr_at_risk": 0, "formula": "string or null",
  "checks": [ { "name": "lease.signature", "result": "pass|fail|skip|error", "detail": "..." } ],
  "result": { }, "approval_id": null,
  "safe_alternatives": ["request_human_approval","flag_suspicious_message","skip_step","abort_task"],
  "correlation_id": "task_id or attack_run_id", "idempotent_replay": false }
```
HTTP status: 200 ALLOW, 202 HOLD, 403 DENY, 409 DENY for `DENY_NONCE_REUSED`, `DENY_DUPLICATE_PAYMENT`, `DENY_CONCURRENT_MODIFICATION`, 401 bad agent token, 422 never (schema failures are DENY_SCHEMA_INVALID with 403 so they are audited), 503 gateway dependency down (body still a DENY with reason `DENY_DEPENDENCY_UNAVAILABLE` when possible).

### 10.2 Reason codes (enum `ReasonCode`)
```
ALLOW_OK
HOLD_BANK_NAME_PARTIAL           HOLD_BANK_COOLING_OFF         HOLD_BANK_CHANGE_UNDER_REVIEW
HOLD_ORACLE_UNAVAILABLE          HOLD_AMOUNT_NEEDS_APPROVAL
DENY_AGENT_UNAUTHENTICATED       DENY_LEASE_INVALID            DENY_LEASE_EXPIRED
DENY_LEASE_REVOKED               DENY_LEASE_SUSPENDED          DENY_CALL_BUDGET_EXHAUSTED
DENY_NONCE_REUSED                DENY_STALE_REQUEST            DENY_SCHEMA_INVALID
DENY_TOOL_NOT_IN_SCOPE           DENY_OBJECT_NOT_IN_SCOPE      DENY_AMOUNT_EXCEEDS_LEASE
DENY_PRICE_VARIANCE              DENY_QTY_EXCEEDS_GR           DENY_BANK_NAME_MISMATCH
DENY_DUPLICATE_PAYMENT           DENY_INVOICE_NOT_PAYABLE      DENY_AMOUNT_MISMATCH
DENY_FREIGHT_UNECONOMIC          DENY_SIGNAL_CONTRADICTED      DENY_CONCURRENT_MODIFICATION
DENY_DENIAL_BUDGET_EXHAUSTED     DENY_POLICY_ERROR             DENY_DEPENDENCY_UNAVAILABLE
```

### 10.3 Rules (gateway `policy/rules.yaml` + pure Python functions)
| rule_id | Tool | Logic (on authoritative ERP data) | Decision |
|---|---|---|---|
| R-INV-01 | post_supplier_invoice | for each item: `unit_price_inr ≤ PO NetPrice × (1 + tolerance)` with tolerance 0.05 | else DENY_PRICE_VARIANCE, inr_at_risk = Σ(qty × (claimed − PO price)), formula string |
| R-INV-02 | post_supplier_invoice | invoiced qty (incl. previously invoiced) ≤ GR qty | else DENY_QTY_EXCEEDS_GR |
| R-INV-03 | post_supplier_invoice | `gross_amount_inr == Σ qty × unit_price` | else DENY_AMOUNT_MISMATCH |
| R-PAY-01 | execute_payment | invoice exists, status POSTED, not PAID, supplier in lease | else DENY_INVOICE_NOT_PAYABLE / DENY_DUPLICATE_PAYMENT |
| R-PAY-02 | execute_payment | `amount_inr == InvoiceGrossAmount` | else DENY_AMOUNT_MISMATCH |
| R-PAY-03 | execute_payment | amount ≤ lease max_payment_inr | else DENY_AMOUNT_EXCEEDS_LEASE |
| R-PAY-04 | execute_payment | no DENIED or HOLD bank-change decision for this supplier in last 24 h | else HOLD_BANK_CHANGE_UNDER_REVIEW, inr_at_risk = amount |
| R-PAY-05 | execute_payment | supplier bank ValidityStartDate older than cooling-off (3 days) | else HOLD_BANK_COOLING_OFF |
| R-BANK-01 | update_supplier_bank | always run oracles: penny-drop(account, ifsc) → holder name; GSTIN(supplier GSTIN) → legal_name, trade_name; score = max(token_set_ratio(holder, legal), token_set_ratio(holder, trade)) after normalising (upper, strip PVT/PRIVATE/LTD/LIMITED/punctuation) | score ≥ 90 → ALLOW (new bank gets ValidityStartDate today, so R-PAY-05 cooling-off applies); 70 ≤ score < 90 → HOLD_BANK_NAME_PARTIAL; < 70 → DENY_BANK_NAME_MISMATCH, inr_at_risk = Σ open POSTED invoices of supplier |
| R-BANK-02 | update_supplier_bank | oracle error or timeout (2 s) | HOLD_ORACLE_UNAVAILABLE |
| R-FRT-01 | book_freight AIR | `(YY1_AirFreightQuoteInr − YY1_SeaFreightPlannedInr) < claimed_delay_days × YY1_DelayPenaltyPerDayInr` (costs from ERP, never from args; even the attacker's own claim must justify the spend) | else DENY_FREIGHT_UNECONOMIC, inr_at_risk = air − sea |
| R-ORD-00 | all write tools | rule evaluation order: generic (R-GEN) first, then tool rules in table order; the first failing rule sets reason_code; all evaluated checks still appear in `checks[]` | |
| R-FRT-02 | book_freight AIR | AIS oracle for PO's port shows disruption (berthed_today < threshold) | else DENY_SIGNAL_CONTRADICTED |
| R-GEN-01 | all | lease valid, ACTIVE, nbf ≤ now < exp, calls_used < max_calls | DENY_LEASE_* / DENY_CALL_BUDGET_EXHAUSTED |
| R-GEN-02 | all | tool in scope; object IDs in args in scope | DENY_TOOL_NOT_IN_SCOPE / DENY_OBJECT_NOT_IN_SCOPE |
| R-GEN-03 | all | call_id unused for this lease; `|now − issued_at| ≤ 60 s` | DENY_NONCE_REUSED / DENY_STALE_REQUEST |
| R-GEN-04 | write | same idempotency_key + same request hash → return stored response, `idempotent_replay: true`, no re-execution; same key + different hash → DENY_NONCE_REUSED | |
| R-GEN-05 | all | any exception in evaluation | DENY_POLICY_ERROR |
| R-GEN-06 | all | 3rd DENY on lease | lease SUSPENDED, reason DENY_DENIAL_BUDGET_EXHAUSTED on that call |

Read tools go through the gateway too (scope + audit), and the gateway returns ERP data with document text marked `provenance`.

Formula strings must be exact and human-readable, e.g. `"invoice ₹12,50,000 > PO ₹9,80,000 × 1.05 = ₹10,29,000 (+27.6%)"`. Use Indian digit grouping.

### 10.4 Other gateway endpoints
| Method path | Role | Purpose |
|---|---|---|
| `POST /v1/auth/login` | public | `{username,password}` → `{token, roles}` |
| `POST /v1/tasks` | business_operator (called by agent runtime on behalf of the user, forwarding the user JWT in `X-On-Behalf-Of`) | create task + lease from template → `{task_id, lease_id, lease_token, scope, exp}` |
| `POST /v1/leases/{id}/revoke` | business_operator, admin | revoke |
| `GET /v1/leases/{id}` | defender, business_* | lease state |
| `GET /v1/decisions?correlation_id=&limit=` and `GET /v1/decisions/{id}` | defender, business_* | |
| `GET /v1/approvals?status=PENDING` / `POST /v1/approvals/{id}/decide` `{decision: "APPROVED"|"REJECTED"}` | business_approver | approve/reject |
| `POST /v1/events` | event_emitter | ingest event |
| `GET /v1/events/stream` | defender, business_*, attacker_sandbox | SSE event stream |
| `POST /v1/sandbox/captures` and `GET /v1/sandbox/captures?tool=` | attacker_sandbox | for attack replay |

## 11. Events and audit log (shared contract)

Events are JSON, emitted over HTTP to `POST /v1/events`, distributed to web via SSE `/v1/events/stream`.
Standard envelope:
```json
{
  "event_id": "uuid",
  "topic": "decision.created | task.started | attack.run.started | erp.mutated",
  "source": "gateway | agent | erp_sim | attacklab",
  "timestamp": "RFC3339",
  "correlation_id": "task_id or attack_run_id",
  "actor": "ops.meera | agent:ap-agent-01 | redteam",
  "payload": { },
  "prev_hash": "hex sha256 or '0000000000000000000000000000000000000000000000000000000000000000'",
  "entry_hash": "hex sha256 over canonical JSON(event minus entry_hash)"
}
```

## 12. Mock S/4HANA (erp_sim) and Golden Seed

### 12.1 Endpoints
Read endpoints (OData V2 JSON shape `{"d": {...}}` or `{"d": {"results": [...]}}`):
- `GET /sap/opu/odata/sap/API_BUSINESS_PARTNER/A_Supplier('100045')`
- `GET /sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartnerBank` (`$filter=BusinessPartner eq '100045'`)
- `GET /sap/opu/odata/sap/API_PURCHASEORDER_PROCESS_SRV/A_PurchaseOrder('4500017')?$expand=to_PurchaseOrderItem`
- `GET /sap/opu/odata/sap/API_MATERIAL_DOCUMENT_SRV/A_MaterialDocumentItem?$filter=PurchaseOrder eq '4500017'`
- `GET /sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice?$filter=SupplierInvoiceIDByExtParty eq '...'`
- `GET /sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice(SupplierInvoice='5105600021',FiscalYear='2026')`

Write endpoints (requires JWT with role `erp_writer`, only gateway service holds this):
- `POST /sap/opu/odata/sap/API_SUPPLIERINVOICE_PROCESS_SRV/A_SupplierInvoice`
- `PATCH /sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartnerBank(BusinessPartner='100045',BankIdentification='0001')`
  - Requires `If-Match: W/"<etag>"`; 428 if missing, 412 if mismatch.
- `POST /sim/v1/payments`
  - Body: `{ "SupplierInvoice": "5105600021", "FiscalYear": "2026", "AmountInr": 4850000 }`
  - Headers: `Idempotency-Key: <key>`, `Authorization: Bearer <erp_writer JWT>`
  - DB table `erp.payments(payment_id pk, supplier_invoice, fiscal_year, amount_inr, paid_to_bank_id, idempotency_key unique, created_at)`.
  - Also unique constraint `UNIQUE (supplier_invoice, fiscal_year)`. If invoice is already PAID, return 409 Conflict.
  - Updates invoice status to `PAID` and sets `PaidToBankIdentification` to current supplier bank.
- `POST /sim/v1/freight-bookings`
  - Body: `{ "PurchaseOrder": "4500030", "Mode": "AIR", "CostInr": 1200000, "Reason": "..." }`
  - Headers: `Idempotency-Key: <key>`
  - DB table `erp.freight_bookings(booking_id pk, purchase_order, mode, cost_inr, reason, idempotency_key, created_at)`.

Simulator extensions (`/sim/v1/*`):
- `GET /sim/v1/inbox?unread_only=true`
- `POST /sim/v1/inbound/email` (attacklab token / redteam): inject an email into inbox
- `GET /sim/v1/documents/{id}/text` (returns extracted text and `provenance: external_email_attachment`)
- `GET /sim/v1/documents/{id}/raw` (returns PDF binary bytes)
- `POST /sim/v1/messages/{id}/flag` `{ "flagged": true, "reason": "..." }`
- `GET /sim/v1/state-digest` sha256 over canonical JSON of protected business state (all supplier banks, all invoices with status, all payments, all freight bookings)
- `POST /sim/v1/admin/reset` restores DB to golden seed state

### 12.2 Golden Seed Data
1. **Supplier 100045**: Ultra Bearings Pvt Ltd
   - `Supplier`: `"100045"`, `SupplierName`: `"Ultra Bearings Pvt Ltd"`, `GSTIN`: `"27AABCU9603R1ZM"`, `EmailDomain`: `"ultra-bearings.com"`
   - Bank `0001`: BankIdentification: `"0001"`, BankAccountHolderName: `"ULTRA BEARINGS PRIVATE LIMITED"`, BankAccount: `"XXXXXX4417"`, FullBankAccount: `"91001004417"`, IFSC: `"HDFC0000123"`, ValidityStartDate: `"2025-04-01"`
2. **Supplier 100099**: Shakti Castings Pvt Ltd (out of scope for task)
   - `Supplier`: `"100099"`, `SupplierName`: `"Shakti Castings Pvt Ltd"`, `GSTIN`: `"29AAECS1234F1Z5"`, `EmailDomain`: `"shakti-castings.com"`
   - Bank `0001`: BankIdentification: `"0001"`, BankAccountHolderName: `"SHAKTI CASTINGS PRIVATE LIMITED"`, BankAccount: `"XXXXXX8812"`, FullBankAccount: `"91001008812"`, IFSC: `"ICIC0000045"`, ValidityStartDate: `"2025-01-01"`
3. **PO 4500017**:
   - `PurchaseOrder`: `"4500017"`, `Supplier`: `"100045"`, `CompanyCode`: `"1000"`
   - Item 10: `Material`: `"BRG-6205ZZ"`, `OrderQuantity`: 1000, `NetPriceAmount`: 980, `Currency`: `"INR"`
   - Goods Receipt: `MaterialDocument`: `"5000017001"`, `PurchaseOrderItem`: "10", `QuantityInEntryUnit`: 1000, `PostingDate`: `"2026-10-25"`
   - Invoice: None yet (pending inbox processing)
4. **PO 4500021**:
   - `PurchaseOrder`: `"4500021"`, `Supplier`: `"100045"`, `CompanyCode`: `"1000"`
   - Item 10: `Material`: `"BRG-7309B"`, `OrderQuantity`: 500, `NetPriceAmount`: 9700, `Currency`: `"INR"`
   - Goods Receipt: `MaterialDocument`: `"5000021001"`, `PurchaseOrderItem`: "10", `QuantityInEntryUnit`: 500, `PostingDate`: `"2026-10-20"`
   - Existing Posted Invoice: `SupplierInvoice`: `"5105600021"`, `FiscalYear`: `"2026"`, `SupplierInvoiceIDByExtParty`: `"INV-UB-2280"`, `InvoiceGrossAmount`: 4850000, `Status`: `"POSTED"`, `DueDate`: `"2026-10-29"`
5. **PO 4500030**:
   - `PurchaseOrder`: `"4500030"`, `Supplier`: `"100045"`, `CompanyCode`: `"1000"`
   - Item 10: `Material`: `"BRG-SPECIAL"`, `OrderQuantity`: 100, `NetPriceAmount`: 50000, `Currency`: `"INR"`
   - Logistics parameters: Port: `"JNPT"`, `YY1_SeaFreightPlannedInr`: 400000, `YY1_AirFreightQuoteInr`: 1200000, `YY1_DelayPenaltyPerDayInr`: 50000
6. **Inbox**:
   - Message `M-1001`: from `"billing@ultra-bearings.com"`, subject `"Invoice INV-UB-2291 for PO 4500017"`, received_at `"2026-10-29T08:30:00Z"`, body `"Please find attached invoice for PO 4500017."`, attachment: `DOC-2291` (`INV-UB-2291.pdf`).
   - Document `DOC-2291`: Legit PDF generated via reportlab, 1000 units × ₹980 = ₹9,80,000 gross.

---

## 13. FINALE OVERLAY v2.1 (ADDITIVE · replaces earlier Section 12 · append to docs/MASTER_SPEC.md)

PRECEDENCE AND SAFETY
- Sections 0-11 stay. This section ADDS and AMENDS only where it says so. On conflict, Sections 0-11 win unless a change request (below) is merged by reviewed PR (owner Pavan, approver Chandan).
- Branch feature/finale-overlay. Never commit to main. Do not delete or rewrite existing files, rules, tools, tests or contracts. New code goes in new paths. Existing files get small additive edits behind env flags that default OFF; with flags OFF, golden_digest and all existing tests must be identical.
- All shared-contract additions in 13.5 go into docs/contract-change-requests.md and are merged by reviewed PR on Day 1 BEFORE module work depends on them.

13.1 WHY THIS OVERLAY (SAP Participant Guide, Theme 1: Resilient Supply Chains)
- Agentic AI that autonomously senses, adapts and recovers. Specialised agents: Sensing & Scenario, Logistics & Inventory, Compliance & Human-in-the-Loop.
- Round 2 needs (a) a functional single-agent prototype and (b) an end-to-end multi-agent showcase simulating a live disruption (shipping closure or tariff spike) with autonomous rerouting, audit logging, human approval, and SAP Learning Hub student edition integration.
- Format: 15 min per team (10 present + 5 Q&A, overtime penalised), one laptop, backup demo video, all 5 members present.
- Judged on: Problem Identification (specificity, root cause, stakeholder validation with evidence), Systems Thinking (process links, 2nd-order consequences, change management), Business Viability (value proposition, revenue model, go-to-market), Demo & Feasibility (function over flash, timeline/skills/cost, presentation and teamwork).
- Teams primarily use the SAP platform and landscape links shared with them; Learning Hub usage earns an edge.

13.2 POSITIONING (one sentence, use everywhere)
"AgentShield lets supply chains recover from disruption autonomously, with every autonomous action leased, rule-checked against ERP truth, human-approved when it matters, and fully audited." Round 1 Agent Firewall = the Compliance & Human-in-the-Loop agent. Never claim SAP certification, SAP partnership, production readiness, or that we trained a model.

13.3 AMENDMENT TO SECTION 3
Multi-agent is now IN scope: a small multi-agent network of role-scoped agents, each with its own agent identity and capability lease (least privilege), coordinated by a deterministic orchestrator state machine (SENSE -> PLAN -> APPROVE (if needed) -> ACT -> VERIFY -> AUDIT) in services/agent/app/orchestrator.py. No new services. One incident = one task_id; each agent holds its own lease_id under it (if the lease schema forbids this, raise a CCR).

13.4 AGENTS
1. Sensing Agent (agent:sensing-01, template SENSE_V1, read-only): reads disruption signals from the signals oracle, which has two channels: AUTHORITATIVE (AIS/port status) and UNVERIFIED (news, emails, tariff notices; provenance external, treated as untrusted text). Emits a DisruptionEvent {signal_ids, confidence, evidence}.
2. Scenario Planning Agent (agent:planner-01, template PLAN_V1): reads shipments, inventory and ERP costs, calls run_scenario_plan, then ranks options (stay on sea, reroute sea, air expedite, alternate supplier). All ₹ and day maths is deterministic code with formula strings; the LLM only selects among computed options and writes the rationale. The LLM never computes ₹.
3. Logistics & Inventory Agent (agent:logistics-01, template LOGISTICS_V1): executes the chosen option via book_freight and related writes through the gateway; requests human approval via request_human_approval.
4. Compliance & HITL = the Agent Firewall gateway (R-GEN, R-FRT, R-BANK, R-PAY rules) plus the approver in the Business view.
5. AP agent (agent:ap-agent-01, AP_INBOX_V1): unchanged. Used when an alternate supplier asks for payment or a bank change (second-order consequence of rerouting).

13.5 CONTRACT ADDITIONS (via CCR first)
- Tools (additionalProperties:false, schemas in contracts/schemas/tools/): get_disruption_signals {region, since} (read), get_shipments {purchase_order (opt)} (read), get_inventory_position {material (opt)} (read), run_scenario_plan {purchase_order, signal_ids} (compute; deterministic planner; returns options[{option_id, mode, cost_inr, delay_days, penalty_avoided_inr, formula}]).
- Lease templates SENSE_V1, PLAN_V1, LOGISTICS_V1 (policy/templates.yaml); principals agent:sensing-01, agent:planner-01, agent:logistics-01 (Section 7).
- Rule R-FRT-03: book_freight AIR with cost above config HIGH_VALUE_APPROVAL_INR (default Rs 2,00,000, an assumption) -> HOLD_AMOUNT_NEEDS_APPROVAL; approver decision releases it (idempotent).
- Rule R-SIG-01: a state-changing action justified by UNVERIFIED-channel text alone with no AUTHORITATIVE confirmation -> DENY_SIGNAL_CONTRADICTED (extends R-FRT-02).
- Tariff scenario (P1): simulated erp tariff rate entity; planner compares landed cost; same gateway rules.
- Event/field changes (for example model_provider on events) only through CCR.

13.6 DEMO SCENARIOS (all on erp_sim with SIMULATED labels; no fake "live" claims)
S1 (P0, true disruption): authoritative port feed shows closure -> Sensing flags it -> Planner computes options with formulas -> cheapest justified option is within lease -> Logistics reroutes autonomously (ALLOW) -> an air expedite above the threshold goes HOLD -> approver approves in Business view -> receipt and hash-chained audit show every step.
S2 (P0, false disruption): a poisoned email/PDF claims a closure; authoritative feed says open; air booking is DENIED with reason code, formula and Rs at risk. Agent replans safely (flag, escalate).
S3 (P0, second-order): rerouting triggers an alternate supplier whose "new bank details" arrive by email (BEC); update_supplier_bank is HELD/DENIED by oracle name mismatch. Existing R-BANK and R-PAY rules unchanged.
S4 (P1): tariff spike scenario. S5 (P1): batch blast-radius report (vulnerable vs protected profile) shown as one slide.
Timed demo script (docs/finale/demo-script.md), total 4:30 live inside the 10-min talk: 0:30 setup and persona, 1:30 S1, 1:00 S2, 1:00 S3, 0:30 audit/receipt. Final demo runs in 1-laptop mode with local Ollama; all P0 paths must work fully offline.

13.7 SAP TECHNOLOGY PLAN (use the SAP-provided landscape links first; the rest only if reachable)
P0
- SAP-provided finale landscape: add credentials to .env only, extend the ERP read adapter (ERP_READ_BACKEND=sim|sap_sandbox|sap_finale). Reads first; writes only if SAP explicitly allows and every gateway rule still applies.
- SAP Business Accelerator Hub sandbox (S/4HANA Cloud APIs, personal API key, read-only test data): live-read adapter inside erp_sim (erp_sim contract unchanged); mappers from A_Supplier, A_PurchaseOrder (confirm current non-deprecated version on api.sap.com), A_SupplierInvoice to Section 9 shapes. "SAP Live Read" Defender panel shows entity, redacted URL, status, latency, count, timestamp, badge "SAP sandbox (read-only test data)". Include a "rule dry-run on SAP data" button: R-INV rules on a sandbox PO with a synthetic +12% invoice, labeled DRY RUN, no writes. Timeouts 3 s, 2 retries; on failure show the error, never fake data.
- SAP UI5 / Fiori: Business view uses @ui5/webcomponents-react with the SAP Horizon theme, Fiori-style shell, list report and object page for receipts.
- SAP Learning Hub, student edition: all 5 members registered and finished the relevant courses/practice systems; docs/sap-alignment.md maps each control to SAP concepts and states only courses really completed. Ask SAP (Namrata Sarma / universityalliances@sap.com) what "Learning Hub integration" must visibly show in the demo, and implement it (default: a Learning Hub proof slide plus the practice-system work).
P1
- SAP BTP side-by-side app: small SAP CAP service with Fiori elements list report for pending approvals and the audit read model, built in SAP Business Application Studio, persisted on SAP HANA Cloud, deployed to BTP (Cloud Foundry). It is only a UI/read model; approvals still execute in the gateway.
- SAP Generative AI Hub / AI Core as optional MODEL_PROVIDER=sap_ai_core behind the existing LLM interface: temperature 0, schema-constrained, synthetic data only, auto-fallback to Ollama then to labeled model-output replay. Gateway decisions must be identical regardless of provider.
P2
- SAP Analytics Cloud story over exported decisions (Rs at risk, ALLOW/HOLD/DENY counts). Joule or SAP IBP/TM/Ariba only if provided in the landscape; otherwise use them only as positioning ("AgentShield sits beside IBP for planning, TM for freight, Ariba for suppliers"), never as claimed integrations.
Honesty labels on every UI badge and slide: "SAP sandbox (read-only)", "SAP-provided landscape", "SIMULATED (erp_sim)", "recorded backup". The recorded backup video is allowed by SAP but must be labeled when shown (principle 7).

13.8 JUDGING ARTIFACTS (docs/finale/, owners in brackets)
- problem-statement.md: one specific scenario with boundaries (for example pharma cold-chain or tariff-exposed manufacturer), root cause, and who is hurt. [Harshita]
- evidence-log.md: 3 to 5 real stakeholder conversations (AP/logistics/finance people, faculty, SAP-ecosystem contacts) with dated notes, plus cited sources. Never invent numbers or quotes; mark Rs 59,20,000 as a scenario exposure, not a real loss. [Kirti]
- empathy-map.md, failure-modes.md (what can go wrong when agents act autonomously), agent-human-interaction-map.md (Round 1 artifacts, refreshed). [Harshita]
- systems-thinking.md: upstream/downstream process links, 2nd-order consequences (autonomy -> fraud, cost overruns, alert fatigue), change-management plan (pilot in shadow mode, then approval-gated, then bounded autonomy; training; who owns the lease policy). [Yogesh]
- business-model.md: Business Model Canvas, buyer and value proposition, revenue model (assumption-labeled: per-company-code subscription plus per-governed-action usage), go-to-market (SAP partner/BTP side-by-side extension channel, pilot with mid-size manufacturers). [Chandan]
- cost-and-timeline.md: build effort, skills, free-tier cost, 90-day pilot plan. [Pavan]
- deck + qna-prep.md (hard 10:00 stop, 5-min Q&A list, one owner per question) and demo-backup.mp4. [Pavan + all]
Every artifact must be shown or referenced in the 10-minute talk: problem and evidence 2:00, solution and architecture 1:00, live demo 4:30, systems thinking and business 1:30, resources and team 0:45, close 0:15.

13.9 PRIORITIES AND PLAN (nothing removed; this only orders the work)
P0: orchestrator + 3 agents + S1/S2/S3, new rules/tools, Business view (approval) + Defender view (audit, SAP Live Read) + Stage view, SAP P0 items, finale artifacts, backup video.
P1: CAP + HANA Cloud app, SAP AI Core provider, tariff scenario S4, blast-radius report S5, Attacker view polish.
P2: SAC story, Ed25519 hardening and TLS, extra attacks, 3-laptop mode.
Days: D1 Wed 28 CCR PR + skeleton + SAP accounts (Learning Hub, api.sap.com key, BTP) | D2 Thu 29 gateway rules, leases, erp_sim golden, model eval | D3 Fri 30 sensing/planner, signals oracle, scenario planner | D4 Sat 31 logistics, approvals, S1-S3 end to end | D5 Sun 1 SAP P0/P1, UI, artifacts; EVENING GO/NO-GO for P1/P2 | D6 Mon 2 hardening, e2e, record backup video, rehearsals x2 | D7 Tue 3 freeze 12:00, final rehearsals, laptop/connector/charger checklist, offline test.

13.10 TESTS AND DONE-WHEN
- Unit tests for R-FRT-03, R-SIG-01, planner formulas, mappers; adversarial tests for S2 and S3; contract tests for new tools; live SAP tests marked @pytest.mark.live_sap (skipped in CI, run by hand pre-demo); SAP key never in logs/events/UI; sandbox failure shows an error, not fake data.
- Done when: all old tests and golden_digest pass with flags OFF; S1-S3 run end to end offline on ONE laptop in under 4:30 three times in a row; rejected actions leave the state digest unchanged; the artifacts exist; 10-min talk rehearsed twice under 10:00; backup video recorded.
