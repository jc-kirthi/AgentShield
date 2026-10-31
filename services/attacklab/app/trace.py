"""HTTP capture helpers for AttackLab scenario runners."""

from typing import Any, Dict, Optional, Tuple
import httpx


async def capture(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json: Any = None,
) -> Tuple[Optional[httpx.Response], Dict[str, Any]]:
    """Execute one HTTP call and record the real request/response.

    Connection failures are recorded as INFRASTRUCTURE_FAILURE. Callers must
    not invent a gateway decision from a missing response.
    """
    record: Dict[str, Any] = {
        "method": method.upper(),
        "url": url,
        "request_headers": {k: v for k, v in (headers or {}).items() if k.lower() != "authorization"},
        "request_body": json,
        "status_code": None,
        "response": None,
        "ok": False,
        "incomplete_reason": None,
    }
    try:
        resp = await client.request(method.upper(), url, headers=headers, json=json)
        record["status_code"] = resp.status_code
        try:
            record["response"] = resp.json()
        except Exception:
            record["response"] = resp.text
        record["ok"] = True
        return resp, record
    except Exception as exc:
        record["incomplete_reason"] = "INFRASTRUCTURE_FAILURE"
        record["error"] = f"{type(exc).__name__}: {exc}"
        return None, record


def gateway_decision_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a gateway decision only from an actual HTTP body.

    Missing or non-JSON responses yield INCOMPLETE — never a synthetic ALLOW/DENY.
    """
    if not record.get("ok"):
        return {
            "decision": "INCOMPLETE",
            "reason_code": "DENY_DEPENDENCY_UNAVAILABLE",
            "run_status": "INFRASTRUCTURE_FAILURE",
            "checks": [],
            "correlation_id": None,
            "message": record.get("error") or record.get("incomplete_reason"),
            "inr_at_risk": 0,
        }
    body = record.get("response")
    if not isinstance(body, dict) or "decision" not in body:
        return {
            "decision": "INCOMPLETE",
            "reason_code": "DENY_DEPENDENCY_UNAVAILABLE",
            "run_status": "INVALID_GATEWAY_RESPONSE",
            "checks": [],
            "correlation_id": None,
            "message": "Gateway response missing decision field",
            "inr_at_risk": 0,
            "raw": body,
        }
    return {
        "decision": body.get("decision"),
        "reason_code": body.get("reason_code"),
        "run_status": "COMPLETED",
        "checks": body.get("checks") or [],
        "correlation_id": body.get("correlation_id"),
        "decision_id": body.get("decision_id"),
        "rule_id": body.get("rule_id"),
        "message": body.get("message"),
        "inr_at_risk": body.get("inr_at_risk", 0),
        "formula": body.get("formula"),
        "approval_id": body.get("approval_id"),
        "idempotent_replay": body.get("idempotent_replay", False),
        "result": body.get("result"),
        "http_status": record.get("status_code"),
    }
