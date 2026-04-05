from fastapi import APIRouter
from collections import defaultdict
from ..models.schemas import MetricsResponse
from .waf import get_request_log, get_engine_stats

router = APIRouter(prefix="/metrics", tags=["Business Risk Dashboard"])

# Map raw module names to ERP module labels
_ERP_MODULE_MAP = {
    "CRM": "CRM", "Email": "CRM", "crm": "CRM",
    "Finance": "Finance", "Payment": "Finance",
    "HR": "HR", "Procurement": "Procurement",
    "Forms": "CRM", "Website": "CRM",
    "AttackLab": "Demo", "generic": "System",
}


def _to_erp_module(raw: str) -> str:
    return _ERP_MODULE_MAP.get(raw or "", raw or "System")


def _normalized_decision(value: str) -> str:
    d = (value or "").strip().lower()
    if d == "sanitize":
        return "block"
    return d or "allow"


@router.get("", response_model=MetricsResponse)
@router.get("/", response_model=MetricsResponse)
async def get_metrics():
    logs = get_request_log()
    if not logs:
        return _demo_metrics()

    total = len(logs)
    blocked = sum(1 for l in logs if _normalized_decision(l.get("decision")) == "block")
    warned = sum(1 for l in logs if _normalized_decision(l.get("decision")) == "warn")
    allowed = total - blocked - warned
    avg_risk = sum(l.get("risk_score", 0) for l in logs) / total

    by_module: dict = defaultdict(int)
    erp_breakdown: dict = defaultdict(int)
    for l in logs:
        if _normalized_decision(l.get("decision")) in ("block", "warn"):
            raw_mod = l.get("module", "unknown")
            by_module[raw_mod] += 1
            erp_breakdown[_to_erp_module(raw_mod)] += 1

    dist = {
        "low": sum(1 for l in logs if l.get("risk_score", 0) < 0.30),
        "medium": sum(1 for l in logs if 0.30 <= l.get("risk_score", 0) < 0.70),
        "high": sum(1 for l in logs if l.get("risk_score", 0) >= 0.70),
    }

    recent = [
        {
            "request_id": l.get("request_id", ""),
            "erp_module": _to_erp_module(l.get("module", "")),
            "module": l.get("module", ""),
            "user_id": l.get("user_id", "—"),
            "action": l.get("action", l.get("type", "activity")),
            "risk_score": l.get("risk_score", 0),
            "decision": _normalized_decision(l.get("decision")).upper(),
            "erp_impact": (
                "transaction_blocked" if _normalized_decision(l.get("decision")) == "block"
                else "flagged_for_review" if _normalized_decision(l.get("decision")) == "warn"
                else "transaction_approved"
            ),
            "patterns": l.get("patterns", [])[:2],
        }
        for l in reversed(logs)
        if _normalized_decision(l.get("decision")) in ("block", "warn")
    ][:10]

    eng = get_engine_stats()

    return MetricsResponse(
        total_requests=total,
        blocked_count=blocked,
        warned_count=warned,
        allowed_count=allowed,
        block_rate=round(blocked / total * 100, 1),
        avg_risk_score=round(avg_risk, 3),
        threats_by_module=dict(by_module),
        risk_distribution=dist,
        recent_attacks=recent,
        llm_calls_total=eng.get("llm_calls", 0),
        llm_calls_skipped=eng.get("llm_skipped", 0),
        decision_cache_hits=eng.get("cache_hits", 0),
        erp_module_breakdown=dict(erp_breakdown),
        recent_decisions=recent,
        network_risk_events=sum(1 for l in logs if l.get("erp_context", {}).get("network") == "risky"),
    )


def _demo_metrics() -> MetricsResponse:
    recent_decisions = [
        {
            "request_id": "a1b2c3", "erp_module": "CRM", "module": "CRM",
            "user_id": "emp_042", "risk_score": 0.94, "decision": "BLOCK",
            "erp_impact": "transaction_blocked", "patterns": ["sql_injection"],
        },
        {
            "request_id": "d4e5f6", "erp_module": "Finance", "module": "Finance",
            "user_id": "emp_017", "risk_score": 0.88, "decision": "BLOCK",
            "erp_impact": "transaction_blocked", "patterns": ["prompt_injection"],
        },
        {
            "request_id": "g7h8i9", "erp_module": "HR", "module": "HR",
            "user_id": "emp_031", "risk_score": 0.47, "decision": "WARN",
            "erp_impact": "flagged_for_review", "patterns": ["xss"],
        },
    ]
    return MetricsResponse(
        total_requests=312, blocked_count=18, warned_count=41, allowed_count=253,
        block_rate=5.8, avg_risk_score=0.21,
        threats_by_module={"CRM": 35, "Finance": 14, "HR": 10},
        risk_distribution={"low": 253, "medium": 41, "high": 18},
        recent_attacks=recent_decisions,
        llm_calls_total=42, llm_calls_skipped=198, decision_cache_hits=61,
        erp_module_breakdown={"CRM": 35, "Finance": 14, "HR": 10},
        recent_decisions=recent_decisions,
        network_risk_events=3,
    )
