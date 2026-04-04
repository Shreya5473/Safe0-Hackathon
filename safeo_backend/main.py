from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routers import waf, simulate, feedback, metrics, erp
from .agents.behavior_agent import BehaviorAgent
from .models.schemas import BehaviorRequest

app = FastAPI(
    title="SafeO ERP Shield — Decision Engine API",
    description=(
        "SafeO ERP Shield: a real-time risk decision engine embedded inside ERP workflows. "
        "Analyzes transactions, employee activity, CRM inputs, and data output for business-context threats."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(waf.router)
app.include_router(simulate.router)
app.include_router(feedback.router)
app.include_router(metrics.router)
app.include_router(erp.router)

_behavior_agent = BehaviorAgent()


@app.post("/waf/behavior")
async def track_behavior(req: BehaviorRequest):
    return _behavior_agent.track_action(req.user_id, req.action)


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "SafeO ERP Shield", "version": "2.0.0"}


@app.get("/")
async def root():
    return {
        "service": "SafeO ERP Shield — Decision Engine",
        "version": "2.0.0",
        "erp_endpoints": [
            "/erp/transaction",
            "/erp/employee/activity",
            "/erp/crm/lead",
            "/erp/finance/action",
            "/erp/network/signal",
            "/erp/dashboard/summary",
        ],
        "legacy_endpoints": [
            "/waf/input",
            "/waf/output",
            "/waf/behavior",
            "/simulate/attack",
            "/feedback",
            "/metrics",
        ],
    }
