import sys
from pathlib import Path

# Ensure backend directory is in sys.path so 'import app...' works when started from project root
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.db.session import init_db, AsyncSessionLocal
from app.models.domain import User, Project, Application, Assessment, Finding
from app.assessment.checks import SecurityHeadersCheck
from app.assessment.interfaces import AssessmentContext
from app.assessment.runner import execute_assessment

from app.api.v1.health import router as health_router
from app.api.v1.auth import router as auth_router, hash_password
from app.api.v1.projects import router as projects_router
from app.api.v1.applications import router as applications_router
from app.api.v1.assessments import router as assessments_router
from app.api.v1.findings import router as findings_router
from app.api.v1.reports import router as reports_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.monitoring import router as monitoring_router
from app.api.v1.intent import router as intent_router
from app.api.v1.evolution import router as evolution_router

async def seed_initial_data():
    async with AsyncSessionLocal() as db:
        # Check if project already exists
        p_stmt = select(Project).limit(1)
        res = await db.execute(p_stmt)
        if res.scalar_one_or_none():
            return

        # 1. Create Default Admin User
        admin_user = User(
            email="admin@cyberai.io",
            password_hash=hash_password("admin123"),
            is_active=True
        )
        db.add(admin_user)
        await db.flush()

        # 2. Create Initial Projects
        proj1 = Project(
            user_id=admin_user.id,
            name="Core Digital Assets",
            description="Main customer portal, e-commerce applications, and public cloud APIs."
        )
        proj2 = Project(
            user_id=admin_user.id,
            name="Internal Infrastructure",
            description="Internal administrative dashboards, microservices, and staging services."
        )
        db.add_all([proj1, proj2])
        await db.flush()

        # 3. Create Applications
        app1 = Application(
            project_id=proj1.id,
            name="Customer Portal & Store",
            base_url="https://example.com",
            environment="Production",
            authorization_confirmed=True,
            allowed_hosts=["example.com"],
            scope_policy="STRICT",
            score=82
        )
        app2 = Application(
            project_id=proj1.id,
            name="Cloud Payment Gateway",
            base_url="https://httpbin.org",
            environment="Production",
            authorization_confirmed=True,
            allowed_hosts=["httpbin.org"],
            scope_policy="STRICT",
            score=68
        )
        app3 = Application(
            project_id=proj2.id,
            name="Internal Auth Service",
            base_url="https://staging.internal.net",
            environment="Staging",
            authorization_confirmed=True,
            allowed_hosts=["staging.internal.net"],
            scope_policy="STRICT",
            score=95
        )
        db.add_all([app1, app2, app3])
        await db.flush()

        # 4. Trigger initial assessment for app1
        assessment1 = Assessment(
            application_id=app1.id,
            name="Baseline Security Assessment",
            type="Full DAST",
            status="PENDING"
        )
        db.add(assessment1)
        await db.commit()

        # Run the assessment to generate real findings
        await execute_assessment(db, assessment1.id)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables and seed initial data
    await init_db()
    try:
        await seed_initial_data()
    except Exception as e:
        print(f"Warning: Seed initialization error: {e}")
    yield

app = FastAPI(
    title="CyberAI API",
    version="1.0.0",
    description="Next-Generation Autonomous Security Assessment Platform",
    lifespan=lifespan
)

# Enable CORS for Frontend Development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API v1 Routers
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(projects_router, prefix="/api/v1")
app.include_router(applications_router, prefix="/api/v1")
app.include_router(assessments_router, prefix="/api/v1")
app.include_router(findings_router, prefix="/api/v1")
app.include_router(reports_router, prefix="/api/v1")
app.include_router(alerts_router, prefix="/api/v1")
app.include_router(monitoring_router, prefix="/api/v1")
app.include_router(intent_router, prefix="/api/v1")
app.include_router(evolution_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "platform": "CyberAI Autonomous Security Assessment",
        "status": "online",
        "version": "1.0.0",
        "docs_url": "/docs"
    }
