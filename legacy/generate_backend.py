import os
from pathlib import Path

backend_dir = Path("backend")
app_dir = backend_dir / "app"
app_dir.mkdir(parents=True, exist_ok=True)
(app_dir / "api" / "v1").mkdir(parents=True, exist_ok=True)
(app_dir / "core").mkdir(parents=True, exist_ok=True)
(app_dir / "db").mkdir(parents=True, exist_ok=True)
(app_dir / "models").mkdir(parents=True, exist_ok=True)
(app_dir / "schemas").mkdir(parents=True, exist_ok=True)
(app_dir / "services").mkdir(parents=True, exist_ok=True)
(app_dir / "assessment").mkdir(parents=True, exist_ok=True)
(backend_dir / "tests").mkdir(parents=True, exist_ok=True)

# Generate config.py
with open(app_dir / "core" / "config.py", "w") as f:
    f.write('''from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberAI API"
    DATABASE_URL: str
    REDIS_URL: str
    SECRET_KEY: str
    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"

settings = Settings()
''')

# Generate db session
with open(app_dir / "db" / "session.py", "w") as f:
    f.write('''from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
''')

# Generate base model
with open(app_dir / "models" / "base.py", "w") as f:
    f.write('''import uuid
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import DateTime
from sqlalchemy.dialects.postgresql import UUID

class Base(DeclarativeBase):
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
''')

# Generate all models
with open(app_dir / "models" / "domain.py", "w") as f:
    f.write('''import uuid
from sqlalchemy import ForeignKey, String, Boolean, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID
from app.models.base import Base

class User(Base):
    __tablename__ = 'users'
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    projects = relationship("Project", back_populates="owner")

class Project(Base):
    __tablename__ = 'projects'
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'))
    name: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String, nullable=True)
    owner = relationship("User", back_populates="projects")
    applications = relationship("Application", back_populates="project")

class Application(Base):
    __tablename__ = 'applications'
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('projects.id'))
    name: Mapped[str] = mapped_column(String)
    base_url: Mapped[str] = mapped_column(String)
    environment: Mapped[str] = mapped_column(String)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_hosts: Mapped[dict] = mapped_column(JSON, nullable=True)
    allowed_paths: Mapped[str] = mapped_column(String, nullable=True)
    excluded_paths: Mapped[str] = mapped_column(String, nullable=True)
    scope_policy: Mapped[str] = mapped_column(String, nullable=True)
    project = relationship("Project", back_populates="applications")

class Endpoint(Base):
    __tablename__ = 'endpoints'
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('applications.id'))
    url_path: Mapped[str] = mapped_column(String)
    http_method: Mapped[str] = mapped_column(String)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=True)
    content_type: Mapped[str] = mapped_column(String, nullable=True)

class AssessmentConfig(Base):
    __tablename__ = 'assessment_configs'
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('applications.id'))
    enabled_checks: Mapped[dict] = mapped_column(JSON)
    rate_limits: Mapped[dict] = mapped_column(JSON, nullable=True)
    auth_context: Mapped[dict] = mapped_column(JSON, nullable=True)

class Assessment(Base):
    __tablename__ = 'assessments'
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('applications.id'))
    config_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('assessment_configs.id'))
    status: Mapped[str] = mapped_column(String)

class Observation(Base):
    __tablename__ = 'observations'
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('assessments.id'))
    check_name: Mapped[str] = mapped_column(String)
    raw_output: Mapped[str] = mapped_column(Text)

class Finding(Base):
    __tablename__ = 'findings'
    application_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('applications.id'))
    title: Mapped[str] = mapped_column(String)
    category: Mapped[str] = mapped_column(String)
    severity: Mapped[str] = mapped_column(String)
    confidence: Mapped[float] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(String)
    endpoint_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('endpoints.id'), nullable=True)
    parameter: Mapped[str] = mapped_column(String, nullable=True)
    impact: Mapped[str] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)

class FindingOccurrence(Base):
    __tablename__ = 'finding_occurrences'
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('findings.id'))
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('assessments.id'))
    observation_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('observations.id'))

class FindingEvidence(Base):
    __tablename__ = 'finding_evidence'
    finding_occurrence_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('finding_occurrences.id'))
    request_context: Mapped[dict] = mapped_column(JSON, nullable=True)
    response_context: Mapped[dict] = mapped_column(JSON, nullable=True)
    evidence_type: Mapped[str] = mapped_column(String)
    sanitized_details: Mapped[str] = mapped_column(Text)

class VerificationRun(Base):
    __tablename__ = 'verification_runs'
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('findings.id'))
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('assessments.id'))
    previous_status: Mapped[str] = mapped_column(String)
    verification_status: Mapped[str] = mapped_column(String)
    notes: Mapped[str] = mapped_column(Text, nullable=True)

class SourceFile(Base):
    __tablename__ = 'source_files'
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('projects.id'))
    file_path: Mapped[str] = mapped_column(String)
    language: Mapped[str] = mapped_column(String)
    content_hash: Mapped[str] = mapped_column(String)

class SourceLocation(Base):
    __tablename__ = 'source_locations'
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('findings.id'))
    source_file_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('source_files.id'))
    start_line: Mapped[int] = mapped_column(nullable=True)
    end_line: Mapped[int] = mapped_column(nullable=True)
    code_context: Mapped[str] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(nullable=True)

class Report(Base):
    __tablename__ = 'reports'
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('projects.id'))
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('assessments.id'))
    format: Mapped[str] = mapped_column(String)
    file_path: Mapped[str] = mapped_column(String)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('users.id'))
    action: Mapped[str] = mapped_column(String)
    resource_type: Mapped[str] = mapped_column(String)
    resource_id: Mapped[str] = mapped_column(String)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=True)
''')

# Generate api health
with open(app_dir / "api" / "v1" / "health.py", "w") as f:
    f.write('''from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.session import get_db

router = APIRouter()

@router.get("/health")
async def health_check():
    return {"status": "ok", "message": "CyberAI API is healthy"}

@router.get("/health/db")
async def db_health_check(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        return {"status": "ok", "message": "Database connection is healthy"}
    except Exception as e:
        raise HTTPException(status_code=503, detail="Database connection failed")
''')

# Generate main
with open(app_dir / "main.py", "w") as f:
    f.write('''from fastapi import FastAPI
from app.api.v1.health import router as health_router

app = FastAPI(title="CyberAI API", version="1.0.0")

app.include_router(health_router, prefix="/api/v1")
''')

# Generate Assessment Interfaces
with open(app_dir / "assessment" / "interfaces.py", "w") as f:
    f.write('''import uuid
from typing import Dict, Any, Optional
from pydantic import BaseModel

class AssessmentContext(BaseModel):
    assessment_id: uuid.UUID
    application_id: uuid.UUID
    base_url: str
    scope_policy: str
    allowed_hosts: list[str]
    allowed_paths: Optional[str] = None
    excluded_paths: Optional[str] = None

class Observation(BaseModel):
    check_name: str
    raw_output: str
    evidence_type: str

class AssessmentCheck:
    def metadata(self) -> Dict[str, Any]:
        raise NotImplementedError
    
    def can_run(self, context: AssessmentContext) -> bool:
        raise NotImplementedError
    
    def run(self, context: AssessmentContext) -> Observation:
        raise NotImplementedError
        
    def verify(self, original_context: Any) -> Observation:
        raise NotImplementedError
''')

# Tests
with open(backend_dir / "tests" / "test_api.py", "w") as f:
    f.write('''from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "CyberAI API is healthy"}
''')

print("Backend files generated successfully.")
