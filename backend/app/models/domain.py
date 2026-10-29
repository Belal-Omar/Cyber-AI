import uuid
from sqlalchemy import ForeignKey, String, Boolean, JSON, Text, Float, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
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
    score: Mapped[int] = mapped_column(Integer, default=85)
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
    config_id: Mapped[uuid.UUID] = mapped_column(ForeignKey('assessment_configs.id'), nullable=True)
    name: Mapped[str] = mapped_column(String, default="Standard Scan")
    type: Mapped[str] = mapped_column(String, default="Full DAST")
    status: Mapped[str] = mapped_column(String, default="PENDING")

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
