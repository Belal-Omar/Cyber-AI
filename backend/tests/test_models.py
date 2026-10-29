from app.models.domain import (
    User, Project, Application, Endpoint, AssessmentConfig,
    Assessment, Observation, Finding, FindingOccurrence,
    FindingEvidence, VerificationRun, SourceFile, SourceLocation,
    Report, AuditLog
)

def test_models_instantiation():
    user = User(email="test@example.com", password_hash="hash")
    project = Project(name="Test Proj", owner=user)
    app = Application(name="Test App", base_url="http://localhost", environment="dev", project=project)
    endpoint = Endpoint(url_path="/api", http_method="GET")
    config = AssessmentConfig(enabled_checks={"xss": True})
    assessment = Assessment(status="QUEUED")
    observation = Observation(check_name="headers", raw_output="missing")
    finding = Finding(title="SQLi", category="AppSec", severity="High", status="OPEN")
    occurrence = FindingOccurrence()
    evidence = FindingEvidence(evidence_type="HTTP", sanitized_details="payload")
    verification = VerificationRun(previous_status="OPEN", verification_status="FIXED")
    source_file = SourceFile(file_path="app.py", language="python", content_hash="abc")
    source_loc = SourceLocation(start_line=10, end_line=12)
    report = Report(format="PDF", file_path="/tmp/r.pdf")
    log = AuditLog(action="CREATE_PROJECT", resource_type="Project", resource_id="123")

    assert user.email == "test@example.com"
    assert project.name == "Test Proj"
    assert app.environment == "dev"
    assert finding.status == "OPEN"
