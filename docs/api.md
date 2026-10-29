# API Specification

The REST API is implemented in FastAPI under `/api/v1/`.

## Authentication
- `POST /auth/login`: Authenticate and receive session token/JWT.
- `POST /auth/logout`: Invalidate session.

## Projects & Applications
- `GET /projects`: List user's projects.
- `POST /projects`: Create a new project.
- `GET /projects/{id}/applications`: List applications in a project.
- `POST /applications`: Register an application (requires explicit authorization confirmation and scope parameters).
- `GET /applications/{id}/endpoints`: List discovered endpoints for an application.

## Assessments
- `POST /assessments`: Trigger a new assessment (requires `application_id` and `assessment_config`).
- `GET /assessments/{id}`: Get assessment status and progress.
- `GET /assessments/{id}/observations`: List raw observations from the assessment.

## Findings & Verification
- `GET /findings`: List findings across applications (supports filtering by status, severity, etc.).
- `GET /findings/{id}`: Detailed finding view (includes endpoints, source locations, and occurrences).
- `GET /findings/{id}/evidence`: Get structured evidence for a finding.
- `PATCH /findings/{id}/status`: Manually update status (e.g., mark as `FALSE_POSITIVE` or `ACCEPTED_RISK`).
- `POST /findings/{id}/verify`: Trigger a verification run for a specific finding.
- `GET /findings/{id}/verifications`: List historical verification runs.

## Reports & Audit
- `POST /reports`: Generate a new report (HTML, PDF, JSON).
- `GET /audit-logs`: Query audit logs for accountability tracking.
