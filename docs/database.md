# Database Schema

The PostgreSQL database schema is designed to separate technical observations from logical findings, manage scope, track endpoints, and retain a complete verification history.

## Core Entities (UUID PKs, created_at, updated_at)

### Identity & Access
- **users**: `id`, `email`, `password_hash`, `is_active`
- **projects**: `id`, `user_id` (FK), `name`, `description`

### Target Management
- **applications**: `id`, `project_id` (FK), `name`, `base_url`, `environment`, `authorization_confirmed` (boolean), `allowed_hosts` (JSON/Array), `allowed_paths`, `excluded_paths`, `scope_policy`
- **endpoints**: `id`, `application_id` (FK), `url_path`, `http_method`, `parameters` (JSON), `content_type`, `discovered_at`

### Assessment Execution
- **assessment_configs**: `id`, `application_id` (FK), `enabled_checks` (JSON), `rate_limits`, `auth_context` (JSON - future)
- **assessments**: `id`, `application_id` (FK), `config_id` (FK), `status` (QUEUED, RUNNING, COMPLETED, etc.), `started_at`, `completed_at`

### Vulnerability Data Model
- **observations**: `id`, `assessment_id` (FK), `check_name`, `raw_output`, `timestamp`. (Raw technical output from a check).
- **findings**: `id`, `application_id` (FK), `title`, `category`, `severity`, `confidence`, `status` (OPEN, UNDER_REVIEW, FIXED, etc.), `endpoint_id` (FK), `parameter`, `impact`, `remediation`. (The logical security issue).
- **finding_occurrences**: `id`, `finding_id` (FK), `assessment_id` (FK), `observation_id` (FK), `timestamp`. (Tracks when a finding was seen in a specific assessment to prevent duplicates).
- **finding_evidence**: `id`, `finding_occurrence_id` (FK), `request_context` (JSON), `response_context` (JSON), `evidence_type`, `sanitized_details`, `timestamp`.

### Verification Lifecycle
- **verification_runs**: `id`, `finding_id` (FK), `assessment_id` (FK - context), `timestamp`, `previous_status`, `verification_status` (FIXED, STILL_PRESENT, INCONCLUSIVE), `notes`

### Source Code Mapping
- **source_files**: `id`, `project_id` (FK), `file_path`, `language`, `content_hash`
- **source_locations**: `id`, `finding_id` (FK), `source_file_id` (FK), `start_line`, `end_line`, `code_context`, `confidence`

### Audit & Reporting
- **reports**: `id`, `project_id` (FK), `assessment_id` (FK), `format`, `file_path`
- **audit_logs**: `id`, `user_id` (FK), `action`, `resource_type`, `resource_id`, `metadata` (JSON), `timestamp`
