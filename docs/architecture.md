# Architecture

The CyberAI platform is built as a modular, decoupled web application focusing on maintainability and strict security boundaries.

## System Components

### 1. Frontend (Web UI)
- **Framework**: React with TypeScript.
- **Tooling**: Vite for fast bundling and HMR.
- **Styling**: Tailwind CSS for responsive and consistent design.
- **Role**: Provides the dashboard for managing projects, applications, assessments, findings, and viewing detailed reports and source code context.

### 2. Backend (FastAPI API)
- **Framework**: Python with FastAPI.
- **Role**: The core REST API serving the frontend, managing authentication, defining the business logic, and orchestrating assessments.
- **Structure**: Uses a modular directory layout (`api`, `core`, `db`, `models`, `schemas`, `services`, `assessment`, `verification`).

### 3. Database
- **Engine**: PostgreSQL.
- **ORM**: SQLAlchemy with Alembic for migrations.
- **Role**: Stores all state, including users, projects, application scopes, assessment configurations, endpoint inventories, observations, findings, occurrences, evidence, and audit logs.

### 4. Background Processing
- **Queue**: Redis and Celery.
- **Role**: Offloads long-running assessment checks, verification runs, and report generation from the main API thread.

### 5. Assessment Engine
- **Role**: A modular subsystem invoked by the backend/workers to run specific security checks against local test targets. It converts raw HTTP/System interaction into structured `observations`.

## High-Level Flow
1. User registers an **Application** under a **Project** (confirming authorization).
2. User configures and triggers an **Assessment**.
3. Background workers execute modular **Assessment Checks**.
4. Checks produce raw **Observations** (technical output).
5. The backend analyzes and deduplicates Observations into logical **Findings** and records **Finding Occurrences**.
6. The user requests a **Verification Run** for a Finding, which triggers a re-run of the specific assessment check against the original context to verify remediation.
