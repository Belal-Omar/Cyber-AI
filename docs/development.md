# Development Guide

CyberAI is built using a modern, containerized monorepo architecture. 

## Development Phases
We follow a strict, phased implementation plan. **Do not jump ahead to functional security testing before the foundation is solid.**

- **PHASE 0**: Architecture and documentation.
- **PHASE 1**: Application Foundation + Database Models + Docker Environment + Frontend Shell + Assessment Interfaces (Current Phase). **Note:** CRUD endpoints are not fully implemented yet; Phase 1 is strictly about laying out the models, directory structures, and environment bindings.
- **PHASE 2**: Authentication and projects.
- **PHASE 3**: Applications and assessments.
- **PHASE 4**: Controlled local assessment engine.
- **PHASE 5**: Findings and evidence.
- **PHASE 6**: Verification/recheck.
- **PHASE 7**: Source-code association.
- **PHASE 8**: AI analysis.
- **PHASE 9**: Reports.
- **PHASE 10**: Security hardening and testing.

## Local Environment Setup
The development environment relies on Docker Compose.

1. Ensure Docker and Docker Compose are installed.
2. Copy `.env.example` to `.env` and fill in dummy local values.
3. Start the stack: `docker compose up --build`

### Test Targets
Local intentionally vulnerable applications are located in `/test-targets/`. All development and integration tests for the Assessment Engine must be pointed here. **Do not use external public websites for testing.**

## Code Quality Standards
- **Python**: Use `mypy` for strict type hinting, `black` for formatting, and `flake8` for linting.
- **React**: Use TypeScript strictly, with `eslint` and `prettier`.
- **Testing**: Maintain high coverage using `pytest` for the backend and `vitest` for the frontend.
