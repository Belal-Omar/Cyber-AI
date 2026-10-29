# Security Model

The CyberAI platform is designed with a strict security model to ensure safe operation, prevent abuse, and protect sensitive vulnerability data.

## 1. Target Authorization & Boundaries
- **Explicit Authorization**: The platform strictly requires users to explicitly confirm authorization before registering any application.
- **Local Targets Only**: During the initial phases (and enforced by the engine design), assessments are strictly bound to controlled, local applications hosted in the `/test-targets/` directory.
- **Scope Enforcement**: Applications have strict scope policies defined by `allowed_hosts`, `allowed_paths`, and `excluded_paths`. The assessment engine refuses to execute checks outside this predefined scope.

## 2. Authentication & Session Management
- **Credentials**: Passwords are securely hashed (e.g., using Argon2 or bcrypt). Plaintext passwords are never stored or logged.
- **Sessions**: Uses secure JWT or session cookies with proper expiration and CSRF protection.

## 3. Data Protection
- **Secrets Management**: No API keys, tokens, or database credentials are exposed in logs, API responses, or error messages.
- **Sanitization**: All evidence and technical observations are sanitized before rendering in the UI to prevent Stored XSS against the platform's users.

## 4. Platform Hardening
- **Input Validation**: All API inputs are strictly validated using Pydantic schemas.
- **Protection against Vulnerabilities**: The platform itself is built to resist SQL Injection (via SQLAlchemy ORM), SSRF (via strict target allowlists and DNS rebinding protections), Path Traversal, and Command Injection (by avoiding arbitrary shell execution).

## 5. Audit Logging
Every significant action is logged for accountability. This includes:
- Project and Application creation/modification.
- Assessment configuration and initiation.
- Finding status changes (e.g., marking as False Positive or Accepted Risk).
- Verification runs.
