# Graduation Project
1. Project Overview

The project is a web-based platform for scanning websites and identifying potential security vulnerabilities. Users will be able to add their websites, start security scans, view the results, and generate reports that explain the detected vulnerabilities and how to fix them.

The platform will also support rescanning websites to check whether previously detected vulnerabilities have been fixed.

2. Technologies Used

The following technologies were selected for the initial development of the project:

Node.js: The runtime environment for the backend.

TypeScript: Used to write more structured and maintainable code.

Express.js: Used to build the backend APIs.

Prisma ORM: Used to manage database operations and connect the backend to the database.

SQLite: Used as the database during development because it is simple to set up and suitable for the current stage of the project.

PostgreSQL can be considered for the production version as the project grows.

3. Work Completed So Far

A. Database Design

The initial database structure was created based on the project's requirements. It includes the following models:

User: Stores user information, such as name, email, password, and account status.

Project: Allows each user to organize their websites into separate projects.

Target: Stores the website URLs that will be scanned.

Scan: Stores scan information, including its status, such as Pending, Running, Completed, or Failed.

Vulnerability: Stores information about detected vulnerabilities, including their names, descriptions, severity levels, remediation steps, and status.

Report: Stores reports associated with scan results.

ScanConfiguration: Stores the configuration options for each target.

AuditLog: Records important actions performed within the platform.

These models provide the initial structure needed to connect users, projects, targets, scans, and their results.

B. Backend API Setup

The initial backend server was set up using Node.js, TypeScript, and Express.js. A few API endpoints were added to test the basic functionality:

GET /api/health — Checks whether the server is running and verifies database connectivity.

POST /api/users — Provides an initial endpoint for creating users.

POST /api/scans/start — Provides an initial endpoint for starting a scan and updating its status.

These endpoints are currently part of the initial implementation. Additional development is required before they can be considered production-ready.

C. Development Environment

The basic development environment was configured, including:

Adjusting tsconfig.json to work with the backend setup.

Configuring the .env file for environment variables and the database connection.

Setting up Prisma to work with the database schema.

The project files are organized to allow further development of the backend and database.

4. How the Frontend and Backend Will Work Together

The project will follow a client-server architecture.

Backend responsibilities:

Handle API requests and business logic.

Manage database operations.

Handle user authentication and permissions.

Start scans and store their results.

Provide scan results and reports to the frontend.

Frontend responsibilities:

Display the website interface and dashboard.

Allow users to manage their projects and website targets.

Send requests to the backend APIs.

Display scan progress, detected vulnerabilities, and reports.

The frontend will communicate with the backend through HTTP requests. It will not connect directly to the database.

5. Next Development Steps

The following tasks are planned for the next stages of development:

User Authentication: Implement registration, login, password hashing, and JWT-based authentication.

Scan Engine: Integrate security scanning tools, such as OWASP ZAP, to perform actual security tests on authorized targets.

Vulnerability Management: Store scan findings in the database and organize them by severity and status.

Reports: Generate reports containing scan results, vulnerability details, and recommended fixes.

Rescan Functionality: Allow users to run scans again and check whether previously reported issues have been resolved.

Frontend Integration: Connect the dashboard to the backend APIs.

Security and Testing: Validate API inputs, enforce access control, handle errors, and test the main application features.

Subscription System: Consider adding a payment gateway and subscription plans after the core functionality is working.

6. Admin Authentication System (Completed)

An end-to-end Admin Authentication and Security Management module has been implemented:

- **Database Engine**: Built on **SQLite (`prisma/dev.db`)** using Prisma ORM (zero external database configuration required).
- **Security & Password Hashing**: Passwords are never hardcoded. All credentials are encrypted using **bcrypt** (salt rounds = 10) and queried dynamically from the `user` table in `prisma/dev.db`.
- **Strict Role Verification**: Enforces `role === 'ADMIN'` at both the login endpoint and on all protected API routes using JWT middleware (`requireAdminAuth`). Non-admin users are rejected with `403 Forbidden`.
- **Audit Logging**: Every successful admin login and unauthorized attempt is logged in real-time to the SQLite `auditlog` table.
- **Frontend Portal (Sential AI Design)**:
  - **Admin Login UI** (`http://localhost:3000/admin/login`): Pixel-perfect implementation of the Sential AI Figma design with input validation, password toggle, status alerts, and responsive layout.
  - **Admin Dashboard Placeholder** (`http://localhost:3000/admin/dashboard`): Protected dashboard route with JWT authentication check, displaying verified admin status and ready for the dashboard UI team.

### Running and Testing the Project:
1. Push database schema to SQLite: `npx prisma db push`
2. Seed default admin and sample data: `npm run seed`
3. Start development server: `npm run dev`
4. Open browser: `http://localhost:3000/admin/login`

**Default Seeded Test Accounts:**
- **Admin Account**: `admin@scanner.local` / `graduationProject77@1` (Role: `ADMIN` -> Access Granted)
- **Regular User**: `analyst@scanner.local` / `User@123456` (Role: `USER` -> Access Denied with 403)
