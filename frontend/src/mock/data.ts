export const mockProjects = [
  { id: 'p1', name: 'Core E-Commerce', description: 'Main digital storefront and payment APIs.', applications: 2, assessments: 14, findings: 15, posture: 78, owner: 'Security Team Alpha' },
  { id: 'p2', name: 'Internal Tools', description: 'Employee portals and HR systems.', applications: 4, assessments: 3, findings: 0, posture: 95, owner: 'IT Ops' },
];

export const mockApplications = [
  { id: '1', name: 'Digital Store', environment: 'Production', baseUrl: 'https://store.example.com', score: 82, endpoints: 42, openFindings: 3 },
  { id: '2', name: 'Secure Document Vault', environment: 'Staging', baseUrl: 'https://vault.staging.example.com', score: 95, endpoints: 18, openFindings: 0 },
  { id: '3', name: 'Payment API', environment: 'Production', baseUrl: 'https://api.example.com', score: 64, endpoints: 120, openFindings: 12 },
];

export const mockFindings = [
  { id: 'f1', title: 'Broken Object Level Authorization', severity: 'HIGH', confidence: 94, status: 'OPEN', application: 'Digital Store', endpoint: 'GET /api/users/{id}', detected: '2026-09-22T01:14:00Z', 
    description: 'The endpoint does not validate if the currently authenticated user has permission to access the requested user ID.',
    method: 'GET', parameter: 'id',
    request: 'GET /api/users/102 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbG...\n',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\n  "id": 102,\n  "email": "admin@example.com",\n  "role": "admin"\n}',
    impact: 'An attacker can enumerate and access arbitrary user profiles, potentially leaking PII or taking over accounts.',
    remediation: 'Implement authorization checks at the controller level to ensure the authenticated JWT subject matches the requested resource ID.'
  },
  { id: 'f2', title: 'Stored Cross-Site Scripting', severity: 'CRITICAL', confidence: 88, status: 'OPEN', application: 'Payment API', endpoint: 'POST /api/comments', detected: '2026-09-21T14:22:00Z',
    description: 'User input is stored and rendered without sanitization.',
    method: 'POST', parameter: 'commentBody',
    request: 'POST /api/comments HTTP/1.1\n\n{"commentBody": "<script>alert(document.cookie)</script>"}',
    response: 'HTTP/1.1 201 Created',
    impact: 'Execution of arbitrary JavaScript in the context of other users browsing the comments.',
    remediation: 'Context-aware output encoding.'
  },
  { id: 'f3', title: 'Missing Security Headers', severity: 'LOW', confidence: 100, status: 'FIXED', application: 'Secure Document Vault', endpoint: 'GET /', detected: '2026-09-20T09:00:00Z',
    description: 'Strict-Transport-Security is missing.',
    method: 'GET', parameter: 'N/A',
    request: 'GET / HTTP/1.1',
    response: 'HTTP/1.1 200 OK',
    impact: 'Susceptible to MITM downgrade attacks.',
    remediation: 'Add HSTS headers.'
  },
];

export const mockAssessments = [
  { id: 'a1', name: 'Q3 Payment API Scan', application: 'Payment API', status: 'RUNNING', progress: 68, started: '2026-09-22T03:10:00Z', type: 'Full DAST' },
  { id: 'a2', name: 'Pre-release Vault Check', application: 'Secure Document Vault', status: 'COMPLETED', progress: 100, started: '2026-09-20T10:00:00Z', type: 'Targeted' },
];

export const mockReports = [
  { id: 'r1', name: 'Payment API Q3 Audit', application: 'Payment API', date: '2026-09-21', status: 'Ready' },
  { id: 'r2', name: 'Vault Pre-release Report', application: 'Secure Document Vault', date: '2026-09-20', status: 'Ready' },
];
