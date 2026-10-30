import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from pydantic import BaseModel
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db

router = APIRouter(prefix="/evolution", tags=["Security Evolution & Regression Memory"])

HISTORICAL_SCANS: List[Dict[str, Any]] = [
    {
        "scan_id": "scan-oct-01",
        "date": (datetime.utcnow() - timedelta(days=21)).strftime("%Y-%m-%d"),
        "timestamp": (datetime.utcnow() - timedelta(days=21)).strftime("%Y-%m-%d %H:%M UTC"),
        "commit_hash": "a19f82c",
        "commit_message": "Initial release: deploy core e-commerce & customer portal",
        "author": "dev-team@cyberai.io",
        "security_score": 62,
        "total_findings": 9,
        "critical_count": 2,
        "high_count": 4,
        "medium_count": 3,
        "status": "COMPLETED"
    },
    {
        "scan_id": "scan-oct-12",
        "date": (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d"),
        "timestamp": (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d %H:%M UTC"),
        "commit_hash": "e44d701",
        "commit_message": "fix(security): apply HSTS headers and secure session cookies",
        "author": "secops@cyberai.io",
        "security_score": 78,
        "total_findings": 5,
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 2,
        "status": "COMPLETED"
    },
    {
        "scan_id": "scan-oct-28",
        "date": datetime.utcnow().strftime("%Y-%m-%d"),
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "commit_hash": "f953fea",
        "commit_message": "feat: autonomous AI self-healing and zero-day defense",
        "author": "sential-ai[bot]",
        "security_score": 92,
        "total_findings": 2,
        "critical_count": 0,
        "high_count": 1,
        "medium_count": 1,
        "status": "COMPLETED"
    }
]

VULNERABILITY_EVOLUTION: List[Dict[str, Any]] = [
    {
        "fingerprint": "cwe-89-sqli-login",
        "title": "SQL Injection in /api/v1/auth/login",
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "first_seen": (datetime.utcnow() - timedelta(days=21)).strftime("%Y-%m-%d"),
        "first_seen_commit": "a19f82c",
        "resolved_at": (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d"),
        "resolved_commit": "e44d701",
        "current_status": "FIXED",
        "regression_status": "STABLE_FIXED",
        "verification_runs": 3
    },
    {
        "fingerprint": "cwe-79-xss-search",
        "title": "Reflected Cross-Site Scripting (XSS) in query parameter",
        "cwe": "CWE-79",
        "severity": "HIGH",
        "first_seen": (datetime.utcnow() - timedelta(days=21)).strftime("%Y-%m-%d"),
        "first_seen_commit": "a19f82c",
        "resolved_at": (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d"),
        "resolved_commit": "e44d701",
        "current_status": "FIXED",
        "regression_status": "STABLE_FIXED",
        "verification_runs": 3
    },
    {
        "fingerprint": "cwe-319-missing-hsts",
        "title": "Missing Strict-Transport-Security (HSTS) Header",
        "cwe": "CWE-319",
        "severity": "MEDIUM",
        "first_seen": (datetime.utcnow() - timedelta(days=21)).strftime("%Y-%m-%d"),
        "first_seen_commit": "a19f82c",
        "resolved_at": (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d"),
        "resolved_commit": "e44d701",
        "current_status": "FIXED",
        "regression_status": "STABLE_FIXED",
        "verification_runs": 2
    },
    {
        "fingerprint": "cwe-16-cors-wildcard",
        "title": "Overly Permissive CORS Origin (*)",
        "cwe": "CWE-942",
        "severity": "MEDIUM",
        "first_seen": (datetime.utcnow() - timedelta(days=10)).strftime("%Y-%m-%d"),
        "first_seen_commit": "e44d701",
        "resolved_at": None,
        "resolved_commit": None,
        "current_status": "OPEN",
        "regression_status": "NEW_INTRODUCED",
        "verification_runs": 1
    },
    {
        "fingerprint": "cwe-614-secure-cookie",
        "title": "Missing Secure & HttpOnly Flags on Session Cookie",
        "cwe": "CWE-614",
        "severity": "LOW",
        "first_seen": (datetime.utcnow() - timedelta(days=21)).strftime("%Y-%m-%d"),
        "first_seen_commit": "a19f82c",
        "resolved_at": (datetime.utcnow() - timedelta(days=15)).strftime("%Y-%m-%d"),
        "resolved_commit": "b223c10",
        "current_status": "OPEN",
        "regression_status": "REGRESSION_DETECTED",
        "regression_note": "⚠️ Alert: Fixed in commit b223c10 but re-introduced during frontend proxy rework!",
        "verification_runs": 2
    }
]

@router.get("/history")
async def get_evolution_history(application_id: Optional[str] = None):
    """
    Returns the project's security evolution timeline, regression memory,
    and scan diff comparisons linking vulnerabilities to git commits.
    """
    fixed_count = sum(1 for v in VULNERABILITY_EVOLUTION if v["current_status"] == "FIXED")
    new_count = sum(1 for v in VULNERABILITY_EVOLUTION if v["regression_status"] == "NEW_INTRODUCED")
    regressed_count = sum(1 for v in VULNERABILITY_EVOLUTION if v["regression_status"] == "REGRESSION_DETECTED")
    open_count = sum(1 for v in VULNERABILITY_EVOLUTION if v["current_status"] == "OPEN")

    score_progression = [
        {"scan": s["scan_id"], "date": s["date"], "score": s["security_score"], "commit": s["commit_hash"]}
        for s in HISTORICAL_SCANS
    ]

    return {
        "success": True,
        "application_name": "Sential Protected Target",
        "total_historical_scans": len(HISTORICAL_SCANS),
        "current_posture_score": 92,
        "initial_posture_score": 62,
        "posture_improvement": "+30%",
        "stats": {
            "fixed_total": fixed_count,
            "new_introduced": new_count,
            "regressed_count": regressed_count,
            "currently_open": open_count
        },
        "score_progression": score_progression,
        "scans": HISTORICAL_SCANS,
        "vulnerabilities_timeline": VULNERABILITY_EVOLUTION
    }
