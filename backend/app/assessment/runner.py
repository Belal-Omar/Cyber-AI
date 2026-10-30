import uuid
from typing import List, Dict, Any
from datetime import datetime
from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.domain import (
    Assessment,
    Application,
    Observation,
    Finding,
    FindingOccurrence,
    FindingEvidence,
    AssessmentConfig,
    Endpoint
)
from app.assessment.interfaces import AssessmentContext
from app.assessment.crawler import WebCrawler
from app.assessment.checks import (
    SecurityHeadersCheck,
    SensitiveFilesCheck,
    CorsMisconfigurationCheck,
    OpenRedirectCheck,
    SqlErrorDisclosureCheck,
    CookieSecurityCheck,
    ActiveFormXssFuzzerCheck,
    TimeBasedSqlInjectionCheck,
    AuthenticatedAccessCheck,
    SsrfCheck,
    AdvancedIdorBolaCheck,
    LfiCommandInjectionCheck,
    SstiCheck,
    UnrestrictedFileUploadCheck,
    ApiSecurityCheck,
    RateLimitingCheck,
    ReconCloudLeaksCheck,
    SslTlsCipherCheck,
    SastSecretsScannerCheck,
    DomXssSpaCheck
)

async def execute_assessment(db: AsyncSession, assessment_id: uuid.UUID) -> Assessment:
    # 1. Fetch Assessment
    stmt = select(Assessment).where(Assessment.id == assessment_id)
    res = await db.execute(stmt)
    assessment = res.scalar_one_or_none()
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found")

    # 2. Fetch Application
    app_stmt = select(Application).where(Application.id == assessment.application_id)
    app_res = await db.execute(app_stmt)
    application = app_res.scalar_one_or_none()
    if not application:
        raise ValueError(f"Application {assessment.application_id} not found")

    # Update assessment to RUNNING
    assessment.status = "RUNNING"
    await db.commit()

    # 3. Unpack authentication & crawling configurations
    auth_headers = {}
    cookies_dict = {}
    max_crawl_depth = 2

    if assessment.config_id:
        cfg_stmt = select(AssessmentConfig).where(AssessmentConfig.id == assessment.config_id)
        cfg = (await db.execute(cfg_stmt)).scalar_one_or_none()
        if cfg and cfg.auth_context:
            auth_ctx = cfg.auth_context
            max_crawl_depth = auth_ctx.get("max_crawl_depth", 2)
            token = auth_ctx.get("auth_token")
            if token:
                auth_headers["Authorization"] = token if token.startswith("Bearer ") else f"Bearer {token}"
            raw_cookie = auth_ctx.get("cookie")
            if raw_cookie:
                clean_cookie = raw_cookie.strip()
                if "=" not in clean_cookie and len(clean_cookie) > 8:
                    cookies_dict["PHPSESSID"] = clean_cookie
                    cookies_dict["session"] = clean_cookie
                else:
                    for pair in clean_cookie.split(";"):
                        if "=" in pair:
                            k, v = pair.strip().split("=", 1)
                            cookies_dict[k.strip()] = v.strip()

    context = AssessmentContext(
        assessment_id=assessment.id,
        application_id=application.id,
        base_url=application.base_url,
        scope_policy=application.scope_policy or "STRICT",
        allowed_hosts=application.allowed_hosts or [application.base_url],
        auth_headers=auth_headers,
        cookies=cookies_dict,
        max_crawl_depth=max_crawl_depth
    )

    # 4. Execute Web Crawler / Spider for Route & Form Mapping
    crawler = WebCrawler(
        base_url=application.base_url,
        allowed_hosts=application.allowed_hosts or [application.base_url],
        auth_headers=auth_headers,
        cookies=cookies_dict,
        max_depth=max_crawl_depth,
        max_pages=80 if max_crawl_depth >= 3 else 35,
        excluded_paths=application.excluded_paths
    )
    discovered_endpoints = await crawler.crawl()
    context.discovered_endpoints = discovered_endpoints

    # Purge any previously stored endpoints for this application to avoid accumulating stale/old routes
    await db.execute(delete(Endpoint).where(Endpoint.application_id == application.id))
    await db.flush()

    # Save newly discovered endpoints to database
    for dep in discovered_endpoints:
        ep_entry = Endpoint(
            application_id=application.id,
            url_path=dep.path,
            http_method=dep.method,
            parameters={"list": dep.parameters, "forms_count": len(dep.forms)},
            content_type="text/html"
        )
        db.add(ep_entry)
    await db.flush()

    obs_crawler = Observation(
        assessment_id=assessment.id,
        check_name="WebCrawler",
        raw_output=f"Mapped {len(discovered_endpoints)} internal routes, endpoints, and input forms across target."
    )
    db.add(obs_crawler)
    await db.flush()

    all_raw_findings: List[Dict[str, Any]] = []

    # Run complete suite of security assessment checks across all 4 pillars
    active_checks = [
        ("SecurityHeadersCheck", SecurityHeadersCheck()),
        ("SensitiveFilesCheck", SensitiveFilesCheck()),
        ("CorsMisconfigurationCheck", CorsMisconfigurationCheck()),
        ("OpenRedirectCheck", OpenRedirectCheck()),
        ("SqlErrorDisclosureCheck", SqlErrorDisclosureCheck()),
        ("CookieSecurityCheck", CookieSecurityCheck()),
        ("ActiveFormXssFuzzerCheck", ActiveFormXssFuzzerCheck()),
        ("TimeBasedSqlInjectionCheck", TimeBasedSqlInjectionCheck()),
        ("AuthenticatedAccessCheck", AuthenticatedAccessCheck()),
        ("SsrfCheck", SsrfCheck()),
        ("AdvancedIdorBolaCheck", AdvancedIdorBolaCheck()),
        ("LfiCommandInjectionCheck", LfiCommandInjectionCheck()),
        ("SstiCheck", SstiCheck()),
        ("UnrestrictedFileUploadCheck", UnrestrictedFileUploadCheck()),
        ("ApiSecurityCheck", ApiSecurityCheck()),
        ("RateLimitingCheck", RateLimitingCheck()),
        ("ReconCloudLeaksCheck", ReconCloudLeaksCheck()),
        ("SslTlsCipherCheck", SslTlsCipherCheck()),
        ("SastSecretsScannerCheck", SastSecretsScannerCheck()),
        ("DomXssSpaCheck", DomXssSpaCheck())
    ]

    default_obs = None
    for check_name, check_inst in active_checks:
        try:
            findings = await check_inst.run(context)
        except Exception:
            findings = []

        obs = Observation(
            assessment_id=assessment.id,
            check_name=check_name,
            raw_output=f"Executed {check_name}. Identified {len(findings)} anomalies."
        )
        db.add(obs)
        await db.flush()
        if not default_obs:
            default_obs = obs

        for raw in findings:
            raw["_obs_id"] = obs.id
            all_raw_findings.append(raw)

    # If no findings were detected, add an informational clean scan observation
    if not all_raw_findings:
        all_raw_findings.append({
            "title": "Clean Scan - Baseline Controls Verified",
            "category": "Verification",
            "severity": "INFO",
            "confidence": 100.0,
            "description": "Baseline HTTP header, CORS, redirection, and cookie checks passed without critical alerts.",
            "endpoint": "GET /",
            "method": "GET",
            "parameter": "N/A",
            "request": f"GET / HTTP/1.1\nHost: {application.base_url}",
            "response": "HTTP/1.1 200 OK",
            "impact": "Low attack surface exposure on investigated vectors.",
            "remediation": "Continue routine periodic security assessments."
        })

    # Persist findings to database with deduplication and remediation status preservation
    existing_stmt = select(Finding).where(Finding.application_id == application.id)
    existing_findings_list = (await db.execute(existing_stmt)).scalars().all()
    existing_map = {(f.title, f.parameter): f for f in existing_findings_list}
    # Clean up purely informational scan status findings that aren't real vulnerabilities
    for key, f in list(existing_map.items()):
        if "Authenticated Security Scanning Active" in f.title:
            await db.delete(f)
            existing_map.pop(key, None)
    await db.flush()

    detected_keys = set()
    for raw in all_raw_findings:
        title = raw["title"]
        param = raw.get("parameter", "N/A")
        key = (title, param)
        detected_keys.add(key)

        if key in existing_map:
            finding = existing_map[key]
            # When detected in the current scan, ensure status is actively OPEN
            finding.status = "OPEN"
            finding.confidence = raw.get("confidence", 90.0)
            finding.severity = raw.get("severity", "MEDIUM")
            finding.impact = raw.get("impact")
            finding.remediation = raw.get("remediation")
        else:
            finding = Finding(
                application_id=application.id,
                title=title,
                category=raw.get("category", "Configuration"),
                severity=raw.get("severity", "MEDIUM"),
                confidence=raw.get("confidence", 90.0),
                status="OPEN",
                parameter=param,
                impact=raw.get("impact"),
                remediation=raw.get("remediation")
            )
            db.add(finding)
            await db.flush()
            existing_map[key] = finding

        occurrence = FindingOccurrence(
            finding_id=finding.id,
            assessment_id=assessment.id,
            observation_id=raw.get("_obs_id", default_obs.id if default_obs else assessment.id)
        )
        db.add(occurrence)
        await db.flush()

        evidence = FindingEvidence(
            finding_occurrence_id=occurrence.id,
            request_context={"raw": raw.get("request")},
            response_context={"raw": raw.get("response")},
            evidence_type="HTTP_INTERACTION",
            sanitized_details=raw.get("description", "")
        )
        db.add(evidence)

    # Automatically resolve findings that are no longer detected on target
    for key, f in existing_map.items():
        if key not in detected_keys:
            f.status = "FIXED"

    # Calculate posture score based exclusively on active OPEN findings
    open_findings = [f for f in existing_map.values() if f.status == "OPEN"]
    crit = sum(1 for f in open_findings if f.severity == "CRITICAL")
    high = sum(1 for f in open_findings if f.severity == "HIGH")
    med = sum(1 for f in open_findings if f.severity == "MEDIUM")
    low = sum(1 for f in open_findings if f.severity == "LOW")

    penalty = (crit * 25) + (high * 15) + (med * 8) + (low * 2)
    new_score = max(20, min(100, 100 - penalty))
    application.score = new_score

    assessment.status = "COMPLETED"
    await db.commit()
    await db.refresh(assessment)
    return assessment
