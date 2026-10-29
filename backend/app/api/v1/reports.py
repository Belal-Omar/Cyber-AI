import uuid
from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.models.domain import Report, Application, Project
from app.schemas.report import ReportResponse

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("", response_model=List[ReportResponse])
async def list_reports(db: AsyncSession = Depends(get_db)):
    stmt = select(Report).order_by(Report.created_at.desc())
    reports = (await db.execute(stmt)).scalars().all()
    
    response = []
    for r in reports:
        app_stmt = select(Application.name).where(Application.id == r.assessment_id)
        app_name = (await db.execute(app_stmt)).scalar() or "Application Scope"
        response.append(ReportResponse(
            id=r.id,
            name=f"Security Assessment Report #{str(r.id)[:8]}",
            application=app_name,
            application_id=None,
            date=r.created_at.strftime("%Y-%m-%d"),
            status="Ready",
            format=r.format or "PDF"
        ))
    
    # If no reports yet, return default system executive summary reports
    if not response:
        response.append(ReportResponse(
            id=uuid.uuid4(),
            name="Executive Security Posture Report",
            application="Enterprise Digital Assets",
            application_id=None,
            date=datetime.utcnow().strftime("%Y-%m-%d"),
            status="Ready",
            format="PDF"
        ))
        
    return response
