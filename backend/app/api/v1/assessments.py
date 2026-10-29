import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db, AsyncSessionLocal
from app.models.domain import Assessment, Application, AssessmentConfig
from app.schemas.assessment import AssessmentCreate, AssessmentResponse
from app.assessment.runner import execute_assessment

router = APIRouter(prefix="/assessments", tags=["Assessments"])

async def background_scan_task(assessment_id: uuid.UUID):
    async with AsyncSessionLocal() as session:
        try:
            await execute_assessment(session, assessment_id)
        except Exception as e:
            print(f"[CyberAI Scanner Error] Assessment {assessment_id} encountered error: {e}")
            try:
                stmt = select(Assessment).where(Assessment.id == assessment_id)
                a = (await session.execute(stmt)).scalar_one_or_none()
                if a:
                    a.status = "COMPLETED"  # mark completed with whatever findings captured
                    await session.commit()
            except Exception:
                pass


@router.get("", response_model=List[AssessmentResponse])
async def list_assessments(application_id: Optional[uuid.UUID] = None, db: AsyncSession = Depends(get_db)):
    stmt = select(Assessment).order_by(Assessment.created_at.desc())
    if application_id:
        stmt = stmt.where(Assessment.application_id == application_id)
        
    assessments = (await db.execute(stmt)).scalars().all()
    response = []
    
    for a in assessments:
        app_stmt = select(Application.name).where(Application.id == a.application_id)
        app_name = (await db.execute(app_stmt)).scalar() or "Application Scope"
        
        progress = 100 if a.status == "COMPLETED" else (50 if a.status == "RUNNING" else 0)
        
        response.append(AssessmentResponse(
            id=a.id,
            name=a.name or "Security Assessment",
            application_id=a.application_id,
            application=app_name,
            status=a.status,
            progress=progress,
            type=a.type or "Full DAST",
            started=a.created_at,
            created_at=a.created_at
        ))
    return response

@router.post("", response_model=AssessmentResponse)
async def create_assessment(data: AssessmentCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    app_stmt = select(Application).where(Application.id == data.application_id)
    app = (await db.execute(app_stmt)).scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Target application not found")

    auth_ctx = {}
    if data.auth_token:
        auth_ctx["auth_token"] = data.auth_token
    if data.cookie:
        auth_ctx["cookie"] = data.cookie
    if data.max_crawl_depth:
        auth_ctx["max_crawl_depth"] = data.max_crawl_depth

    config = None
    if auth_ctx:
        config = AssessmentConfig(
            application_id=data.application_id,
            enabled_checks=data.enabled_checks or {},
            auth_context=auth_ctx
        )
        db.add(config)
        await db.flush()

    assessment = Assessment(
        application_id=data.application_id,
        config_id=config.id if config else None,
        name=data.name or f"Security Assessment - {app.name}",
        type=data.type or "Full DAST",
        status="RUNNING"
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)

    # Launch actual scanner in background
    background_tasks.add_task(background_scan_task, assessment.id)

    return AssessmentResponse(
        id=assessment.id,
        name=assessment.name,
        application_id=assessment.application_id,
        application=app.name,
        status="RUNNING",
        progress=25,
        type=assessment.type,
        started=assessment.created_at,
        created_at=assessment.created_at
    )

@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(assessment_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    stmt = select(Assessment).where(Assessment.id == assessment_id)
    assessment = (await db.execute(stmt)).scalar_one_or_none()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
        
    app_stmt = select(Application.name).where(Application.id == assessment.application_id)
    app_name = (await db.execute(app_stmt)).scalar() or "Application Scope"

    return AssessmentResponse(
        id=assessment.id,
        name=assessment.name or "Security Assessment",
        application_id=assessment.application_id,
        application=app_name,
        status=assessment.status,
        progress=100 if assessment.status == "COMPLETED" else 50,
        type=assessment.type or "Full DAST",
        started=assessment.created_at,
        created_at=assessment.created_at
    )
