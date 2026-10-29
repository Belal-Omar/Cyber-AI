import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.db.session import get_db
from app.models.domain import Project, Application, Assessment, Finding
from app.schemas.project import ProjectCreate, ProjectResponse

router = APIRouter(prefix="/projects", tags=["Projects"])

@router.get("", response_model=List[ProjectResponse])
async def list_projects(db: AsyncSession = Depends(get_db)):
    stmt = select(Project).order_by(Project.created_at.desc())
    result = await db.execute(stmt)
    projects = result.scalars().all()
    
    response = []
    for p in projects:
        # Count applications
        app_stmt = select(func.count(Application.id)).where(Application.project_id == p.id)
        app_count = (await db.execute(app_stmt)).scalar() or 0
        
        # Count findings
        findings_count = 0
        apps_res = await db.execute(select(Application.id).where(Application.project_id == p.id))
        app_ids = apps_res.scalars().all()
        if app_ids:
            f_stmt = select(func.count(Finding.id)).where(Finding.application_id.in_(app_ids))
            findings_count = (await db.execute(f_stmt)).scalar() or 0
            
            assessments_stmt = select(func.count(Assessment.id)).where(Assessment.application_id.in_(app_ids))
            assessments_count = (await db.execute(assessments_stmt)).scalar() or 0
        else:
            assessments_count = 0

        response.append(ProjectResponse(
            id=p.id,
            name=p.name,
            description=p.description or "",
            user_id=p.user_id,
            created_at=p.created_at,
            applications_count=app_count,
            assessments_count=assessments_count,
            findings_count=findings_count,
            posture=88 if findings_count == 0 else max(40, 100 - findings_count * 10),
            owner="Security Team"
        ))
    return response

@router.post("", response_model=ProjectResponse)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db)):
    project = Project(
        name=data.name,
        description=data.description
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description or "",
        user_id=project.user_id,
        created_at=project.created_at,
        applications_count=0,
        assessments_count=0,
        findings_count=0,
        posture=100,
        owner="Security Team"
    )

@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    stmt = select(Project).where(Project.id == project_id)
    project = (await db.execute(stmt)).scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description or "",
        user_id=project.user_id,
        created_at=project.created_at,
        applications_count=0,
        assessments_count=0,
        findings_count=0,
        posture=85,
        owner="Security Team"
    )
