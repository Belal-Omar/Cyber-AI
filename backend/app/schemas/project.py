import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class ProjectBase(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectResponse(ProjectBase):
    id: uuid.UUID
    user_id: Optional[uuid.UUID] = None
    created_at: datetime
    applications_count: int = 0
    assessments_count: int = 0
    findings_count: int = 0
    posture: int = 85
    owner: str = "Admin Team"

    class Config:
        from_attributes = True
