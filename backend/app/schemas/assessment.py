import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

class AssessmentCreate(BaseModel):
    application_id: uuid.UUID
    name: Optional[str] = None
    type: str = "Full DAST"
    enabled_checks: Optional[Dict[str, Any]] = None
    auth_token: Optional[str] = None
    cookie: Optional[str] = None
    max_crawl_depth: Optional[int] = 3

class AssessmentResponse(BaseModel):
    id: uuid.UUID
    name: str
    application_id: uuid.UUID
    application: str
    status: str
    progress: int = 100
    type: str = "Full DAST"
    started: datetime
    created_at: datetime

    class Config:
        from_attributes = True
