import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

class ApplicationBase(BaseModel):
    name: str
    base_url: str
    environment: str = "Production"
    authorization_confirmed: bool = True
    allowed_hosts: Optional[List[str]] = None
    allowed_paths: Optional[str] = None
    excluded_paths: Optional[str] = None
    scope_policy: Optional[str] = "STRICT"

class ApplicationCreate(ApplicationBase):
    project_id: Optional[uuid.UUID] = None

class ApplicationResponse(ApplicationBase):
    id: uuid.UUID
    project_id: Optional[uuid.UUID] = None
    created_at: datetime
    score: int = 80
    endpoints: int = 1
    openFindings: int = 0

    class Config:
        from_attributes = True

class VerifyAuthorizationRequest(BaseModel):
    target_url: str
    method: str = "file"  # "file", "dns", "written"
    token: str = "sential-verify=ns_9d4f2a7c"
    bypass: bool = False

class VerifyAuthorizationResponse(BaseModel):
    verified: bool
    method: str
    message: str
    details: Optional[str] = None

