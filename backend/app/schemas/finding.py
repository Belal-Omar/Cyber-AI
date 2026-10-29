import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class FindingResponse(BaseModel):
    id: uuid.UUID
    title: str
    category: str
    severity: str
    confidence: float = 90.0
    status: str
    application: str
    application_id: uuid.UUID
    endpoint: str = "GET /"
    detected: datetime
    description: Optional[str] = None
    method: str = "GET"
    parameter: Optional[str] = "N/A"
    target_file: Optional[str] = "index.php"
    request: Optional[str] = None
    response: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None

    class Config:
        from_attributes = True

class VerificationRequest(BaseModel):
    notes: Optional[str] = "Triggered verification re-scan"
    target_url: Optional[str] = None
    force: Optional[bool] = False

class VerificationResponse(BaseModel):
    finding_id: uuid.UUID
    status: str
    message: str
    verified_at: datetime
