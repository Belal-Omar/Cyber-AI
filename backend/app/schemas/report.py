import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel

class ReportResponse(BaseModel):
    id: uuid.UUID
    name: str
    application: str
    application_id: Optional[uuid.UUID] = None
    date: str
    status: str = "Ready"
    format: str = "PDF"

    class Config:
        from_attributes = True
