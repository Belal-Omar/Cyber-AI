import uuid
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

class DiscoveredEndpoint(BaseModel):
    url: str
    path: str
    method: str = "GET"
    parameters: List[str] = []
    forms: List[Dict[str, Any]] = []
    status_code: Optional[int] = None
    is_authenticated: bool = False

class AssessmentContext(BaseModel):
    assessment_id: uuid.UUID
    application_id: uuid.UUID
    base_url: str
    scope_policy: str = "STRICT"
    allowed_hosts: List[str] = []
    allowed_paths: Optional[str] = None
    excluded_paths: Optional[str] = None
    auth_headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    auth_context: Optional[Dict[str, Any]] = None
    discovered_endpoints: List[DiscoveredEndpoint] = []
    max_crawl_depth: int = 3

class Observation(BaseModel):
    check_name: str
    raw_output: str
    evidence_type: str

class AssessmentCheck:
    def metadata(self) -> Dict[str, Any]:
        raise NotImplementedError
    
    def can_run(self, context: AssessmentContext) -> bool:
        raise NotImplementedError
    
    def run(self, context: AssessmentContext) -> Observation:
        raise NotImplementedError
        
    def verify(self, original_context: Any) -> Observation:
        raise NotImplementedError
