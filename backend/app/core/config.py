from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_DB_PATH = (_BACKEND_DIR / "cyberai.db").as_posix()

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberAI API"
    DATABASE_URL: str = f"sqlite+aiosqlite:///{_DB_PATH}"
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    SECRET_KEY: str = "dev-secret-key-do-not-use-in-production"
    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
