from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberAI API"
    DATABASE_URL: str = "sqlite+aiosqlite:///./cyberai.db"
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    SECRET_KEY: str = "dev-secret-key-do-not-use-in-production"
    ENVIRONMENT: str = "development"

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
