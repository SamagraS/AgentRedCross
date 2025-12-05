# db_config.py
import os

class DBConfig:
    """Centralized PostgreSQL configuration."""

    HOST = os.getenv("DB_HOST", "localhost")
    PORT = os.getenv("DB_PORT", "5432")
    USER = os.getenv("DB_USER", "postgres")
    PASSWORD = os.getenv("DB_PASSWORD", "postgres")
    NAME = os.getenv("DB_NAME", "hospital_db")

    @classmethod
    def connection_url(cls) -> str:
        return f"postgresql://{cls.USER}:{cls.PASSWORD}@{cls.HOST}:{cls.PORT}/{cls.NAME}"
