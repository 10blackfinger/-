import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")
    SUPABASE_SERVICE_KEY: str = os.getenv("SUPABASE_SERVICE_KEY", "")

    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    GITHUB_REPO: str = os.getenv("GITHUB_REPO", "your-username/10blackfingers")

    GITHUB_WORKFLOW_FILE: str = "security-scan.yml"

    MAX_SCAN_DURATION_MINUTES: int = 30
    RATE_LIMIT_PER_MINUTE: int = 60


settings = Settings()