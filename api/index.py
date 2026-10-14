import os
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


app = FastAPI(title="10blackfingers API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- Lazy Supabase client -----
_supabase_client = None

def get_supabase():
    global _supabase_client
    if _supabase_client is None:
        from supabase import create_client
        url = os.getenv("SUPABASE_URL", "")
        key = os.getenv("SUPABASE_SERVICE_KEY", "")
        if not url or not key:
            raise RuntimeError("Supabase credentials missing")
        _supabase_client = create_client(url, key)
    return _supabase_client


# ----- Models -----
class ScanRequest(BaseModel):
    url: str
    consent: bool
    session_id: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


# ----- Routes -----
@app.get("/")
def root():
    return {
        "name": "10blackfingers API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/api")
def api_root():
    return {
        "name": "10blackfingers API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    import uuid
    import httpx

    if not request.consent:
        raise HTTPException(status_code=400, detail="Consent is required")

    scan_id = str(uuid.uuid4())
    target_url = request.url

    try:
        sb = get_supabase()
        sb.table("scans").insert({
            "id": scan_id,
            "target_url": target_url,
            "status": "pending",
            "session_id": request.session_id,
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DB error: {str(e)}")

    # Trigger GitHub Actions (best-effort)
    github_token = os.getenv("GITHUB_TOKEN", "")
    github_repo = os.getenv("GITHUB_REPO", "10blackfinger/-")
    if github_token:
        try:
            url = f"https://api.github.com/repos/{github_repo}/actions/workflows/security-scan.yml/dispatches"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            payload = {
                "ref": "main",
                "inputs": {"scan_id": scan_id, "target_url": target_url},
            }
            async with httpx.AsyncClient(timeout=30.0) as client:
                await client.post(url, headers=headers, json=payload)
        except Exception:
            pass

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan has been queued successfully"
    )


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    try:
        sb = get_supabase()
        scan_result = sb.table("scans").select("*").eq("id", scan_id).execute()
        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")
        results = sb.table("results").select("*").eq("scan_id", scan_id).execute()
        return {"scan": scan_result.data[0], "results": results.data or []}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")


@app.get("/api/scans")
async def list_scans(session_id: str, limit: int = 10):
    try:
        sb = get_supabase()
        scans = sb.table("scans") \
            .select("*") \
            .eq("session_id", session_id) \
            .order("created_at", desc=True) \
            .limit(limit) \
            .execute()
        return {"scans": scans.data or []}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"List error: {str(e)}")