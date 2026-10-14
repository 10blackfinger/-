from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from supabase import create_client, Client
import httpx
import uuid
import os
from datetime import datetime


# Settings from environment
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO = os.getenv("GITHUB_REPO", "10blackfinger/-")
GITHUB_WORKFLOW_FILE = "security-scan.yml"


app = FastAPI(
    title="10blackfingers API",
    description="AI-Powered Web Vulnerability Scanner",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)


class ScanRequest(BaseModel):
    url: str
    consent: bool
    session_id: str


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@app.get("/")
async def root():
    return {
        "name": "10blackfingers API",
        "version": "1.0.0",
        "status": "running"
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/scan", response_model=ScanResponse)
async def create_scan(request: ScanRequest):
    if not request.consent:
        raise HTTPException(
            status_code=400,
            detail="Consent is required before scanning"
        )

    scan_id = str(uuid.uuid4())
    target_url = request.url

    try:
        scan_data = {
            "id": scan_id,
            "target_url": target_url,
            "status": "pending",
            "session_id": request.session_id,
        }
        supabase.table("scans").insert(scan_data).execute()

        supabase.table("logs").insert({
            "scan_id": scan_id,
            "level": "info",
            "message": f"Scan created for {target_url}"
        }).execute()

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to create scan: {str(e)}"
        )

    try:
        await trigger_github_action(scan_id, target_url)
    except Exception as e:
        supabase.table("scans").update({
            "status": "failed",
            "error_message": f"Failed to trigger scan: {str(e)}"
        }).eq("id", scan_id).execute()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to start scan: {str(e)}"
        )

    return ScanResponse(
        scan_id=scan_id,
        status="pending",
        message="Scan has been queued successfully"
    )


@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    try:
        scan_result = supabase.table("scans").select("*").eq("id", scan_id).execute()

        if not scan_result.data:
            raise HTTPException(status_code=404, detail="Scan not found")

        scan = scan_result.data[0]
        results = supabase.table("results").select("*").eq("scan_id", scan_id).execute()

        return {
            "scan": scan,
            "results": results.data or []
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch scan: {str(e)}"
        )


@app.get("/api/scans")
async def list_scans(session_id: str, limit: int = 10):
    try:
        scans = supabase.table("scans") \
            .select("*") \
            .eq("session_id", session_id) \
            .order("created_at", desc=True) \
            .limit(limit) \
            .execute()

        return {"scans": scans.data or []}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to list scans: {str(e)}"
        )


async def trigger_github_action(scan_id: str, target_url: str):
    if not GITHUB_TOKEN:
        raise Exception("GITHUB_TOKEN not configured")

    url = f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/{GITHUB_WORKFLOW_FILE}/dispatches"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    payload = {
        "ref": "main",
        "inputs": {
            "scan_id": scan_id,
            "target_url": target_url
        }
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(url, headers=headers, json=payload)

        if response.status_code != 204:
            raise Exception(f"GitHub API error: {response.status_code}")

    supabase.table("scans").update({
        "status": "running",
        "started_at": datetime.utcnow().isoformat()
    }).eq("id", scan_id).execute()