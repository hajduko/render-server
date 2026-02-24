from __future__ import annotations
import os
import json
import time
import uuid
from typing import Optional, Dict, List

import boto3
from botocore.exceptions import ClientError
from fastapi import FastAPI, Request, Depends, Form, HTTPException, Path
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from itsdangerous import URLSafeSerializer

from pydantic import BaseModel

from .config import (
    SESSION_SECRET, REDIRECT_PATH,
    AWS_REGION, S3_BUCKET, SQS_QUEUE_URL, DDB_PROJECTS, DDB_JOBS,
    CLOUDFRONT_DOMAIN, CLOUDFRONT_KEY_PAIR_ID,
)
from .auth import get_auth_url, acquire_token_by_authorization_code
from .cloudfront_sign import sign_cloudfront_url

# ---------- FastAPI ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://render.sawin.hu"],  # you can lock this down later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static (potree libs, css, etc.)
static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Session (same pattern as your existing app) :contentReference[oaicite:9]{index=9}
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)
state_serializer = URLSafeSerializer(SESSION_SECRET, salt="state-salt")  # :contentReference[oaicite:10]{index=10}

templates = Jinja2Templates(directory="templates")

# ---------- AWS clients ----------
s3 = boto3.client("s3", region_name=AWS_REGION)
sqs = boto3.client("sqs", region_name=AWS_REGION)
ddb = boto3.client("dynamodb", region_name=AWS_REGION)

def now_epoch() -> int:
    return int(time.time())

# ---------- Auth dependencies ----------
def get_current_user(request: Request):
    user = request.session.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

def require_admin(user=Depends(get_current_user)):
    roles = user.get("roles") or []
    if "Admin" not in roles:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return user

# ---------- Root/login/callback/logout ----------
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    user = request.session.get("user")
    if user:
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse("login.html", {"request": request, "user": None})

@app.get("/login")
async def login(request: Request):
    # Create a CSRF-safe state and store it in session (same as current) :contentReference[oaicite:11]{index=11}
    state = state_serializer.dumps({"csrf": "token"})
    request.session["state"] = state
    auth_url = get_auth_url(state)
    return RedirectResponse(url=auth_url)

@app.get(REDIRECT_PATH)
async def auth_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None):
    # same behavior as your current callback :contentReference[oaicite:12]{index=12}
    if error:
        return templates.TemplateResponse("error.html", {"request": request, "message": f"Login failed: {error}", "user": request.session.get("user")})

    if not code or not state:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Missing code or state", "user": request.session.get("user")})

    saved_state = request.session.get("state")
    if not saved_state or saved_state != state:
        return templates.TemplateResponse("error.html", {"request": request, "message": "Invalid state", "user": request.session.get("user")})

    result = acquire_token_by_authorization_code(code)

    if "error" in result:
        msg = result.get("error_description") or result["error"]
        return templates.TemplateResponse("error.html", {"request": request, "message": f"Token error: {msg}", "user": request.session.get("user")})

    id_token_claims = result.get("id_token_claims", {})
    roles = id_token_claims.get("roles", []) or []

    request.session["user"] = {
        "name": id_token_claims.get("name"),
        "oid": id_token_claims.get("oid"),
        "email": id_token_claims.get("preferred_username") or id_token_claims.get("email"),
        "tid": id_token_claims.get("tid"),
        "roles": roles,
        "is_admin": "Admin" in roles,
    }

    request.session.pop("state", None)
    return RedirectResponse(url="/")

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/")

# ---------- AWS-backed dashboard logic ----------

class PresignFile(BaseModel):
    name: str
    content_type: str

class PresignRequest(BaseModel):
    pid: str
    files: List[PresignFile] = []
    others: List[PresignFile] = []

class CompleteRequest(BaseModel):
    pid: str

IMAGE_EXTS = (".jpg", ".jpeg", ".tif", ".tiff")
OTHER_EXTS = IMAGE_EXTS + (".mp4",)
VIDEO_EXTS = (".mp4",)

def _list_s3_keys(bucket: str, prefix: str) -> List[str]:
    """List all object keys under a prefix (handles pagination)."""
    keys: List[str] = []
    token: Optional[str] = None

    while True:
        kwargs = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kwargs["ContinuationToken"] = token

        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            k = obj.get("Key")
            if k and not k.endswith("/"):
                keys.append(k)

        if resp.get("IsTruncated"):
            token = resp.get("NextContinuationToken")
        else:
            break

    return keys

def _safe_name(filename: str) -> str:
    return os.path.basename(filename).replace("\\", "/").split("/")[-1]

def _key(pid: str, kind: str, name: str) -> str:
    return f"projects/{pid}/input/{kind}/{_safe_name(name)}"

def ddb_put_project(pid: str, user_email: str):
    ddb.put_item(
        TableName=DDB_PROJECTS,
        Item={
            "pid": {"S": pid},
            "status": {"S": "QUEUED"},
            "updatedAt": {"N": str(now_epoch())},
            "ownerEmail": {"S": user_email},
        },
    )

def ddb_put_job(job_id: str, pid: str, user: Dict):
    ddb.put_item(
        TableName=DDB_JOBS,
        Item={
            "job_id": {"S": job_id},
            "pid": {"S": pid},
            "status": {"S": "QUEUED"},
            "createdAt": {"N": str(now_epoch())},
            "updatedAt": {"N": str(now_epoch())},
            "requestedByOid": {"S": user.get("oid", "")},
            "requestedByEmail": {"S": user.get("email", "")},
            "requestedByName": {"S": user.get("name", "")},
        },
    )

def sqs_enqueue(job_id: str, pid: str, user: Dict):
    sqs.send_message(
        QueueUrl=SQS_QUEUE_URL,
        MessageBody=json.dumps(
            {
                "job_id": job_id,
                "pid": pid,
                "job_type": "render",
                "requested_by_oid": user.get("oid"),
                "requested_by_email": user.get("email"),
                "requested_by_name": user.get("name"),
            }
        ),
    )

def s3_key_exists(bucket: str, key: str) -> bool:
    try:
        s3.get_object(Bucket=bucket, Key=key)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        return code not in ("404", "NoSuchKey")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, user=Depends(get_current_user)):
    # Small scale -> Scan OK. Later: query GSI by status/updatedAt.
    resp = ddb.scan(TableName=DDB_PROJECTS)
    projects = []
    for it in resp.get("Items", []):
        projects.append({
            "pid": it["pid"]["S"],
            "status": it.get("status", {"S": "UNKNOWN"})["S"],
            "updatedAt": int(it.get("updatedAt", {"N": "0"})["N"]),
        })
    projects.sort(key=lambda x: x["pid"].lower())
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user, "projects": projects})

@app.post("/upload/presign")
async def upload_presign(req: PresignRequest, user=Depends(get_current_user)):
    pid = req.pid.strip()
    if not pid:
        raise HTTPException(400, "Missing project_id")

    uploads = []

    for f in req.files:
        name = _safe_name(f.name)
        if not name.lower().endswith(IMAGE_EXTS):
            continue
        key = _key(pid, "images", name)
        url = s3.generate_presigned_url(
            "put_object",
            Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": f.content_type or "application/octet-stream"},
            ExpiresIn=3600,
        )
        uploads.append({"name": name, "key": key, "url": url, "content_type": f.content_type, "kind": "images"})

    for f in req.others:
        name = _safe_name(f.name)
        if not name.lower().endswith(OTHER_EXTS):
            continue
        key = _key(pid, "others", name)
        url = s3.generate_presigned_url(
            "put_object",
            Params={"Bucket": S3_BUCKET, "Key": key, "ContentType": f.content_type or "application/octet-stream"},
            ExpiresIn=3600,
        )
        uploads.append({"name": name, "key": key, "url": url, "content_type": f.content_type, "kind": "others"})

    if not uploads:
        raise HTTPException(400, "No valid files to upload")

    return {"pid": pid, "uploads": uploads}

@app.post("/upload/complete")
async def upload_complete(req: CompleteRequest, user=Depends(get_current_user)):
    pid = req.pid.strip()
    if not pid:
        raise HTTPException(400, "Missing project_id")

    # Optional sanity check: at least one image exists
    resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"projects/{pid}/input/images/", MaxKeys=1)
    if not resp.get("Contents"):
        raise HTTPException(400, "No images found in S3 for this pid")

    job_id = str(uuid.uuid4())
    ddb_put_project(pid, user_email=user["email"])
    ddb_put_job(job_id, pid, user)
    sqs_enqueue(job_id, pid, user)
    return {"ok": True, "pid": pid, "job_id": job_id}

# ---------- Viewer + signed redirect for Potree ----------
@app.get("/project/{pid}", response_class=HTMLResponse)
async def project_view(request: Request, pid: str = Path(...), user=Depends(get_current_user)):
    # ---- 1) Detect Potree: check if cloud.js exists in S3 under viewer/potree/ ----
    potree_prefix = f"projects/{pid}/viewer/potree/"
    cloud_js_key = potree_prefix + "cloud.js"

    has_potree = s3_key_exists(S3_BUCKET, cloud_js_key)

    # This is the URL your template should load for Potree (signed via /cf redirect)
    # If has_potree is False, you can still pass it; template can hide viewer.
    cloud_js = f"/cf/{cloud_js_key}"

    # ---- 2) List "others" media files from S3 ----
    others_prefix = f"projects/{pid}/input/others/"
    keys = _list_s3_keys(S3_BUCKET, others_prefix)

    images: List[str] = []
    videos: List[str] = []

    for key in keys:
        name = key.rsplit("/", 1)[-1]
        ext = os.path.splitext(name)[1].lower()

        if ext in IMAGE_EXTS:
            images.append(f"/cf/{key}")   # signed redirect per request
        elif ext in VIDEO_EXTS:
            videos.append(f"/cf/{key}")

    images.sort()
    videos.sort()

    return templates.TemplateResponse(
        "project.html",
        {
            "request": request,
            "user": user,
            "pid": pid,
            "has_potree": has_potree,
            "cloud_js": cloud_js,   # keep this name if your template expects cloud_js
            "images": images,
            "videos": videos,
        },
    )

@app.get("/cf/{path:path}")
async def cf_signed_redirect(path: str, user=Depends(get_current_user)):
    resource_url = f"{CLOUDFRONT_DOMAIN.rstrip('/')}/{path.lstrip('/')}"
    signed = sign_cloudfront_url(
        resource_url=resource_url,
        key_pair_id=CLOUDFRONT_KEY_PAIR_ID,
        expires_in_seconds=3600,
    )
    return RedirectResponse(url=signed, status_code=302)

@app.get("/download/{pid}/e57")
async def download_e57(pid: str, user=Depends(get_current_user)):
    key = f"projects/{pid}/output/e57/{pid}.e57"
    if not s3_key_exists(S3_BUCKET, key):
        raise HTTPException(404, "E57 not found yet")
    return RedirectResponse(url=f"/cf/{key}", status_code=302)

# ---------- Logs page ----------
@app.get("/logs/{pid}", response_class=HTMLResponse)
async def project_logs(request: Request, pid: str, user=Depends(get_current_user)):
    prefix = f"projects/{pid}/output/logs/"
    resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)

    keys = [o["Key"] for o in resp.get("Contents", []) if o["Key"].endswith(".log")]
    keys.sort(reverse=True)

    log_text = ""
    if keys:
        obj = s3.get_object(Bucket=S3_BUCKET, Key=keys[0])
        log_text = obj["Body"].read().decode("utf-8", errors="replace")

    return templates.TemplateResponse(
        "logs.html",
        {"request": request, "user": user, "pid": pid, "keys": keys, "log_text": log_text},
    )

@app.get("/health")
async def health():
    return {"status": "ok"}