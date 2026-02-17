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

from .config import (
    SESSION_SECRET, REDIRECT_PATH,
    AWS_REGION, S3_BUCKET, SQS_QUEUE_URL, DDB_PROJECTS, DDB_JOBS,
    CLOUDFRONT_DOMAIN, CLOUDFRONT_KEY_PAIR_ID, CLOUDFRONT_PRIVATE_KEY_PATH,
)
from .auth import get_auth_url, acquire_token_by_authorization_code
from .cloudfront_sign import sign_cloudfront_url

# ---------- FastAPI ----------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # you can lock this down later
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

# ---------- Auth dependencies (copied behavior) ----------
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

# ---------- Root/login/callback/logout (copied flow) ----------
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

@app.post("/upload")
async def upload_images(request: Request, user=Depends(get_current_user)):
    # keep your form style: pid + files + others
    form = await request.form(max_files=10000, max_fields=10001)

    pid = str(form.get("pid", "")).strip()
    if not pid:
        raise HTTPException(400, "Missing project_id")

    files = form.getlist("files")
    if not files:
        raise HTTPException(400, "No files received")

    # Upload images
    saved = 0
    for f in files:
        name = os.path.basename(f.filename)
        if not name.lower().endswith((".jpg", ".jpeg", ".tif", ".tiff")):
            continue
        key = f"projects/{pid}/input/images/{name}"
        s3.upload_fileobj(f.file, S3_BUCKET, key)
        saved += 1

    if saved == 0:
        raise HTTPException(400, "No valid image files uploaded")

    # Upload others (optional)
    others = form.getlist("others")
    for f in others:
        name = os.path.basename(f.filename)
        if not name.lower().endswith((".jpg", ".jpeg", ".tif", ".tiff", ".avi", ".mp4")):
            continue
        key = f"projects/{pid}/input/others/{name}"
        s3.upload_fileobj(f.file, S3_BUCKET, key)

    # Create DDB records + enqueue SQS job
    job_id = str(uuid.uuid4())
    ddb_put_project(pid, user_email=user["email"])
    ddb_put_job(job_id, pid, user)
    sqs_enqueue(job_id, pid, user)

    return RedirectResponse("/dashboard", status_code=302)

# ---------- Viewer + signed redirect for Potree ----------
@app.get("/project/{pid}", response_class=HTMLResponse)
async def project_view(request: Request, pid: str = Path(...), user=Depends(get_current_user)):
    # Potree will request many files; route through /cf/... so each request gets signed.
    cloud_js = f"/cf/projects/{pid}/viewer/potree/cloud.js"
    return templates.TemplateResponse("project.html", {"request": request, "user": user, "pid": pid, "cloud_js": cloud_js})

@app.get("/cf/{path:path}")
async def cf_signed_redirect(path: str, user=Depends(get_current_user)):
    resource_url = f"{CLOUDFRONT_DOMAIN.rstrip('/')}/{path.lstrip('/')}"
    signed = sign_cloudfront_url(
        resource_url=resource_url,
        key_pair_id=CLOUDFRONT_KEY_PAIR_ID,
        private_key_pem_path=CLOUDFRONT_PRIVATE_KEY_PATH,
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