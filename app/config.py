import os
from dotenv import load_dotenv

load_dotenv()

# ---------- Microsoft Auth (same as your current config.py) ----------
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
APP_BASE_URL = os.getenv("APP_BASE_URL", "https://render.sawin.hu")
SESSION_SECRET = os.getenv("SESSION_SECRET", "ultrasecretsessionsecret2025")

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
    raise RuntimeError("TENANT_ID, CLIENT_ID, CLIENT_SECRET must be set in .env")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"

REDIRECT_PATH = "/auth/callback"
REDIRECT_URI = f"{APP_BASE_URL}{REDIRECT_PATH}"

SCOPES = ["User.Read"]

# ---------- AWS (new) ----------
AWS_REGION = os.getenv("AWS_REGION", "eu-central-1")
S3_BUCKET = os.getenv("S3_BUCKET")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
DDB_PROJECTS = os.getenv("DDB_PROJECTS", "render_projects")
DDB_JOBS = os.getenv("DDB_JOBS", "render_jobs")

# CloudFront signed URL (new)
CLOUDFRONT_DOMAIN = os.getenv("CLOUDFRONT_DOMAIN")  # e.g. https://cdn.render.sawin.hu
CLOUDFRONT_KEY_PAIR_ID = os.getenv("CLOUDFRONT_KEY_PAIR_ID")
CLOUDFRONT_PRIVATE_KEY_PATH = os.getenv("CLOUDFRONT_PRIVATE_KEY_PATH", "/etc/render/cloudfront_private_key.pem")

if not all([S3_BUCKET, SQS_QUEUE_URL, CLOUDFRONT_DOMAIN, CLOUDFRONT_KEY_PAIR_ID]):
    raise RuntimeError("S3_BUCKET, SQS_QUEUE_URL, CLOUDFRONT_DOMAIN, CLOUDFRONT_KEY_PAIR_ID must be set in .env")