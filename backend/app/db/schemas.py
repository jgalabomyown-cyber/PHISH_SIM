from pydantic import BaseModel, EmailStr
from app.db.models import Role
from datetime import datetime
from typing import Optional, List

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: Role = Role.PENTESTER

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: Role
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ScanResultIn(BaseModel):
    scan_type: str
    target: str | None = None
    findings: list = []

class ScanResultOut(ScanResultIn):
    id: int
    status: str

    class Config:
        from_attributes = True

class NoteIn(BaseModel):
    title: str
    content_md: str = ""

class NoteOut(NoteIn):
    id: int
    attachments: list = []

    class Config:
        from_attributes = True

class DiscoveredDeviceIn(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    device_name: Optional[str] = None
    os_fingerprint: Optional[str] = None
    open_ports: list = []
    matched_cves: list = []

class DiscoveredDeviceOut(DiscoveredDeviceIn):
    id: int
    remediation_status: str
    remediation_notes: Optional[str] = None
    patched_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class NetworkScanCreate(BaseModel):
    """Body for POST /api/scan/start."""
    target_subnet: str
    scan_type: str = "subnet"

class NetworkScanOut(BaseModel):
    id: int
    target_subnet: str
    scan_type: str
    status: str
    total_devices: int
    total_vulnerabilities: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class NetworkScanDetail(NetworkScanOut):
    devices: List[DiscoveredDeviceOut] = []

class DevicePatchRequest(BaseModel):
    """Optional body for POST /api/scan/resolve/{device_id}."""
    remediation_notes: Optional[str] = None

class DeviceStatusOut(BaseModel):
    id: int
    ip_address: str
    remediation_status: str
    remediation_notes: Optional[str] = None
    patched_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# --- APPEND to bottom of app/db/schemas.py ---
# --- Module 2: PHish_SIm schemas ---
import uuid as _uuid

class CampaignTarget(BaseModel):
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None

class SMTPConfig(BaseModel):
    host: str
    port: int = 587
    username: str
    # application-specific password; never echoed back in any Out schema
    password: str
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
    dispatch: bool = True   # False = create as draft, no emails sent

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
    target_count: int = 0
    created_at: Optional[datetime] = None
    dispatch_scheduled_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class CampaignSummaryOut(PhishingCampaignOut):
    total_clicks: int = 0
    total_captures: int = 0

class HarvestIn(BaseModel):
    """Body posted by the mock login form."""
    username: Optional[str] = None
    password: Optional[str] = None
    private_ip: Optional[str] = None   # optional client-side telemetry
