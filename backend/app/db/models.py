import enum
from sqlalchemy import (Column, Integer, String, Enum, Boolean, DateTime,
                        Text, JSON, ForeignKey, func)
from sqlalchemy.orm import relationship
from app.db.database import Base

class Role(str, enum.Enum):
    ADMIN = "admin"
    PENTESTER = "pentester"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(Role), nullable=False, default=Role.PENTESTER)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# --- Module 1: Offensive Testing Suite ---
class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_type = Column(String(32), nullable=False)   # wireless | subnet | host | mobile
    target = Column(String(255))
    findings = Column(JSON, default=list)            # structured JSON from agents
    status = Column(String(32), default="open")      # open | patched
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# --- Module 2: PHish_SIm ---
class PhishCampaign(Base):
    __tablename__ = "phish_campaigns"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(128), nullable=False)
    template = Column(Text)
    listener_port = Column(Integer)
    telemetry = Column(JSON, default=list)  # timestamps, IPs, geo, UA, captured inputs
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# --- Module 3: Payload & Control Matrix ---
class GeneratedPayload(Base):
    __tablename__ = "generated_payloads"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    platform = Column(String(32), nullable=False)    # windows-x64 | linux | macos | android-arm
    lhost = Column(String(64))
    lport = Column(Integer)
    file_path = Column(String(512))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class OOBInteraction(Base):
    __tablename__ = "oob_interactions"

    id = Column(Integer, primary_key=True)
    token = Column(String(64), index=True, nullable=False)  # unique subdomain token
    protocol = Column(String(16))                    # dns | http | ldap
    source_ip = Column(String(64))
    details = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# --- Module 5: Study Room ---
class StudyPath(Base):
    __tablename__ = "study_paths"

    id = Column(Integer, primary_key=True)
    title = Column(String(128), nullable=False)      # e.g. "Penetration Tester Path (OSCP)"
    certs = Column(JSON, default=list)
    modules = Column(JSON, default=list)

class Note(Base):
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(255))
    content_md = Column(Text, default="")            # Markdown/WYSIWYG body
    attachments = Column(JSON, default=list)         # uploaded pcap/PoC files
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class NetworkScan(Base):
    """Module 1.2: metadata for a single subnet scan run."""
    __tablename__ = "network_scans"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    target_subnet = Column(String(64), nullable=False)      # e.g. "192.168.1.0/24"
    scan_type = Column(String(32), default="subnet")        # subnet | wireless | host
    status = Column(String(32), default="pending")          # pending | running | completed | failed
    total_devices = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("User")
    devices = relationship("DiscoveredDevice", back_populates="scan",
                           cascade="all, delete-orphan")


class DiscoveredDevice(Base):
    """Module 1.2: a live host found during a scan, with CVE matches + lifecycle."""
    __tablename__ = "discovered_devices"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("network_scans.id"), nullable=False, index=True)

    ip_address = Column(String(45), nullable=False, index=True)   # IPv4/IPv6
    mac_address = Column(String(32), nullable=True)
    device_name = Column(String(255), nullable=True)              # hostname / netbios
    os_fingerprint = Column(String(255), nullable=True)

    open_ports = Column(JSON, default=list)        # [{"port": 445, "proto": "tcp", "service": "smb"}]
    matched_cves = Column(JSON, default=list)      # [{"cve": "CVE-2017-0144", "cvss": 8.1, "desc": "..."}]

    # Remediation lifecycle: "Vulnerable" -> "Patched" (Module 1.2 remediation logging)
    remediation_status = Column(String(32), default="Vulnerable", index=True)
    remediation_notes = Column(Text, nullable=True)
    patched_at = Column(DateTime(timezone=True), nullable=True)
    patched_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    scan = relationship("NetworkScan", back_populates="devices")

# --- APPEND to bottom of app/db/models.py ---
# --- Module 2: PHish_SIm — Social Engineering Suite ---

class PhishingCampaign(Base):
    """Module 2: a single authorized SE engagement scenario."""
    __tablename__ = "phishing_campaigns"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)

    # Engagement authorization metadata (audit trail)
    engagement_ref = Column(String(128), nullable=True)   # e.g. "ENG-2026-041 Rules of Eng."

    # Targets: JSON list of {"email": "...", "first_name": "...", "last_name": "..."}
    target_emails = Column(JSON, default=list)

    # SMTP relay configuration (application-specific password)
    smtp_host = Column(String(255), nullable=False)
    smtp_port = Column(Integer, default=587)
    smtp_username = Column(String(255), nullable=False)
    smtp_password_enc = Column(String(512), nullable=False)  # Fernet-encrypted at rest
    from_display = Column(String(255), nullable=False)       # e.g. "IT Helpdesk <it@corp.example>"

    # Email body with {tracker_url} and {first_name} tokens
    subject = Column(String(255), nullable=False)
    body_html = Column(Text, nullable=False)

    # The mock login page branding the victim lands on
    landing_title = Column(String(128), default="Sign in to continue")

    # public | draft | running | completed
    status = Column(String(32), default="draft", index=True)
    tracker_id = Column(String(64), unique=True, index=True)  # per-campaign UUID

    dispatch_scheduled_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User")
    telemetry = relationship("PhishingTelemetry", back_populates="campaign",
                             cascade="all, delete-orphan")


class PhishingTelemetry(Base):
    """Module 2: silent client profiling per target interaction."""
    __tablename__ = "phishing_telemetry"

    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("phishing_campaigns.id"),
                         nullable=False, index=True)

    # Identity of the interaction (visitor may be reused across clicks)
    visitor_token = Column(String(64), index=True)     # per-target visitor UUID (cookie)
    target_email = Column(String(255), nullable=True)  # resolved if token known

    # Network
    public_ip = Column(String(64), nullable=True)      # X-Forwarded-For safe parse
    private_ip = Column(String(64), nullable=True)     # from browser telemetry if captured
    geo_country = Column(String(64), nullable=True)
    geo_region = Column(String(64), nullable=True)
    geo_city = Column(String(64), nullable=True)

    # Client environment
    user_agent = Column(Text, nullable=True)
    browser = Column(String(64), nullable=True)
    os_name = Column(String(64), nullable=True)
    device_name = Column(String(64), nullable=True)
    accept_language = Column(String(128), nullable=True)

    # Lifecycle
    click_timestamp = Column(DateTime(timezone=True), server_default=func.now())
    referer = Column(Text, nullable=True)

    # Captured payload (Module 2 credential log column)
    captured_input = Column(Text, nullable=True)        # plaintext credentials/form fields JSON
    captured_at = Column(DateTime(timezone=True), nullable=True)

    campaign = relationship("PhishingCampaign", back_populates="telemetry")
