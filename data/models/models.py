# SQLAlchemy models for Threat Defense System
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    ForeignKey,
    DateTime,
    Text,
    Boolean,
    JSON,
)
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from datetime import datetime, timezone
import os
from dotenv import load_dotenv

load_dotenv()  # reads .env file into os.environ

Base = declarative_base()

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError(
        "DATABASE_URL environment variable not set. Check your .env file."
    )
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine, expire_on_commit=False)


def get_session():
    """Create and return a new database session"""
    return Session()


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    type = Column(String)
    risk_level = Column(String)
    vulnerabilities = relationship(
        "Vulnerability", secondary="asset_vulnerabilities", back_populates="assets"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    description = Column(String)
    severity = Column(String)
    cve_id = Column(String(20))
    cvss_base_score = Column(Float)
    cvss_vector = Column(String(100))
    assets = relationship(
        "Asset", secondary="asset_vulnerabilities", back_populates="vulnerabilities"
    )


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"
    asset_id = Column(Integer, ForeignKey("assets.id"), primary_key=True)
    vulnerability_id = Column(
        Integer, ForeignKey("vulnerabilities.id"), primary_key=True
    )
    asset = relationship("Asset", overlaps="assets,vulnerabilities")
    vulnerability = relationship("Vulnerability", overlaps="assets,vulnerabilities")


class AttackEdge(Base):
    __tablename__ = "attack_edges"
    id = Column(Integer, primary_key=True)
    from_asset_id = Column(Integer, ForeignKey("assets.id"))
    to_asset_id = Column(Integer, ForeignKey("assets.id"))
    attack_technique = Column(String)
    difficulty = Column(String)


class AttackPath(Base):
    __tablename__ = "attack_paths"
    id = Column(Integer, primary_key=True)

    # Path definition
    source_asset_id = Column(Integer, ForeignKey("assets.id"))
    target_asset_id = Column(Integer, ForeignKey("assets.id"))
    attack_steps = Column(JSON)

    # Scoring
    difficulty_score = Column(Float)  # 1-10 (1-trivial, 10-impossible)
    time_to_exploit = Column(Integer)  # minutes
    success_probability = Column(Float)  # 0-1
    risk_score = Column(Float)  # Combined metric

    # Metadata
    created_at = Column(DateTime(timezone=True))
    threat_actor_profile = Column(String(120))  # "script kiddie", "eqiped", "APT"


class ThreatScenario(Base):
    __tablename__ = "threat_scenarios"
    id = Column(Integer, primary_key=True)
    name = Column(String)
    likelihood = Column(String)
    impact = Column(String)
    description = Column(String)


class ScenarioAsset(Base):
    __tablename__ = "scenario_assets"
    scenario_id = Column(Integer, ForeignKey("threat_scenarios.id"), primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), primary_key=True)
    scenario = relationship("ThreatScenario")
    asset = relationship("Asset")


class ThreatClassification(Base):
    __tablename__ = "threat_classifications"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"))
    threat_type = Column(String)
    exploitability_score = Column(Float)
    impact_score = Column(Float)
    risk_score = Column(Float)
    mitre_tactic = Column(String)
    mitre_tactics = Column(String)  # Add this field for multiple tactics
    severity = Column(String)
    timestamp = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class ThreatReview(Base):
    __tablename__ = "threat_reviews"
    id = Column(Integer, primary_key=True)
    threat_classification_id = Column(
        Integer,
        ForeignKey("threat_classifications.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    reviewer_analyst_id = Column(Integer, ForeignKey("analysts.id"), nullable=True)
    status = Column(String(32), nullable=False, default="pending")  # pending, reviewed
    decision = Column(String(32), nullable=True)
    original_threat_type = Column(String(120), nullable=True)
    final_threat_type = Column(String(120), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=True,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=True,
    )
    decided_at = Column(DateTime(timezone=True), nullable=True)

    claimed_by = Column(Integer, ForeignKey("analysts.id"), nullable=True, index=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)

    # In-Review Lockin
    locked_by = Column(
        Integer, ForeignKey("analysts.id"), nullable=True, index=True
    )  # Who has it open currenty
    locked_at = Column(DateTime(timezone=True), nullable=True)
    lock_expires_at = Column(
        DateTime(timezone=True), nullable=True
    )  # 10 min from locked_at

    # SLA Tracking
    severity = Column(String(32), nullable=True)  # critical, high, medium, low
    sla_deadline = Column(DateTime(timezone=True), nullable=True)
    sla_breached = Column(
        Boolean, default=False, index=True
    )  # Set to true if auto-escalated
    sla_escalated_at = Column(DateTime(timezone=True), nullable=True)

    # Analysts + Feedback Loop
    review_time_seconds = Column(Integer, nullable=True)  # Calculated at submit time
    is_training_data = Column(
        Boolean, default=False
    )  # True if saved to analyst_curated pool

    escalation_notified_at = Column(DateTime(timezone=True), nullable=True)
    escalation_notes = Column(Text, nullable=True)
    escalated_to_analyst_id = Column(Integer, ForeignKey("analysts.id"), nullable=True)


class AnalystCuratedTrainingData(Base):
    __tablename__ = "analyst_curated_training_data"

    id = Column(Integer, primary_key=True)
    threat_review_id = Column(
        Integer, ForeignKey("threat_reviews.id"), nullable=False, index=True
    )

    # The training pair
    vulnerability_description = Column(Text, nullable=False)
    analyst_corrected_threat_type = Column(String(120), nullable=False, index=True)

    # Metadata
    threat_severity = Column(String(32), nullable=True)
    analyst_id = Column(Integer, ForeignKey("analysts.id"), nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Tracking
    used_in_model_version = Column(
        String(64), nullable=True
    )  # e.g., "nb_v3_analyst_feedback"
    used_in_retrain_at = Column(DateTime(timezone=True), nullable=True)


class ReviewerAnalytics(Base):
    __tablename__ = "reviewer_analytics"

    id = Column(Integer, primary_key=True)
    analyst_id = Column(
        Integer, ForeignKey("analysts.id"), nullable=False, unique=True, index=True
    )

    # Counters
    total_reviews = Column(Integer, default=0)
    confirmed_count = Column(Integer, default=0)
    false_positive_count = Column(Integer, default=0)
    escalated_count = Column(Integer, default=0)

    # Times
    avg_review_seconds = Column(Float, default=0)  # computed field, updated daily
    total_review_time_seconds = Column(Integer, default=0)

    # Compliance
    sla_compliant = Column(
        Integer, default=0
    )  # COunt of reviews finished before deadline
    sla_breached = Column(Integer, default=0)
    sla_compliance_pct = Column(Float, default=0)  # 0-100

    # Metadata
    last_review_at = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class AssetBehaviorBaseline(Base):
    __tablename__ = "asset_behavior_baselines"
    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, unique=True)

    # Statistical metrics
    metric_type = Column(String(50), default="log_event_count")
    baseline_mean = Column(Float, default=0.0)  # Average value
    baseline_std = Column(Float, default=1.0)  # Standard deviation
    baseline_min = Column(Float, default=0.0)  # Minimum observed value
    baseline_max = Column(Float, default=100.0)  # Maximum observed value

    # Hourly patterns (hour-of-day: 0-23)
    hourly_pattern = Column(JSON, default={})  # {0:45.2, 1: 32.1, ...}

    # Daily patterns (day-of-week: 0-6, where 0=Monday, 6=Sunday)
    daily_pattern = Column(JSON, default={})  # {0: 350, 1:340, ...}

    # Metadata
    baseline_ready = Column(Boolean, default=False)
    observations_count = Column(Integer, default=0)  # How many data points used
    created_at = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    asset = relationship("Asset", backref="behavior_baseline")


class LogEvent(Base):
    __tablename__ = "log_events"
    id = Column(Integer, primary_key=True)
    timestamp = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    source = Column(String, nullable=True)
    level = Column(String, nullable=True)
    message = Column(String, nullable=True)
    data = Column(String)  # Store the full log as JSON string


class Analyst(Base):
    __tablename__ = "analysts"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    role = Column(
        String(50), default="analyst"
    )  # analyst, senior_analyst, manager, admin
    active = Column(Boolean, default=True)
    password_hash = Column(
        String(255), nullable=True
    )  # for existing rows during migration
    last_login = Column(DateTime(timezone=True), nullable=True)
    must_change_password = Column(
        Boolean, default=False
    )  # True until analyst sets their own password
    notification_threshold = Column(
        String(20), default="medium"
    )  # low, medium, high, critical
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    email_notifications = relationship("EmailNotification", back_populates="analyst")


class EmailNotification(Base):
    __tablename__ = "email_notifications"
    id = Column(Integer, primary_key=True)
    analyst_id = Column(Integer, ForeignKey("analysts.id"))
    threat_id = Column(Integer, ForeignKey("threat_classifications.id"))
    subject = Column(String(500), nullable=False)
    email_template = Column(String(50), nullable=False)  # alert, escalation, summary
    sent_at = Column(DateTime, default=datetime.utcnow)
    delivery_status = Column(
        String(20), default="pending"
    )  # pending, sent, delivered, failed
    error_message = Column(Text)
    opened_at = Column(DateTime)
    clicked_at = Column(DateTime)

    # Relationships
    analyst = relationship("Analyst", back_populates="email_notifications")
    threat = relationship("ThreatClassification")


class ResponseAction(Base):
    __tablename__ = "response_actions"
    id = Column(Integer, primary_key=True)
    threat_id = Column(Integer, ForeignKey("threat_classifications.id"))
    action_type = Column(
        String(50), nullable=False
    )  # monitor, alert, contain, isolate, block
    action_status = Column(
        String(20), default="pending"
    )  # pending, executing, completed, failed
    automate = Column(Boolean, default=True)
    executed_by = Column(String(100))  # system or analyst name
    executed_at = Column(DateTime, default=datetime.utcnow)
    details = Column(JSON)  # Store action-specific data
    result_message = Column(Text)

    # Relationships
    threat = relationship("ThreatClassification")


class HuntingResult(Base):
    __tablename__ = "hunting_results"
    id = Column(Integer, primary_key=True)
    threat_id = Column(Integer, ForeignKey("threat_classifications.id"))
    ioc_matches = Column(JSON)  # List of matched IOCs with details
    ioc_match_count = Column(Integer, default=0)
    entity_correlations = Column(JSON)  # Related threats and entities
    ml_correlations = Column(JSON)  # ML-based correlations
    anomaly_detected = Column(Boolean, default=False)
    anomaly_score = Column(Float, default=0.0)
    patterns_detected = Column(JSON)  # Attack patterns matched
    hunting_confidence = Column(Float)  # Overall confidence score (0-1)
    hunting_status = Column(
        String(20), default="completed"
    )  # completed, pending, failed
    agent_id = Column(String(50), default="hunter_001")
    timestamp = Column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    threat = relationship("ThreatClassification")
