from datetime import datetime
from typing import Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .settings import settings

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class APIKey(Base):
    __tablename__ = "api_keys"

    # key_hash is the HMAC-SHA256 of the raw key — the plaintext key is never
    # stored after creation. key_prefix stores first 8 chars for display only.
    key_hash = Column(String, primary_key=True)
    key_prefix = Column(String, nullable=False)  # e.g. "GAI_ab12" — safe to display
    user_id = Column(String, nullable=False)
    org_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)


class Policy(Base):
    """Legacy precheck-local policy table — kept for backward compat with the
    YAML-import flow (Phase 2.3). Org-scoped policies live in DashboardPolicy
    below, which mirrors the dashboard's Prisma Policy model. See ADR-005."""

    __tablename__ = "policies"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    rules = Column(Text)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class DashboardPolicy(Base):
    """Read-only mirror of the dashboard's `Policy` table (Prisma model).

    Precheck reads this table directly via the shared Postgres connection;
    the dashboard owns writes. See ADR-005 (policy source of truth).

    The table name is `Policy` (Prisma default — model name unchanged).
    Column names use the Prisma @map snake_case form where applicable.
    """

    __tablename__ = "Policy"

    id = Column(String, primary_key=True)
    org_id = Column("org_id", String, nullable=False, index=True)
    user_id = Column("user_id", String, nullable=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    version = Column(String, nullable=False, default="v1")
    defaults = Column(JSON, nullable=False)
    tool_access = Column("tool_access", JSON, nullable=False, default=dict)
    deny_tools = Column("deny_tools", JSON, nullable=False, default=list)
    allow_tools = Column("allow_tools", JSON, nullable=False, default=list)
    network_scopes = Column("network_scopes", JSON, nullable=False, default=list)
    network_tools = Column("network_tools", JSON, nullable=False, default=list)
    on_error = Column("on_error", String, nullable=False, default="block")
    is_active = Column("isActive", Boolean, nullable=False, default=True)
    priority = Column(Integer, nullable=False, default=0)
    created_at = Column("createdAt", DateTime, default=datetime.utcnow)
    updated_at = Column("updatedAt", DateTime, default=datetime.utcnow)


class UsageEvent(Base):
    __tablename__ = "usage_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False)
    tool = Column(String, nullable=False)
    scope = Column(String)
    decision = Column(String, nullable=False)
    policy_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    payload_hash = Column(String)  # SHA256 of payload for deduplication


class Quota(Base):
    __tablename__ = "quotas"

    user_id = Column(String, primary_key=True)
    daily_limit = Column(Integer, default=1000)
    monthly_limit = Column(Integer, default=30000)
    current_daily = Column(Integer, default=0)
    current_monthly = Column(Integer, default=0)
    last_reset_daily = Column(DateTime, default=datetime.utcnow)
    last_reset_monthly = Column(DateTime, default=datetime.utcnow)


class Budget(Base):
    __tablename__ = "budgets"

    user_id = Column(String, primary_key=True)
    monthly_limit = Column(Float, default=10.0)  # Default $10/month
    current_spend = Column(Float, default=0.0)
    llm_spend = Column(Float, default=0.0)
    purchase_spend = Column(Float, default=0.0)
    budget_type = Column(String, default="user")  # "user" or "organization"
    last_reset = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class BudgetTransaction(Base):
    __tablename__ = "budget_transactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, nullable=False)
    transaction_type = Column(String, nullable=False)  # "llm" or "purchase"
    amount = Column(Float, nullable=False)
    description = Column(String)
    tool = Column(String)
    correlation_id = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


# Database setup
engine = create_engine(settings.db_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def create_tables():
    """Create all precheck-owned tables.

    `DashboardPolicy` is intentionally excluded — that table is owned and
    migrated by the dashboard (Prisma). Precheck only reads it. See ADR-005.
    """
    owned_tables = [
        t for t in Base.metadata.sorted_tables if t.name != "Policy"
    ]
    Base.metadata.create_all(bind=engine, tables=owned_tables)


def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
