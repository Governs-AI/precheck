from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from typing import Optional
from .settings import settings

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(String, primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class APIKey(Base):
    __tablename__ = "api_keys"

    key = Column(String, primary_key=True)
    user_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)  # None means the key never expires

class Policy(Base):
    __tablename__ = "policies"
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    rules = Column(Text)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

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
    """Create all tables"""
    Base.metadata.create_all(bind=engine)

def get_db():
    """Get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
