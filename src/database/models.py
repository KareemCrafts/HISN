# src/database/models.py
from sqlalchemy import create_engine, Column, String, Float, DateTime, Text
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone
import uuid

Base = declarative_base()

class Alert(Base):
    __tablename__ = "alerts"

    id                   = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp            = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    host                 = Column(String, nullable=False)
    user                 = Column(String, nullable=True)
    event_id             = Column(String, nullable=True)
    rule_name            = Column(String, nullable=False)
    sigma_rule_id        = Column(String, nullable=True)
    mitre_technique_id   = Column(String, nullable=False)
    mitre_technique_name = Column(String, nullable=False)
    mitre_tactic         = Column(String, nullable=False)
    severity             = Column(String, nullable=False)
    confidence           = Column(Float, nullable=False)
    raw_event            = Column(Text, nullable=True)

def init_db(db_path: str = "soc_copilot.db"):
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    return engine
