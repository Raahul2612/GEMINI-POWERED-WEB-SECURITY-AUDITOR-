"""
Database models and utilities for storing audit results.
"""
from sqlalchemy import create_engine, Column, String, Float, Text, DateTime, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import logging
from config import DATABASE_URL

logger = logging.getLogger(__name__)

Base = declarative_base()

class AuditResult(Base):
    """Database model for storing audit results."""
    __tablename__ = "audit_results"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_id = Column(String(100), unique=True, nullable=False, index=True)
    vulnerability_id = Column(String(50), nullable=False)
    vulnerability_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    cvss_score = Column(Float, nullable=False)
    input_data = Column(Text)
    description = Column(Text)
    justification = Column(Text)
    remediation = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        """Convert model instance to dictionary."""
        return {
            "id": self.id,
            "audit_id": self.audit_id,
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "input_data": self.input_data,
            "description": self.description,
            "justification": self.justification,
            "remediation": self.remediation,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class DatabaseManager:
    """Manages database operations."""
    
    def __init__(self, database_url=None):
        self.database_url = database_url or DATABASE_URL
        self.engine = create_engine(self.database_url, connect_args={"check_same_thread": False})
        self.SessionLocal = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        logger.info(f"Database initialized at {self.database_url}")
    
    def get_session(self):
        """Get a database session."""
        return self.SessionLocal()
    
    def save_audit_results(self, audit_id, results):
        """Save audit results to the database."""
        session = self.get_session()
        try:
            saved_count = 0
            for result in results:
                audit_result = AuditResult(
                    audit_id=audit_id,
                    vulnerability_id=result.get("id"),
                    vulnerability_type=result.get("type"),
                    severity=result.get("severity"),
                    cvss_score=result.get("cvss"),
                    input_data=result.get("input"),
                    description=result.get("description"),
                    justification=result.get("justification"),
                    remediation=result.get("remediation")
                )
                session.add(audit_result)
                saved_count += 1
            session.commit()
            logger.info(f"Saved {saved_count} audit results for audit_id: {audit_id}")
            return saved_count
        except Exception as e:
            session.rollback()
            logger.error(f"Error saving audit results: {e}")
            raise
        finally:
            session.close()
    
    def get_audit_history(self, limit=50):
        """Retrieve recent audit history."""
        session = self.get_session()
        try:
            results = session.query(AuditResult).order_by(AuditResult.created_at.desc()).limit(limit).all()
            return [r.to_dict() for r in results]
        except Exception as e:
            logger.error(f"Error retrieving audit history: {e}")
            return []
        finally:
            session.close()
    
    def get_audit_by_id(self, audit_id):
        """Retrieve all results for a specific audit ID."""
        session = self.get_session()
        try:
            results = session.query(AuditResult).filter(AuditResult.audit_id == audit_id).all()
            return [r.to_dict() for r in results]
        except Exception as e:
            logger.error(f"Error retrieving audit: {e}")
            return []
        finally:
            session.close()

# Global database manager instance
db_manager = DatabaseManager()

