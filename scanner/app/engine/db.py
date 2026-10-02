from datetime import datetime, timedelta
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    desc,
    func,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from engine.config import settings

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    filename = Column(String(255), nullable=False)
    path = Column(Text, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    size = Column(Integer, nullable=False, default=0)
    verdict = Column(String(32), nullable=True)  # pass, review, block
    score = Column(Integer, nullable=True, default=0)
    status = Column(String(32), nullable=False, default="scanning")  # scanning, completed, failed
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    check_results = relationship("CheckResult", back_populates="scan", cascade="all, delete-orphan")


class CheckResult(Base):
    __tablename__ = "check_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    checker = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)  # pass, warn, fail, skip
    score = Column(Integer, nullable=False, default=0)
    details_json = Column(Text, nullable=False, default="{}")

    scan = relationship("Scan", back_populates="check_results")

    @property
    def details(self) -> Dict[str, Any]:
        try:
            return json.loads(self.details_json)
        except Exception:
            return {}


class ReputationCache(Base):
    __tablename__ = "reputation_cache"

    id = Column(Integer, primary_key=True, autoincrement=True)
    checker = Column(String(64), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False)
    score = Column(Integer, nullable=False, default=0)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    @property
    def details(self) -> Dict[str, Any]:
        try:
            return json.loads(self.details_json)
        except Exception:
            return {}


class WebScan(Base):
    """Web configuration and response audit session."""
    __tablename__ = "web_scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_url = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="running")   # running / complete / error
    score = Column(Integer, nullable=True)
    grade = Column(String(4), nullable=True)
    pages_crawled = Column(Integer, nullable=False, default=0)
    findings_count = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    findings = relationship("WebFinding", back_populates="web_scan", cascade="all, delete-orphan")


class WebFinding(Base):
    """Individual finding from a web audit scan."""
    __tablename__ = "web_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    web_scan_id = Column(Integer, ForeignKey("web_scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(16), nullable=False)          # short uuid from Finding.id
    title = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False)            # critical/high/medium/low/info
    evidence = Column(Text, nullable=False, default="")
    remediation = Column(Text, nullable=False, default="")
    owasp_category = Column(Text, nullable=False, default="")
    url = Column(Text, nullable=False, default="")
    check_name = Column(String(64), nullable=False, default="")

    web_scan = relationship("WebScan", back_populates="findings")


# Database engine & sessionmaker factory
def get_engine(db_path: Optional[Path] = None):
    target = db_path or settings.db_path
    target.parent.mkdir(parents=True, exist_ok=True)
    url = f"sqlite:///{target.resolve()}"
    return create_engine(url, connect_args={"check_same_thread": False}, echo=False)


_engine = get_engine()
SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False)


def init_db(db_path: Optional[Path] = None):
    eng = get_engine(db_path) if db_path else _engine
    Base.metadata.create_all(bind=eng)


init_db()



def create_scan(filename: str, path: str, sha256: str, size: int) -> int:
    with SessionLocal() as session:
        scan = Scan(
            filename=filename,
            path=str(path),
            sha256=sha256.lower(),
            size=size,
            status="scanning",
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def add_result(scan_id: int, checker: str, status: str, score: int, details: Dict[str, Any]) -> int:
    with SessionLocal() as session:
        res = CheckResult(
            scan_id=scan_id,
            checker=checker,
            status=status,
            score=score,
            details_json=json.dumps(details),
        )
        session.add(res)
        session.commit()
        session.refresh(res)
        return res.id


def finish_scan(scan_id: int, verdict: str, score: int, status: str = "completed") -> Optional[Dict[str, Any]]:
    with SessionLocal() as session:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        scan.verdict = verdict
        scan.score = score
        scan.status = status
        scan.updated_at = datetime.utcnow()
        session.commit()
        session.refresh(scan)
        return get_scan(scan_id)


def get_scan(scan_id: int) -> Optional[Dict[str, Any]]:
    with SessionLocal() as session:
        scan = session.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return None
        results = [
            {
                "id": r.id,
                "checker": r.checker,
                "status": r.status,
                "score": r.score,
                "details": r.details,
            }
            for r in scan.check_results
        ]
        return {
            "id": scan.id,
            "filename": scan.filename,
            "path": scan.path,
            "sha256": scan.sha256,
            "size": scan.size,
            "verdict": scan.verdict,
            "score": scan.score,
            "status": scan.status,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
            "check_results": results,
        }


def list_scans(limit: int = 100) -> List[Dict[str, Any]]:
    with SessionLocal() as session:
        scans = session.query(Scan).order_by(desc(Scan.id)).limit(limit).all()
        out = []
        for s in scans:
            out.append(
                {
                    "id": s.id,
                    "filename": s.filename,
                    "path": s.path,
                    "sha256": s.sha256,
                    "size": s.size,
                    "verdict": s.verdict,
                    "score": s.score,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                    "updated_at": s.updated_at.isoformat() if s.updated_at else None,
                    "results_count": len(s.check_results),
                }
            )
        return out


def cached_verdict_by_sha256(sha256: str) -> Optional[Dict[str, Any]]:
    with SessionLocal() as session:
        scan = (
            session.query(Scan)
            .filter(Scan.sha256 == sha256.lower(), Scan.status == "completed", Scan.verdict.isnot(None))
            .order_by(desc(Scan.id))
            .first()
        )
        if not scan:
            return None
        return {
            "verdict": scan.verdict,
            "score": scan.score,
            "cached_from_scan_id": scan.id,
        }


def get_reputation_cache(checker: str, sha256: str) -> Optional[Dict[str, Any]]:
    with SessionLocal() as session:
        entry = (
            session.query(ReputationCache)
            .filter(ReputationCache.checker == checker, ReputationCache.sha256 == sha256.lower())
            .order_by(desc(ReputationCache.id))
            .first()
        )
        if not entry:
            return None
        return {
            "status": entry.status,
            "score": entry.score,
            "details": entry.details,
        }


def set_reputation_cache(checker: str, sha256: str, status: str, score: int, details: Dict[str, Any]):
    with SessionLocal() as session:
        entry = ReputationCache(
            checker=checker,
            sha256=sha256.lower(),
            status=status,
            score=score,
            details_json=json.dumps(details),
            created_at=datetime.utcnow(),
        )
        session.add(entry)
        session.commit()


def stats() -> Dict[str, Any]:
    with SessionLocal() as session:
        total = session.query(func.count(Scan.id)).scalar() or 0
        passed = session.query(func.count(Scan.id)).filter(Scan.verdict == "pass").scalar() or 0
        review = session.query(func.count(Scan.id)).filter(Scan.verdict == "review").scalar() or 0
        blocked = session.query(func.count(Scan.id)).filter(Scan.verdict == "block").scalar() or 0

        # Hourly scans for the last 24h
        now = datetime.utcnow()
        day_ago = now - timedelta(hours=24)
        recent_scans = (
            session.query(Scan.created_at)
            .filter(Scan.created_at >= day_ago)
            .all()
        )

        hourly: Dict[str, int] = {}
        for h in range(24):
            t = (day_ago + timedelta(hours=h)).strftime("%H:00")
            hourly[t] = 0

        for (created_at,) in recent_scans:
            if created_at:
                key = created_at.strftime("%H:00")
                if key in hourly:
                    hourly[key] += 1

        hourly_list = [{"hour": k, "count": v} for k, v in hourly.items()]

        return {
            "total_scans": total,
            "passed": passed,
            "review": review,
            "blocked": blocked,
            "verdict_split": [
                {"name": "Pass", "value": passed, "color": "#10b981"},
                {"name": "Review", "value": review, "color": "#f59e0b"},
                {"name": "Block", "value": blocked, "color": "#ef4444"},
            ],
            "scans_per_hour": hourly_list,
        }
