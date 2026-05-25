from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class ScanRecord(db.Model):
    __tablename__ = "scan_record"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_time = db.Column(db.DateTime, nullable=False, default=datetime.now)
    total_processes = db.Column(db.Integer, nullable=False, default=0)
    high_risk_count = db.Column(db.Integer, nullable=False, default=0)
    trigger_type = db.Column(db.Enum("manual", "scheduled"), nullable=False, default="manual")

    snapshots = db.relationship("ProcessSnapshot", backref="scan", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_time": self.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_processes": self.total_processes,
            "high_risk_count": self.high_risk_count,
            "trigger_type": self.trigger_type,
        }


class ProcessSnapshot(db.Model):
    __tablename__ = "process_snapshot"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan_record.id"), nullable=False)
    pid = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    exe_path = db.Column(db.Text, nullable=True)
    cmdline = db.Column(db.Text, nullable=True)
    username = db.Column(db.String(50), nullable=True)
    parent_pid = db.Column(db.Integer, nullable=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    risk_level = db.Column(db.Enum("low", "medium", "high", "critical"), nullable=False, default="low")

    hits = db.relationship("RuleHit", backref="snapshot", lazy="dynamic")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "pid": self.pid,
            "name": self.name,
            "exe_path": self.exe_path,
            "cmdline": self.cmdline,
            "username": self.username,
            "parent_pid": self.parent_pid,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
        }


class RuleHit(db.Model):
    __tablename__ = "rule_hit"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    snapshot_id = db.Column(db.Integer, db.ForeignKey("process_snapshot.id"), nullable=False)
    rule_id = db.Column(db.Integer, db.ForeignKey("rule.id"), nullable=False)
    detail = db.Column(db.Text, nullable=True)

    rule = db.relationship("Rule", backref="hits")

    def to_dict(self):
        return {
            "id": self.id,
            "snapshot_id": self.snapshot_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule.name if self.rule else None,
            "rule_category": self.rule.category if self.rule else None,
            "detail": self.detail,
        }


class Rule(db.Model):
    __tablename__ = "rule"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    weight = db.Column(db.Float, nullable=False, default=1.0)
    score = db.Column(db.Integer, nullable=False, default=10)
    is_builtin = db.Column(db.Boolean, nullable=False, default=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)

    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "weight": self.weight,
            "score": self.score,
            "is_builtin": self.is_builtin,
            "enabled": self.enabled,
        }
