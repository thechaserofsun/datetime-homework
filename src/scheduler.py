from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from src.models import db, Rule, ScanRecord, ProcessSnapshot, RuleHit
from src.scanner import scan_all_processes
from src.ruler import evaluate
from datetime import datetime

_scheduler = None
_current_interval_minutes = 30


def get_scheduler():
    return _scheduler


def get_interval():
    return _current_interval_minutes


def scan_job(app):
    with app.app_context():
        try:
            processes = scan_all_processes()
        except Exception as e:
            print(f"[Scheduler] 扫描失败: {e}")
            return

        rules = Rule.query.filter_by(enabled=True).all()

        record = ScanRecord(
            scan_time=datetime.now(),
            total_processes=len(processes),
            high_risk_count=0,
            trigger_type="scheduled",
        )
        db.session.add(record)
        db.session.flush()

        high_risk_count = 0

        for p in processes:
            hits, score, level = evaluate(p, rules)
            if level in ("high", "critical"):
                high_risk_count += 1

            snapshot = ProcessSnapshot(
                scan_id=record.id,
                pid=p["pid"],
                name=p["name"],
                exe_path=p["exe_path"],
                cmdline=p["cmdline"],
                username=p["username"],
                parent_pid=p["parent_pid"],
                risk_score=score,
                risk_level=level,
            )
            db.session.add(snapshot)
            db.session.flush()

            for h in hits:
                hit = RuleHit(
                    snapshot_id=snapshot.id,
                    rule_id=h["rule_id"],
                    detail=h["detail"],
                )
                db.session.add(hit)

        record.high_risk_count = high_risk_count
        db.session.commit()
        print(f"[Scheduler] 定时扫描完成: {len(processes)} 个进程, 高风险 {high_risk_count} 个")


def init_scheduler(app):
    global _scheduler, _current_interval_minutes
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_func = scan_job
    _scheduler.add_job(
        scan_job,
        "interval",
        minutes=_current_interval_minutes,
        id="scan_job",
        args=[app],
    )
    _scheduler.start()
    print(f"[Scheduler] 定时巡检已启动，间隔 {_current_interval_minutes} 分钟")


def update_interval(app, minutes):
    global _current_interval_minutes, _scheduler
    if minutes < 1:
        minutes = 1
    _current_interval_minutes = minutes

    if _scheduler and _scheduler.running:
        _scheduler.reschedule_job("scan_job", trigger="interval", minutes=minutes)
        print(f"[Scheduler] 巡检间隔已更新为 {minutes} 分钟")
