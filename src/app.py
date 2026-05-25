import os
import sys
import json
import logging
from datetime import datetime
from flask import Flask, jsonify, render_template, request
from src.config import Config
from src.models import db, Rule, ScanRecord, ProcessSnapshot, RuleHit
from src.scanner import scan_all_processes, scan_single_process
from src.ruler import evaluate, PREVENTION_ADVICE
from src.scheduler import init_scheduler, update_interval, get_scheduler, get_interval

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def setup_logging():
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)

    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    date_str = datetime.now().strftime("%Y-%m-%d")

    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(os.path.join(log_dir, f"scan_{date_str}.log"), encoding="utf-8"),
            logging.StreamHandler(),
        ],
    )


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
    )
    app.config.from_object(Config)

    db.init_app(app)

    with app.app_context():
        try:
            db.create_all()
            print("[DB] 数据库表同步完成")
        except Exception as e:
            print(f"[DB] 数据库连接失败: {e}")
            print("[DB] 请确认 MySQL 服务已启动，且数据库 process_analyzer 已创建")

    init_scheduler(app)

    # ---------- 页面路由 ----------
    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/processes")
    def processes():
        return render_template("processes.html")

    @app.route("/detail")
    def detail():
        return render_template("detail.html")

    @app.route("/rules")
    def rules():
        return render_template("rules.html")

    @app.route("/history")
    def history():
        return render_template("history.html")

    # ---------- API 路由 ----------
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        logger = logging.getLogger("scan")
        trigger = request.json.get("trigger", "manual") if request.json else "manual"
        logger.info(f"开始扫描，触发方式: {trigger}")
        try:
            processes = scan_all_processes()
        except Exception as e:
            logger.error(f"扫描采集失败: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

        rules = Rule.query.filter_by(enabled=True).all()

        record = ScanRecord(
            scan_time=datetime.now(),
            total_processes=len(processes),
            high_risk_count=0,
            trigger_type=trigger,
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
        logger.info(f"扫描完成: {len(processes)} 个进程, 高风险 {high_risk_count} 个, scan_id={record.id}")

        return jsonify({
            "status": "ok",
            "data": {
                "scan_id": record.id,
                "total_processes": record.total_processes,
                "high_risk_count": high_risk_count,
                "scan_time": record.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
            },
        })

    @app.route("/api/processes", methods=["GET"])
    def api_processes():
        scan_id = request.args.get("scan_id", type=int)
        level = request.args.get("level", type=str)
        keyword = request.args.get("keyword", type=str)

        query = ProcessSnapshot.query

        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        else:
            latest = ScanRecord.query.order_by(ScanRecord.id.desc()).first()
            if latest:
                query = query.filter_by(scan_id=latest.id)

        if level:
            query = query.filter_by(risk_level=level)

        if keyword:
            query = query.filter(
                db.or_(
                    ProcessSnapshot.name.contains(keyword),
                    ProcessSnapshot.pid == int(keyword) if keyword.isdigit() else False,
                )
            )

        snapshots = query.order_by(ProcessSnapshot.risk_score.desc()).all()
        return jsonify({"status": "ok", "data": [s.to_dict() for s in snapshots]})

    @app.route("/api/process/<int:pid>", methods=["GET"])
    def api_process_detail(pid):
        scan_id = request.args.get("scan_id", type=int)

        query = ProcessSnapshot.query.filter_by(pid=pid)
        if scan_id:
            query = query.filter_by(scan_id=scan_id)
        else:
            latest = ScanRecord.query.order_by(ScanRecord.id.desc()).first()
            if latest:
                query = query.filter_by(scan_id=latest.id)

        snapshot = query.first()
        if not snapshot:
            data = scan_single_process(pid)
            if not data:
                return jsonify({"status": "error", "message": f"进程 PID={pid} 不存在或无法访问"}), 404
            return jsonify({"status": "ok", "data": data})

        live_data = scan_single_process(pid)
        result = snapshot.to_dict()
        result["live"] = live_data
        result["hits"] = [h.to_dict() for h in snapshot.hits]

        # 根据命中规则类别生成预防措施
        hit_categories = set()
        for h in snapshot.hits:
            if h.rule:
                hit_categories.add(h.rule.category)
        result["prevention"] = [PREVENTION_ADVICE.get(c, "建议加强该方面的安全监控与审计") for c in hit_categories]

        return jsonify({"status": "ok", "data": result})

    @app.route("/api/rules", methods=["GET"])
    def api_rules():
        rules = Rule.query.all()
        return jsonify({"status": "ok", "data": [r.to_dict() for r in rules]})

    @app.route("/api/rules", methods=["POST"])
    def api_add_rule():
        data = request.json
        if not data or not data.get("name") or not data.get("category"):
            return jsonify({"status": "error", "message": "缺少必填字段"}), 400
        rule = Rule(
            category=data["category"],
            name=data["name"],
            description=data.get("description", ""),
            weight=data.get("weight", 1.0),
            score=data.get("score", 10),
            is_builtin=False,
            enabled=True,
        )
        db.session.add(rule)
        db.session.commit()
        return jsonify({"status": "ok", "data": rule.to_dict()})

    @app.route("/api/history", methods=["GET"])
    def api_history():
        records = ScanRecord.query.order_by(ScanRecord.id.desc()).limit(50).all()
        return jsonify({"status": "ok", "data": [r.to_dict() for r in records]})

    @app.route("/api/trend", methods=["GET"])
    def api_trend():
        records = ScanRecord.query.order_by(ScanRecord.id.asc()).limit(100).all()
        data = []
        for r in records:
            data.append({
                "scan_time": r.scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_processes": r.total_processes,
                "high_risk_count": r.high_risk_count,
            })
        return jsonify({"status": "ok", "data": data})

    @app.route("/api/schedule", methods=["GET"])
    def api_get_schedule():
        scheduler = get_scheduler()
        return jsonify({
            "status": "ok",
            "data": {
                "running": scheduler is not None and scheduler.running,
                "interval_minutes": get_interval(),
            },
        })

    @app.route("/api/schedule", methods=["POST"])
    def api_set_schedule():
        data = request.json or {}
        action = data.get("action", "update")

        if action == "stop":
            scheduler = get_scheduler()
            if scheduler and scheduler.running:
                scheduler.shutdown(wait=False)
            return jsonify({"status": "ok", "data": {"running": False, "interval_minutes": get_interval()}})

        minutes = int(data.get("interval_minutes", get_interval()))
        if minutes < 1:
            return jsonify({"status": "error", "message": "间隔不能小于1分钟"}), 400

        if action == "start":
            scheduler = get_scheduler()
            if not scheduler or not scheduler.running:
                init_scheduler(app)
            else:
                update_interval(app, minutes)
            return jsonify({"status": "ok", "data": {"running": True, "interval_minutes": minutes}})

        # default: update interval
        update_interval(app, minutes)
        return jsonify({"status": "ok", "data": {"running": True, "interval_minutes": minutes}})

    return app


if __name__ == "__main__":
    setup_logging()
    app = create_app()
    app.run(host="0.0.0.0", port=5000, debug=True)
