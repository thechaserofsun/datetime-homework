import os
from urllib.parse import quote_plus


class Config:
    # MySQL 连接配置
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "127.0.0.1")
    MYSQL_PORT = int(os.environ.get("MYSQL_PORT", 3306))
    MYSQL_USER = os.environ.get("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "935167Lbj@")
    MYSQL_DATABASE = os.environ.get("MYSQL_DATABASE", "process_analyzer")

    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{MYSQL_USER}:{quote_plus(MYSQL_PASSWORD)}"
        f"@{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DATABASE}?charset=utf8mb4"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 风险等级阈值
    RISK_LEVEL_THRESHOLDS = {
        "low": (0, 20),
        "medium": (21, 50),
        "high": (51, 80),
        "critical": (81, 9999),
    }

    # 默认定时巡检间隔（分钟）
    DEFAULT_SCAN_INTERVAL = 30

    # 日志目录
    LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
