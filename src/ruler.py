import os
from src.models import db, Rule

# 系统关键进程名及合法路径
SYSTEM_PROC_NAMES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe", "services.exe", "wininit.exe", "smss.exe", "dwm.exe", "taskhostw.exe"}

SYSTEM_DIRS = {
    os.path.normcase(p)
    for p in [
        os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
        os.environ.get("SystemRoot", r"C:\Windows") + r"\SysWOW64",
        os.environ.get("SystemRoot", r"C:\Windows") + r"\System",
        os.environ.get("SystemRoot", r"C:\Windows") + "\\",
    ]
}

# 这些进程即使路径在系统目录也可能被误报，直接排除
SKIP_PROCESSES = {"system idle process"}

BROWSER_NAMES = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe"}

HIGH_RISK_PORTS = {4444, 5555, 6666, 6667, 8888, 31337, 1234, 4443, 9999}

# 系统进程的合法子进程白名单
SYSTEM_CHILD_WHITELIST = {
    "svchost.exe": {"svchost.exe", "taskeng.exe", "taskhost.exe", "dllhost.exe", "sihost.exe", "ctfmon.exe"},
    "services.exe": {"svchost.exe", "lsass.exe", "lsm.exe", "mpcmdrun.exe"},
    "lsass.exe": set(),
    "csrss.exe": {"conhost.exe", "csrss.exe"},
    "wininit.exe": {"services.exe", "lsass.exe", "lsm.exe", "wininit.exe"},
    "smss.exe": {"csrss.exe", "wininit.exe", "smss.exe", "autochk.exe"},
}

TEMP_DIR_KEYWORDS = {"\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\"}

CREDENTIAL_PATHS = {"\\sam", "\\system32\\config\\", "\\credentials\\", "\\microsoft\\protect\\", "\\microsoft\\vault\\"}

BROWSER_DATA_PATHS = {"\\google\\chrome\\user data\\", "\\microsoft\\edge\\user data\\", "\\mozilla\\firefox\\profiles\\"}

# 风险等级阈值
RISK_THRESHOLDS = {
    "low": (0, 20),
    "medium": (21, 50),
    "high": (51, 80),
    "critical": (81, 9999),
}


def determine_level(score):
    for level, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "low"


# ========== 规则匹配函数 ==========

def rule_system_name_path_mismatch(proc):
    """进程名模仿系统关键进程但路径不在系统目录"""
    name = proc.get("name", "").lower()
    if name in SKIP_PROCESSES or name not in SYSTEM_PROC_NAMES:
        return None
    exe_path = proc.get("exe_path", "")
    if not exe_path:
        return None
    norm_path = os.path.normcase(exe_path)
    for d in SYSTEM_DIRS:
        if norm_path.startswith(d):
            return None
    return f"进程名 {name} 模仿系统进程，但路径 {exe_path} 不在系统目录"


def rule_non_browser_external_conn(proc):
    """非浏览器进程发起外连"""
    name = proc.get("name", "").lower()
    if name in BROWSER_NAMES:
        return None
    conns = proc.get("connections", [])
    for c in conns:
        if c.get("remote_ip") and c["remote_ip"] not in ("127.0.0.1", "::1", "0.0.0.0") and c.get("status") != "LISTEN":
            return f"非浏览器进程 {name} 发起外连 {c['remote_ip']}:{c['remote_port']}"
    return None


def rule_high_risk_port(proc):
    """连接高风险端口"""
    conns = proc.get("connections", [])
    for c in conns:
        if c.get("remote_port") in HIGH_RISK_PORTS:
            return f"连接高风险端口 {c['remote_port']} ({c.get('remote_ip', 'unknown')})"
    return None


def rule_explorer_spawn_cmd(proc):
    """explorer.exe 直接派生 cmd/powershell"""
    parent_name = proc.get("parent_name", "").lower()
    if parent_name != "explorer.exe":
        return None
    name = proc.get("name", "").lower()
    if name in ("cmd.exe", "powershell.exe", "pwsh.exe"):
        return f"explorer.exe 派生了 {name}"
    return None


def rule_system_unexpected_child(proc):
    """系统关键进程派生非预期子进程"""
    parent_name = proc.get("parent_name", "").lower()
    if parent_name not in SYSTEM_CHILD_WHITELIST:
        return None
    name = proc.get("name", "").lower()
    whitelist = SYSTEM_CHILD_WHITELIST[parent_name]
    if name not in whitelist:
        return f"系统进程 {parent_name} 派生了非预期子进程 {name}"
    return None


def rule_empty_path(proc):
    """进程路径为空"""
    exe_path = proc.get("exe_path", "")
    if not exe_path:
        return "进程可执行路径为空"
    return None


def rule_path_not_exist(proc):
    """进程路径在磁盘上不存在"""
    exe_path = proc.get("exe_path", "")
    if not exe_path:
        return None
    if not os.path.exists(exe_path):
        return f"进程路径 {exe_path} 在磁盘上不存在"
    return None


def rule_temp_dir_execution(proc):
    """从临时目录运行"""
    exe_path = proc.get("exe_path", "")
    if not exe_path:
        return None
    norm = os.path.normcase(exe_path)
    for kw in TEMP_DIR_KEYWORDS:
        if kw in norm:
            return f"进程从临时目录运行: {exe_path}"
    return None


def rule_access_credential_dir(proc):
    """访问用户凭据目录"""
    open_files = proc.get("open_files", [])
    name = proc.get("name", "").lower()
    if name in BROWSER_NAMES:
        return None
    for f in open_files:
        norm = os.path.normcase(f)
        for kw in CREDENTIAL_PATHS:
            if kw in norm:
                return f"访问凭据相关路径: {f}"
    return None


def rule_access_browser_data(proc):
    """非浏览器进程访问浏览器数据目录"""
    open_files = proc.get("open_files", [])
    name = proc.get("name", "").lower()
    if name in BROWSER_NAMES:
        return None
    for f in open_files:
        norm = os.path.normcase(f)
        for kw in BROWSER_DATA_PATHS:
            if kw in norm:
                return f"访问浏览器数据: {f}"
    return None


def rule_high_cpu(proc):
    """长期高CPU占用"""
    name = proc.get("name", "").lower()
    if name in SKIP_PROCESSES:
        return None
    cpu = proc.get("cpu_percent", 0)
    if cpu > 80:
        return f"CPU 占用 {cpu:.1f}%"
    return None


def rule_high_memory(proc):
    """高内存占用"""
    rss = proc.get("rss", 0)
    name = proc.get("name", "").lower()
    LARGE_APP_WHITELIST = {"chrome.exe", "msedge.exe", "firefox.exe", "code.exe", "idea64.exe", "javaw.exe", "devenv.exe", "clion64.exe", "pycharm64.exe"}
    if name in LARGE_APP_WHITELIST:
        return None
    if rss > 500 * 1024 * 1024:  # 500MB
        return f"内存占用 {rss / 1024 / 1024:.0f}MB"
    return None


# 规则 ID → 匹配函数 映射
RULE_FUNCTIONS = {
    1: rule_system_name_path_mismatch,
    2: rule_non_browser_external_conn,
    3: rule_high_risk_port,
    4: rule_explorer_spawn_cmd,
    5: rule_system_unexpected_child,
    6: rule_empty_path,
    7: rule_path_not_exist,
    8: rule_temp_dir_execution,
    9: rule_access_credential_dir,
    10: rule_access_browser_data,
    11: rule_high_cpu,
    12: rule_high_memory,
}


def evaluate(proc_data, rules=None):
    """对单个进程执行规则匹配，返回命中列表和总分"""
    if rules is None:
        rules = Rule.query.filter_by(enabled=True).all()

    # 跳过系统空闲进程等无需评估的进程
    name = proc_data.get("name", "").lower()
    if name in SKIP_PROCESSES:
        return [], 0, "low"

    hits = []
    total_score = 0

    for rule in rules:
        func = RULE_FUNCTIONS.get(rule.id)
        if not func:
            continue
        detail = func(proc_data)
        if detail:
            weighted_score = int(rule.score * rule.weight)
            total_score += weighted_score
            hits.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "rule_category": rule.category,
                "rule_score": rule.score,
                "rule_weight": rule.weight,
                "weighted_score": weighted_score,
                "detail": detail,
            })

    return hits, total_score, determine_level(total_score)


# 预防措施建议（按规则类别）
PREVENTION_ADVICE = {
    "伪装检测": "1. 启用 Windows 系统文件签名验证（sigcheck），定期校验系统进程路径合法性；2. 使用应用白名单策略（AppLocker/WDAC），仅允许合法路径执行系统关键进程；3. 部署 EDR 产品监控进程路径与名称的异常匹配",
    "网络异常": "1. 配置主机防火墙出站规则，默认拒绝非必要外连；2. 部署网络流量监控（IDS/IPS），检测异常外连与C2通信；3. 对非浏览器进程的网络行为进行严格审计，启用DNS查询日志",
    "进程关系异常": "1. 监控系统关键进程的子进程派生行为，建立基线白名单；2. 禁用不必要的命令行工具（如通过软件限制策略限制 cmd/powershell 执行）；3. 启用进程创建审计（Event ID 4688），配置命令行日志记录",
    "路径异常": "1. 限制临时目录的执行权限，禁止从 Temp/Downloads 目录启动可执行文件；2. 定期扫描系统中路径不存在或路径为空的可疑进程；3. 启用 Windows AMFI（强制完整性级别），防止内存驻留恶意软件",
    "文件访问异常": "1. 限制非授权进程对凭据存储目录和浏览器数据目录的访问（NTFS ACL）；2. 启用文件系统审计（File System Audit），记录对敏感路径的访问行为；3. 使用 Credential Guard 保护 Windows 凭据，防止凭据窃取",
    "资源异常": "1. 设置进程资源配额（Job Object），限制单进程 CPU/内存上限；2. 部署挖矿检测规则，监控长时高资源占用的非白名单进程；3. 定期审查后台服务进程列表，清理不必要的常驻程序",
}
