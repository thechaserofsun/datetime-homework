import os
import logging
import psutil

logger = logging.getLogger(__name__)

# 系统目录路径，用于伪装检测
SYSTEM_DIRS = {
    os.path.normcase(p)
    for p in [
        os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
        os.environ.get("SystemRoot", r"C:\Windows") + r"\SysWOW64",
        os.environ.get("SystemRoot", r"C:\Windows") + r"\System",
    ]
}


def _safe_call(func, default=None):
    try:
        return func()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
        return default
    except Exception:
        return default


def _get_connections(proc):
    conns = _safe_call(lambda: proc.connections())
    if not conns:
        return []
    result = []
    for c in conns:
        if c.status == "LISTEN" or c.raddr:
            result.append({
                "local_ip": c.laddr.ip if c.laddr else "",
                "local_port": c.laddr.port if c.laddr else 0,
                "remote_ip": c.raddr.ip if c.raddr else "",
                "remote_port": c.raddr.port if c.raddr else 0,
                "status": c.status,
                "family": "TCP" if c.family == 2 else "TCP6" if c.family == 10 else str(c.family),
            })
    return result


def _get_memory_maps(proc):
    maps = _safe_call(lambda: proc.memory_maps())
    if not maps:
        return []
    return [m.path for m in maps if m.path and m.path.lower().endswith(".dll")]


def _get_open_files(proc):
    files = _safe_call(lambda: proc.open_files())
    if not files:
        return []
    return [f.path for f in files]


def scan_single_process(pid):
    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        logger.warning(f"无法访问进程 PID={pid}")
        return None

    exe_path = _safe_call(lambda: proc.exe()) or ""
    name = _safe_call(lambda: proc.name()) or ""
    cmdline = _safe_call(lambda: proc.cmdline())
    cmdline_str = " ".join(cmdline) if cmdline else ""
    username = _safe_call(lambda: proc.username()) or ""
    parent = _safe_call(lambda: proc.parent())
    parent_pid = parent.pid if parent else None
    parent_name = parent.name() if parent else ""

    children = _safe_call(lambda: proc.children(recursive=False))
    children_list = [{"pid": c.pid, "name": _safe_call(lambda: c.name()) or ""} for c in (children or [])]

    cpu_percent = _safe_call(lambda: proc.cpu_percent(interval=0.1)) or 0.0
    memory_info = _safe_call(lambda: proc.memory_info())
    rss = memory_info.rss if memory_info else 0

    connections = _get_connections(proc)
    dll_list = _get_memory_maps(proc)
    open_files = _get_open_files(proc)

    return {
        "pid": pid,
        "name": name,
        "exe_path": exe_path,
        "cmdline": cmdline_str,
        "username": username,
        "parent_pid": parent_pid,
        "parent_name": parent_name,
        "children": children_list,
        "cpu_percent": cpu_percent,
        "rss": rss,
        "connections": connections,
        "dll_list": dll_list,
        "open_files": open_files,
    }


def scan_all_processes():
    processes = []
    for proc in psutil.process_iter():
        pid = proc.pid
        data = scan_single_process(pid)
        if data:
            processes.append(data)
    logger.info(f"扫描完成，共采集 {len(processes)} 个进程")
    return processes
