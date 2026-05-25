-- ============================================
-- 可疑进程行为分析与风险评分系统 - 数据库初始化
-- ============================================

CREATE DATABASE IF NOT EXISTS process_analyzer
    DEFAULT CHARACTER SET utf8mb4
    DEFAULT COLLATE utf8mb4_unicode_ci;

USE process_analyzer;

SET NAMES utf8mb4;

-- 扫描记录表
CREATE TABLE IF NOT EXISTS scan_record (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    scan_time       DATETIME NOT NULL,
    total_processes INT NOT NULL DEFAULT 0,
    high_risk_count INT NOT NULL DEFAULT 0,
    trigger_type    ENUM('manual', 'scheduled') NOT NULL DEFAULT 'manual'
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 进程快照表
CREATE TABLE IF NOT EXISTS process_snapshot (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    scan_id     INT NOT NULL,
    pid         INT NOT NULL,
    name        VARCHAR(100) NOT NULL,
    exe_path    TEXT,
    cmdline     TEXT,
    username    VARCHAR(50),
    parent_pid  INT,
    risk_score  INT NOT NULL DEFAULT 0,
    risk_level  ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'low',
    FOREIGN KEY (scan_id) REFERENCES scan_record(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 规则表（需在 rule_hit 之前创建，因为外键引用）
CREATE TABLE IF NOT EXISTS rule (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    category    VARCHAR(50) NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description TEXT,
    weight      FLOAT NOT NULL DEFAULT 1.0,
    score       INT NOT NULL DEFAULT 10,
    is_builtin  BOOLEAN NOT NULL DEFAULT TRUE,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 规则命中表
CREATE TABLE IF NOT EXISTS rule_hit (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    snapshot_id INT NOT NULL,
    rule_id     INT NOT NULL,
    detail      TEXT,
    FOREIGN KEY (snapshot_id) REFERENCES process_snapshot(id) ON DELETE CASCADE,
    FOREIGN KEY (rule_id) REFERENCES rule(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================
-- 内置规则数据
-- ============================================

INSERT INTO rule (category, name, description, weight, score, is_builtin, enabled) VALUES
-- 伪装检测
('伪装检测', '系统进程名路径不匹配',
 '进程名模仿系统关键进程（svchost、lsass、csrss、winlogon、explorer）但可执行路径不在系统目录',
 1.5, 30, TRUE, TRUE),

-- 网络异常
('网络异常', '非浏览器进程发起外连',
 '排除已知浏览器（chrome、msedge、firefox、iexplore）外的进程建立了 TCP 外部连接',
 1.2, 20, TRUE, TRUE),

('网络异常', '连接高风险端口',
 '进程连接到已知恶意/敏感端口（4444、5555、6666、6667、8888 等）',
 1.5, 25, TRUE, TRUE),

-- 进程关系异常
('进程关系异常', 'explorer派生命令行进程',
 'explorer.exe 直接派生 cmd.exe 或 powershell.exe，可能为恶意脚本执行',
 1.3, 25, TRUE, TRUE),

('进程关系异常', '系统进程派生非预期子进程',
 '系统关键进程（svchost、lsass、csrss、services）派生了不属于其常规子进程列表的进程',
 1.5, 25, TRUE, TRUE),

-- 路径异常
('路径异常', '进程路径为空',
 '进程的可执行路径无法获取，可能为内核级或受保护进程，也可能为伪装',
 1.0, 15, TRUE, TRUE),

('路径异常', '进程路径不存在',
 '进程声称的可执行路径在磁盘上不存在，常见于内存驻留恶意软件',
 1.3, 20, TRUE, TRUE),

('路径异常', '从临时目录运行',
 '进程从临时目录（Temp、tmp、Downloads）运行，常见于恶意软件投递',
 1.2, 15, TRUE, TRUE),

-- 文件访问异常
('文件访问异常', '访问用户凭据目录',
 '进程访问 Windows 凭据存储目录或 SAM 数据库相关路径',
 1.5, 25, TRUE, TRUE),

('文件访问异常', '访问浏览器数据目录',
 '非浏览器进程访问浏览器用户数据目录（Cookie、密码、历史记录）',
 1.2, 20, TRUE, TRUE),

-- 资源异常
('资源异常', '长期高CPU占用',
 '进程 CPU 占用率持续超过 80%',
 0.8, 10, TRUE, TRUE),

('资源异常', '高内存占用',
 '进程内存占用（RSS）超过 500MB 且不属于已知大型应用',
 0.8, 10, TRUE, TRUE);
