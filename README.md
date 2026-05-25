# 可疑进程行为分析与风险评分系统

## 环境要求

- Python 3.9+
- MySQL 8.0+
- Windows 10/11

## 安装步骤

1. 安装 Python 依赖

```bash
pip install -r requirements.txt
```

2. 初始化 MySQL 数据库

```bash
mysql -u root -p < sql/init.sql
```

3. 修改数据库连接配置（如有需要）

编辑 `src/config.py` 中的 MySQL 连接信息，或通过环境变量设置：

```bash
set MYSQL_HOST=127.0.0.1
set MYSQL_PORT=3306
set MYSQL_USER=root
set MYSQL_PASSWORD=your_password
set MYSQL_DATABASE=process_analyzer
```

## 启动

```bash
python src/app.py
```

启动后访问 http://localhost:5000

## 项目结构

```
├── src/              # 后端源码
├── sql/              # 数据库初始化脚本
├── templates/        # 前端 HTML 页面
├── static/           # 静态资源（CSS/JS）
├── logs/             # 运行日志
├── 项目文档/          # 需求与设计文档
└── requirements.txt  # Python 依赖
```
