(function () {
    var params = new URLSearchParams(window.location.search);
    var pid = params.get("pid");

    if (!pid) {
        document.querySelector(".content").innerHTML = "<h1>未指定进程 PID</h1>";
        return;
    }

    loadDetail(pid);

    function loadDetail(pid) {
        fetch("/api/process/" + pid)
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok") {
                    document.querySelector(".content").innerHTML = "<h1>进程不存在</h1><p>" + escapeHtml(res.message || "") + "</p>";
                    return;
                }
                renderAll(res.data);
            });
    }

    function renderAll(data) {
        document.title = data.name + " (PID " + data.pid + ") - 进程详情";
        renderInfo(data);
        renderTree(data);
        renderConnections(data);
        renderDlls(data);
        renderFiles(data);
        renderRuleHits(data);
        renderRiskReport(data);
        renderPrevention(data);
    }

    function renderInfo(d) {
        var live = d.live || {};
        if (!d.risk_score && d.risk_score !== 0) d.risk_score = 0;
        if (!d.risk_level) d.risk_level = "low";
        var grid = document.getElementById("info-grid");
        var items = [
            ["PID", d.pid],
            ["进程名", d.name],
            ["路径", d.exe_path || "无"],
            ["命令行", d.cmdline || "无"],
            ["用户", d.username || "无"],
            ["父进程", (d.parent_pid || "无") + (live.parent_name ? " (" + live.parent_name + ")" : "")],
            ["风险分值", d.risk_score],
            ["风险等级", d.risk_level],
            ["CPU", (live.cpu_percent || 0).toFixed(1) + "%"],
            ["内存", formatMem(live.rss || 0)],
        ];

        grid.innerHTML = items.map(function (it) {
            var val = it[1];
            if (it[0] === "风险等级") {
                val = "<span class=\"level-tag " + val + "\">" + levelLabel(val) + "</span>";
            }
            return "<div class=\"info-item\"><span class=\"info-label\">" + it[0] + "</span><span class=\"info-value\">" + escapeHtml(String(val)) + "</span></div>";
        }).join("");
    }

    function renderTree(d) {
        var live = d.live || {};
        var container = document.getElementById("process-tree");
        var html = "";
        if (d.parent_pid) {
            html += "<div class=\"tree-node tree-parent\">&#9654; 父进程: PID=" + d.parent_pid + " " + escapeHtml(live.parent_name || "") + "</div>";
        }
        html += "<div class=\"tree-node tree-current\">&#9658; 当前进程: PID=" + d.pid + " " + escapeHtml(d.name) + "</div>";
        if (live.children && live.children.length) {
            live.children.forEach(function (c) {
                html += "<div class=\"tree-node tree-child\">&#9655; 子进程: PID=" + c.pid + " " + escapeHtml(c.name || "") + "</div>";
            });
        }
        container.innerHTML = html;
    }

    function renderConnections(d) {
        var live = d.live || {};
        var conns = live.connections || [];
        var tbody = document.querySelector("#conn-table tbody");
        tbody.innerHTML = "";
        if (conns.length === 0) {
            tbody.innerHTML = "<tr><td colspan=\"3\" style=\"color:#999\">无网络连接</td></tr>";
            return;
        }
        conns.forEach(function (c) {
            var tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + escapeHtml(c.remote_ip || "-") + "</td>" +
                "<td>" + (c.remote_port || "-") + "</td>" +
                "<td>" + escapeHtml(c.status || "-") + "</td>";
            tbody.appendChild(tr);
        });
    }

    function renderDlls(d) {
        var live = d.live || {};
        var dlls = live.dll_list || [];
        var ul = document.getElementById("dll-list");
        ul.innerHTML = "";
        if (dlls.length === 0) {
            ul.innerHTML = "<li style=\"color:#999\">无DLL信息</li>";
            return;
        }
        dlls.slice(0, 50).forEach(function (dll) {
            var li = document.createElement("li");
            li.textContent = dll;
            li.title = dll;
            ul.appendChild(li);
        });
        if (dlls.length > 50) {
            var li = document.createElement("li");
            li.style.color = "#999";
            li.textContent = "... 共 " + dlls.length + " 个DLL";
            ul.appendChild(li);
        }
    }

    function renderFiles(d) {
        var live = d.live || {};
        var files = live.open_files || [];
        var ul = document.getElementById("file-list");
        ul.innerHTML = "";
        if (files.length === 0) {
            ul.innerHTML = "<li style=\"color:#999\">无打开文件</li>";
            return;
        }
        files.slice(0, 50).forEach(function (f) {
            var li = document.createElement("li");
            li.textContent = f;
            li.title = f;
            ul.appendChild(li);
        });
    }

    function renderRuleHits(d) {
        var hits = d.hits || [];
        var tbody = document.querySelector("#rule-hit-table tbody");
        tbody.innerHTML = "";
        if (hits.length === 0) {
            tbody.innerHTML = "<tr><td colspan=\"4\" style=\"color:#999\">未命中任何规则</td></tr>";
            return;
        }
        hits.forEach(function (h) {
            var tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + escapeHtml(h.rule_category || "") + "</td>" +
                "<td>" + escapeHtml(h.rule_name || "") + "</td>" +
                "<td>" + (h.weighted_score || "-") + "</td>" +
                "<td>" + escapeHtml(h.detail || "") + "</td>";
            tbody.appendChild(tr);
        });
    }

    function renderRiskReport(d) {
        var hits = d.hits || [];
        if (hits.length === 0) {
            document.getElementById("risk-report-section").style.display = "none";
            return;
        }
        document.getElementById("risk-report-section").style.display = "";
        var container = document.getElementById("risk-report");

        // 1. 风险对象
        var categories = {};
        hits.forEach(function (h) { categories[h.rule_category] = true; });
        var catStr = Object.keys(categories).join("、");

        // 2. 触发条件
        var triggerHtml = hits.map(function (h) {
            return "<li><strong>" + escapeHtml(h.rule_name) + "</strong>: " + escapeHtml(h.detail) + "</li>";
        }).join("");

        // 3. 风险证据
        var evidenceHtml = hits.map(function (h) {
            return "<li>[" + escapeHtml(h.rule_category) + "] " + escapeHtml(h.detail) + " (加权分值: " + h.weighted_score + ")</li>";
        }).join("");

        // 4. 影响分析
        var impactMap = {
            "伪装检测": "攻击者可能通过伪装系统进程绕过安全检测，实现持久化驻留",
            "网络异常": "恶意软件可能正在与C2服务器通信，泄露敏感数据或接收指令",
            "进程关系异常": "攻击者可能利用合法进程派生恶意子进程，实现权限提升或横向移动",
            "路径异常": "恶意软件可能通过异常路径运行，规避安全检测",
            "文件访问异常": "恶意软件可能正在窃取用户凭据或浏览器敏感数据",
            "资源异常": "异常资源占用可能是挖矿程序或DoS攻击的表现",
        };
        var impactHtml = Object.keys(categories).map(function (c) {
            return "<li>" + escapeHtml(c) + ": " + (impactMap[c] || "存在潜在安全风险") + "</li>";
        }).join("");

        // 5. 展示结论
        var levelDesc = { low: "低风险", medium: "中风险", high: "高风险", critical: "极高风险" };

        container.innerHTML =
            "<div class=\"risk-report-item\"><div class=\"risk-report-label\">1. 风险对象</div><div class=\"risk-report-value\">进程 " + escapeHtml(d.name) + " (PID=" + d.pid + ")，风险类别: " + escapeHtml(catStr) + "</div></div>" +
            "<div class=\"risk-report-item\"><div class=\"risk-report-label\">2. 触发条件</div><div class=\"risk-report-value\"><ul>" + triggerHtml + "</ul></div></div>" +
            "<div class=\"risk-report-item\"><div class=\"risk-report-label\">3. 风险证据</div><div class=\"risk-report-value\"><ul>" + evidenceHtml + "</ul></div></div>" +
            "<div class=\"risk-report-item\"><div class=\"risk-report-label\">4. 影响分析</div><div class=\"risk-report-value\"><ul>" + impactHtml + "</ul></div></div>" +
            "<div class=\"risk-report-item\"><div class=\"risk-report-label\">5. 展示结论</div><div class=\"risk-report-value\">该进程风险分值为 <strong>" + d.risk_score + "</strong>，判定为 <span class=\"level-tag " + d.risk_level + "\">" + (levelDesc[d.risk_level] || d.risk_level) + "</span>，共命中 " + hits.length + " 条规则</div></div>";
    }

    function renderPrevention(d) {
        var preventions = d.prevention || [];
        if (preventions.length === 0) {
            document.getElementById("prevention-section").style.display = "none";
            return;
        }
        document.getElementById("prevention-section").style.display = "";
        var container = document.getElementById("prevention-content");
        container.innerHTML = preventions.map(function (p) {
            return "<div class=\"prevention-item\">" + escapeHtml(p) + "</div>";
        }).join("");
    }

    function levelLabel(l) {
        return { low: "低", medium: "中", high: "高", critical: "极高" }[l] || l;
    }

    function formatMem(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1024 / 1024).toFixed(1) + " MB";
    }

    function escapeHtml(s) {
        var div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
    }
})();
