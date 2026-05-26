// ========== 全局扫描函数（onclick 直接调用，确保可靠） ==========
var _scanRunning = false;

function startScan() {
    if (_scanRunning) return;
    _scanRunning = true;

    var btn = document.getElementById("scan-btn");
    var overlay = document.getElementById("scan-overlay");
    var modalText = document.getElementById("scan-modal-text");
    var modalSub = document.getElementById("scan-modal-sub");

    // 按钮立即反馈
    btn.disabled = true;
    btn.textContent = "扫描中...";
    btn.style.opacity = "0.6";

    // 遮罩层
    if (overlay) {
        overlay.style.display = "flex";
        if (modalText) modalText.textContent = "正在采集进程信息...";
        if (modalSub) modalSub.textContent = "请稍候，采集与评分需要一些时间";
    }

    fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ trigger: "manual" })
    })
    .then(function (r) { return r.json(); })
    .then(function (res) {
        _scanRunning = false;
        btn.disabled = false;
        btn.textContent = "立即扫描";
        btn.style.opacity = "1";

        if (res.status === "ok") {
            if (overlay) {
                if (modalText) modalText.textContent = "扫描完成!";
                if (modalSub) modalSub.textContent = "共 " + res.data.total_processes + " 个进程，高风险 " + res.data.high_risk_count + " 个";
            }
            setTimeout(function () {
                if (overlay) overlay.style.display = "none";
                loadDashboard();
                loadTrend();
            }, 1200);
        } else {
            if (overlay) overlay.style.display = "none";
            alert("扫描失败: " + (res.message || "未知错误"));
        }
    })
    .catch(function (e) {
        _scanRunning = false;
        btn.disabled = false;
        btn.textContent = "立即扫描";
        btn.style.opacity = "1";
        if (overlay) overlay.style.display = "none";
        alert("扫描失败，请检查后端服务\n" + e);
    });
}

// ========== 页面逻辑 ==========
(function () {
    var pieChart = null;
    var trendChart = null;

    window.loadDashboard = function () {
        fetch("/api/processes")
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok") return;
                var procs = res.data;
                var counts = { low: 0, medium: 0, high: 0, critical: 0 };
                procs.forEach(function (p) { counts[p.risk_level]++; });

                document.getElementById("total-count").textContent = procs.length || "0";
                document.getElementById("critical-count").textContent = counts.critical;
                document.getElementById("high-count").textContent = counts.high;
                document.getElementById("medium-count").textContent = counts.medium;
                document.getElementById("low-count").textContent = counts.low;

                if (procs.length === 0) {
                    document.getElementById("total-count").textContent = "--";
                    var tbody = document.querySelector("#top-risk-table tbody");
                    tbody.innerHTML = "<tr><td colspan=\"6\" style=\"text-align:center;color:#999\">暂无扫描数据，请点击立即扫描</td></tr>";
                    return;
                }

                renderPieChart(counts);
                renderTopRiskTable(procs.slice(0, 10));
            })
            .catch(function (e) { console.error("loadDashboard error:", e); });
    };

    function renderPieChart(counts) {
        var el = document.getElementById("pie-chart");
        if (!el) return;
        var ctx = el.getContext("2d");
        if (pieChart) pieChart.destroy();
        if (typeof Chart === "undefined") return;
        pieChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["低风险", "中风险", "高风险", "极高风险"],
                datasets: [{
                    data: [counts.low, counts.medium, counts.high, counts.critical],
                    backgroundColor: ["#4caf50", "#ffc107", "#ff9800", "#f44336"],
                }],
            },
            options: {
                responsive: true,
                plugins: { legend: { position: "bottom" } },
            },
        });
    }

    window.loadTrend = function () {
        fetch("/api/trend")
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok" || !res.data.length) return;
                var labels = res.data.map(function (d) { return d.scan_time.substring(5, 16); });
                var highData = res.data.map(function (d) { return d.high_risk_count; });
                var totalData = res.data.map(function (d) { return d.total_processes; });

                var el = document.getElementById("trend-chart");
                if (!el) return;
                var ctx = el.getContext("2d");
                if (trendChart) trendChart.destroy();
                if (typeof Chart === "undefined") return;
                trendChart = new Chart(ctx, {
                    type: "line",
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: "进程总数",
                                data: totalData,
                                borderColor: "#1976d2",
                                backgroundColor: "rgba(25,118,210,0.1)",
                                fill: true,
                                tension: 0.3,
                            },
                            {
                                label: "高风险数",
                                data: highData,
                                borderColor: "#f44336",
                                backgroundColor: "rgba(244,67,54,0.1)",
                                fill: true,
                                tension: 0.3,
                            },
                        ],
                    },
                    options: {
                        responsive: true,
                        scales: { y: { beginAtZero: true } },
                        plugins: { legend: { position: "bottom" } },
                    },
                });
            })
            .catch(function (e) { console.error("loadTrend error:", e); });
    };

    function renderTopRiskTable(procs) {
        var tbody = document.querySelector("#top-risk-table tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        procs.forEach(function (p) {
            if (p.risk_score === 0) return;
            var tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + p.pid + "</td>" +
                "<td>" + escapeHtml(p.name) + "</td>" +
                "<td title=\"" + escapeHtml(p.exe_path || "") + "\">" + escapeHtml(truncate(p.exe_path || "-", 50)) + "</td>" +
                "<td>" + p.risk_score + "</td>" +
                "<td><span class=\"level-tag " + p.risk_level + "\">" + levelLabel(p.risk_level) + "</span></td>" +
                "<td><a class=\"btn btn-sm btn-primary\" href=\"/detail?pid=" + p.pid + "\">详情</a></td>";
            tbody.appendChild(tr);
        });
    }

    // ========== 巡检状态 ==========
    function loadScheduleStatus() {
        fetch("/api/schedule")
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok") return;
                var d = res.data;
                var badge = document.getElementById("schedule-status");
                if (d.running) {
                    badge.textContent = "巡检: 运行中 (" + d.interval_minutes + "分钟)";
                    badge.className = "schedule-badge schedule-running";
                    document.getElementById("schedule-stop-btn").style.display = "";
                    document.getElementById("schedule-start-btn").style.display = "none";
                } else {
                    badge.textContent = "巡检: 已停止";
                    badge.className = "schedule-badge schedule-stopped";
                    document.getElementById("schedule-stop-btn").style.display = "none";
                    document.getElementById("schedule-start-btn").style.display = "";
                }
                document.getElementById("schedule-interval").value = d.interval_minutes;
            })
            .catch(function (e) { console.error("loadScheduleStatus error:", e); });
    }

    // 更新间隔
    document.getElementById("schedule-update-btn").addEventListener("click", function () {
        var minutes = parseInt(document.getElementById("schedule-interval").value);
        fetch("/api/schedule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interval_minutes: minutes, action: "update" }),
        })
        .then(function (r) { return r.json(); })
        .then(function (res) {
            if (res.status === "ok") {
                alert("巡检间隔已更新为 " + res.data.interval_minutes + " 分钟");
                loadScheduleStatus();
            }
        });
    });

    // 停止巡检
    document.getElementById("schedule-stop-btn").addEventListener("click", function () {
        fetch("/api/schedule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ action: "stop" }),
        })
        .then(function (r) { return r.json(); })
        .then(function () { loadScheduleStatus(); });
    });

    // 启动巡检
    document.getElementById("schedule-start-btn").addEventListener("click", function () {
        var minutes = parseInt(document.getElementById("schedule-interval").value);
        fetch("/api/schedule", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ interval_minutes: minutes, action: "start" }),
        })
        .then(function (r) { return r.json(); })
        .then(function () { loadScheduleStatus(); });
    });

    // 工具函数
    function levelLabel(l) {
        return { low: "低", medium: "中", high: "高", critical: "极高" }[l] || l;
    }
    function escapeHtml(s) {
        var div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
    }
    function truncate(s, n) {
        return s.length > n ? s.substring(0, n) + "..." : s;
    }

    loadDashboard();
    loadTrend();
    loadScheduleStatus();
})();
