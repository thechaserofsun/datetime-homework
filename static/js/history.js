(function () {
    var trendChart = null;

    loadHistory();
    loadTrend();

    function loadHistory() {
        fetch("/api/history")
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok") return;
                renderTable(res.data);
            });
    }

    function renderTable(records) {
        var tbody = document.getElementById("history-tbody");
        tbody.innerHTML = "";
        if (records.length === 0) {
            tbody.innerHTML = "<tr><td colspan=\"5\" style=\"color:#999;text-align:center\">暂无扫描记录</td></tr>";
            return;
        }
        records.forEach(function (r) {
            var tr = document.createElement("tr");
            var triggerLabel = r.trigger_type === "scheduled" ? "定时巡检" : "手动扫描";
            tr.innerHTML =
                "<td>" + escapeHtml(r.scan_time) + "</td>" +
                "<td>" + r.total_processes + "</td>" +
                "<td>" + r.high_risk_count + "</td>" +
                "<td>" + triggerLabel + "</td>" +
                "<td><a class=\"btn btn-sm btn-primary\" href=\"/processes?scan_id=" + r.id + "\">查看</a></td>";
            tbody.appendChild(tr);
        });
    }

    function loadTrend() {
        fetch("/api/trend")
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok" || !res.data.length) return;
                var labels = res.data.map(function (d) { return d.scan_time.substring(5, 16); });
                var highData = res.data.map(function (d) { return d.high_risk_count; });
                var totalData = res.data.map(function (d) { return d.total_processes; });

                var ctx = document.getElementById("history-trend-chart").getContext("2d");
                if (trendChart) trendChart.destroy();
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
            });
    }

    function escapeHtml(s) {
        var div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
    }
})();
