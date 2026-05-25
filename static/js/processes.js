(function () {
    var allProcesses = [];
    var PAGE_SIZE = 30;
    var currentPage = 1;

    function loadProcesses() {
        var level = document.getElementById("level-filter").value;
        var keyword = document.getElementById("search-input").value.trim();

        var url = "/api/processes?";
        if (level) url += "level=" + level + "&";
        if (keyword) url += "keyword=" + encodeURIComponent(keyword) + "&";

        fetch(url)
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok") return;
                allProcesses = res.data;
                currentPage = 1;
                renderTable();
                renderPagination();
            });
    }

    function renderTable() {
        var tbody = document.getElementById("process-tbody");
        tbody.innerHTML = "";
        var start = (currentPage - 1) * PAGE_SIZE;
        var page = allProcesses.slice(start, start + PAGE_SIZE);

        if (page.length === 0) {
            tbody.innerHTML = "<tr><td colspan=\"7\" style=\"text-align:center;color:#999\">暂无数据</td></tr>";
            return;
        }

        page.forEach(function (p) {
            var tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + p.pid + "</td>" +
                "<td>" + escapeHtml(p.name) + "</td>" +
                "<td title=\"" + escapeHtml(p.exe_path || "") + "\">" + escapeHtml(truncate(p.exe_path || "-", 45)) + "</td>" +
                "<td>" + escapeHtml(p.username || "-") + "</td>" +
                "<td>" + p.risk_score + "</td>" +
                "<td><span class=\"level-tag " + p.risk_level + "\">" + levelLabel(p.risk_level) + "</span></td>" +
                "<td><a class=\"btn btn-sm btn-primary\" href=\"/detail?pid=" + p.pid + "\">详情</a></td>";
            tbody.appendChild(tr);
        });
    }

    function renderPagination() {
        var total = Math.ceil(allProcesses.length / PAGE_SIZE);
        var container = document.getElementById("pagination");
        container.innerHTML = "";
        if (total <= 1) return;

        for (var i = 1; i <= total; i++) {
            var btn = document.createElement("button");
            btn.textContent = i;
            btn.className = "btn btn-sm" + (i === currentPage ? " btn-primary" : "");
            btn.dataset.page = i;
            btn.addEventListener("click", function () {
                currentPage = parseInt(this.dataset.page);
                renderTable();
                renderPagination();
            });
            container.appendChild(btn);
        }
    }

    document.getElementById("filter-btn").addEventListener("click", loadProcesses);
    document.getElementById("search-input").addEventListener("keydown", function (e) {
        if (e.key === "Enter") loadProcesses();
    });
    document.getElementById("level-filter").addEventListener("change", loadProcesses);

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

    loadProcesses();
})();
