(function () {
    loadRules();

    function loadRules() {
        fetch("/api/rules")
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status !== "ok") return;
                renderRules(res.data);
            });
    }

    function renderRules(rules) {
        var tbody = document.getElementById("rules-tbody");
        tbody.innerHTML = "";
        rules.forEach(function (r) {
            var tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + r.id + "</td>" +
                "<td>" + escapeHtml(r.category) + "</td>" +
                "<td>" + escapeHtml(r.name) + "</td>" +
                "<td title=\"" + escapeHtml(r.description || "") + "\">" + escapeHtml(truncate(r.description || "-", 40)) + "</td>" +
                "<td>" + r.weight + "</td>" +
                "<td>" + r.score + "</td>" +
                "<td>" + (r.is_builtin ? "内置" : "自定义") + "</td>" +
                "<td><span class=\"level-tag " + (r.enabled ? "low" : "") + "\">" + (r.enabled ? "启用" : "禁用") + "</span></td>";
            tbody.appendChild(tr);
        });
    }

    document.getElementById("add-rule-form").addEventListener("submit", function (e) {
        e.preventDefault();
        var form = e.target;
        var data = {
            category: form.category.value,
            name: form.name.value,
            description: form.description.value,
            weight: parseFloat(form.weight.value),
            score: parseInt(form.score.value),
        };

        fetch("/api/rules", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        })
            .then(function (r) { return r.json(); })
            .then(function (res) {
                if (res.status === "ok") {
                    alert("规则添加成功");
                    form.reset();
                    loadRules();
                } else {
                    alert("添加失败: " + (res.message || ""));
                }
            });
    });

    function escapeHtml(s) {
        var div = document.createElement("div");
        div.textContent = s;
        return div.innerHTML;
    }

    function truncate(s, n) {
        return s.length > n ? s.substring(0, n) + "..." : s;
    }
})();
