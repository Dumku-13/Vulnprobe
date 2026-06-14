/* notifications.js — VulnProbe in-app notification bell.
 *
 * Drop a container `<span id="notif-bell"></span>` into any nav and include
 * this script. It renders a bell + unread badge, polls /api/notifications
 * every 30s, and shows a dropdown of recent notifications.
 */
(function () {
  "use strict";

  var mount = document.getElementById("notif-bell");
  if (!mount) return;

  // ── Styles (injected once) ────────────────────────────────────────────────
  var css = "" +
    "#notif-bell{position:relative;display:inline-block}" +
    ".notif-trigger{cursor:pointer;background:transparent;border:1px solid var(--border,rgba(0,255,136,.15));" +
      "color:var(--muted,#8b949e);font-size:14px;padding:8px 12px;border-radius:6px;transition:all .2s;font-family:inherit}" +
    ".notif-trigger:hover{color:var(--accent,#00ff88);border-color:var(--accent,#00ff88)}" +
    ".notif-badge{position:absolute;top:-6px;right:-6px;min-width:16px;height:16px;padding:0 4px;border-radius:8px;" +
      "background:#f85149;color:#fff;font-size:10px;font-weight:700;line-height:16px;text-align:center;display:none}" +
    ".notif-panel{position:absolute;right:0;top:120%;width:320px;max-height:380px;overflow-y:auto;z-index:50;" +
      "background:#161b22;border:1px solid var(--border,rgba(0,255,136,.15));border-radius:8px;" +
      "box-shadow:0 8px 30px rgba(0,0,0,.5);display:none;font-family:'Courier New',monospace}" +
    ".notif-panel.open{display:block}" +
    ".notif-head{display:flex;justify-content:space-between;align-items:center;padding:10px 12px;" +
      "border-bottom:1px solid var(--border,rgba(0,255,136,.15))}" +
    ".notif-head span{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted,#8b949e)}" +
    ".notif-readall{cursor:pointer;background:none;border:none;color:var(--accent,#00ff88);font-size:10px;font-family:inherit}" +
    ".notif-readall:hover{text-decoration:underline}" +
    ".notif-item{display:block;padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.04);" +
      "color:#c9d1d9;font-size:12px;text-decoration:none;line-height:1.4;cursor:pointer}" +
    ".notif-item:hover{background:rgba(0,255,136,.05)}" +
    ".notif-item.unread{border-left:3px solid var(--accent,#00ff88)}" +
    ".notif-item .t{color:#6e7681;font-size:10px;margin-top:4px;display:block}" +
    ".notif-empty{padding:24px 12px;text-align:center;color:#6e7681;font-size:12px}";
  var style = document.createElement("style");
  style.textContent = css;
  document.head.appendChild(style);

  // ── Markup ────────────────────────────────────────────────────────────────
  mount.innerHTML =
    '<button class="notif-trigger" type="button" aria-label="Notifications">🔔' +
    '<span class="notif-badge"></span></button>' +
    '<div class="notif-panel">' +
      '<div class="notif-head"><span>Notifications</span>' +
      '<button class="notif-readall" type="button">Mark all read</button></div>' +
      '<div class="notif-list"></div></div>';

  var trigger = mount.querySelector(".notif-trigger");
  var badge = mount.querySelector(".notif-badge");
  var panel = mount.querySelector(".notif-panel");
  var list = mount.querySelector(".notif-list");
  var readAllBtn = mount.querySelector(".notif-readall");

  function fmtTime(iso) {
    if (!iso) return "";
    return String(iso).replace("T", " ").slice(0, 16) + " UTC";
  }

  function render(data) {
    var n = (data && data.unread_count) || 0;
    badge.textContent = n > 99 ? "99+" : n;
    badge.style.display = n > 0 ? "block" : "none";

    var items = (data && data.notifications) || [];
    if (!items.length) {
      list.innerHTML = '<div class="notif-empty">No notifications yet.</div>';
      return;
    }
    list.innerHTML = items.map(function (it) {
      var cls = "notif-item" + (it.read ? "" : " unread");
      return '<a class="' + cls + '" data-id="' + it.id + '" data-link="' +
        (it.link || "") + '">' + escapeHtml(it.message) +
        '<span class="t">' + fmtTime(it.created_at) + "</span></a>";
    }).join("");

    Array.prototype.forEach.call(list.querySelectorAll(".notif-item"), function (el) {
      el.addEventListener("click", function (e) {
        e.preventDefault();
        var id = el.getAttribute("data-id");
        var link = el.getAttribute("data-link");
        fetch("/api/notifications/" + id + "/read", { method: "POST", credentials: "include" })
          .finally(function () {
            if (link) window.location = link; else refresh();
          });
      });
    });
  }

  function escapeHtml(s) {
    var d = document.createElement("div");
    d.textContent = s == null ? "" : s;
    return d.innerHTML;
  }

  function refresh() {
    fetch("/api/notifications", { credentials: "include" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { if (data) render(data); })
      .catch(function () { /* ignore transient errors */ });
  }

  trigger.addEventListener("click", function (e) {
    e.stopPropagation();
    panel.classList.toggle("open");
    if (panel.classList.contains("open")) refresh();
  });

  document.addEventListener("click", function (e) {
    if (!mount.contains(e.target)) panel.classList.remove("open");
  });

  readAllBtn.addEventListener("click", function (e) {
    e.stopPropagation();
    fetch("/api/notifications/read-all", { method: "POST", credentials: "include" })
      .finally(refresh);
  });

  refresh();
  setInterval(refresh, 30000);
})();
