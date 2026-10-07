/**
 * Centro de Notificaciones de seguridad — consume /api/notifications
 * (sincronizado desde alerts_canonical_service en el backend).
 * No inventa severity/confidence/evidence; usa NOT_AVAILABLE / —.
 */
(function () {
  "use strict";

  var WAIT = "Cargando notificaciones de seguridad…";

  function $(id) {
    return document.getElementById(id);
  }

  function fmt(v) {
    if (v === null || v === undefined || v === "") return "NOT_AVAILABLE";
    return String(v);
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function priorityLabel(p) {
    var x = String(p || "info").toLowerCase();
    if (x === "critical") return "🔴 CRÍTICA";
    if (x === "high") return "🟠 ALTA";
    if (x === "warning") return "🟡 MEDIA";
    return "🔵 INFORMACIÓN";
  }

  var panel = null;
  var currentFilter = "amenazas";

  function ensurePanel() {
    if (panel) return panel;
    panel = document.createElement("div");
    panel.id = "novus-notif-panel";
    panel.className = "novus-notif-panel hidden";
    panel.innerHTML =
      '<div class="novus-notif-head">' +
      "<strong>Notificaciones de seguridad</strong>" +
      '<button type="button" id="novus-notif-close" aria-label="Cerrar">&times;</button></div>' +
      '<div class="novus-notif-filters" id="novus-notif-filters"></div>' +
      '<div class="novus-notif-list" id="novus-notif-list"></div>';
    document.body.appendChild(panel);
    $("novus-notif-close").onclick = close;
    var filters = [
      ["amenazas", "Amenazas"],
      ["seguridad", "Seguridad"],
      ["unread", "No leídas"],
      ["critical", "Críticas"],
      ["high", "Altas"],
      ["red", "Red"],
      ["comportamiento", "Comportamiento"],
      ["all", "Todas"],
      ["sistema", "Sistema"],
    ];
    var box = $("novus-notif-filters");
    filters.forEach(function (f) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "novus-notif-chip" + (f[0] === currentFilter ? " active" : "");
      b.textContent = f[1];
      b.dataset.filter = f[0];
      b.onclick = function () {
        currentFilter = f[0];
        Array.prototype.forEach.call(box.querySelectorAll(".novus-notif-chip"), function (c) {
          c.classList.toggle("active", c.dataset.filter === currentFilter);
        });
        loadList();
      };
      box.appendChild(b);
    });
    return panel;
  }

  function badge(n) {
    var el = $("alert-count");
    var el2 = $("layout-alert-badge");
    var text = typeof n === "number" && n > 0 ? String(n > 99 ? "99+" : n) : "0";
    if (el) {
      el.textContent = text;
      el.classList.remove("hidden");
    }
    if (el2) el2.textContent = text;
  }

  function refreshBadge() {
    fetch("/api/notifications/unread-count?kind=security", { credentials: "same-origin" })
      .then(function (r) {
        return r.json();
      })
      .then(function (d) {
        if (d && typeof d.unread_count === "number") badge(d.unread_count);
      })
      .catch(function () {});
  }

  function payloadFields(n) {
    var p = n.payload || {};
    if (typeof p === "string") {
      try {
        p = JSON.parse(p);
      } catch (e) {
        p = {};
      }
    }
    var evid = p.evidence || p.evidence_summary || p.evidence_items;
    if (Array.isArray(evid)) {
      evid = evid.length ? evid.slice(0, 3).map(function (x) {
        return typeof x === "string" ? x : JSON.stringify(x);
      }).join("; ") : "NOT_AVAILABLE";
    }
    return {
      threat_type: p.threat_type || n.title || "NOT_AVAILABLE",
      severity: p.severity || n.priority || "NOT_AVAILABLE",
      confidence: p.confidence != null && p.confidence !== "" ? p.confidence : "NOT_AVAILABLE",
      timestamp: p.timestamp || ((n.event_date || "") + " " + (n.event_time || "")).trim() || "NOT_AVAILABLE",
      asset: n.related_equipment || p.origin || p.scope || "NOT_AVAILABLE",
      tenant: p.tenant_id || n.tenant_id || "NOT_AVAILABLE",
      event_id: p.event_id || p.alert_id || n.source_ref || "NOT_AVAILABLE",
      status: p.status || n.status || "NOT_AVAILABLE",
      remediation: p.remediation_status || "NOT_AVAILABLE",
      evidence: evid || "NOT_AVAILABLE",
    };
  }

  function renderItem(n) {
    var f = payloadFields(n);
    return (
      '<article class="novus-notif-item" data-id="' +
      esc(n.notification_id) +
      '">' +
      '<div class="novus-notif-meta">' +
      '<span class="pri ' +
      esc(n.priority || "info") +
      '">' +
      esc(priorityLabel(n.priority)) +
      "</span>" +
      "<span>" +
      esc(fmt(n.category)) +
      "</span>" +
      "<span>" +
      esc(fmt(f.timestamp)) +
      "</span>" +
      "<span>" +
      esc(fmt(f.status)) +
      "</span></div>" +
      "<h4>" +
      esc(fmt(f.threat_type)) +
      "</h4>" +
      '<p class="desc">' +
      esc(fmt(n.description)) +
      "</p>" +
      '<ul class="novus-notif-fields text-[10px] text-gray-500" style="margin:0.35rem 0;padding-left:1rem;list-style:disc">' +
      "<li>Severidad: " +
      esc(fmt(f.severity)) +
      "</li>" +
      "<li>Confianza: " +
      esc(fmt(f.confidence)) +
      "</li>" +
      "<li>Activo/IP: " +
      esc(fmt(f.asset)) +
      "</li>" +
      "<li>Tenant: " +
      esc(fmt(f.tenant)) +
      "</li>" +
      "<li>event_id: " +
      esc(fmt(f.event_id)) +
      "</li>" +
      "<li>Evidencia: " +
      esc(fmt(f.evidence)) +
      "</li>" +
      "<li>Remediación: " +
      esc(fmt(f.remediation)) +
      "</li></ul>" +
      '<div class="novus-notif-actions">' +
      (n.detail_url ? '<a href="' + esc(n.detail_url) + '">Ver detalles</a>' : "") +
      (n.incident_url ? '<a href="' + esc(n.incident_url) + '">Ir al incidente</a>' : "") +
      '<button type="button" data-act="read">Marcar leído</button>' +
      '<button type="button" data-act="archive">Archivar</button>' +
      "</div></article>"
    );
  }

  function loadList() {
    ensurePanel();
    var list = $("novus-notif-list");
    list.innerHTML = '<div class="text-gray-500 text-xs p-3">' + WAIT + "</div>";
    var q = "/api/notifications?limit=40&kind=security";
    if (currentFilter === "unread") q += "&status=unread";
    else if (currentFilter === "critical") q += "&priority=critical";
    else if (currentFilter === "high") q += "&priority=high";
    else if (currentFilter === "all") q = "/api/notifications?limit=40";
    else if (currentFilter === "sistema") q = "/api/notifications?limit=40&kind=system&category=sistema";
    else q += "&category=" + encodeURIComponent(currentFilter);
    fetch(q, { credentials: "same-origin" })
      .then(function (r) {
        return r.json();
      })
      .then(function (d) {
        if (typeof d.unread_count === "number") badge(d.unread_count);
        var items = d.notifications || [];
        if (!items.length) {
          list.innerHTML =
            '<div class="text-gray-500 text-xs p-3">Sin notificaciones de seguridad reales para este filtro.</div>';
          return;
        }
        list.innerHTML = items.map(renderItem).join("");
        list.querySelectorAll("[data-act]").forEach(function (btn) {
          btn.addEventListener("click", function () {
            var art = btn.closest(".novus-notif-item");
            var id = art && art.getAttribute("data-id");
            if (!id) return;
            var act = btn.getAttribute("data-act");
            var url =
              "/api/notifications/" +
              encodeURIComponent(id) +
              "/" +
              (act === "archive" ? "archive" : "read");
            fetch(url, { method: "POST", credentials: "same-origin" })
              .then(function () {
                loadList();
                refreshBadge();
              })
              .catch(function () {});
          });
        });
      })
      .catch(function () {
        list.innerHTML =
          '<div class="text-red-400 text-xs p-3">No se pudieron cargar notificaciones.</div>';
      });
  }

  function open() {
    ensurePanel();
    panel.classList.remove("hidden");
    loadList();
  }

  function close() {
    if (panel) panel.classList.add("hidden");
  }

  window.NovusNotificationCenter = { open: open, close: close, refreshBadge: refreshBadge };

  document.addEventListener("DOMContentLoaded", function () {
    var bellWrap = document.getElementById("novus-bell-btn");
    if (bellWrap) {
      bellWrap.onclick = function (e) {
        e.preventDefault();
        e.stopPropagation();
        open();
      };
    }
    var layoutBell = document.getElementById("layout-bell-btn");
    if (layoutBell) {
      layoutBell.onclick = function (e) {
        e.preventDefault();
        open();
      };
    }
    refreshBadge();
    setInterval(refreshBadge, 45000);
  });
})();
