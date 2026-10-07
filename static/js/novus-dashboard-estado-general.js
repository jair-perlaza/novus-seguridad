/**
 * Estado de Protección / Amenazas — consume /api/security/summary (+ alerts).
 * Reemplaza el panel que esperaba SSE de escaneo continuo sin resolver.
 * No inventa amenazas ni porcentajes. No usa CPU/RAM/tráfico aquí.
 */
(function () {
  "use strict";

  var panel = document.getElementById("novus-estado-general-panel");
  if (!panel) return;

  var headline = document.getElementById("novus-eg-headline");
  var waitEl = document.getElementById("novus-eg-waiting");
  var errEl = document.getElementById("novus-eg-error");
  var bodyEl = document.getElementById("novus-eg-security-body");
  var threatList = document.getElementById("novus-eg-threat-list");
  var metaEl = document.getElementById("novus-eg-meta");
  var badgeEl = document.getElementById("novus-eg-status-badge");
  var lastPayload = null;
  var pollTimer = null;
  var POLL_MS = 30000;

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function na(v) {
    if (v === null || v === undefined || v === "") return "NOT_AVAILABLE";
    return String(v);
  }

  function riskRank(r) {
    var s = String(r || "").toUpperCase();
    if (s.indexOf("CRIT") >= 0) return 4;
    if (s.indexOf("HIGH") >= 0 || s.indexOf("ALTA") >= 0) return 3;
    if (s.indexOf("MED") >= 0 || s.indexOf("WARN") >= 0) return 2;
    if (s.indexOf("LOW") >= 0) return 1;
    return 0;
  }

  function setBadge(mode, label) {
    if (!badgeEl) return;
    badgeEl.textContent = label;
    badgeEl.className =
      "novus-eg-status-badge " +
      (mode === "ok"
        ? "ok"
        : mode === "warn"
          ? "warn"
          : mode === "crit"
            ? "crit"
            : mode === "na"
              ? "na"
              : "idle");
  }

  function renderUnavailable(reason) {
    if (waitEl) {
      waitEl.classList.remove("hidden");
      waitEl.textContent = reason || "DATOS NO DISPONIBLES";
    }
    if (headline) headline.textContent = "DATOS NO DISPONIBLES";
    setBadge("na", "NO DISPONIBLE");
    if (threatList) threatList.innerHTML = "";
    if (bodyEl) {
      bodyEl.innerHTML =
        '<p class="text-[11px] text-gray-500">Sin evidencia de seguridad suficiente para declarar protección activa ni amenazas.</p>';
    }
  }

  function mapEngineRuntime(state) {
    var s = String(state || "").toLowerCase();
    if (s === "activo" || s === "active") return "ACTIVE";
    if (s === "analizando" || s === "analyzing") return "ACTIVE";
    if (s === "requiere_atencion" || s === "attention") return "DEGRADED";
    if (s === "inactivo" || s === "idle") return "IDLE";
    if (s === "no_disponible" || s === "unavailable") return "NOT_CONFIGURED";
    if (s === "error") return "ERROR";
    return "NOT_VERIFIABLE";
  }

  function engineStats(engines) {
    var stats = {
      ACTIVE: 0,
      DEGRADED: 0,
      IDLE: 0,
      NOT_CONFIGURED: 0,
      NOT_VERIFIABLE: 0,
      ERROR: 0,
      DISABLED_BY_POLICY: 0,
      total: 0,
      last_activity: "NOT_AVAILABLE",
    };
    (engines || []).forEach(function (e) {
      stats.total += 1;
      var rt = mapEngineRuntime(e && e.state);
      stats[rt] = (stats[rt] || 0) + 1;
    });
    return stats;
  }

  function renderEngineLine(stats) {
    if (!stats || !stats.total) {
      return '<p class="text-[10px] text-gray-500">Motores: DATOS NO DISPONIBLES</p>';
    }
    return (
      '<p class="text-[10px] text-gray-400 mt-2">' +
      "Motores ACTIVE: " +
      stats.ACTIVE +
      " · IDLE: " +
      stats.IDLE +
      " · NOT_CONFIGURED: " +
      stats.NOT_CONFIGURED +
      " · DEGRADED: " +
      stats.DEGRADED +
      "</p>"
    );
  }

  function renderProtected(summary, engines) {
    if (waitEl) waitEl.classList.add("hidden");
    if (headline) headline.textContent = "PROTECCIÓN ACTIVA";
    setBadge("ok", "PROTECCIÓN ACTIVA");
    var stats = engineStats(engines);
    var threatLine;
    if (typeof summary.total_threats === "number") {
      threatLine = "Amenazas confirmadas: " + summary.total_threats;
    } else {
      threatLine = "Amenazas confirmadas: DATOS NO DISPONIBLES (sin análisis válido)";
    }
    if (bodyEl) {
      bodyEl.innerHTML =
        '<p class="text-[11px] text-emerald-300/90 font-medium">Sin amenazas confirmadas en fuente canónica</p>' +
        '<p class="text-[10px] text-gray-500 mt-1">' +
        threatLine +
        "</p>" +
        renderEngineLine(stats) +
        '<p class="text-[10px] text-gray-500 mt-1">No implica ausencia absoluta de malware.</p>';
    }
    if (threatList) threatList.innerHTML = "";
    if (metaEl) {
      metaEl.textContent =
        "Fuente: " +
        esc(summary.source || "security_summary") +
        " · " +
        esc(summary.observed_at || summary.timestamp || "NOT_AVAILABLE");
    }
  }

  function renderInvestigate(alerts, summary) {
    if (waitEl) waitEl.classList.add("hidden");
    if (headline) headline.textContent = "AMENAZA EN INVESTIGACIÓN";
    setBadge("warn", "INVESTIGACIÓN");
    if (bodyEl) {
      bodyEl.innerHTML =
        '<p class="text-[11px] text-amber-300">Actividad sospechosa / pendiente de revisión</p>';
    }
    renderThreatRows(alerts);
    if (metaEl) {
      metaEl.textContent =
        "Alertas: " +
        alerts.length +
        " · " +
        esc(summary.observed_at || summary.timestamp || "NOT_AVAILABLE");
    }
  }

  function renderThreat(alerts, summary) {
    if (waitEl) waitEl.classList.add("hidden");
    if (headline) headline.textContent = "AMENAZA DETECTADA";
    setBadge("crit", "AMENAZA DETECTADA");
    var top = alerts[0] || {};
    if (bodyEl) {
      bodyEl.innerHTML =
        '<p class="text-[11px] text-red-300 font-semibold">' +
        esc(top.threat_type || "Amenaza") +
        "</p>" +
        '<p class="text-[10px] text-gray-400 mt-1">Severidad: ' +
        esc(na(top.risk_level)) +
        " · Confianza: " +
        esc(na(top.confidence)) +
        "</p>" +
        '<p class="text-[10px] text-gray-500 mt-1">' +
        esc(top.evidence_summary || "Evidencia: ver lista") +
        "</p>";
    }
    renderThreatRows(alerts);
    if (metaEl) {
      metaEl.textContent =
        "event/ref: " +
        esc(na(top.id || top.event_id)) +
        " · " +
        esc(na(top.timestamp || top.date));
    }
  }

  function renderThreatRows(alerts) {
    if (!threatList) return;
    var rows = (alerts || []).slice(0, 5);
    if (!rows.length) {
      threatList.innerHTML = "";
      return;
    }
    threatList.innerHTML = rows
      .map(function (a) {
        return (
          "<li>" +
          '<span class="text-gray-200">' +
          esc(a.threat_type || "alerta") +
          "</span>" +
          '<span class="text-gray-500">' +
          esc(na(a.risk_level)) +
          " · " +
          esc(na(a.confidence)) +
          "</span></li>"
        );
      })
      .join("");
  }

  function renderPartial(summary, engines, stats) {
    if (waitEl) waitEl.classList.add("hidden");
    if (headline) headline.textContent = "PROTECCIÓN PARCIAL";
    setBadge("warn", "PARCIAL");
    var threatLine =
      typeof summary.total_threats === "number"
        ? "Amenazas confirmadas: " + summary.total_threats
        : "Amenazas confirmadas: DATOS NO DISPONIBLES";
    if (bodyEl) {
      bodyEl.innerHTML =
        '<p class="text-[11px] text-amber-300 font-medium">Algunos motores CORE activos; otros IDLE / NOT_CONFIGURED</p>' +
        '<p class="text-[10px] text-gray-500 mt-1">' +
        threatLine +
        "</p>" +
        renderEngineLine(stats) +
        '<p class="text-[10px] text-gray-500 mt-1">No equivale a cobertura AV comercial.</p>';
    }
    if (metaEl) {
      metaEl.textContent =
        "Fuente: " +
        esc(summary.source || "security_summary+engines") +
        " · " +
        esc(summary.observed_at || summary.timestamp || "NOT_AVAILABLE");
    }
  }

  function classify(summary, alerts) {
    if (!summary || summary.status === "error") {
      return "unavailable";
    }
    // stale snapshot is usable evidence; do not spin forever on motors
    if (summary.status === "loading" || summary.snapshot_pending) {
      if (waitEl) {
        waitEl.classList.remove("hidden");
        waitEl.textContent = "Actualizando métricas de seguridad…";
      }
      if (headline) headline.textContent = "Actualizando…";
      setBadge("idle", "PENDING");
      return "pending";
    }
    var list = Array.isArray(alerts) ? alerts : summary.alerts || [];
    var confirmed = list.filter(function (a) {
      var r = riskRank(a && a.risk_level);
      return r >= 3;
    });
    var mid = list.filter(function (a) {
      var r = riskRank(a && a.risk_level);
      return r === 2;
    });
    if (summary.has_active_ransomware === true || confirmed.length) {
      return "threat";
    }
    if (mid.length || (typeof summary.total_threats === "number" && summary.total_threats > 0 && list.length)) {
      return "investigate";
    }
    if (summary.total_threats === null || summary.total_threats === undefined) {
      var cs = summary.component_status || {};
      if (cs.alerts === "pending" || summary.counters_pending) {
        return "pending";
      }
      if (summary.status === "ok" && list.length === 0) {
        return "protected";
      }
      return "unavailable";
    }
    if (Number(summary.total_threats) === 0 && !list.length) {
      return "protected";
    }
    if (Number(summary.total_threats) > 0) {
      return "investigate";
    }
    return "protected";
  }

  function classifyProtection(summary, alerts, engines) {
    var mode = classify(summary, alerts);
    var stats = engineStats(engines);
    if (mode === "threat" || mode === "investigate" || mode === "pending" || mode === "unavailable") {
      return { mode: mode, stats: stats };
    }
    if (!stats.total) {
      return { mode: "unavailable", stats: stats };
    }
    if (stats.ACTIVE > 0 && (stats.IDLE > 0 || stats.NOT_CONFIGURED > 0 || stats.DEGRADED > 0)) {
      return { mode: "partial", stats: stats };
    }
    if (stats.ACTIVE > 0) {
      return { mode: "protected", stats: stats };
    }
    if (stats.IDLE > 0 && stats.ACTIVE === 0) {
      return { mode: "engines_idle", stats: stats };
    }
    return { mode: "unavailable", stats: stats };
  }

  function apply(summary, alerts, engines) {
    lastPayload = { summary: summary, alerts: alerts, engines: engines || [] };
    if (errEl) errEl.classList.add("hidden");
    var classified = classifyProtection(summary, alerts, engines || []);
    var mode = classified.mode;
    var stats = classified.stats;
    var list = Array.isArray(alerts) ? alerts : [];
    list = list.filter(function (a) {
      var blob = JSON.stringify(a || {}).toLowerCase();
      if (blob.indexOf("mitm") < 0) return true;
      if (blob.indexOf("not_verifiable") >= 0 || blob.indexOf("trust store") >= 0) return false;
      if (blob.indexOf("ssl stripping") >= 0 && blob.indexOf("certificado desconocido") < 0) return false;
      return true;
    });
    if (mode === "unavailable") {
      renderUnavailable("DATOS NO DISPONIBLES");
      if (bodyEl && engines && engines.length) {
        bodyEl.innerHTML += renderEngineLine(stats);
      }
      return;
    }
    if (mode === "pending") {
      return;
    }
    if (mode === "engines_idle") {
      if (waitEl) {
        waitEl.classList.remove("hidden");
        waitEl.textContent = "ANÁLISIS EN CURSO — motores CORE en IDLE / arrancando";
      }
      if (headline) headline.textContent = "ANÁLISIS EN CURSO";
      setBadge("idle", "IDLE");
      if (bodyEl) bodyEl.innerHTML = renderEngineLine(stats);
      return;
    }
    if (mode === "threat") {
      renderThreat(list, summary || {});
      if (bodyEl) bodyEl.innerHTML += renderEngineLine(stats);
      return;
    }
    if (mode === "investigate") {
      renderInvestigate(list, summary || {});
      if (bodyEl) bodyEl.innerHTML += renderEngineLine(stats);
      return;
    }
    if (mode === "partial") {
      renderPartial(summary || {}, engines, stats);
      return;
    }
    renderProtected(summary || {}, engines);
  }

  function fetchJson(url) {
    return fetch(url, { credentials: "same-origin" }).then(function (r) {
      if (r.status === 401 || r.status === 403) {
        return { _auth: true, status: r.status };
      }
      return r.json();
    });
  }

  function refresh() {
    Promise.all([
      fetchJson("/api/security/summary"),
      fetchJson("/api/security/alerts?limit=20"),
      fetchJson("/api/manual-defense/engines"),
    ])
      .then(function (pair) {
        var summary = pair[0] || {};
        var alertsBody = pair[1] || {};
        var enginesBody = pair[2] || {};
        if (summary._auth || alertsBody._auth) {
          renderUnavailable("Sesión requerida");
          return;
        }
        var alerts = alertsBody.alerts || summary.alerts || [];
        var engines = enginesBody.engines || [];
        apply(summary, alerts, engines);
      })
      .catch(function () {
        renderUnavailable("DATOS NO DISPONIBLES");
        if (errEl) {
          errEl.classList.remove("hidden");
          errEl.textContent = "No se pudo consultar fuentes canónicas de seguridad";
        }
      });
  }

  function openDetails() {
    var modal = document.getElementById("novus-eg-detail-modal");
    var modalBody = document.getElementById("novus-eg-detail-body");
    if (!modal || !modalBody) return;
    var s = (lastPayload && lastPayload.summary) || {};
    var a = (lastPayload && lastPayload.alerts) || [];
    modalBody.innerHTML =
      '<div class="novus-eg-detail-section"><h4>Estado de protección</h4><ul>' +
      "<li><span>status</span><span>" +
      esc(na(s.status)) +
      "</span></li>" +
      "<li><span>total_threats</span><span>" +
      esc(s.total_threats == null ? "NOT_AVAILABLE" : s.total_threats) +
      "</span></li>" +
      "<li><span>ransomware_active</span><span>" +
      esc(s.has_active_ransomware === true ? "yes" : s.has_active_ransomware === false ? "no" : "NOT_AVAILABLE") +
      "</span></li>" +
      "<li><span>alerts</span><span>" +
      a.length +
      "</span></li>" +
      "<li><span>source</span><span>" +
      esc(na(s.source)) +
      "</span></li></ul></div>" +
      '<div class="novus-eg-detail-section"><h4>Alertas canónicas</h4><ul>' +
      (a.length
        ? a
            .slice(0, 15)
            .map(function (x) {
              return (
                "<li><span>" +
                esc(x.threat_type || x.id) +
                '</span><span class="text-gray-400">' +
                esc(na(x.risk_level)) +
                " · " +
                esc(na(x.confidence)) +
                "</span></li>"
              );
            })
            .join("")
        : "<li><span>Sin alertas confirmadas</span><span></span></li>") +
      "</ul></div>";
    modal.classList.add("open");
  }

  function closeDetails() {
    var modal = document.getElementById("novus-eg-detail-modal");
    if (modal) modal.classList.remove("open");
  }

  window.NovusEstadoGeneral = { openDetails: openDetails, closeDetails: closeDetails, refresh: refresh };

  var modal = document.getElementById("novus-eg-detail-modal");
  if (modal) {
    modal.addEventListener("click", function (e) {
      if (e.target === modal) closeDetails();
    });
  }
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeDetails();
  });

  if (headline) headline.textContent = "Cargando estado de seguridad…";
  if (waitEl) {
    waitEl.classList.remove("hidden");
    waitEl.textContent = "Consultando fuente canónica de seguridad…";
  }
  refresh();
  pollTimer = setInterval(refresh, POLL_MS);
})();
