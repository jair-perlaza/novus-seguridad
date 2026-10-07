/**
 * Monitor huérfano (dashboard.html no enrutado) — solo SSE.
 * Mantiene compatibilidad si alguien reactiva la plantilla.
 */
(function () {
  var panel = document.getElementById("novus-auto-monitor");
  var statusText = document.getElementById("novus-monitor-status-text");
  var bar = document.getElementById("novus-monitor-progress-bar");
  var phaseLabel = document.getElementById("novus-monitor-phase-label");
  var reportLink = document.getElementById("novus-monitor-report-link");

  if (!panel || !statusText) return;

  function apply(data) {
    if (!data || data._novusRecovery) return;
    if (!data.active && !data.status) return;
    panel.style.display = "flex";
    var st = data.status || "unknown";
    var pct = null;
    if (
      data.progress_source === "completed_motors_only" &&
      data.progress_pct != null &&
      Number(data.completed_count || 0) > 0
    ) {
      pct = Math.max(0, Math.min(100, Number(data.progress_pct)));
    }
    if (st === "phase1_running" || st === "phase2_running") {
      statusText.textContent =
        Number(data.completed_count || 0) > 0
          ? data.current_label || data.current_mechanism || "Motor en curso"
          : data.waiting_message || "Esperando resultados del motor...";
      if (data.phase2 && data.phase2.phase_label && phaseLabel) {
        phaseLabel.textContent = data.phase2.phase_label;
      }
    } else if (st === "completed" || st === "partial") {
      statusText.textContent =
        st === "completed"
          ? "Monitoreo continuo activo. Informe disponible en Reportes."
          : "Análisis parcial completado. Revise el informe en Reportes.";
      if (data.report_id && reportLink) {
        reportLink.style.display = "inline";
        reportLink.href = "/reportes?highlight=" + encodeURIComponent(data.report_id);
      }
    } else if (st === "error") {
      statusText.textContent = data.motor_error || data.error || "Error de motor";
    } else {
      statusText.textContent = data.waiting_message || "Esperando resultados del motor...";
    }
    if (bar) bar.style.width = pct == null ? "0%" : pct + "%";
  }

  if (typeof EventSource === "undefined") {
    statusText.textContent = "Esperando resultados del motor...";
    return;
  }
  var es = new EventSource("/api/monitoring/stream");
  es.addEventListener("monitoring", function (ev) {
    try {
      apply(JSON.parse(ev.data));
    } catch (e) {}
  });
})();
