/**
 * NOVUS Dashboard client cache — restauración instantánea al regresar al Dashboard.
 */
(function (global) {
  'use strict';

  var KEY = 'novus_dashboard_kpi_v1';
  var MAX_AGE_MS = 120000;

  function load() {
    try {
      var raw = sessionStorage.getItem(KEY);
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (!parsed || !parsed.saved_at) return null;
      if (Date.now() - parsed.saved_at > MAX_AGE_MS) return null;
      return parsed;
    } catch (e) {
      return null;
    }
  }

  function save(live, security) {
    try {
      sessionStorage.setItem(
        KEY,
        JSON.stringify({
          live: live || null,
          security: security || null,
          saved_at: Date.now(),
        })
      );
    } catch (e) {
      /* quota / private mode */
    }
  }

  function fetchWithTimeout(fetchJson, url, ms) {
    ms = ms || 12000;
    return Promise.race([
      fetchJson(url),
      new Promise(function (_, reject) {
        setTimeout(function () {
          reject(new Error('timeout'));
        }, ms);
      }),
    ]);
  }

  function restoreKPIsToDOM(cached) {
    if (!cached) return false;
    var live = cached.live;
    var security = cached.security;
    if (!live && !security) return false;
    try {
      if (live && live.status === 'success') {
        var nodesEl = document.getElementById('nodes-val');
        if (nodesEl) {
          if (typeof NovusMetrics !== 'undefined' && NovusMetrics.applyNetworkNodesKpi) {
            NovusMetrics.applyNetworkNodesKpi(live);
          } else {
            nodesEl.innerText = typeof NovusMetrics !== 'undefined' ? NovusMetrics.formatCount(live.nodos_red) : live.nodos_red;
          }
        }
        if (document.getElementById('users-val')) document.getElementById('users-val').innerText = live.usuarios;
        if (document.getElementById('cpu-live')) document.getElementById('cpu-live').innerText = NovusMetrics.formatPercent(live.cpu, 1);
        if (document.getElementById('ram-live')) document.getElementById('ram-live').innerText = NovusMetrics.formatPercent(live.ram, 1);
        if (document.getElementById('disk-live')) document.getElementById('disk-live').innerText = NovusMetrics.formatPercent(live.disk, 1);
        if (document.getElementById('traffic-val')) document.getElementById('traffic-val').innerText = NovusMetrics.formatTrafficTotal(live.traffic_recv, live.traffic_sent, undefined, live.traffic_meta);
      }
      if (security && (security.status === 'ok' || security.status === 'loading')) {
        var counters = security.counters || {};
        var threats = security.total_threats;
        if (document.getElementById('threats-val')) {
          document.getElementById('threats-val').innerText =
            threats === null || threats === undefined ? 'Sin datos disponibles' : threats;
        }
        if (document.getElementById('endpoints-val')) {
          var ep = counters.endpoints_total;
          document.getElementById('endpoints-val').innerText =
            typeof NovusMetrics !== 'undefined' ? NovusMetrics.formatCount(ep) : ep;
        }
      }
      var tsEl = document.getElementById('dashboard-data-ts');
      if (tsEl) tsEl.textContent = 'Últimos datos (caché local) — actualizando…';
      return true;
    } catch (e) {
      return false;
    }
  }

  global.NovusDashboardCache = {
    load: load,
    save: save,
    fetchWithTimeout: fetchWithTimeout,
    restoreKPIsToDOM: restoreKPIsToDOM,
  };
})(typeof window !== 'undefined' ? window : this);
