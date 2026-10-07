/**
 * NOVUS progressive fetch — deduplicación, abort al cambiar vista, sin polling duplicado.
 */
(function (global) {
  'use strict';

  const inflight = new Map();
  let pageController = new AbortController();

  function resetPageRequests() {
    try {
      pageController.abort();
    } catch (e) { /* noop */ }
    pageController = new AbortController();
    inflight.clear();
  }

  if (typeof window !== 'undefined') {
    window.addEventListener('beforeunload', resetPageRequests);
    window.addEventListener('pagehide', resetPageRequests);
  }

  async function fetchJson(url, options) {
    const opts = options || {};
    const key = opts.method === 'POST' ? url + ':POST' : url;
    if (inflight.has(key)) {
      return inflight.get(key);
    }
    const signal = opts.signal || pageController.signal;
    const promise = fetch(url, {
      credentials: 'same-origin',
      headers: opts.headers || {},
      method: opts.method || 'GET',
      body: opts.body,
      signal: signal,
    })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .finally(function () {
        inflight.delete(key);
      });
    inflight.set(key, promise);
    return promise;
  }

  function showSkeleton(el, text) {
    if (!el) return;
    el.dataset.novusLoading = '1';
    el.innerHTML =
      '<div class="novus-skeleton animate-pulse text-gray-500 text-xs py-2">' +
      (text || 'Cargando datos…') +
      '</div>';
  }

  function setFreshness(el, meta) {
    if (!el || !meta) return;
    const ts = meta.generated_at_utc || meta.observed_at || meta.updated_at;
    const stale = meta.snapshot_stale || meta.snapshot_pending;
    el.textContent = ts
      ? 'Actualizado: ' + ts + (stale ? ' (actualizando…)' : '')
      : 'Datos aún no disponibles';
    el.className = stale
      ? 'text-[10px] text-amber-400 uppercase tracking-wider'
      : 'text-[10px] text-gray-500 uppercase tracking-wider';
  }

  global.NovusFetch = {
    fetchJson: fetchJson,
    resetPageRequests: resetPageRequests,
    showSkeleton: showSkeleton,
    setFreshness: setFreshness,
  };
})(typeof window !== 'undefined' ? window : globalThis);
