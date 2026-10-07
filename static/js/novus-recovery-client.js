/**
 * Cliente NOVUS — recuperación automática en fetch/XHR; sin alertas de error técnicas.
 */
(function () {
    const RECOVERY_MSG = 'NOVUS está recuperando el servicio...';
    const RETRY_DELAY_MS = 3000;
    const MAX_AUTO_RETRIES = 8;

    let overlayEl = null;
    let retryCount = 0;

    function ensureOverlay() {
        if (overlayEl) return overlayEl;
        overlayEl = document.createElement('div');
        overlayEl.id = 'novus-recovery-overlay';
        overlayEl.setAttribute('role', 'status');
        overlayEl.style.cssText =
            'position:fixed;inset:0;z-index:99999;background:rgba(6,9,15,.92);display:flex;align-items:center;justify-content:center;padding:24px;';
        overlayEl.innerHTML =
            '<div style="text-align:center;max-width:420px;color:#e2e8f0;font-family:system-ui,sans-serif">' +
            '<div style="width:56px;height:56px;margin:0 auto 20px;border-radius:50%;border:3px solid rgba(99,102,241,.2);border-top-color:#6366f1;animation:novusSpin 1s linear infinite"></div>' +
            '<p style="font-size:16px;color:#a5b4fc;margin:0 0 8px">' +
            RECOVERY_MSG +
            '</p>' +
            '<p style="font-size:12px;color:#64748b;margin:0" id="novus-recovery-sub">Reintentando…</p></div>';
        if (!document.getElementById('novus-recovery-keyframes')) {
            const st = document.createElement('style');
            st.id = 'novus-recovery-keyframes';
            st.textContent = '@keyframes novusSpin{to{transform:rotate(360deg)}}';
            document.head.appendChild(st);
        }
        document.body.appendChild(overlayEl);
        return overlayEl;
    }

    function hideOverlay() {
        retryCount = 0;
        if (overlayEl && overlayEl.parentNode) overlayEl.parentNode.removeChild(overlayEl);
        overlayEl = null;
    }

    function showRecovery(sub) {
        ensureOverlay();
        const subEl = document.getElementById('novus-recovery-sub');
        if (subEl && sub) subEl.textContent = sub;
    }

    function isRecoveryPayload(data) {
        if (!data || typeof data !== 'object') return false;
        if (data._novusRecovery || data.status === 'recovering') return true;
        if (data.status === 'error') return true;
        return false;
    }

    function normalizeJson(data) {
        if (!data || typeof data !== 'object') {
            return { status: 'recovering', message: RECOVERY_MSG, _novusRecovery: true };
        }
        if (isRecoveryPayload(data)) {
            data.status = 'recovering';
            data.message = RECOVERY_MSG;
            data._novusRecovery = true;
            delete data.traceback;
            delete data.error_detail;
            delete data.stack;
        }
        return data;
    }

    async function retryFetch(origArgs, attempt) {
        if (attempt >= MAX_AUTO_RETRIES) {
            showRecovery('Redirigiendo al inicio…');
            setTimeout(function () {
                window.location.href = '/';
            }, 1500);
            return null;
        }
        showRecovery('Reintento ' + (attempt + 1) + ' de ' + MAX_AUTO_RETRIES);
        await new Promise(function (r) {
            setTimeout(r, RETRY_DELAY_MS);
        });
        return window.__novusOrigFetch.apply(window, origArgs);
    }

    window.__novusOrigFetch = window.fetch.bind(window);
    window.fetch = async function (...args) {
        let res;
        try {
            res = await window.__novusOrigFetch(...args);
        } catch (err) {
            showRecovery('Reconectando…');
            res = await retryFetch(args, retryCount++);
            if (!res) {
                return new Response(
                    JSON.stringify({ status: 'recovering', message: RECOVERY_MSG, _novusRecovery: true }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }
        }

        const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
        const isApi = url.includes('/api/');
        const recoveryHeader = res.headers.get('X-Novus-Recovery');

        if (!isApi && !recoveryHeader && res.ok) {
            hideOverlay();
            return res;
        }

        if (!isApi && !recoveryHeader && !res.ok) {
            showRecovery('Recuperando vista…');
            const retry = await retryFetch(args, retryCount++);
            return retry || res;
        }

        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (isApi && ct.includes('application/json')) {
            try {
                const clone = res.clone();
                const data = await clone.json();
                if (!res.ok || isRecoveryPayload(data) || recoveryHeader) {
                    showRecovery('Recuperando datos…');
                    if (isRecoveryPayload(data) && data.login_required) {
                        window.location.href =
                            '/login?next=' + encodeURIComponent(window.location.pathname || '/');
                        return res;
                    }
                    const retry = await retryFetch(args, retryCount++);
                    if (retry && retry.ok && !retry.headers.get('X-Novus-Recovery')) {
                        hideOverlay();
                        return retry;
                    }
                    const normalized = normalizeJson(data);
                    return new Response(JSON.stringify(normalized), {
                        status: 200,
                        statusText: 'OK',
                        headers: { 'Content-Type': 'application/json' },
                    });
                }
            } catch (_) {
                /* ignore */
            }
        }

        if (res.ok) hideOverlay();
        return res;
    };

    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
        this.__novusUrl = url;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        this.addEventListener('load', function () {
            const url = this.__novusUrl || '';
            if (!url.includes('/api/')) return;
            if (this.status >= 400 || this.getResponseHeader('X-Novus-Recovery')) {
                showRecovery('Recuperando…');
            } else if (this.status >= 200 && this.status < 300) {
                hideOverlay();
            }
        });
        this.addEventListener('error', function () {
            showRecovery('Reconectando…');
        });
        return origSend.apply(this, arguments);
    };

    window.NovusRecoveryClient = {
        showRecovery,
        hideOverlay,
        RECOVERY_MSG,
    };

    window.NovusApiGuard = {
        userMessageFromJson: function () {
            return RECOVERY_MSG;
        },
        showError: function () {
            showRecovery();
        },
    };

    window.addEventListener('error', function () {
        showRecovery('Restableciendo interfaz…');
    });
    window.addEventListener('unhandledrejection', function () {
        showRecovery('Restableciendo interfaz…');
    });
})();
