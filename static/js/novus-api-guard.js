/**
 * Evita mostrar JSON/tracebacks técnicos al usuario en respuestas fetch.
 */
(function () {
    const GENERIC = 'No pudimos completar la operación. Contacte al administrador NOVUS si persiste.';

    function userMessageFromJson(data) {
        if (!data || typeof data !== 'object') return GENERIC;
        if (typeof data.message === 'string' && data.message.trim()) return data.message.trim();
        return GENERIC;
    }

    const origFetch = window.fetch.bind(window);
    window.fetch = async function (...args) {
        const res = await origFetch(...args);
        const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
        const isApi = url.includes('/api/');
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!isApi || !ct.includes('application/json') || res.ok) {
            return res;
        }
        try {
            const clone = res.clone();
            const data = await clone.json();
            if (data && data.status === 'error' && !data._novusGuardHandled) {
                data._novusGuardHandled = true;
                data.message = userMessageFromJson(data);
                delete data.error_detail;
                delete data.traceback;
                return new Response(JSON.stringify(data), {
                    status: 200,
                    statusText: res.statusText,
                    headers: res.headers,
                });
            }
        } catch (_) { /* ignore */ }
        return res;
    };

    window.NovusApiGuard = {
        userMessageFromJson,
        showError(data) {
            alert(userMessageFromJson(data));
        },
    };
})();
