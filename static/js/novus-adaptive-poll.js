/**
 * Polling adaptativo NOVUS — reduce solicitudes cuando no hay cambios.
 * No convierte datos LIVE en estáticos: acelera cuando hay actividad.
 */
(function (global) {
    "use strict";

    function createPoll(fn, options) {
        options = options || {};
        var baseMs = options.baseMs || 10000;
        var minMs = options.minMs || 5000;
        var maxMs = options.maxMs || 60000;
        var revisionKey = options.revisionKey || "_novusPollRevision";
        var interval = baseMs;
        var unchanged = 0;
        var timer = null;
        var stopped = false;

        function schedule(ms) {
            if (stopped) return;
            timer = setTimeout(tick, ms);
        }

        async function tick() {
            if (stopped) return;
            var revBefore = global[revisionKey];
            try {
                await fn();
            } catch (e) {
                console.debug("NovusAdaptivePoll", e);
            }
            if (stopped) return;
            if (global[revisionKey] === revBefore) {
                unchanged += 1;
                interval = Math.min(maxMs, Math.round(baseMs * Math.pow(1.4, unchanged)));
            } else {
                unchanged = 0;
                interval = minMs;
            }
            schedule(interval);
        }

        tick();
        return function stop() {
            stopped = true;
            if (timer) clearTimeout(timer);
        };
    }

    global.NovusAdaptivePoll = { create: createPoll };
})(typeof window !== "undefined" ? window : globalThis);
