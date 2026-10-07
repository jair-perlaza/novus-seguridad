/**
 * NOVUS — utilidades de presentación de métricas verificables.
 * No convierte fallos de motor ni valores ausentes en ceros.
 */
(function (global) {
    const NO_DATA = 'Sin datos disponibles';

    function isNumeric(v) {
        return typeof v === 'number' && !Number.isNaN(v);
    }

    function formatCount(v) {
        return isNumeric(v) ? String(v) : NO_DATA;
    }

    function formatPercent(v, decimals) {
        const d = decimals === undefined ? 1 : decimals;
        if (isNumeric(v)) return v.toFixed(d) + '%';
        if (v === NO_DATA || v === null || v === undefined) return NO_DATA;
        return String(v);
    }

    function parseTrafficMb(v) {
        if (isNumeric(v)) return v;
        if (typeof v === 'string' && v !== NO_DATA) {
            const n = Number(v);
            return Number.isNaN(n) ? null : n;
        }
        return null;
    }

    function sumTrafficMb(recv, sent) {
        const r = parseTrafficMb(recv);
        const s = parseTrafficMb(sent);
        if (r === null && s === null) return NO_DATA;
        return ((r || 0) + (s || 0)).toFixed(2);
    }

    function formatTrafficTotal(recv, sent, unit, meta) {
        if (meta && meta.measured === false) {
            if (meta.pending || meta.data_state === 'PENDING') {
                return meta.display || 'PENDING';
            }
            if (meta.data_state === 'NOT_AVAILABLE') {
                return meta.display || 'NOT_AVAILABLE';
            }
            return meta.display || 'NOT_AVAILABLE';
        }
        const state = (meta && meta.data_state) ? String(meta.data_state) : 'LIVE';
        // Never coerce NOT_AVAILABLE / PENDING into a numeric 0.00
        if (state === 'NOT_AVAILABLE' || state === 'PENDING') {
            return state === 'PENDING' ? (meta.display || 'PENDING') : (meta.display || 'NOT_AVAILABLE');
        }
        const u = (meta && meta.unit) ? (' ' + meta.unit) : (unit || ' MB/s');
        const sum = sumTrafficMb(recv, sent);
        if (sum === NO_DATA) return 'NOT_AVAILABLE';
        // LIVE: 0.00 MB/s is a real measurement (round-to-zero), not NOT_AVAILABLE
        return state + ': ' + sum + u;
    }

    function formatMetricLine(cpu, ram, disk) {
        const parts = [
            'CPU ' + formatPercent(cpu, 1),
            'RAM ' + formatPercent(ram, 1),
            'Disco ' + formatPercent(disk, 1),
        ];
        if (parts.every(function (p) { return p.indexOf(NO_DATA) !== -1; })) return NO_DATA;
        return parts.join(' | ');
    }

    function pickMetric(primary, fallback) {
        if (isNumeric(primary)) return primary;
        if (isNumeric(fallback)) return fallback;
        if (primary === NO_DATA || fallback === NO_DATA) return NO_DATA;
        return null;
    }

    function hostStatusHtml(cpu, ram, disk, extras) {
        extras = extras || {};
        let html = '<div>CPU: ' + formatPercent(cpu, 1) + '</div>';
        html += '<div>RAM: ' + formatPercent(ram, 1) + '</div>';
        html += '<div>Disco: ' + formatPercent(disk, 1) + '</div>';
        if (extras.procesos !== undefined) {
            html += '<div>Procesos: ' + formatCount(extras.procesos) + '</div>';
        }
        if (extras.conexiones !== undefined) {
            html += '<div>Sockets red (host): <button type="button" class="text-indigo-400 underline cursor-pointer bg-transparent border-0 p-0" onclick="NovusMetrics.openConnectionsDetailPanel(window._novusConexionesMeta||{})">' + formatCount(extras.conexiones) + ' · detalle</button></div>';
        }
        return html;
    }

    function updateAlertBadgeEl(badgeEl, count) {
        if (!badgeEl) return;
        if (isNumeric(count)) {
            badgeEl.textContent = String(count);
            badgeEl.classList.remove('hidden');
        } else {
            badgeEl.textContent = '—';
        }
    }

    function pushTrafficHistory(history, recv, sent, maxLen) {
        const limit = maxLen || 12;
        const r = parseTrafficMb(recv);
        const s = parseTrafficMb(sent);
        if (r === null && s === null) return false;
        history.push((r || 0) + (s || 0));
        if (history.length > limit) history.shift();
        return true;
    }

    function isMonitoringNotConfigured(data) {
        return !!(data && data.status === 'monitoring_not_configured');
    }

    function monitoringNotConfiguredMessage(data) {
        if (data && data.message) return data.message;
        return 'El monitoreo de red aún no está configurado para esta empresa.';
    }

    function monitoringNotConfiguredHtml(message) {
        const text = message || 'El monitoreo de red aún no está configurado para esta empresa.';
        return '<div class="rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-100 p-4 text-center text-sm">' +
            text + '</div>';
    }

    const EVIDENCE_LABELS = {
        verified: 'Verificado',
        ip: 'Dirección IP',
        attempts: 'Intentos',
        source: 'Fuente',
        evidence: 'Evidencia',
        message: 'Mensaje',
        email: 'Cuenta',
        unique_ips: 'IPs distintas',
        unique_emails: 'Cuentas distintas',
        process: 'Proceso',
        file: 'Archivo',
        path: 'Ruta',
        port: 'Puerto',
        command_line: 'Línea de comando',
        description: 'Descripción',
    };

    function formatEvidenceValue(value) {
        if (value === null || value === undefined || value === '') return 'Sin datos disponibles';
        if (typeof value === 'boolean') return value ? 'Sí' : 'No';
        if (typeof value === 'number') return String(value);
        if (typeof value === 'string') return value;
        if (Array.isArray(value)) {
            return value.map(function (item) {
                return typeof item === 'object' ? formatEvidenceValue(item) : String(item);
            }).join('; ');
        }
        if (typeof value === 'object') {
            return formatEvidenceObject(value);
        }
        return String(value);
    }

    function formatEvidenceObject(obj) {
        if (!obj || typeof obj !== 'object') return 'Sin datos disponibles';
        const parts = [];
        Object.keys(obj).forEach(function (key) {
            const val = obj[key];
            if (val === null || val === undefined || val === '') return;
            const label = EVIDENCE_LABELS[key] || key.replace(/_/g, ' ');
            parts.push(label + ': ' + formatEvidenceValue(val));
        });
        return parts.length ? parts.join(' · ') : 'Sin datos disponibles';
    }

    function renderEvidenceItemsHtml(items) {
        if (!items || !items.length) return '';
        return items.map(function (item) {
            return '<div class="bg-[#0a0f18] rounded-lg p-3 border border-gray-800/80">' +
                '<div class="text-[8px] uppercase text-gray-600 mb-1">' + item.label + '</div>' +
                '<div class="text-gray-300 leading-snug">' + formatEvidenceValue(item.value) + '</div></div>';
        }).join('');
    }

    function renderDetailRowsHtml(rows) {
        return rows.map(function (row) {
            const label = row[0];
            const value = row[1];
            return '<div class="bg-[#0a0f18] rounded-lg p-3 border border-gray-800/80">' +
                '<div class="text-[8px] uppercase text-gray-600 mb-1">' + label + '</div>' +
                '<div class="text-gray-300 leading-snug">' + formatEvidenceValue(value) + '</div></div>';
        }).join('');
    }

    function formatThreatForDisplay(threat) {
        const details = threat && threat.details;
        if (!details) return 'Sin evidencia verificable';
        if (typeof details === 'string') return details;
        if (details.evidence) return formatEvidenceValue(details.evidence);
        if (details.message) return formatEvidenceValue(details.message);
        return formatEvidenceObject(details);
    }

    function closeMetricModal() {
        const modal = document.getElementById('novus-metric-modal');
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    }

    function openMetricModal(title, subtitle, bodyHtml) {
        const modal = document.getElementById('novus-metric-modal');
        const t = document.getElementById('novus-metric-modal-title');
        const s = document.getElementById('novus-metric-modal-sub');
        const b = document.getElementById('novus-metric-modal-body');
        if (!modal || !t || !b) return;
        t.textContent = title || 'Detalle de métrica';
        if (s) s.textContent = subtitle || '';
        b.innerHTML = bodyHtml || '';
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }

    async function openConnectionsDetailPanel(liveMeta) {
        openMetricModal('Conexiones de red del host', 'Cargando…', '<p class="text-gray-500">Obteniendo desglose psutil…</p>');
        try {
            const res = await fetch('/api/dashboard/connections-detail');
            const data = await res.json();
            const c = data.connections || {};
            if (!c.available) {
                openMetricModal('Conexiones', 'Información no disponible', '<p>No se pudo leer psutil.net_connections en este nodo.</p>');
                return;
            }
            const rows = [
                ['Qué representa', c.definition],
                ['Fuente / cálculo', c.source + ' — ' + (c.calculation || '')],
                ['Actualizado', c.updated_at],
                ['Total sockets (IPv4/IPv6)', c.total],
                ['TCP', c.tcp],
                ['UDP', c.udp],
                ['IPv4', c.ipv4],
                ['IPv6', c.ipv6],
                ['Locales / loopback', c.local_loopback_or_sin_remoto],
                ['Remotas (con raddr)', c.remote_endpoints],
                ['Establecidas remotas', c.established_remote],
                ['Relacionadas HTTPS (443)', c.https_related],
                ['Relacionadas DNS (53)', c.dns_related],
                ['ESTABLISHED', c.established],
                ['LISTEN', c.listen],
                ['TIME_WAIT', c.time_wait],
                ['NOVUS / Python / Flask', (c.by_process_category || {}).novus_stack],
                ['Ngrok', (c.by_process_category || {}).ngrok],
                ['Cursor IDE', (c.by_process_category || {}).cursor_ide],
                ['Navegador', (c.by_process_category || {}).navegador],
                ['Sistema Windows', (c.by_process_category || {}).sistema_windows],
                ['Riesgo asociado', c.risk_level],
                ['¿Es normal?', c.is_normal_hint],
            ];
            let html = '<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">' + renderDetailRowsHtml(rows) + '</div>';
            if (c.recommended_actions && c.recommended_actions.length) {
                html += '<div class="mt-4"><div class="text-[10px] uppercase text-gray-500 mb-2">Acciones recomendadas</div><ul class="list-disc pl-5 space-y-1 text-gray-400">';
                c.recommended_actions.forEach(function (a) { html += '<li>' + a + '</li>'; });
                html += '</ul></div>';
            }
            if (c.top_processes && c.top_processes.length) {
                html += '<div class="mt-4"><div class="text-[10px] uppercase text-gray-500 mb-2">Procesos (top)</div><div class="space-y-1 font-mono text-xs">';
                c.top_processes.forEach(function (p) {
                    html += '<div class="flex justify-between border-b border-gray-800/50 py-1"><span>' + p.process + '</span><span>' + p.connections + '</span></div>';
                });
                html += '</div></div>';
            }
            if (liveMeta && liveMeta.label) {
                html = '<p class="text-xs text-indigo-300 mb-3">' + liveMeta.label + ': valor principal mostrado en tarjeta = ' + formatCount(liveMeta.value) + '</p>' + html;
            }
            openMetricModal('Conexiones de red del host NOVUS', c.updated_at + ' · ' + c.source, html);
        } catch (err) {
            openMetricModal('Conexiones', 'Error', '<p class="text-red-400">' + String(err) + '</p>');
        }
    }

    function formatNetworkNodesDisplay(live) {
        if (!live) return { main: NO_DATA, sub: '' };
        const meta = live.nodos_red_meta || {};
        const val = live.nodos_red;
        const fresh = (meta.data_freshness || '').toLowerCase();
        const hist = meta.historical_device_count;
        if (val === NO_DATA || val === null || val === undefined) {
            return { main: NO_DATA, sub: '' };
        }
        if (fresh === 'stale' && isNumeric(hist) && hist > 0) {
            return {
                main: 'Sin datos disponibles',
                sub: hist + ' en último descubrimiento (desactualizado)',
            };
        }
        if (fresh === 'cached' && isNumeric(hist) && hist > 0 && val === 0) {
            return {
                main: formatCount(val),
                sub: hist + ' en último descubrimiento (CACHED)',
            };
        }
        return { main: formatCount(val), sub: fresh ? String(fresh).toUpperCase() : '' };
    }

    function applyNetworkNodesKpi(live) {
        const disp = formatNetworkNodesDisplay(live);
        const mainEl = document.getElementById('nodes-val');
        const subEl = document.getElementById('nodes-val-sub');
        if (mainEl) mainEl.innerText = disp.main;
        if (subEl) {
            subEl.textContent = disp.sub || '';
            subEl.classList.toggle('hidden', !disp.sub);
        }
        return disp;
    }

    global.NovusMetrics = {
        NO_DATA: NO_DATA,
        isNumeric: isNumeric,
        formatCount: formatCount,
        formatPercent: formatPercent,
        parseTrafficMb: parseTrafficMb,
        sumTrafficMb: sumTrafficMb,
        formatTrafficTotal: formatTrafficTotal,
        formatMetricLine: formatMetricLine,
        pickMetric: pickMetric,
        hostStatusHtml: hostStatusHtml,
        updateAlertBadgeEl: updateAlertBadgeEl,
        pushTrafficHistory: pushTrafficHistory,
        isMonitoringNotConfigured: isMonitoringNotConfigured,
        monitoringNotConfiguredMessage: monitoringNotConfiguredMessage,
        monitoringNotConfiguredHtml: monitoringNotConfiguredHtml,
        formatEvidenceValue: formatEvidenceValue,
        formatEvidenceObject: formatEvidenceObject,
        renderEvidenceItemsHtml: renderEvidenceItemsHtml,
        renderDetailRowsHtml: renderDetailRowsHtml,
        formatThreatForDisplay: formatThreatForDisplay,
        formatNetworkNodesDisplay: formatNetworkNodesDisplay,
        applyNetworkNodesKpi: applyNetworkNodesKpi,
        openConnectionsDetailPanel: openConnectionsDetailPanel,
        openMetricModal: openMetricModal,
        closeMetricModal: closeMetricModal,
    };
})(window);
