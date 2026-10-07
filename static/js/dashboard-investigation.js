/**
 * Centro de investigación del Dashboard NOVUS — nodos interactivos con evidencia real.
 */
(function (global) {
    'use strict';

    let priorityCache = null;
    let securityCache = null;
    let liveCache = null;

    function esc(s) {
        if (s == null) return '';
        const d = document.createElement('div');
        d.textContent = String(s);
        return d.innerHTML;
    }

    function setCaches(security, live) {
        securityCache = security;
        liveCache = live;
    }

    function openInvestigationModal(title, bodyHtml, actionsHtml) {
        let modal = document.getElementById('dashboard-investigation-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'dashboard-investigation-modal';
            modal.className = 'fixed inset-0 z-[200] hidden items-center justify-center bg-black/70 p-4';
            modal.innerHTML = `
                <div class="bg-[#0c121d] border border-gray-700 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl">
                    <div class="flex items-center justify-between px-5 py-4 border-b border-gray-800">
                        <h3 id="dash-inv-title" class="text-sm font-bold text-white"></h3>
                        <button type="button" onclick="NovusDashboardInvestigation.close()" class="text-gray-500 hover:text-white text-lg">&times;</button>
                    </div>
                    <div id="dash-inv-body" class="flex-1 overflow-y-auto px-5 py-4 text-[11px] text-gray-300 space-y-3"></div>
                    <div id="dash-inv-actions" class="px-5 py-4 border-t border-gray-800 flex flex-wrap gap-2"></div>
                </div>`;
            document.body.appendChild(modal);
            modal.addEventListener('click', (e) => { if (e.target === modal) NovusDashboardInvestigation.close(); });
        }
        document.getElementById('dash-inv-title').textContent = title;
        document.getElementById('dash-inv-body').innerHTML = bodyHtml;
        document.getElementById('dash-inv-actions').innerHTML = actionsHtml || '';
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }

    function closeModal() {
        const modal = document.getElementById('dashboard-investigation-modal');
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    }

    async function openDevice(ip) {
        if (!ip) return;
        openInvestigationModal('Cargando dispositivo…', '<div class="text-gray-500">Consultando NDR…</div>', '');
        try {
            const r = await fetch('/api/network/ndr/device/' + encodeURIComponent(ip));
            const data = await r.json();
            if (data.status === 'not_found' || r.status === 404) {
                openInvestigationModal('Dispositivo', '<p>Sin datos disponibles para esta IP.</p>', '');
                return;
            }
            const node = data.device || data.node || data;
            const alerts = data.alerts || [];
            const history = data.history || [];
            const vulns = data.vulnerabilities || [];
            let html = `
                <div class="grid grid-cols-2 gap-2">
                    <div><span class="text-gray-500">IP</span><br>${esc(node.ip)}</div>
                    <div><span class="text-gray-500">MAC</span><br>${esc(node.mac || 'Sin datos disponibles')}</div>
                    <div><span class="text-gray-500">Tipo</span><br>${esc(node.device_type || '—')}</div>
                    <div><span class="text-gray-500">Riesgo</span><br>${esc(node.risk_level || '—')}</div>
                    <div><span class="text-gray-500">Confianza</span><br>${esc(node.confidence || data.confidence || 'Sin datos disponibles')}</div>
                    <div><span class="text-gray-500">Estado</span><br>${esc(node.status || '—')}</div>
                </div>`;
            if (alerts.length) {
                html += '<div class="mt-3"><div class="text-[9px] uppercase text-amber-400 mb-1">Alertas</div>';
                alerts.forEach(a => {
                    html += `<div class="bg-[#0a0f18] p-2 rounded border border-gray-800 mb-1">${esc(a.title || a.id)} — ${esc(typeof NovusMetrics !== 'undefined' ? NovusMetrics.formatEvidenceValue(a.plain_explanation || a.evidence || a.detail || '') : (a.plain_explanation || a.evidence || ''))}</div>`;
                });
                html += '</div>';
            }
            if (history.length) {
                html += '<div class="mt-2"><div class="text-[9px] uppercase text-gray-500 mb-1">Historial</div>';
                history.slice(0, 8).forEach(h => {
                    html += `<div class="text-[10px] text-gray-400">[${esc(h.time || h.timestamp)}] ${esc(h.event || h.title)}</div>`;
                });
                html += '</div>';
            }
            if (vulns.length) {
                html += `<div class="mt-2 text-red-300">${vulns.length} vulnerabilidad(es) asociada(s)</div>`;
            }
            const actions = `
                <button type="button" class="px-3 py-2 rounded-lg bg-indigo-600 text-white text-[10px]" onclick="NovusDashboardInvestigation.investigate('${esc(ip)}')">Investigar</button>
                <button type="button" class="px-3 py-2 rounded-lg bg-cyan-900/50 border border-cyan-500/40 text-cyan-200 text-[10px]" onclick="NovusDashboardInvestigation.consultKernel('${esc(ip)}')">Consultar Kernel IA</button>
                <a href="/network" class="px-3 py-2 rounded-lg bg-gray-800 text-gray-300 text-[10px] no-underline">Ir a Red</a>
                <a href="/topology" class="px-3 py-2 rounded-lg bg-gray-800 text-gray-300 text-[10px] no-underline">Ir a Topology</a>
                <button type="button" class="px-3 py-2 rounded-lg bg-gray-800 text-gray-300 text-[10px]" onclick="NovusDashboardInvestigation.exportDevice('${esc(ip)}')">Exportar</button>`;
            openInvestigationModal('Dispositivo: ' + ip, html, actions);
        } catch (e) {
            openInvestigationModal('Error', '<p>No fue posible cargar el dispositivo.</p>', '');
        }
    }

    async function investigate(ip) {
        if (typeof NovusAction !== 'undefined') {
            await NovusAction.runApi({
                title: 'Investigar ' + ip,
                url: '/api/network/ndr/device/' + encodeURIComponent(ip) + '/investigate',
                method: 'POST',
                successStatus: 'Completado',
                onComplete: () => openDevice(ip),
            });
        } else {
            const r = await fetch('/api/network/ndr/device/' + encodeURIComponent(ip) + '/investigate', { method: 'POST' });
            const d = await r.json();
            alert(d.message || d.status || 'Investigación completada');
            openDevice(ip);
        }
    }

    function consultKernel(ip, extra) {
        const payload = Object.assign({ ip: ip }, extra || {});
        if (typeof consultKernelIA === 'function') {
            consultKernelIA('dashboard', payload);
            return;
        }
        if (typeof NovusAIKernel !== 'undefined') {
            NovusAIKernel.consultModule('dashboard', payload);
        } else {
            openInvestigationModal('Kernel IA', '<p>Panel Kernel no disponible.</p>', '');
        }
    }

    function exportDevice(ip) {
        const blob = new Blob([JSON.stringify({ ip, exported_at: new Date().toISOString(), source: 'NOVUS Dashboard' }, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'novus-device-' + ip.replace(/\./g, '-') + '.json';
        a.click();
    }

    async function openKpi(type) {
        if (type === 'nodes') {
            document.getElementById('device-viewport')?.scrollIntoView({ behavior: 'smooth' });
            return;
        }
        if (type === 'traffic') {
            document.getElementById('trafficChart')?.scrollIntoView({ behavior: 'smooth' });
            const meta = liveCache?.traffic_meta || {};
            const unit = meta.unit || 'MB';
            const recv = liveCache?.traffic_recv;
            const sent = liveCache?.traffic_sent;
            const recvDisp = (recv === null || recv === undefined) ? (meta.display || 'Sin datos disponibles') : recv;
            const sentDisp = (sent === null || sent === undefined) ? (meta.display || 'Sin datos disponibles') : sent;
            const mbps = (meta.recv_mbps != null || meta.sent_mbps != null)
                ? `<p>Mbps RX/TX: <strong>${esc(meta.recv_mbps ?? '—')}</strong> / <strong>${esc(meta.sent_mbps ?? '—')}</strong></p>`
                : '';
            const win = meta.window_sec != null ? `<p>Ventana: <strong>${esc(meta.window_sec)}</strong> s</p>` : '';
            openInvestigationModal('Tráfico de red', `
                <p>Estado: <strong>${esc(meta.data_state || 'UNKNOWN')}</strong></p>
                <p>Recibido: <strong>${esc(recvDisp)}</strong> ${esc(unit)}</p>
                <p>Enviado: <strong>${esc(sentDisp)}</strong> ${esc(unit)}</p>
                ${mbps}${win}
                <p class="text-gray-500 text-[10px]">Fuente: ${esc(meta.source || 'psutil.net_io_counters')}</p>`, `
                <a href="/network" class="px-3 py-2 rounded-lg bg-indigo-600 text-white text-[10px] no-underline">Ir a Red</a>`);
            return;
        }
        if (type === 'threats') {
            try {
                const r = await fetch('/api/security/threats');
                const d = await r.json();
                const threats = d.threats || d.data?.threats || [];
                const procs = d.suspicious_processes || [];
                if (!threats.length && !procs.length) {
                    openInvestigationModal('Amenazas', '<p>Sin amenazas verificadas en el último escaneo.</p>', `
                        <a href="/xdr" class="px-3 py-2 rounded-lg bg-gray-800 text-[10px] text-gray-300 no-underline">Ir a XDR</a>`);
                    return;
                }
                let html = '';
                threats.forEach(t => {
                    html += `<div class="border border-red-900/40 p-2 rounded mb-2"><strong>${esc(t.type)}</strong> — ${esc(NovusMetrics.formatThreatForDisplay(t))}</div>`;
                });
                procs.slice(0, 10).forEach(p => {
                    html += `<div class="border border-amber-900/40 p-2 rounded mb-2">Proceso: ${esc(p.name)} PID ${esc(p.pid)}</div>`;
                });
                openInvestigationModal('Amenazas verificadas', html, `
                    <a href="/xdr" class="px-3 py-2 rounded-lg bg-red-900/40 text-red-200 text-[10px] no-underline">Ir a XDR</a>
                    <button type="button" class="px-3 py-2 rounded-lg bg-cyan-900/50 text-cyan-200 text-[10px]" onclick="NovusDashboardInvestigation.consultKernel(null,{module:'threats'})">Consultar Kernel IA</button>`);
            } catch (e) {
                openInvestigationModal('Amenazas', '<p>Error al cargar amenazas.</p>', '');
            }
            return;
        }
        if (type === 'vulnerabilities') {
            try {
                const r = await fetch('/api/security/vulnerabilities');
                const d = await r.json();
                const vulns = d.vulnerabilities || d.data || [];
                if (!vulns.length) {
                    openInvestigationModal('Vulnerabilidades', '<p>Sin vulnerabilidades verificadas.</p>', `
                        <a href="/vulnerabilidades" class="px-3 py-2 rounded-lg bg-gray-800 text-[10px] no-underline">Ir a Vulnerabilidades</a>`);
                    return;
                }
                let html = '<ul class="space-y-2">';
                vulns.slice(0, 15).forEach(v => {
                    html += `<li class="border border-gray-800 p-2 rounded">${esc(v.nombre || v.id)} — ${esc(v.riesgo || '')}</li>`;
                });
                html += '</ul>';
                openInvestigationModal('Vulnerabilidades (' + vulns.length + ')', html, `
                    <a href="/vulnerabilidades" class="px-3 py-2 rounded-lg bg-amber-900/40 text-amber-200 text-[10px] no-underline">Ir a Vulnerabilidades</a>`);
            } catch (e) {
                openInvestigationModal('Vulnerabilidades', '<p>Error al cargar.</p>', '');
            }
            return;
        }
        if (type === 'endpoints') {
            const inv = securityCache?.endpoint_inventory || [];
            let html = inv.length
                ? '<ul>' + inv.slice(0, 20).map(e => `<li>${esc(e.ip || e.hostname)} — ${esc(e.source || '')}</li>`).join('') + '</ul>'
                : '<p>Sin inventario de endpoints.</p>';
            openInvestigationModal('Endpoints (' + inv.length + ')', html, `
                <a href="/endpoints" class="px-3 py-2 rounded-lg bg-purple-900/40 text-purple-200 text-[10px] no-underline">Ir a Endpoints</a>`);
            return;
        }
        if (type === 'status') {
            const t = document.getElementById('threats-val')?.textContent || '—';
            openInvestigationModal('Estado del sistema', `<p>Amenazas: ${esc(t)}</p><p>Última actualización: ${esc(liveCache?.timestamp || '—')}</p>`, '');
            return;
        }
        if (type === 'users') {
            const u = liveCache?.usuarios ?? 'Sin datos disponibles';
            openInvestigationModal('Usuarios conectados', `<p>${esc(u)} sesión(es) activa(s) medida(s) por el sistema.</p>`, '');
            return;
        }
        if (type === 'cpu' || type === 'ram' || type === 'disk') {
            try {
                const r = await fetch('/api/dashboard/metrics');
                const d = await r.json();
                const m = d.metrics || {};
                const label = { cpu: 'CPU', ram: 'RAM', disk: 'DISK' }[type];
                const val = m[type] ?? m[type + '_percent'] ?? liveCache?.[type] ?? 'Sin datos disponibles';
                openInvestigationModal(label + ' — detalle', `
                    <div class="space-y-2">
                        <div><span class="text-gray-500">Uso actual:</span> ${esc(NovusMetrics.formatEvidenceValue(val))}</div>
                        ${m.uptime_horas != null ? `<div><span class="text-gray-500">Tiempo activo:</span> ${esc(m.uptime_horas)} h</div>` : ''}
                        ${m.procesos_activos != null ? `<div><span class="text-gray-500">Procesos:</span> ${esc(m.procesos_activos)}</div>` : ''}
                    </div>`, '');
            } catch (e) {
                openInvestigationModal(type.toUpperCase(), '<p>Sin datos disponibles.</p>', '');
            }
        }
    }

    function openPriorityDetail() {
        const d = priorityCache;
        if (!d || d.status !== 'success') {
            openInvestigationModal('Prioridad', '<p>Sin datos de prioridad cargados.</p>', '');
            return;
        }
        let html = `<p><strong>${esc(d.title)}</strong></p>`;
        if (d.details) {
            const rows = [];
            if (d.details.evidence_summary) rows.push(['Evidencia', d.details.evidence_summary]);
            if (d.details.impact) rows.push(['Impacto', d.details.impact]);
            if (d.details.origin) rows.push(['Origen', d.details.origin]);
            if (d.details.asset) rows.push(['Activo', d.details.asset]);
            if (d.details.motor) rows.push(['Motor', d.details.motor]);
            if (d.details.probability) rows.push(['Probabilidad', d.details.probability]);
            if (d.details.inaction) rows.push(['Si no actúa', d.details.inaction]);
            html += NovusMetrics.renderDetailRowsHtml(rows);
            if (d.details.evidence_items && d.details.evidence_items.length) {
                html += NovusMetrics.renderEvidenceItemsHtml(d.details.evidence_items);
            }
        }
        const actions = [];
        if (d.action_url) {
            actions.push(`<a href="${esc(d.action_url)}" class="px-3 py-2 rounded-lg bg-indigo-600 text-white text-[10px] no-underline">${esc(d.action_label || 'Ir al módulo')}</a>`);
        }
        actions.push(`<button type="button" class="px-3 py-2 rounded-lg bg-cyan-900/50 text-cyan-200 text-[10px]" onclick="NovusDashboardInvestigation.consultKernel(null,{finding_id:''})">Consultar Kernel IA</button>`);
        if (d.priority_type === 'vulnerability' && typeof NovusRemediation !== 'undefined') {
            actions.push(`<button type="button" class="px-3 py-2 rounded-lg bg-amber-900/50 text-amber-200 text-[10px]" onclick="window.location.href='/vulnerabilidades'">Remediar</button>`);
        }
        openInvestigationModal('Prioridad actual — ' + (d.level || 'Estable'), html, actions.join(''));
    }

    function cachePriority(d) {
        priorityCache = d;
    }

    async function refreshEventLog() {
        const logContainer = document.getElementById('event-log');
        if (!logContainer) return;
        try {
            const secData = securityCache || null;
            const evResp = await fetch('/api/network/events?limit=15');
            const evData = await evResp.json();
            const secResolved = secData || {};
            const events = evData.events || [];
            const threats = secResolved.threats?.threats || secResolved.threats || [];
            const entries = [];
            events.forEach(ev => {
                entries.push({
                    text: `[${ev.time || ''}] ${ev.title || ev.event || ev.detail || 'Evento'}`,
                    ip: ev.ip,
                    click: ev.ip ? () => openDevice(ev.ip) : null,
                });
            });
            threats.slice(0, 5).forEach(t => {
                if (t.details) {
                    entries.push({
                        text: `Amenaza: ${t.type || 'detectada'}`,
                        click: () => openKpi('threats'),
                    });
                }
            });
            if (!entries.length) {
                logContainer.innerHTML = '<div class="text-[10px] text-gray-500 py-2">Sin eventos verificados. Esperando telemetría real…</div>';
                return;
            }
            logContainer.innerHTML = entries.map((e, i) => {
                const click = e.click ? `onclick="NovusDashboardInvestigation._eventClick(${i})" style="cursor:pointer"` : '';
                return `<div class="text-[10px] text-gray-400 border-b border-gray-800 py-2 font-mono hover:text-indigo-300" ${click} data-idx="${i}">${esc(e.text)}</div>`;
            }).join('');
            logContainer._entries = entries;
        } catch (err) {
            logContainer.innerHTML = '<div class="text-[10px] text-gray-500 py-2">Sin datos disponibles para eventos.</div>';
        }
    }

    function eventClick(idx) {
        const log = document.getElementById('event-log');
        const entry = log?._entries?.[idx];
        if (entry?.click) entry.click();
    }

    async function openAlerts() {
        try {
            const r = await fetch('/api/security/alerts');
            const d = await r.json();
            const alerts = d.alerts || [];
            const html = typeof NovusAlerts !== 'undefined'
                ? NovusAlerts.renderDashboardAlertsModal(alerts)
                : (alerts.length
                    ? `<p>${alerts.length} alerta(s) verificada(s)</p>`
                    : '<p class="text-gray-400">No hay alertas activas con evidencia verificable.</p>');
            openInvestigationModal('Alertas verificadas', html, `
                <a href="/incidentes" class="px-3 py-2 rounded-lg bg-red-900/40 text-red-200 text-[10px] no-underline">Centro de incidentes</a>
                <a href="/xdr" class="px-3 py-2 rounded-lg bg-gray-800 text-[10px] no-underline">XDR</a>`);
        } catch (e) {
            openInvestigationModal('Alertas', '<p>Error al cargar alertas verificables.</p>', '');
        }
    }

    global.NovusDashboardInvestigation = {
        setCaches,
        openDevice,
        investigate,
        consultKernel,
        exportDevice,
        openKpi,
        openPriorityDetail,
        cachePriority,
        refreshEventLog,
        openAlerts,
        close: closeModal,
        _eventClick: eventClick,
    };
})(window);
