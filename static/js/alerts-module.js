/**
 * Módulo de presentación de alertas NOVUS — sin JSON crudo al cliente.
 */
(function (global) {
    'use strict';

    function esc(s) {
        if (s == null) return '';
        return String(s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function riskClass(level) {
        const l = String(level || '').toUpperCase();
        if (l.includes('CRIT')) return 'text-red-400 bg-red-950/40 border-red-800';
        if (l.includes('HIGH') || l.includes('ALTA')) return 'text-orange-300 bg-orange-950/30 border-orange-800';
        if (l.includes('MED')) return 'text-yellow-300 bg-yellow-950/20 border-yellow-800';
        return 'text-blue-300 bg-blue-950/20 border-blue-800';
    }

    function statusBadge(status) {
        const s = String(status || 'activo').toLowerCase();
        if (s.includes('resuel')) return '<span class="px-2 py-0.5 rounded text-[10px] bg-green-900/40 text-green-300 border border-green-800">Resuelto</span>';
        if (s.includes('escal')) return '<span class="px-2 py-0.5 rounded text-[10px] bg-red-900/40 text-red-300 border border-red-800 animate-pulse">Activa — escalada</span>';
        return '<span class="px-2 py-0.5 rounded text-[10px] bg-red-900/30 text-red-200 border border-red-800/60">Activa</span>';
    }

    function renderEvidenceList(items) {
        if (!items || !items.length) {
            return '<p class="text-sm text-gray-500 italic">Sin evidencias estructuradas.</p>';
        }
        return `<ul class="space-y-2">${items.map(it =>
            `<li class="flex gap-2 text-sm"><span class="text-gray-500 shrink-0">${esc(it.label)}:</span><span class="text-gray-200">${esc(it.value)}</span></li>`
        ).join('')}</ul>`;
    }

    function renderTimeline(timeline) {
        if (!timeline || !timeline.length) {
            return '<p class="text-sm text-gray-500 italic">Sin eventos de cronología registrados.</p>';
        }
        return timeline.map(ev =>
            `<div class="border-l-2 border-indigo-700 pl-3 py-1 text-xs">
                <span class="text-gray-500 font-mono">${esc(ev.time || '—')}</span>
                <span class="text-indigo-300 ml-2">${esc(ev.phase || '')}</span>
                <span class="text-gray-300"> · ${esc(ev.action || ev.detail || '')}</span>
            </div>`
        ).join('');
    }

    function renderAlertCard(alert) {
        const id = alert.id || 'ALT-UNK';
        const actions = (alert.auto_actions || []).slice(0, 4).map(a =>
            `<span class="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">${esc(a)}</span>`
        ).join(' ');

        return `
        <article class="glass-card rounded-xl p-5 md:p-6 border border-gray-800 hover:border-indigo-800/50 transition-colors" data-alert-id="${esc(id)}">
            <div class="flex flex-wrap items-start justify-between gap-3 mb-4">
                <div>
                    <p class="text-[10px] uppercase tracking-widest text-gray-500 font-bold">${esc(id)}</p>
                    <h2 class="text-lg font-bold text-white mt-1">${esc(alert.threat_type || 'Alerta de seguridad')}</h2>
                </div>
                ${statusBadge(alert.status)}
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-sm mb-4">
                <div><span class="text-gray-500 text-xs uppercase">Nivel de riesgo</span><p class="font-semibold ${riskClass(alert.risk_level).split(' ')[0]}">${esc(alert.risk_level || '—')}</p></div>
                <div><span class="text-gray-500 text-xs uppercase">Confianza</span><p class="text-gray-200">${esc(alert.confidence || 'Sin dato')}</p></div>
                <div><span class="text-gray-500 text-xs uppercase">Origen</span><p class="text-gray-200 font-mono">${esc(alert.origin || '—')}</p></div>
                <div><span class="text-gray-500 text-xs uppercase">Fecha</span><p class="text-gray-200">${esc(alert.date || '—')}</p></div>
                <div><span class="text-gray-500 text-xs uppercase">Hora</span><p class="text-gray-200 font-mono">${esc(alert.time || '—')}</p></div>
                <div><span class="text-gray-500 text-xs uppercase">Motor</span><p class="text-indigo-300 text-xs">${esc(alert.motor || '—')}</p></div>
            </div>
            <div class="mb-4">
                <p class="text-xs uppercase text-gray-500 mb-1">Evidencias encontradas</p>
                <p class="text-sm text-gray-300">${esc(alert.evidence_summary || '—')}</p>
            </div>
            <div class="mb-4 flex flex-wrap gap-2 items-center">
                <span class="text-xs text-gray-500 uppercase">Remediación:</span>
                <span class="text-xs text-gray-300">${esc(alert.remediation_status || 'Pendiente')}</span>
            </div>
            ${actions ? `<div class="mb-4 flex flex-wrap gap-1">${actions}</div>` : ''}
            <div class="flex flex-wrap gap-2 pt-3 border-t border-gray-800">
                <button type="button" class="novus-alert-btn px-3 py-1.5 rounded-lg bg-gray-800 text-xs text-gray-200 hover:bg-gray-700" data-action="evidence" data-id="${esc(id)}">Ver evidencias</button>
                <button type="button" class="novus-alert-btn px-3 py-1.5 rounded-lg bg-indigo-900/40 text-xs text-indigo-200 border border-indigo-800 hover:bg-indigo-800/40" data-action="kernel" data-id="${esc(id)}">Consultar Kernel IA</button>
                <button type="button" class="novus-alert-btn px-3 py-1.5 rounded-lg bg-gray-800 text-xs text-gray-200 hover:bg-gray-700" data-action="timeline" data-id="${esc(id)}">Ver cronología</button>
                <button type="button" class="novus-alert-btn px-3 py-1.5 rounded-lg bg-gray-800 text-xs text-gray-200 hover:bg-gray-700" data-action="playbook" data-id="${esc(id)}">Ver playbook</button>
                <button type="button" class="novus-alert-btn px-3 py-1.5 rounded-lg bg-gray-800 text-xs text-gray-200 hover:bg-gray-700" data-action="technical" data-id="${esc(id)}">Ver detalles técnicos</button>
            </div>
        </article>`;
    }

    function openModal(title, bodyHtml, footerHtml) {
        let modal = document.getElementById('novus-alerts-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'novus-alerts-modal';
            modal.className = 'fixed inset-0 z-[9000] flex items-center justify-center p-4 bg-black/70';
            modal.innerHTML = `
                <div class="bg-[#0d1117] border border-gray-700 rounded-xl max-w-2xl w-full max-h-[85vh] overflow-hidden shadow-2xl">
                    <div class="flex justify-between items-center px-5 py-4 border-b border-gray-800">
                        <h3 id="novus-alerts-modal-title" class="text-sm font-bold text-white"></h3>
                        <button type="button" id="novus-alerts-modal-close" class="text-gray-400 hover:text-white text-xl">&times;</button>
                    </div>
                    <div id="novus-alerts-modal-body" class="p-5 overflow-y-auto max-h-[60vh] text-sm text-gray-300"></div>
                    <div id="novus-alerts-modal-footer" class="px-5 py-3 border-t border-gray-800 flex gap-2 justify-end"></div>
                </div>`;
            document.body.appendChild(modal);
            modal.querySelector('#novus-alerts-modal-close').onclick = closeModal;
            modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
        }
        document.getElementById('novus-alerts-modal-title').textContent = title;
        document.getElementById('novus-alerts-modal-body').innerHTML = bodyHtml;
        document.getElementById('novus-alerts-modal-footer').innerHTML = footerHtml || '';
        modal.classList.remove('hidden');
        modal.style.display = 'flex';
    }

    function closeModal() {
        const modal = document.getElementById('novus-alerts-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    async function fetchAlert(id) {
        const r = await fetch(`/api/security/alerts/${encodeURIComponent(id)}`);
        const d = await r.json();
        if (d.status !== 'ok') throw new Error(d.message || 'Error');
        return d.alert;
    }

    async function handleAction(action, id, cached) {
        try {
            const alert = cached || await fetchAlert(id);
            switch (action) {
                case 'evidence':
                    openModal('Evidencias — ' + id, renderEvidenceList(alert.evidence_items), '');
                    break;
                case 'kernel':
                    window.NovusModuleExtra = { incident_id: id, alert_id: id };
                    if (typeof consultKernelIA === 'function') {
                        closeModal();
                        consultKernelIA('incidentes', { incident_id: id, alert_id: id });
                    }
                    break;
                case 'timeline':
                    openModal('Cronología — ' + id, renderTimeline(alert.timeline), '');
                    break;
                case 'playbook':
                    openModal('Playbook aplicado', alert.playbook_id
                        ? `<p>Playbook: <strong>${esc(alert.playbook_id)}</strong></p>`
                        : '<p class="text-gray-500 italic">Ningún playbook automático vinculado a esta alerta.</p><a href="/playbooks" class="text-indigo-400 text-sm">Ir a Playbooks</a>', '');
                    break;
                case 'technical': {
                    const tr = await fetch(`/api/security/alerts/${encodeURIComponent(id)}?technical=1`);
                    const td = await tr.json();
                    const items = td.alert?.technical_detail || [];
                    openModal('Detalles técnicos — ' + id, renderEvidenceList(Array.isArray(items) ? items : []), '');
                    break;
                }
                default:
                    break;
            }
        } catch (err) {
            openModal('Error', `<p class="text-red-400">${esc(err.message)}</p>`, '');
        }
    }

    function bindCardActions(container, alertsById) {
        container.querySelectorAll('.novus-alert-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.dataset.action;
                const id = btn.dataset.id;
                handleAction(action, id, alertsById[id]);
            });
        });
    }

    function renderAlertsList(alerts, containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        const byId = {};
        alerts.forEach(a => { byId[a.id] = a; });
        if (!alerts.length) {
            container.innerHTML = `
                <div class="glass-card rounded-xl p-16 text-center text-gray-500">
                    <i class="fas fa-shield-alt text-4xl text-gray-700 mb-4"></i>
                    <p>No hay alertas activas con evidencia verificable en este momento.</p>
                </div>`;
            return;
        }
        container.innerHTML = alerts.map(renderAlertCard).join('');
        bindCardActions(container, byId);
    }

    async function loadAndRender(containerId) {
        const r = await fetch('/api/security/alerts');
        const d = await r.json();
        renderAlertsList(d.alerts || [], containerId);
        return d;
    }

    function renderDashboardAlertsModal(alerts) {
        if (!alerts.length) {
            return '<p class="text-sm text-gray-400">No hay alertas activas con evidencia verificable.</p>';
        }
        return alerts.slice(0, 8).map(a => `
            <div class="border-b border-gray-800 py-3 last:border-0">
                <div class="flex justify-between gap-2">
                    <span class="text-xs font-bold text-white">${esc(a.threat_type)}</span>
                    ${statusBadge(a.status)}
                </div>
                <p class="text-[10px] text-gray-500 mt-1">${esc(a.motor)} · ${esc(a.origin)} · ${esc(a.date)} ${esc(a.time)}</p>
                <p class="text-xs text-gray-400 mt-1">${esc(a.evidence_summary)}</p>
            </div>`).join('');
    }

    global.NovusAlerts = {
        renderAlertCard,
        renderAlertsList,
        loadAndRender,
        openModal,
        closeModal,
        handleAction,
        renderDashboardAlertsModal,
        esc,
    };
})(window);
