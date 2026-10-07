/**
 * Módulo Reportes NOVUS — vista ejecutiva; sin estructuras crudas en UI principal.
 */
(function (global) {
    const MODULE = "novus-reports-module";

    function byId(id) {
        return document.getElementById(id);
    }

    function escapeHtml(text) {
        const d = document.createElement("div");
        d.textContent = text == null ? "" : String(text);
        return d.innerHTML;
    }

    function sevClass(sev) {
        const s = String(sev || "").toLowerCase();
        if (s.indexOf("crit") >= 0 || s.indexOf("crít") >= 0) return "novus-sev-critico";
        if (s.indexOf("alto") >= 0 || s.indexOf("high") >= 0) return "novus-sev-alto";
        if (s.indexOf("med") >= 0) return "novus-sev-medio";
        if (s.indexOf("baj") >= 0 || s.indexOf("low") >= 0) return "novus-sev-bajo";
        return "novus-sev-info";
    }

    function userStatus(msg) {
        if (global.NovusRecoveryClient) {
            global.NovusRecoveryClient.showRecovery(msg || "Preparando informe...");
            return;
        }
        const status = byId("novus-report-detail-status");
        if (status) status.textContent = msg || "Preparando informe...";
    }

    function renderExecutiveCards(exec) {
        if (!exec) return "";
        const fields = [
            ["Fecha", exec.fecha],
            ["Hora", exec.hora],
            ["Usuario", exec.usuario],
            ["Equipo", exec.equipo],
            ["Red analizada", exec.red_analizada],
            ["Estado general", exec.estado_general],
            ["Nivel de riesgo", exec.nivel_riesgo],
            ["Prioridad", exec.prioridad],
        ];
        let cards = '<div class="novus-report-card-grid">';
        fields.forEach(function (pair) {
            cards +=
                '<div class="novus-report-kpi"><span class="novus-report-kpi-label">' +
                escapeHtml(pair[0]) +
                '</span><span class="novus-report-kpi-value ' +
                (pair[0].indexOf("riesgo") >= 0 || pair[0] === "Prioridad" ? sevClass(pair[1]) : "") +
                '">' +
                escapeHtml(pair[1]) +
                "</span></div>";
        });
        cards += "</div>";
        if (exec.resumen) {
            cards +=
                '<div class="novus-report-callout"><i class="fas fa-shield-alt"></i><p>' +
                escapeHtml(exec.resumen).replace(/\n/g, "<br>") +
                "</p></div>";
        }
        return cards;
    }

    function renderScanSummary(scan) {
        if (!scan) return "";
        const rows = [
            ["Equipos detectados", scan.equipos_detectados],
            ["Equipos nuevos", scan.equipos_nuevos],
            ["Equipos desconocidos", scan.equipos_desconocidos],
            ["Endpoints", scan.endpoints],
            ["Servicios analizados", scan.servicios_analizados],
            ["Tiempo del análisis", scan.tiempo_analisis],
        ];
        let html = '<table class="novus-report-table"><tbody>';
        rows.forEach(function (r) {
            html +=
                "<tr><th>" +
                escapeHtml(r[0]) +
                "</th><td>" +
                escapeHtml(r[1]) +
                "</td></tr>";
        });
        html += "</tbody></table>";
        return html;
    }

    function renderDevices(devices) {
        if (!devices || !devices.length) {
            return '<p class="novus-report-muted">No hay dispositivos documentados en este informe.</p>';
        }
        let html =
            '<table class="novus-report-table"><thead><tr><th>Nombre</th><th>IP</th><th>MAC</th><th>Tipo</th><th>Estado</th><th>Sistema operativo</th><th>Fabricante</th></tr></thead><tbody>';
        devices.forEach(function (d) {
            html +=
                "<tr><td>" +
                escapeHtml(d.nombre) +
                "</td><td>" +
                escapeHtml(d.ip) +
                "</td><td>" +
                escapeHtml(d.mac) +
                "</td><td>" +
                escapeHtml(d.tipo) +
                "</td><td>" +
                escapeHtml(d.estado) +
                "</td><td>" +
                escapeHtml(d.sistema_operativo) +
                "</td><td>" +
                escapeHtml(d.fabricante) +
                "</td></tr>";
        });
        html += "</tbody></table>";
        return html;
    }

    function renderPorts(ports) {
        if (!ports || !ports.length) {
            return '<p class="novus-report-muted">Sin puertos abiertos registrados.</p>';
        }
        let html =
            '<table class="novus-report-table"><thead><tr><th>Puerto</th><th>Servicio</th><th>Estado</th><th>Nivel de riesgo</th><th>Descripción</th></tr></thead><tbody>';
        ports.forEach(function (p) {
            html +=
                "<tr><td>" +
                escapeHtml(p.puerto) +
                "</td><td>" +
                escapeHtml(p.servicio) +
                "</td><td>" +
                escapeHtml(p.estado) +
                '</td><td class="' +
                sevClass(p.nivel_riesgo) +
                '">' +
                escapeHtml(p.nivel_riesgo) +
                "</td><td>" +
                escapeHtml(p.descripcion) +
                "</td></tr>";
        });
        html += "</tbody></table>";
        return html;
    }

    function renderVulns(vulns) {
        if (!vulns || !vulns.length) {
            return '<p class="novus-report-muted">Sin vulnerabilidades documentadas.</p>';
        }
        let html = "";
        vulns.forEach(function (v) {
            html +=
                '<article class="novus-report-finding"><header><h4>' +
                escapeHtml(v.nombre) +
                '</h4><span class="novus-report-badge ' +
                sevClass(v.criticidad) +
                '">' +
                escapeHtml(v.criticidad) +
                "</span></header>";
            html += "<p>" + escapeHtml(v.descripcion) + "</p>";
            html +=
                '<p class="novus-report-meta-line"><strong>Equipo:</strong> ' +
                escapeHtml(v.equipo) +
                "</p>";
            html +=
                '<p class="novus-report-meta-line"><strong>Evidencias:</strong> ' +
                escapeHtml(v.evidencias) +
                "</p>";
            html +=
                '<p class="novus-report-rec"><i class="fas fa-wrench"></i> ' +
                escapeHtml(v.recomendacion) +
                "</p></article>";
        });
        return html;
    }

    function renderKernel(kernel) {
        if (!kernel) return "";
        let html = '<div class="novus-report-kernel">';
        html +=
            '<p><strong>Qué encontró.</strong> ' +
            escapeHtml(kernel.que_encontro) +
            "</p>";
        html +=
            '<p><strong>Qué significa.</strong> ' +
            escapeHtml(kernel.que_significa) +
            "</p>";
        if (kernel.riesgos && kernel.riesgos.length) {
            html += "<p><strong>Riesgos.</strong></p><ul>";
            kernel.riesgos.forEach(function (r) {
                html += "<li>" + escapeHtml(r) + "</li>";
            });
            html += "</ul>";
        }
        html +=
            '<p><strong>Prioridad.</strong> <span class="' +
            sevClass(kernel.prioridad) +
            '">' +
            escapeHtml(kernel.prioridad) +
            "</span></p>";
        if (kernel.acciones_recomendadas && kernel.acciones_recomendadas.length) {
            html += "<p><strong>Acciones recomendadas.</strong></p><ul>";
            kernel.acciones_recomendadas.forEach(function (a) {
                html += "<li>" + escapeHtml(a) + "</li>";
            });
            html += "</ul>";
        }
        html += "</div>";
        return html;
    }

    function renderRecommendations(recs) {
        if (!recs) return "";
        let html = "";
        [
            ["Alta prioridad", "alta"],
            ["Prioridad media", "media"],
            ["Prioridad baja", "baja"],
        ].forEach(function (pair) {
            const items = recs[pair[1]] || [];
            if (!items.length) return;
            html += '<div class="novus-report-priority-block"><h4>' + escapeHtml(pair[0]) + "</h4><ul>";
            items.forEach(function (item) {
                html += "<li>" + escapeHtml(item) + "</li>";
            });
            html += "</ul></div>";
        });
        return html || '<p class="novus-report-muted">Sin recomendaciones adicionales.</p>';
    }

    function renderEvidences(items) {
        if (!items || !items.length) {
            return '<p class="novus-report-muted">' + escapeHtml("Sin evidencia verificable.") + "</p>";
        }
        let html = '<ul class="novus-report-evidence-list">';
        items.forEach(function (e) {
            html += "<li>" + escapeHtml(e) + "</li>";
        });
        html += "</ul>";
        return html;
    }

    function renderPresentation(pres) {
        if (!pres) return '<p class="novus-report-muted">Sin evidencia verificable.</p>';
        let html = '<div class="novus-report-doc">';
        html +=
            '<header class="novus-report-doc-title"><i class="fas fa-file-shield"></i> ' +
            escapeHtml(pres.title || "INFORME DE SEGURIDAD NOVUS") +
            "</header>";

        html += sectionBlock("Resumen ejecutivo", renderExecutiveCards(pres.executive));
        html += sectionBlock("Resumen del escaneo", renderScanSummary(pres.scan_summary));
        html += sectionBlock("Dispositivos analizados", renderDevices(pres.devices));
        html += sectionBlock("Puertos abiertos", renderPorts(pres.open_ports));
        html += sectionBlock("Vulnerabilidades", renderVulns(pres.vulnerabilities));
        html += sectionBlock(
            (pres.kernel_analysis && pres.kernel_analysis.titulo) || "Análisis del Kernel IA",
            renderKernel(pres.kernel_analysis)
        );
        html += sectionBlock("Recomendaciones", renderRecommendations(pres.recommendations));
        html += sectionBlock("Evidencias", renderEvidences(pres.evidences));
        html += "</div>";
        return html;
    }

    function sectionBlock(title, inner) {
        return (
            '<section class="novus-report-section"><h3><i class="fas fa-angle-right"></i> ' +
            escapeHtml(title) +
            "</h3>" +
            inner +
            "</section>"
        );
    }

    const NovusReports = {
        activeReportId: null,
        activeView: null,
        isAdmin: false,
        technicalJson: null,

        init() {
            const root = byId("novus-reports-root");
            if (root && root.getAttribute("data-novus-admin") === "1") {
                this.isAdmin = true;
            }
            const overlay = byId("novus-report-detail-overlay");
            if (!overlay) return;
            overlay.addEventListener("click", (e) => {
                if (e.target === overlay) this.closeDetail();
            });
            document.addEventListener("keydown", (e) => {
                if (e.key === "Escape" && overlay && !overlay.classList.contains("hidden")) {
                    this.closeDetail();
                }
            });
            const dl = byId("novus-report-detail-download");
            if (dl) {
                dl.addEventListener("click", () => this.downloadPdfFromDetail());
            }
            const tabExec = byId("novus-report-tab-executive");
            const tabTech = byId("novus-report-tab-technical");
            if (tabExec) tabExec.addEventListener("click", () => this.switchTab("executive"));
            if (tabTech) tabTech.addEventListener("click", () => this.switchTab("technical"));
        },

        switchTab(mode) {
            const exec = byId("novus-report-pane-executive");
            const tech = byId("novus-report-pane-technical");
            const tabExec = byId("novus-report-tab-executive");
            const tabTech = byId("novus-report-tab-technical");
            if (!exec || !tech) return;
            const showExec = mode === "executive";
            exec.classList.toggle("hidden", !showExec);
            tech.classList.toggle("hidden", showExec);
            if (tabExec) tabExec.classList.toggle("active", showExec);
            if (tabTech) tabTech.classList.toggle("active", !showExec);
        },

        async openDetail(reportId) {
            if (!reportId) return;
            this.activeReportId = reportId;
            const overlay = byId("novus-report-detail-overlay");
            const body = byId("novus-report-detail-body");
            const title = byId("novus-report-detail-title");
            if (!overlay || !body) return;

            overlay.classList.remove("hidden");
            requestAnimationFrame(() => overlay.classList.add("active"));
            if (title) title.textContent = "Informe " + reportId;
            body.innerHTML = '<p class="novus-report-muted">Cargando informe...</p>';
            this.switchTab("executive");

            try {
                const response = await fetch("/api/reports/" + encodeURIComponent(reportId) + "/detail-view");
                const data = await response.json();
                if (data.status === "recovering" || data.status !== "success" || !data.view) {
                    userStatus("Preparando informe...");
                    this.closeDetail();
                    return;
                }
                this.isAdmin = this.isAdmin || !!data.is_admin;
                this.technicalJson = data.view.technical_audit_json || null;
                this.activeView = data.view;
                this.renderDetail(data.view);
                const tabTech = byId("novus-report-tab-technical");
                if (tabTech) {
                    tabTech.classList.toggle("hidden", !this.isAdmin || !this.technicalJson);
                }
            } catch (err) {
                userStatus("Preparando informe...");
                this.closeDetail();
            }
        },

        renderDetail(view) {
            const body = byId("novus-report-detail-body");
            const meta = byId("novus-report-detail-meta");
            const execPane = byId("novus-report-pane-executive");
            const techPane = byId("novus-report-pane-technical");
            if (!body || !view) return;

            if (meta) {
                meta.innerHTML =
                    "<span>" +
                    escapeHtml(view.fecha) +
                    "</span> · <span>" +
                    escapeHtml(view.tipo) +
                    '</span> · <strong class="' +
                    sevClass(view.severidad) +
                    '">' +
                    escapeHtml(view.severidad) +
                    "</strong> · " +
                    escapeHtml(view.equipo);
            }

            const pres = view.presentation;
            if (execPane) {
                execPane.innerHTML = renderPresentation(pres) || '<p class="novus-report-muted">Sin evidencia verificable.</p>';
            } else {
                body.innerHTML = renderPresentation(pres);
            }

            if (techPane && this.technicalJson) {
                techPane.innerHTML =
                    '<p class="novus-report-tech-note"><i class="fas fa-lock"></i> Información técnica completa (solo administradores). No compartir con clientes finales.</p>' +
                    '<pre class="novus-report-tech-pre">' +
                    escapeHtml(this.technicalJson) +
                    "</pre>";
            }
        },

        closeDetail() {
            const overlay = byId("novus-report-detail-overlay");
            if (!overlay) return;
            overlay.classList.remove("active");
            setTimeout(() => overlay.classList.add("hidden"), 220);
        },

        downloadPdf(reportId) {
            const id = reportId || this.activeReportId;
            if (!id) return;
            global.location.href = "/api/reports/" + encodeURIComponent(id) + "/export?format=pdf";
        },

        downloadPdfFromDetail() {
            if (this.activeView && this.activeView.pdf_url) {
                global.location.href = this.activeView.pdf_url;
                return;
            }
            this.downloadPdf(this.activeReportId);
        },

        consultKernel(reportId) {
            if (!reportId) return;
            global.NovusModuleExtra = { report_id: reportId, read_only: true };
            if (typeof global.consultKernelIA === "function") {
                global.consultKernelIA("reportes", { report_id: reportId, read_only: true });
            } else if (global.NovusAIKernel && global.NovusAIKernel.consultModule) {
                global.NovusAIKernel.consultModule("reportes", { report_id: reportId, read_only: true });
            }
        },
    };

    global.NovusReports = NovusReports;
    document.addEventListener("DOMContentLoaded", () => NovusReports.init());
})(window);
