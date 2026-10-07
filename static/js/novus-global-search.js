(function (global) {
    const NovusGlobalSearch = {
        debounceTimer: null,
        results: [],
        suggestions: [],
        activeIndex: 0,
        kernelMeta: null,
        inlineInput: null,

        escape(text) {
            const d = document.createElement("div");
            d.textContent = text == null ? "" : String(text);
            return d.innerHTML;
        },

        getActiveInput() {
            return this.inlineInput || document.getElementById("novus-global-search-input");
        },

        getResultsBox() {
            if (this.inlineInput) {
                return document.getElementById("novus-inline-search-results");
            }
            return document.getElementById("novus-search-results");
        },

        open() {
            const inline = document.querySelector('[data-novus-search-inline="true"]');
            if (inline) {
                inline.focus();
                this.inlineInput = inline;
                return;
            }
            const overlay = document.getElementById("novus-search-overlay");
            const input = document.getElementById("novus-global-search-input");
            if (!overlay || !input) return;
            overlay.classList.remove("hidden");
            requestAnimationFrame(() => overlay.classList.add("active"));
            input.value = "";
            this.results = [];
            this.suggestions = [];
            this.activeIndex = 0;
            this.clearResults();
            this.setKernelStrip("");
            setTimeout(() => input.focus(), 60);
        },

        close() {
            if (this.inlineInput) {
                this.clearResults();
                this.setKernelStrip("");
                const box = this.getResultsBox();
                if (box) box.classList.add("hidden");
                return;
            }
            const overlay = document.getElementById("novus-search-overlay");
            if (!overlay) return;
            overlay.classList.remove("active");
            setTimeout(() => overlay.classList.add("hidden"), 180);
        },

        clearResults() {
            const box = this.getResultsBox();
            if (box) box.innerHTML = "";
        },

        setKernelStrip(text) {
            const ids = this.inlineInput
                ? ["novus-inline-search-kernel"]
                : ["novus-search-kernel-strip"];
            ids.forEach((id) => {
                const el = document.getElementById(id);
                if (!el) return;
                if (!text) {
                    el.innerHTML = "";
                    el.classList.add("hidden");
                    return;
                }
                el.classList.remove("hidden");
                el.innerHTML = "<strong>Kernel IA</strong> · " + this.escape(text);
            });
        },

        highlight() {
            const box = this.getResultsBox();
            if (!box) return;
            box.querySelectorAll(".novus-search-item").forEach((el, idx) => {
                el.classList.toggle("active", idx === this.activeIndex);
            });
        },

        async recordClick(itemId) {
            if (!itemId || String(itemId).startsWith("suggest-")) return;
            try {
                await fetch("/api/search/click", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ item_id: itemId }),
                });
            } catch (e) {
                /* noop */
            }
        },

        navigate(url, itemId) {
            if (itemId) this.recordClick(itemId);
            if (!url || url === "#") return;
            this.close();
            global.location.href = url;
        },

        selectActive() {
            const all = this.buildRenderableList();
            const item = all[this.activeIndex];
            if (!item) return;
            const input = this.getActiveInput();
            if (item._suggestQuery) {
                if (input) {
                    input.value = item._suggestQuery;
                    this.search(item._suggestQuery);
                }
                return;
            }
            if (item.url) this.navigate(item.url, item.id);
        },

        buildRenderableList() {
            const list = (this.suggestions || []).map((s) =>
                Object.assign({}, s, { _suggestQuery: s.name })
            );
            return list.concat(this.results || []);
        },

        renderResults() {
            const box = this.getResultsBox();
            if (!box) return;
            const all = this.buildRenderableList();
            if (!all.length) {
                box.innerHTML = '<div class="novus-search-empty">Sin resultados</div>';
                box.classList.remove("hidden");
                return;
            }
            box.classList.remove("hidden");
            box.innerHTML = all
                .map((item, idx) => {
                    const isSuggest = !!item._suggestQuery;
                    return (
                        '<div class="novus-search-item' +
                        (idx === 0 ? " active" : "") +
                        '" data-idx="' +
                        idx +
                        '" data-url="' +
                        this.escape(item.url || "") +
                        '" data-id="' +
                        this.escape(item.id || "") +
                        '" data-suggest="' +
                        (isSuggest ? this.escape(item._suggestQuery) : "") +
                        '">' +
                        '<div class="novus-search-item-icon"><i class="fas ' +
                        this.escape(item.icon || "fa-circle") +
                        '"></i></div>' +
                        '<div class="novus-search-item-body">' +
                        '<div class="novus-search-item-name">' +
                        this.escape(item.name) +
                        "</div>" +
                        '<div class="novus-search-item-meta">' +
                        this.escape(item.location || item.type || "") +
                        "</div>" +
                        (item.description
                            ? '<div class="novus-search-item-desc">' +
                              this.escape(item.description) +
                              "</div>"
                            : "") +
                        "</div>" +
                        '<span class="novus-search-type' +
                        (isSuggest ? " suggest" : "") +
                        '">' +
                        this.escape(item.type || "") +
                        "</span></div>"
                    );
                })
                .join("");

            const self = this;
            box.querySelectorAll(".novus-search-item").forEach((el) => {
                el.addEventListener("click", () => {
                    const suggest = el.getAttribute("data-suggest");
                    if (suggest) {
                        const input = self.getActiveInput();
                        if (input) {
                            input.value = suggest;
                            self.search(suggest);
                        }
                        return;
                    }
                    self.navigate(el.getAttribute("data-url"), el.getAttribute("data-id"));
                });
                el.addEventListener("mouseenter", () => {
                    self.activeIndex = parseInt(el.getAttribute("data-idx"), 10);
                    self.highlight();
                });
            });
        },

        async search(query) {
            const q = (query || "").trim();
            if (!q) {
                this.clearResults();
                this.setKernelStrip("");
                const box = this.getResultsBox();
                if (box) box.classList.add("hidden");
                return;
            }
            try {
                const response = await fetch(
                    "/api/search?q=" + encodeURIComponent(q) + "&limit=25"
                );
                const data = await response.json();
                if (data.status !== "success") {
                    this.clearResults();
                    return;
                }
                this.results = data.results || [];
                this.suggestions = data.suggestions || [];
                this.kernelMeta = data.kernel || null;
                const k = data.kernel || {};
                let strip = k.interpretation || "";
                if (data.corrected_query && data.corrected_query !== q) {
                    strip = "Consulta corregida: «" + data.corrected_query + "». " + strip;
                }
                this.setKernelStrip(strip);
                this.activeIndex = 0;
                this.renderResults();
            } catch (err) {
                this.clearResults();
            }
        },

        onInput(value) {
            clearTimeout(this.debounceTimer);
            this.debounceTimer = setTimeout(() => this.search(value.trim()), 160);
        },

        bindKeyNav(input) {
            input.addEventListener("keydown", (e) => {
                const all = this.buildRenderableList();
                if (e.key === "ArrowDown") {
                    e.preventDefault();
                    this.activeIndex = Math.min(this.activeIndex + 1, all.length - 1);
                    this.highlight();
                } else if (e.key === "ArrowUp") {
                    e.preventDefault();
                    this.activeIndex = Math.max(this.activeIndex - 1, 0);
                    this.highlight();
                } else if (e.key === "Enter") {
                    e.preventDefault();
                    this.selectActive();
                } else if (e.key === "Escape") {
                    this.close();
                }
            });
        },

        initInline() {
            document.querySelectorAll('[data-novus-search-inline="true"]').forEach((input) => {
                if (!(input instanceof HTMLInputElement)) return;
                this.inlineInput = input;
                input.removeAttribute("readonly");
                input.classList.remove("cursor-pointer", "novus-search-trigger");
                input.classList.add("cursor-text");
                input.addEventListener("input", (e) => this.onInput(e.target.value));
                input.addEventListener("click", () => input.focus());
                input.addEventListener("focus", () => {
                    this.inlineInput = input;
                });
                this.bindKeyNav(input);
            });
            if (this.inlineInput) {
                document.addEventListener("click", (e) => {
                    const bar = this.inlineInput.closest(".novus-global-search-bar");
                    if (bar && !bar.contains(e.target)) {
                        const box = document.getElementById("novus-inline-search-results");
                        if (box) box.classList.add("hidden");
                    }
                });
            }
        },

        bindTriggers() {
            document
                .querySelectorAll("[data-novus-search-trigger]")
                .forEach((el) => {
                    if (el.getAttribute("data-novus-search-inline") === "true") return;
                    el.classList.add("novus-search-trigger");
                    el.addEventListener("click", (e) => {
                        e.preventDefault();
                        this.open();
                    });
                    el.addEventListener("focus", (e) => {
                        e.preventDefault();
                        el.blur();
                        this.open();
                    });
                });
            document.querySelectorAll(".novus-global-search-bar input").forEach((el) => {
                if (el.id === "search-input" && el.getAttribute("data-novus-search-inline") === "true") {
                    return;
                }
                if (el.id === "novus-global-search-input") return;
                el.classList.add("novus-search-trigger");
                el.addEventListener("click", (e) => {
                    e.preventDefault();
                    this.open();
                });
            });
        },

        init() {
            this.initInline();
            const input = document.getElementById("novus-global-search-input");
            const overlay = document.getElementById("novus-search-overlay");
            if (input && overlay) {
                input.addEventListener("input", (e) => this.onInput(e.target.value));
                this.bindKeyNav(input);
                overlay.addEventListener("click", (e) => {
                    if (e.target === overlay) this.close();
                });
            }

            document.addEventListener("keydown", (e) => {
                const mod = e.ctrlKey || e.metaKey;
                if (mod && (e.key === "k" || e.key === "K" || e.key === "/")) {
                    e.preventDefault();
                    this.open();
                }
            });

            this.bindTriggers();
        },
    };

    global.NovusGlobalSearch = NovusGlobalSearch;
    document.addEventListener("DOMContentLoaded", () => NovusGlobalSearch.init());
})(window);
