/**
 * Acceso seguro al DOM — evita TypeError por elementos inexistentes.
 */
(function (global) {
    function byId(id) {
        if (!id) return null;
        return document.getElementById(id);
    }

    function setDisabled(id, disabled) {
        const el = byId(id);
        if (el && 'disabled' in el) {
            el.disabled = !!disabled;
            return true;
        }
        return false;
    }

    function setText(id, text) {
        const el = byId(id);
        if (el) {
            el.textContent = text == null ? '' : String(text);
            return true;
        }
        return false;
    }

    function setHtml(id, html) {
        const el = byId(id);
        if (el) {
            el.innerHTML = html == null ? '' : String(html);
            return true;
        }
        return false;
    }

    function setStyle(id, prop, value) {
        const el = byId(id);
        if (el && el.style) {
            el.style[prop] = value;
            return true;
        }
        return false;
    }

    function on(id, event, handler) {
        const el = byId(id);
        if (el) {
            el.addEventListener(event, handler);
            return true;
        }
        return false;
    }

    global.NovusDom = {
        byId,
        setDisabled,
        setText,
        setHtml,
        setStyle,
        on,
        userStatus(message) {
            return message || 'NOVUS está procesando la solicitud...';
        },
    };
})(window);
