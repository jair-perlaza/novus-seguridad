# NOVUS — Acceso remoto privado (beta)

NOVUS está preparado para compartirse con personas autorizadas mediante un **túnel HTTPS** mientras su PC/servidor de desarrollo permanece encendido. No requiere abrir puertos en el router.

## Requisitos previos

1. NOVUS ejecutándose en el puerto **5000** (`HOST=0.0.0.0`).
2. Archivo `.env` basado en `.env.example` con:
   - `NOVUS_ENV=beta`
   - `SECRET_KEY` (cadena aleatoria larga)
   - `NOVUS_ALLOW_REGISTRATION=False`
   - `NOVUS_BEHIND_PROXY=True`
   - `SESSION_COOKIE_SECURE=True` y `REMEMBER_COOKIE_SECURE=True`
   - `PREFERRED_URL_SCHEME=https`
3. Credenciales de usuario creadas previamente en la base de datos (sin registro público).

## Paso 1 — Iniciar NOVUS

```powershell
cd C:\NOVUS
py main.py
```

Verifique que responde en `http://127.0.0.1:5000/login`.

## Paso 2 — Crear túnel (Cloudflare Tunnel, ejemplo)

**No se instala automáticamente.** Usted ejecuta el túnel en otra terminal:

```powershell
cloudflared tunnel --url http://127.0.0.1:5000
```

Cloudflare mostrará una URL HTTPS temporal, por ejemplo:
`https://novus-xxxxx.trycloudflare.com`

## Paso 3 — Configurar URL pública

Añada en `.env` (opcional pero recomendado para OAuth Gmail):

```
NOVUS_PUBLIC_URL=https://novus-xxxxx.trycloudflare.com
```

Reinicie NOVUS para aplicar cambios de entorno.

## Paso 4 — Compartir con socios

1. Comparta **solo la URL del túnel** + credenciales individuales.
2. El socio abrirá la URL → verá **Login** → accede al Dashboard tras autenticarse.
3. Mantenga abierta la terminal del túnel mientras dure la sesión remota.

## Alternativas de túnel

| Herramienta | Comando orientativo |
|-------------|---------------------|
| Cloudflare | `cloudflared tunnel --url http://127.0.0.1:5000` |
| ngrok | `ngrok http 5000` |
| localtunnel | `npx localtunnel --port 5000` |

## Seguridad implementada

- Autenticación obligatoria en todas las rutas y APIs (excepto login/logout).
- Registro público deshabilitado en modo `beta`.
- Rate limiting en login y APIs.
- Cabeceras de seguridad HTTP.
- Soporte `ProxyFix` para túneles/proxies inversos.
- Rutas de prueba (`test_sector_auth`) bloqueadas.
- URLs relativas en el frontend (sin dependencia de localhost).

## Notas

- La URL del túnel **cambia** en cada sesión (salvo túnel con nombre fijo en Cloudflare).
- No exponga el puerto 5000 directamente en Internet.
- Use HTTPS del túnel; las cookies seguras requieren `SESSION_COOKIE_SECURE=True`.
