# oneserver

*Unified reverse proxy and static hosting automation framework powered by Nginx*

`oneserver` is an automation utility that compiles a single, human-readable `settings.json` file into highly optimized, production-ready Nginx proxy configurations (`nginx-proxy.conf`). It supports standard reverse proxying, high-performance static file hosting, temporary/permanent redirects, custom error pages, and fine-grained rate limiting.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue?style=flat-square&logo=docker)](https://docker.com)
[![Nginx](https://img.shields.io/badge/Nginx-Compatible-green?style=flat-square&logo=nginx)](https://nginx.org)

---

## Features

- 🎯 **Unified Configuration**: Define all domains, SSL keys, timeouts, rate limits, error pages, and routing paths in a single JSON file.
- ⚡ **Static File Hosting**: High-performance static serving directly from Nginx with advanced path-to-file mapping rules.
- 🔀 **Custom Redirects**: Seamless temporary (302) and permanent (301) redirection with optional path forwarding.
- 🔒 **Security Hardening**: Generates modern SSL/TLS configurations, strict security headers (CSP, HSTS, X-Frame-Options), and gzip compression.
- 🚦 **Per-Domain Rate Limiting**: Limit request traffic globally or per-path with burst handling and nodelay configurations.
- 🛠️ **Custom Error Pages**: Domain-scoped error handlers mapping HTTP status codes (or `*` fallbacks) to custom static pages or redirects.
- 🌐 **Real IP Resolution**: Pre-configured to trust private and Docker bridge networks (`172.16.0.0/12`, etc.) to extract client IPs from `X-Forwarded-For`.
- ⚠️ **WSL2 Networking Checks**: Automatically detects WSL VM network settings and warns if running in NAT mode instead of mirrored mode.

---

## Visual Settings Editor

`oneserver` includes an interactive, browser-based editor located in [settings-editor/index.html](file:///Users/lucaszhang/oneserver/settings-editor/index.html).

You can open this file in any web browser to:
1. Load, view, and modify your existing `settings.json`.
2. Add, remove, or configure routing, redirections, and static paths visually.
3. Export the validated JSON configuration.

---

## Quick Start

### 1. Configure Domains
Create a `settings.json` file in the root directory (see [settings.json.example](file:///Users/lucaszhang/oneserver/settings.json.example) for a complete template). Comments using `//` are fully supported:

```json
[
  {
    "domain": "app.example.com",
    "forwarding": "host.docker.internal:3000",
    "type": "https-only"
  }
]
```

### 2. Generate Configuration
Run the Python compilation script:

```bash
python3 generate_nginx_config.py
```
This generates the optimized [nginx-proxy.conf](file:///Users/lucaszhang/oneserver/nginx-proxy.conf).

### 3. Deploy
Reload or restart your Nginx container:

```bash
docker compose exec oneserver nginx -t && docker compose restart oneserver
```

---

## Settings Specification (`settings.json`)

Each domain configuration object in the settings array supports the following fields:

### Core Fields
| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `domain` | String | Yes | - | The domain name to serve (e.g. `app.example.com`). |
| `forwarding` | String | Yes* | - | Backend address (`host:port`). *Not required for static hosting types.* |
| `type` | String | No | `"https-only"` | Server type. Supports: `"http"`, `"https"`, `"https-only"`, `"redirect-temp"`, `"redirect-perm"`, `"static-http"`, `"static-https"`, or `"static-https-only"`. |

### SSL / Security Fields
| Field | Type | Default | Description |
|---|---|---|---|
| `ca-bundle` | String | *Auto-inferred* | Relative path to SSL certificate file (e.g. `fullchain.pem`). Required for secure redirects and static HTTPS. |
| `private-key` | String | *Auto-inferred* | Relative path to SSL private key file (e.g. `privkey.pem`). Required for secure redirects and static HTTPS. |
| `security-headers` | Boolean | `true` | Enables HSTS, X-Frame-Options, X-Content-Type-Options, etc. |
| `csp-unsafe-eval` | Boolean | `false` | Allows `unsafe-eval` in the Content Security Policy header. |
| `csp-wildcard` | Boolean | `false` | Relaxes CSP constraints to allow wildcards in source mappings. |
| `no-x-forwarded-for` | Boolean | `false` | If `true`, Nginx will omit the `X-Forwarded-For` and `X-Real-IP` proxy headers from requests to the backend. |

### Performance & Limits
| Field | Type | Default | Description |
|---|---|---|---|
| `rate-limit` | Num / Dict | - | Rate limit per minute. Pass a number for global limit, or a path-to-limit dictionary. |
| `websocket` | Boolean | `true` | Configures upstream connection upgrade headers for WebSocket support. |
| `compression` | Boolean | `true` | Enables Gzip compression for static files and API payloads. |
| `timeout` | String | `"120s"` | Connection timeout limit (e.g., `"60s"`, `"5m"`). |
| `max-body-size` | String | `"10m"` | Maximum allowed request client body size (e.g., `"50g"`, `"500m"`). |
| `allowed-paths` | Array | `[]` | Whitelist of allowed path prefixes. Other paths return a 404 (or 403). |
| `path` | Dict | `{}` | Route-to-file mappings (required for static serving types). |
| `forward-url-path` | Boolean | `false` | If `true`, the requested URL path is appended to the forwarding target on redirects. |
| `service` | String | `""` | Tag/identifier associated with the target backend service. |

> [!NOTE]
> Snake_case variant keys (e.g. `rate_limit`, `ca_bundle`, `private_key`, `security_headers`, `csp_unsafe_eval`, `csp_wildcard`, `max_body_size`, `allowed_paths`, `proxy_buffering_off`, `proxy_cache_off`, `no_x_forwarded_for`, `forward_url_path`) are fully compatible and normalized automatically.

---

## Advanced Configurations

### Custom Redirects
By using `redirect-temp` (302) or `redirect-perm` (301), you can configure high-performance redirects at the proxy level:

```json
{
  "domain": "short.url",
  "forwarding": "https://target-domain.com/landing",
  "type": "redirect-perm",
  "forward-url-path": true,
  "ca-bundle": "fullchain.pem",
  "private-key": "privkey.pem"
}
```
* With `forward-url-path: false` (default): Visiting `short.url/hello` redirects directly to `https://target-domain.com/landing`.
* With `forward-url-path: true`: Visiting `short.url/hello` redirects to `https://target-domain.com/landing/hello`.

### Static File Server
Static serving handles route-to-file mappings relative to the `/public` directory inside the Nginx container:

```json
{
  "domain": "static.example.com",
  "type": "static-https-only",
  "ca-bundle": "fullchain.pem",
  "private-key": "privkey.pem",
  "path": {
    "/hello": "hello.html",
    "/hello/": "hello/",
    "/hello/*": "hello.html",
    "/hello/**": "hello.html"
  }
}
```
- **Exact Match** (`/hello`): Serves `/public/hello.html` exactly.
- **Directory Prefix** (`/hello/`): Serves files under `/public/hello/`.
- **Single-Segment Wildcard** (`/hello/*`): Matches `/hello/abc`, but deeper routes (e.g. `/hello/abc/def`) return a 404.
- **Recursive Wildcard** (`/hello/**`): Matches all subpaths at any depth (e.g., `/hello/abc/def/ghi`).

> [!ERROR]
> The path generator validates mappings at compile time. Source paths without a trailing slash (e.g., `/hello`) mapping to directory targets (e.g., `hello/`) will throw an error, as will defining conflicting wildcards (`/*` and `/**`) on the same base path.

---

## Custom Error Handlers

Error handlers can be configured per domain by prefixing the `type` with `{code}:` or `*:`:

```json
[
  {
    "domain": "app.example.com",
    "type": "https-only",
    "forwarding": "localhost:3000"
  },
  {
    "domain": "app.example.com",
    "type": "404:redirect-perm",
    "forwarding": "https://example.com/not-found"
  },
  {
    "domain": "app.example.com",
    "type": "500:static-https",
    "ca-bundle": "fullchain.pem",
    "private-key": "privkey.pem",
    "path": {
      "/": "errors/500.html"
    }
  },
  {
    "domain": "app.example.com",
    "type": "*:static-http",
    "path": {
      "/": "errors/fallback.html"
    }
  }
]
```
* **Specific Codes**: If Nginx or the backend returns `404` or `500`, Nginx intercepts the response and applies the redirect or serves the static error page.
* **Wildcard Fallback (`*`)**: Handles all other error status codes (400, 403, 502, 503, 504) through a single fallback page.
* **Nginx Fallback**: If no wildcard handler is defined, unhandled error codes fall back to Nginx's default error pages.

---

## Docker & Host Networking

To support low-overhead forwarding and direct host port binding in Docker, `oneserver` runs in **host network mode** inside `docker-compose.yml`:

```yaml
services:
  oneserver:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: oneserver
    network_mode: "host"
    volumes:
      - ${ONESERVER_PWD:-.}/cert:/etc/nginx/ssl:ro
      - ${ONESERVER_PWD:-.}/nginx-logs:/var/log/nginx
      - ${ONESERVER_PWD:-.}/public:/public:ro
    restart: unless-stopped
```

> [!WARNING]
> Since the container is running in `network_mode: "host"`, Nginx shares the host's networking stack directly. Avoid mapping `ports` in compose, and configure backend forwardings to point to `localhost:<port>` or `127.0.0.1:<port>`.

---

## WSL2 Networking Compatibility

If running `oneserver` inside Windows Subsystem for Linux (WSL2), Nginx's ability to see the real client IP address depends on your WSL configuration:

1. **NAT Mode (Default)**: WSL NATs all incoming connections. Nginx inside the container will see all client IPs as the virtual VM host gateway IP. The generator outputs a warning when NAT mode is detected.
2. **Mirrored Mode**: Shares the Windows host's network interfaces directly with WSL. In this mode, Nginx receives connections with the real, original public client IP intact.

To enable mirrored networking, add the following to your `%USERPROFILE%\.wslconfig` in Windows:
```ini
[wsl2]
networkingMode=mirrored
```
Then restart WSL by running `wsl --shutdown` in PowerShell.
