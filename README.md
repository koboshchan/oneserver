# oneserver

*Unified proxy configuration generator for Nginx and Ferron*

`oneserver` is an automation framework that translates a single `settings.json` file into highly optimized configuration files for both **Nginx** (`nginx-proxy.conf`) and **Ferron** (`ferron.kdl`). It includes a built-in visual settings editor to manage reverse proxy rules easily.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue?style=flat-square&logo=docker)](https://docker.com)
[![Nginx](https://img.shields.io/badge/Nginx-Compatible-green?style=flat-square&logo=nginx)](https://nginx.org)
[![Ferron](https://img.shields.io/badge/Ferron-Supported-orange?style=flat-square)](https://github.com/lucaszhang/ferron)

---

## Features

- 🎯 **Unified Configuration**: Maintain your routing rules, rate limits, timeouts, and SSL paths in a single JSON file.
- ⚡ **Multi-Proxy Output**: Compile config files for either **Nginx** (`nginx-proxy.conf`) or **Ferron** (`ferron.kdl`) using the same source file.
- 🛠️ **Visual Editor**: Build and manage proxy configurations in your web browser with a clean GUI interface.
- 🔒 **Production Ready**: Generates modern security headers, Gzip compression, WebSocket support, rate limiting, and HTTP-to-HTTPS redirects automatically.
- 🚀 **Advanced Routing**: Support for allowed path filters, request timeouts, request body size limits, caching controls, and proxy buffering toggles.

---

## Visual Settings Editor

`oneserver` includes a web-based visual editor located in [settings-editor/index.html](file:///Users/lucaszhang/oneserver/settings-editor/index.html).

You can open this file in any modern web browser to:
1. Load and view existing `settings.json` configurations.
2. Interactively add, delete, or configure domain rules.
3. Export the formatted JSON settings back into your project.

---

## Quick Start

### 1. Configure Domains
Create a `settings.json` file in the root directory (see [settings.json.example](file:///Users/lucaszhang/oneserver/settings.json.example) for inspiration). Comments using `//` are fully supported:

```json
[
  {
    "domain": "api.example.com",
    "forwarding": "host.docker.internal:8000",
    "type": "https-only",
    "rate-limit": {
      "/": 100,
      "/upload": 5
    }
  }
]
```

### 2. Generate Configurations

Run the generator script for your proxy of choice:

#### For Nginx
```bash
python3 generate_nginx_config.py
```
This generates an optimized [nginx-proxy.conf](file:///Users/lucaszhang/oneserver/nginx-proxy.conf).

#### For Ferron
```bash
python3 generate_ferron_config.py
```
This generates a [ferron.kdl](file:///Users/lucaszhang/oneserver/ferron.kdl) config.

### 3. Command Line Options
Both scripts support the following parameters:

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--input` | `-i` | Input settings JSON path | `settings.json` |
| `--output` | `-o` | Output configuration path | `nginx-proxy.conf` / `ferron.kdl` |
| `--dry-run` | | Print the generated output to stdout without writing | |

---

## Settings Specification (`settings.json`)

The following fields can be configured for each domain:

### Core Fields
| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `domain` | String | Yes | - | The domain name (e.g. `api.example.com`). |
| `forwarding` | String | Yes | - | Backend target address (e.g. `127.0.0.1:8080`, `host.docker.internal:3000`). |
| `type` | String | No | `"https-only"` | Protocol type: `"http"`, `"https"`, or `"https-only"` (HTTPS with HTTP redirect). |

### SSL / Security Fields
| Field | Type | Default | Description |
|---|---|---|---|
| `ca-bundle` | String | *Auto-inferred* | Relative path to SSL certificate file (e.g., `fullchain.pem`). |
| `private-key` | String | *Auto-inferred* | Relative path to SSL private key file (e.g., `privkey.pem`). |
| `security-headers` | Boolean | `true` | Enables strict security headers (HSTS, X-Frame-Options, X-Content-Type-Options). |
| `csp-unsafe-eval` | Boolean | `false` | Allows `unsafe-eval` in the Content Security Policy header. |
| `csp-wildcard` | Boolean | `false` | Relaxes CSP constraints, allowing wildcards in source mappings. |

### Performance & Limits
| Field | Type | Default | Description |
|---|---|---|---|
| `rate-limit` | Num / Dict | - | Rate limit per minute. Pass a number for global limit, or a path-to-limit dictionary. |
| `websocket` | Boolean | `true` | Configures upstream connection upgrade headers for WebSocket support. |
| `compression` | Boolean | `true` | Enables Gzip compression for static files and API payloads. |
| `timeout` | String | `"120s"` | Connection timeout limit (e.g., `"60s"`, `"10m"`). |
| `max-body-size` | String | `"10m"` | Maximum allowed request client body size (e.g., `"50g"`, `"500m"`). |
| `allowed-paths` | Array | `[]` | Limit access to specific URL paths. Requests to other paths return a 403 Forbidden. |
| `proxy-buffering-off` | Boolean | `false` | Disables proxy buffering, turning on real-time streaming for SSE/events. |
| `proxy-cache-off` | Boolean | `false` | Configures headers and proxy directives to bypass caching. |
| `service` | String | `""` | Tag/identifier associated with the target backend service. |

> [!NOTE]
> Snake_case variant keys (e.g. `rate_limit`, `ca_bundle`, `private_key`, `security_headers`, `csp_unsafe_eval`, `csp_wildcard`, `max_body_size`, `allowed_paths`, `proxy_buffering_off`, `proxy_cache_off`) are fully compatible and normalized automatically by the generator scripts.

---

## Advanced Configurations

### Rate Limiting

Rate limiting is separated per-domain to prevent resource starvation.

```json
"rate-limit": {
  "/": 200,
  "/api": 50,
  "/api/upload": 5,
  "/test/*/endpoint": 10
}
```
- **Path Precedence**: Specific endpoints take priority over general paths.
- **Wildcard Support**: Use `*` to match dynamic path segments.
- **Burst Handling**: A burst parameter with `nodelay` is automatically added to prevent false-positives on bursty browser traffic.

### Allowed Path Restriction

If `allowed-paths` is specified, Nginx and Ferron will reject requests targeting unregistered paths:

```json
"allowed-paths": ["/public", "/api/v1"]
```

---

## Docker Integration

To deploy the generated Nginx configuration:

1. **Compile config file**:
   ```bash
   python3 generate_nginx_config.py
   ```
2. **Reload / Restart Nginx**:
   ```bash
   docker compose exec oneserver nginx -t && docker compose restart oneserver
   ```
