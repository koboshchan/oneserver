# oneserver

**One settings file. Multiple domains. Nginx at the edge.**

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)](Dockerfile)
[![Nginx](https://img.shields.io/badge/Nginx-1.31.9-009639?logo=nginx&logoColor=white)](Dockerfile)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

oneserver turns a JSON array of domain settings into a complete Nginx configuration. Route requests to containerized applications, serve static files, and manage redirects without maintaining a separate server block for every domain.

The generator uses the Python standard library. Docker builds the configuration with Python 3.11, then copies it into an Nginx Alpine image.

[Quick start](#quick-start) · [Configuration](#configuration) · [Docker](#docker) · [Certificates](#certificates) · [Troubleshooting](#security-and-troubleshooting)

## Features

| Capability | What it provides |
| --- | --- |
| Reverse proxy | HTTP or HTTPS upstreams, WebSocket upgrade headers, timeouts, upload limits, and streaming controls |
| Static hosting | Exact paths, directory prefixes, and single-level or recursive wildcard mappings |
| Redirects | 301 or 302 responses with optional request-path forwarding |
| Traffic controls | Per-domain or per-path request limits and allowed-path rules |
| Error handling | Domain-specific numeric status handlers and a separate unknown-host default server |
| Service templates | Dedicated Jellyfin and Open WebUI configurations |
| Settings editor | A local browser UI for importing, editing, and downloading JSON |

## Quick start

Install Python 3.11 for local generation. Deployment additionally needs Docker Engine with Compose, available ports 80 and 443, and reachable upstream services. Public HTTPS also needs DNS pointing to the host and valid certificates.

```sh
git clone https://github.com/koboshchan/oneserver.git
cd oneserver
```

Create `settings.json` with a minimal HTTP route. Use a backend name resolvable from the Nginx container.

```json
[
  {
    "domain": "app.example.com",
    "type": "http",
    "forwarding": "app:3000"
  }
]
```

Generate a configuration for inspection.

```sh
python3 generate_nginx_config.py --input settings.json --output nginx-proxy.conf
```

| Option | Default | Purpose |
| --- | --- | --- |
| `--input`, `-i` | `settings.json` | Read settings from another file |
| `--output`, `-o` | `nginx-proxy.conf` | Choose the generated file |
| `--dry-run` | Off | Print the configuration without writing it |

Run the generator from the repository root so it can find `services/`. Generation validates settings and emits text. It does not check certificates, resolve upstream hosts, or reload Nginx.

## Configuration

The input must be an array, with one primary entry per domain. The generator accepts `//` comments outside strings. Use the examples here as a starting point.

| Setting | Default | Behavior |
| --- | --- | --- |
| `domain` | Required | Hostname for the route |
| `type` | `https-only` | Route mode from the table below |
| `forwarding` | Required for proxies and redirects | Upstream `host:port` or `http(s)://host:port`, or a redirect destination |
| `ca-bundle`, `private-key` | Domain-specific paths for proxies | Certificate filenames relative to `/etc/nginx/ssl/` |
| `path` | `{}` | Static URL-to-file mappings relative to `/public/` |
| `service` | Empty | Load `services/<name>.conf` instead of the generic TLS server block |
| `rate-limit` | None | Requests per minute, as a number or a path-to-number object |
| `allowed-paths` | `[]` | Restrict proxy or redirect routes, returning 404 elsewhere |
| `timeout` | `120s` | Proxy connect, send, and read timeouts |
| `max-body-size` | `10m` | Maximum client request body size |
| `websocket` | `true` | Send upstream connection-upgrade headers |
| `compression` | `true` | Enable gzip for supported content types |
| `security-headers` | `true` | Emit CSP and other headers, including HSTS on TLS routes |
| `csp-unsafe-eval`, `csp-wildcard` | `false` | Relax the generated CSP |
| `proxy-buffering-off`, `proxy-cache-off` | `false` | Disable proxy buffering or caching |
| `proxy-intercept-errors` | `false` | Let Nginx apply error handlers to upstream error responses |
| `no-x-forwarded-for` | `false` | Omit generated X-Forwarded-For and X-Real-IP headers |
| `no-x-forwarded-host` | `false` | Omit the generated X-Forwarded-Host header |
| `forward-url-path` | `false` | Append the incoming request path and query to a redirect |

Hyphenated option names in this table also accept underscore spellings. Service templates have their own behavior and ignore many generic options.

| Route type | Behavior |
| --- | --- |
| `http` | Proxy on port 80 |
| `https`, `https-only` | Proxy on port 443 and redirect HTTP to HTTPS |
| `static-http` | Serve static files on port 80 |
| `static-https`, `static-https-only` | Serve static files over HTTPS and redirect HTTP |
| `redirect-temp`, `redirect-perm` | Redirect over HTTPS with 302 or 301, with an HTTP-to-HTTPS redirect first |

### HTTPS proxy and streaming

Place `fullchain.pem` and `privkey.pem` in `cert/` for this shared-certificate example. The certificate must cover the configured hostname.

```json
[
  {
    "domain": "app.example.com",
    "type": "https-only",
    "forwarding": "app:3000",
    "ca-bundle": "fullchain.pem",
    "private-key": "privkey.pem",
    "websocket": false,
    "proxy-buffering-off": true,
    "proxy-cache-off": true,
    "timeout": "600s",
    "max-body-size": "25m",
    "rate-limit": {
      "/api/": 120,
      "/": 300
    }
  }
]
```

Without explicit certificate filenames, HTTPS proxy routes look under `cert/<domain>/`. Redirects and secure static routes require explicit certificate filenames. Rate limits use per-client-IP buckets with a burst of five and `nodelay`; separate path rules use separate buckets, not one aggregate quota.

### Static files and redirects

```json
[
  {
    "domain": "static.example.com",
    "type": "static-https-only",
    "ca-bundle": "fullchain.pem",
    "private-key": "privkey.pem",
    "path": {
      "/hello": "hello.html",
      "/assets/": "assets/",
      "/preview/*": "preview.html",
      "/docs/**": "docs/"
    }
  },
  {
    "domain": "old.example.com",
    "type": "redirect-perm",
    "forwarding": "https://app.example.com",
    "forward-url-path": true,
    "ca-bundle": "fullchain.pem",
    "private-key": "privkey.pem"
  }
]
```

Files are served from the mounted `public/` directory. `/*` matches one path segment; `/**` matches recursively. A source without a trailing slash cannot map to a directory target, and the same base cannot define both wildcard forms.

> [!WARNING]
> Static mappings are not an access allowlist. Unless you map `/`, the generator also adds a root fallback that serves files from `/public`. Put only public content in this directory.

### Error pages and unknown hosts

Add a separate entry with the same `domain` and a numeric prefix such as `"type": "404:static-http"`, with `"path": {"/": "errors/404.html"}`. For upstream error responses, enable `proxy-intercept-errors` on the main proxy entry.

An error entry must have a matching primary domain entry. Numeric status codes from 300 through 599 are accepted, with no duplicates per domain. Wildcard error types such as `*:static-http` are not supported.

At most one `default-server` entry can handle unmatched hostnames. Use an explicit mode such as `default-server:http` with a `forwarding` target. Without a configured default server, unmatched hosts receive 404. A TLS default server still needs a usable certificate.

> [!NOTE]
> [settings.json.example](settings.json.example) contains older examples, including an unsupported wildcard error handler. It is a field reference, not a configuration to deploy unchanged.

### Service templates and editor

Set `"service": "jellyfin"` or `"service": "openwebui"` on a proxy entry to use a template from [services/](services/). Templates substitute the domain, upstream, certificate paths, body-size limit, and error-handler placeholders. They define their own headers, buffering, timeouts, and other behavior. The generator warns when explicitly supplied options are ignored by a template.

Open [settings-editor/index.html](settings-editor/index.html) locally in a browser to import a file, edit fields or raw JSON, and download `settings.json`. The editor uses strict JSON, so remove comments before importing. Its type picker covers basic proxy types; use raw JSON for advanced entries. Downloading settings does not apply them to the server.

## Docker

The checked-in [Dockerfile](Dockerfile) generates configuration during a multi-stage build. The stock [Compose file](docker-compose.yml) publishes ports 80 and 443 and mounts certificates, logs, and public files.

| Host location | Container location | Purpose |
| --- | --- | --- |
| `cert/` | `/etc/nginx/ssl` | Read-only certificates and private keys |
| `nginx-logs/` | `/var/log/nginx` | Access and error logs |
| `public/` | `/public` | Read-only static content |

`ONESERVER_PWD` overrides the host base path for these mounts. It does not change the Docker build context.

Attach application containers to the shared `oneserver_bridge` network. Other Compose projects should declare that network as external. Use the application container's network name and internal port as `forwarding`; `localhost` inside Nginx refers to Nginx itself.

For a new installation, after checking settings, certificates, upstream connectivity, and port availability, build and start the proxy.

```sh
docker compose up -d --build
docker compose exec oneserver nginx -t
```

> [!IMPORTANT]
> In stock Compose, the configuration is baked into the image. Editing `settings.json` or generating a host-side `nginx-proxy.conf` does not update a running container. Rebuild and recreate it to apply changes. Installations that separately bind-mount `nginx-proxy.conf` must validate and reload that mounted configuration instead. Check the actual Compose file before choosing an update workflow, and preserve any deployment-specific overrides.

## Certificates

oneserver does not issue or automatically renew certificates. You can supply your own certificate files under `cert/`.

An optional sibling [oneservercertbot](https://github.com/koboshchan/oneservercertbot) project provides a `run.sh` entry point for a standalone HTTP-01 Certbot workflow. It collects secure domains from the settings, rewrites their certificate filenames, copies the resulting shared certificate into oneserver, and attempts a Compose rebuild.

> [!CAUTION]
> The companion workflow is disruptive. It stops oneserver to free port 80, clears its own certificate working directory, rewrites `settings.json`, and grants broad permissions to certificate files. It mounts the Docker socket and must be treated as privileged host administration. Back up settings and both certificate directories, review the script, include every required secure domain, and arrange a maintenance window before running it. Do not treat it as an unattended renewal service.

The companion uses a simpler comment parser than the generator, so review settings containing literal double slashes before using it. Its final Compose command is not reliably reflected in its exit status. Inspect issuance and build logs, validate Nginx, and verify public HTTPS for all domains afterward.

## Security and troubleshooting

> [!WARNING]
> Settings and service templates generate Nginx directives and should only come from trusted administrators. Generated real-IP configuration trusts broad private network ranges. Verify that every trusted hop sanitizes forwarded headers before relying on client-IP rate limits or audit logs.

| Symptom | Check |
| --- | --- |
| Certificate file missing | Confirm the configured path exists inside `/etc/nginx/ssl`, including the default TLS server's certificate |
| Host not found or 502 | Check the upstream name, internal port, shared network, and application availability |
| Changes are not visible | Determine whether configuration is image-baked or bind-mounted before rebuilding or reloading |
| Service option has no effect | Inspect the selected `services/*.conf` template and generator warnings |
| JSON parsing or wildcard error | Use supported numeric error handlers and account for strict JSON in the editor |
| All clients share a rate-limit bucket | Verify forwarded-header trust and the Docker/WSL network path |

The generator warns when it detects WSL2 NAT networking. Mirrored networking may help preserve client addresses, but verify the complete forwarding path. Networking changes and WSL restarts interrupt running workloads and should be scheduled separately.

[generate_nginx_config.py](generate_nginx_config.py) is the active implementation. The Ferron generator and `.kdl` templates are legacy; the Ferron entry point exits with a deprecation error.

## License

[MIT](LICENSE)
