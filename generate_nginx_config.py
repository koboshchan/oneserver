#!/usr/bin/env python3
"""
Nginx Proxy Configuration Generator
Converts settings.json to nginx-proxy.conf
"""

import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Set
import urllib.parse


def load_settings(file_path: str) -> List[Dict[str, Any]]:
    """Load settings safely from JSON file, stripping comments if present."""
    try:
        with open(file_path, "r") as f:
            content = f.read()
        
        # Simple comment stripping (//)
        lines = []
        for line in content.splitlines():
            if "//" in line:
                line = line.split("//")[0]
            lines.append(line)
        
        settings = json.loads("\n".join(lines))

        if not isinstance(settings, list):
            raise ValueError("Settings must be a list of domain configurations")

        return settings
    except FileNotFoundError:
        print(f"Error: Settings file '{file_path}' not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{file_path}': {e}")
        sys.exit(1)


def validate_setting(setting: Dict[str, Any]) -> Dict[str, Any]:
    """Validate, normalize, and safely parse domain parameters."""
    required_fields = ["domain", "forwarding"]

    for field in required_fields:
        if field not in setting:
            raise ValueError(f"Missing required field '{field}' in domain configuration")

    # Normalize rate-limit format
    rate_limit = setting.get("rate-limit", setting.get("rate_limit", {}))
    if isinstance(rate_limit, (int, float)):
        rate_limit = {"/": rate_limit}
    elif not isinstance(rate_limit, dict):
        rate_limit = {}

    connection_type = setting.get("type", "https-only")
    if connection_type not in ["http", "https", "https-only"]:
        raise ValueError(f"Invalid type '{connection_type}'. Must be 'http', 'https', or 'https-only'")

    # Normalize allowed-paths safely
    allowed_paths = setting.get("allowed-paths", setting.get("allowed_paths", []))
    if not isinstance(allowed_paths, list):
        raise ValueError("'allowed-paths' must be a list of path strings")

    normalized_paths = []
    for path in allowed_paths:
        if not isinstance(path, str):
            raise ValueError("All entries in 'allowed-paths' must be strings")
        p = path.strip()
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/")
        normalized_paths.append(p)

    validated = {
        "domain": setting["domain"].strip(),
        "forwarding": setting["forwarding"].strip(),
        "type": connection_type,
        "ca_bundle": setting.get("ca-bundle", setting.get("ca_bundle", "")),
        "private_key": setting.get("private-key", setting.get("private_key", "")),
        "rate_limit": rate_limit,
        "websocket": setting.get("websocket", True),
        "compression": setting.get("compression", True),
        "security_headers": setting.get("security-headers", setting.get("security_headers", True)),
        "csp_unsafe_eval": setting.get("csp-unsafe-eval", setting.get("csp_unsafe_eval", False)) or False,
        "csp_wildcard": setting.get("csp-wildcard", setting.get("csp_wildcard", False)) or False,
        "timeout": setting.get("timeout", "120s"),
        "max_body_size": setting.get("max-body-size", setting.get("max_body_size", "10m")),
        "allowed_paths": normalized_paths,
        "proxy_buffering_off": setting.get("proxy-buffering-off", setting.get("proxy_buffering_off", False)) or False,
        "proxy_cache_off": setting.get("proxy-cache-off", setting.get("proxy_cache_off", False)) or False,
        "service": setting.get("service", "").strip(),
    }

    # Robust URL/host/port extraction handling IPv6 addresses seamlessly
    forwarding_target = validated["forwarding"]
    if not (forwarding_target.startswith("http://") or forwarding_target.startswith("https://")):
        forwarding_target = f"http://{forwarding_target}"
    
    try:
        parsed_url = urllib.parse.urlparse(forwarding_target)
        validated["host"] = parsed_url.hostname if parsed_url.hostname else "127.0.0.1"
        # Preserve bracket formatting if it is an explicit IPv6 string literal
        if ":" in validated["host"] and not validated["host"].startswith("["):
            validated["host"] = f"[{validated['host']}]"
        validated["port"] = parsed_url.port if parsed_url.port else 80
    except Exception:
        raise ValueError(f"Could not parse forwarding target address: {validated['forwarding']}")

    validated["upstream_name"] = validated["domain"].replace(".", "_").replace("-", "_") + "_backend"
    return validated


def build_proxy_pass_block(setting: Dict[str, Any], indent: str, rate_zone: str = "") -> str:
    """Consolidate generation logic to avoid code repetition across routes."""
    lines = [
        f"{indent}proxy_pass http://{setting['upstream_name']};",
        f"{indent}proxy_set_header Host $host;",
        f"{indent}proxy_set_header X-Real-IP $remote_addr;",
        f"{indent}proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        f"{indent}proxy_set_header X-Forwarded-Proto $scheme;",
        f"{indent}proxy_set_header X-Forwarded-Host $host;",
        f"{indent}proxy_set_header X-Forwarded-Port $server_port;"
    ]

    if rate_zone:
        lines.insert(0, f"{indent}limit_req zone={rate_zone} burst=5 nodelay;")

    if setting["websocket"]:
        lines.extend([
            f"{indent}proxy_http_version 1.1;",
            f"{indent}proxy_set_header Upgrade $http_upgrade;",
            f"{indent}proxy_set_header Connection \"upgrade\";"
        ])

    if setting["proxy_buffering_off"]:
        lines.append(f"{indent}proxy_buffering off;")
    if setting["proxy_cache_off"]:
        lines.append(f"{indent}proxy_cache off;")

    lines.extend([
        f"{indent}proxy_connect_timeout {setting['timeout']};",
        f"{indent}proxy_send_timeout {setting['timeout']};",
        f"{indent}proxy_read_timeout {setting['timeout']};"
    ])
    return "\n".join(lines)


def generate_security_headers(setting: Dict[str, Any], indent: str = "        ", is_ssl: bool = False) -> str:
    """Build standardized, robust security headers."""
    if not setting["security_headers"]:
        return ""

    headers = [
        f'{indent}add_header X-Frame-Options "SAMEORIGIN" always;',
        f'{indent}add_header X-XSS-Protection "1; mode=block" always;',
        f'{indent}add_header X-Content-Type-Options "nosniff" always;',
        f'{indent}add_header Referrer-Policy "no-referrer-when-downgrade" always;'
    ]

    if is_ssl:
        headers.append(f'{indent}add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;')

    csp = ""
    if setting["csp_wildcard"]:
        csp = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; worker-src * 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src *; img-src * data: blob:; frame-src *;"
    elif setting["csp_unsafe_eval"]:
        csp = "script-src 'self' 'unsafe-eval' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self' https: wss: data: blob:; default-src 'self' http: https: data: blob: 'unsafe-inline';"
    else:
        csp = "script-src 'self' 'unsafe-inline'; connect-src 'self' https: wss: data:; default-src 'self' http: https: data: blob: 'unsafe-inline';"

    if csp:
        headers.append(f'{indent}add_header Content-Security-Policy "{csp}" always;')

    return "\n" + "\n".join(headers)


def generate_routes(setting: Dict[str, Any], domain_safe: str, indent: str = "        ") -> str:
    """
    Unified path router logic. Evaluates and merges constraints gracefully 
    to completely circumvent potential duplicate location rules inside Nginx blocks.
    """
    blocks = []
    
    # Process rate-limit parameters mapped to distinct locations
    processed_limits: Dict[str, str] = {}
    for path, rate in setting["rate_limit"].items():
        if rate > 0:
            zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone"
            processed_limits[path] = zone_name.replace("__", "_").strip("_")

    # Context A: Target constraints specified explicitly via allowed_paths whitelist
    if setting["allowed_paths"]:
        for path in setting["allowed_paths"]:
            rate_zone = processed_limits.get(path, "")
            
            # Directory / Subpath catch matches
            blocks.append(f"{indent}location ^~ {path}/ {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone)}\n{indent}}}")
            # Literal Route Matches
            blocks.append(f"{indent}location = {path} {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone)}\n{indent}}}")
        
        # Deny unauthorized access patterns explicitly
        blocks.append(f"{indent}location / {{\n{indent}    return 404;\n{indent}}}")
        return "\n\n".join(blocks)

    # Context B: Standard deployment structure mixed with arbitrary standalone rate-limiting zones
    all_defined_paths: Set[str] = set(processed_limits.keys())
    
    # Sort paths carefully: longest string literal rules take priority structural parsing sequence
    for path in sorted(all_defined_paths, key=lambda x: (-len(x), x)):
        if path == "/":
            continue
        rate_zone = processed_limits[path]
        loc_modifier = "~ " if "*" in path else ""
        clean_path = path.replace("*", ".*") if "*" in path else path
        
        blocks.append(f"{indent}location {loc_modifier}{clean_path} {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone)}\n{indent}}}")

    # Fallback primary route block location targeting context root "/"
    root_rate_zone = processed_limits.get("/", "")
    blocks.append(f"{indent}location / {{\n{build_proxy_pass_block(setting, indent + '    ', root_rate_zone)}\n{indent}}}")

    return "\n\n".join(blocks)


def generate_upstream_blocks(settings: List[Dict[str, Any]]) -> str:
    """Generate independent upstream server block allocations cleanly mapped for individual profiles."""
    return "\n\n".join([
        f"    upstream {s['upstream_name']} {{\n        server {s['host']}:{s['port']};\n        keepalive 32;\n    }}"
        for s in settings
    ])


def generate_rate_limit_zones(settings: List[Dict[str, Any]]) -> str:
    """Build shared memory limits allocating proportional slots directly based on rulesets."""
    zones = []
    for s in settings:
        domain_safe = s["domain"].replace(".", "_").replace("-", "_")
        for path, rate in s["rate_limit"].items():
            if rate > 0:
                zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone".replace("__", "_").strip("_")
                zones.append(f"    limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={int(rate)}r/m;")
    return "\n    # Rate limiting zones\n" + "\n".join(zones) if zones else ""


def generate_http_redirect_server(settings: List[Dict[str, Any]]) -> str:
    """Generate universal port 80 routing behaviors supporting structural certificate lifecycle requests."""
    redirect_domains = [s["domain"] for s in settings if s["type"] in ["https", "https-only"]]
    forward_settings = [s for s in settings if s["type"] == "http"]
    blocks = []

    if redirect_domains:
        blocks.append(f"""    # HTTP to HTTPS redirect
    server {{
        listen 80;
        server_name {" ".join(redirect_domains)};

        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

        location / {{
            return 301 https://$host$request_uri;
        }}
    }}""")

    for s in forward_settings:
        domain_safe = s["domain"].replace(".", "_").replace("-", "_")
        gzip_toggle = "\n        gzip off;" if not s["compression"] else ""
        blocks.append(f"""    # {s['domain']} - HTTP Core Forwarding
    server {{
        listen 80;
        server_name {s['domain']};
        client_max_body_size {s['max_body_size']};{generate_security_headers(s)}{gzip_toggle}

        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

{generate_routes(s, domain_safe)}
    }}""")

    return "\n\n".join(blocks)


def generate_ssl_server_block(setting: Dict[str, Any]) -> str:
    """Generate comprehensive production-hardened TLS context configuration parameters."""
    domain = setting["domain"]
    domain_safe = domain.replace(".", "_").replace("-", "_")
    
    ssl_cert = f"/etc/nginx/ssl/{setting['ca_bundle']}" if setting["ca_bundle"] else f"/etc/nginx/ssl/{domain}/fullchain.pem"
    ssl_key = f"/etc/nginx/ssl/{setting['private_key']}" if setting["private_key"] else f"/etc/nginx/ssl/{domain}/privkey.pem"

    gzip_toggle = "\n        gzip off;" if not setting["compression"] else ""

    return f"""    # {domain} - Production TLS Context
    server {{
        listen 443 ssl;
        http2 on;
        server_name {domain};

        ssl_certificate {ssl_cert};
        ssl_certificate_key {ssl_key};
        client_max_body_size {setting['max_body_size']};{generate_security_headers(setting, is_ssl=True)}{gzip_toggle}

{generate_routes(setting, domain_safe)}
    }}"""


def generate_nginx_config(settings: List[Dict[str, Any]]) -> str:
    """Compile global unified definitions framework orchestrating secondary modular dependencies."""
    gzip_config = ""
    if any(s["compression"] for s in settings):
        gzip_config = """
    # Gzip compression
    gzip on;
    gzip_comp_level 6;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/x-javascript application/javascript text/xml application/xml application/rss+xml text/javascript image/svg+xml application/vnd.ms-fontobject application/x-font-ttf font/opentype;"""

    # Separate standard configurations from custom service templates
    standard_settings = [s for s in settings if not s["service"]]
    service_blocks = []

    for s in settings:
        if s["service"]:
            template_path = Path("services") / f"{s['service']}.conf"
            if template_path.exists():
                with open(template_path, "r") as f:
                    template = f.read()
                
                ssl_cert = f"/etc/nginx/ssl/{s['ca_bundle']}" if s['ca_bundle'] else f"/etc/nginx/ssl/{s['domain']}/fullchain.pem"
                ssl_key = f"/etc/nginx/ssl/{s['private_key']}" if s['private_key'] else f"/etc/nginx/ssl/{s['domain']}/privkey.pem"
                
                block = template.replace("{{domain}}", s["domain"]) \
                                .replace("{{upstream_name}}", s["upstream_name"]) \
                                .replace("{{ssl_cert}}", ssl_cert) \
                                .replace("{{ssl_key}}", ssl_key) \
                                .replace("{{max_body_size}}", s["max_body_size"]) \
                                .replace("{{host}}", s["host"]) \
                                .replace("{{port}}", str(s["port"]))
                service_blocks.append(f"    # Custom Service: {s['service']}\n{block}")

    ssl_servers = [generate_ssl_server_block(s) for s in standard_settings if s["type"] in ["https", "https-only"]]
    ssl_servers_text = "\n\n".join(ssl_servers) if ssl_servers else ""
    
    service_servers_text = "\n\n".join(service_blocks) if service_blocks else ""

    return f"""events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_names_hash_bucket_size 128;{gzip_config}{generate_rate_limit_zones(settings)}

    # Production SSL Hardening Context Parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Upstream Definitions
{generate_upstream_blocks(settings)}

{generate_http_redirect_server(standard_settings)}

{ssl_servers_text}

{service_servers_text}
}}"""


def main():
    parser = argparse.ArgumentParser(description="Generate production nginx proxy configurations safely from standard settings schema matrices.")
    parser.add_argument("--input", "-i", default="settings.json", help="Input parameters schema source path mapping.")
    parser.add_argument("--output", "-o", default="nginx-proxy.conf", help="Target assembly destination file output path.")
    parser.add_argument("--dry-run", action="store_true", help="Output stream raw string asset evaluation dumps to standard stdout instead.")

    args = parser.parse_args()
    settings_data = load_settings(args.input)

    try:
        validated_settings = [validate_setting(s) for s in settings_data]
    except ValueError as e:
        print(f"Validation Operational Error: {e}")
        sys.exit(1)

    nginx_config = generate_nginx_config(validated_settings)

    if args.dry_run:
        print(nginx_config)
    else:
        try:
            with open(args.output, "w") as f:
                f.write(nginx_config)
            print(f"\033[92m\u2714 Nginx proxy mapping generated successfully to: {args.output}\033[0m")
        except IOError as e:
            print(f"Disk Write Operational Error payload anomaly observed on out-stream: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
