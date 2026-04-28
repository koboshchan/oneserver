#!/usr/bin/env python3
"""
Nginx Proxy Configuration Generator
Converts settings.json to nginx-proxy.conf

Usage: python generate_nginx_config.py [--input settings.json] [--output nginx-proxy.conf]
"""

import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any


def load_settings(file_path: str) -> List[Dict[str, Any]]:
    """Load settings from JSON file."""
    try:
        with open(file_path, "r") as f:
            settings = json.load(f)

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
    """Validate and normalize a single domain setting."""
    required_fields = ["domain", "forwarding"]

    for field in required_fields:
        if field not in setting:
            raise ValueError(
                f"Missing required field '{field}' in domain configuration"
            )

    # Handle rate-limit (can be number or object)
    rate_limit = setting.get("rate-limit", {})
    if isinstance(rate_limit, (int, float)):
        # Convert number to object format for consistency
        rate_limit = {"/": rate_limit}
    elif not isinstance(rate_limit, dict):
        rate_limit = {}

    # Validate type field
    connection_type = setting.get("type", "https-only")
    if connection_type not in ["http", "https", "https-only"]:
        raise ValueError(
            f"Invalid type '{connection_type}'. Must be 'http', 'https', or 'https-only'"
        )

    # Validate allowed-paths
    allowed_paths = setting.get("allowed-paths", [])
    if not isinstance(allowed_paths, list):
        raise ValueError("'allowed-paths' must be a list of path strings")

    # Normalize paths (ensure they start with / and don't end with /)
    normalized_paths = []
    for path in allowed_paths:
        if not isinstance(path, str):
            raise ValueError("All entries in 'allowed-paths' must be strings")
        normalized_path = path.strip()
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path
        if len(normalized_path) > 1 and normalized_path.endswith("/"):
            normalized_path = normalized_path.rstrip("/")
        normalized_paths.append(normalized_path)

    # Set defaults
    validated = {
        "domain": setting["domain"].strip(),
        "forwarding": setting["forwarding"].strip(),
        "type": connection_type,
        "ca_bundle": setting.get("ca-bundle", ""),
        "private_key": setting.get("private-key", ""),
        "rate_limit": rate_limit,
        "websocket": setting.get("websocket", True),
        "compression": setting.get("compression", True),
        "security_headers": setting.get("security-headers", True),
        "csp_unsafe_eval": setting.get("csp-unsafe-eval")
        or setting.get("csp_unsafe_eval"),
        "csp_wildcard": setting.get("csp-wildcard") or setting.get("csp_wildcard"),
        "timeout": setting.get("timeout", "120s"),
        "max_body_size": setting.get("max-body-size", "10m"),
        "allowed_paths": normalized_paths,
        "proxy_buffering_off": setting.get("proxy-buffering-off", False),
        "proxy_cache_off": setting.get("proxy-cache-off", False),
    }

    # Parse forwarding address
    if ":" in validated["forwarding"]:
        host, port = validated["forwarding"].split(":", 1)
        validated["host"] = host
        validated["port"] = int(port)
    else:
        validated["host"] = validated["forwarding"]
        validated["port"] = 80

    # Generate upstream name
    validated["upstream_name"] = (
        validated["domain"].replace(".", "_").replace("-", "_") + "_backend"
    )

    return validated


def generate_upstream_blocks(settings: List[Dict[str, Any]]) -> str:
    """Generate upstream server blocks."""
    upstreams = []

    for setting in settings:
        upstream = f"""    upstream {setting["upstream_name"]} {{
        server {setting["host"]}:{setting["port"]};
        keepalive 32;
    }}"""
        upstreams.append(upstream)

    return "\n\n".join(upstreams)


def generate_location_blocks(
    setting: Dict[str, Any],
    upstream_name: str,
    websocket_headers: str,
    timeout: str,
    indent: str = "        ",
) -> str:
    """Generate location blocks for allowed paths or main location."""
    extra_proxy_directives = ""
    if setting.get("proxy_buffering_off"):
        extra_proxy_directives += f"\n{indent}    proxy_buffering off;"
    if setting.get("proxy_cache_off"):
        extra_proxy_directives += f"\n{indent}    proxy_cache off;"
    # If allowed-paths is specified, generate blocks only for those paths
    if setting["allowed_paths"]:
        location_blocks = []

        # Generate location blocks for each allowed path
        for path in setting["allowed_paths"]:
            location_block = f"""{indent}# Allow access to {path}
{indent}location ^~ {path}/ {{
{indent}    proxy_pass http://{upstream_name};
{indent}    proxy_set_header Host $host;
{indent}    proxy_set_header X-Real-IP $remote_addr;
{indent}    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
{indent}    proxy_set_header X-Forwarded-Proto $scheme;
{indent}    proxy_set_header X-Forwarded-Host $host;
{indent}    proxy_set_header X-Forwarded-Port $server_port;{websocket_headers}{extra_proxy_directives}

{indent}    # Timeouts
{indent}    proxy_connect_timeout {timeout};
{indent}    proxy_send_timeout {timeout};
{indent}    proxy_read_timeout {timeout};
{indent}}}
{indent}
{indent}# Allow exact path matches
{indent}location = {path} {{
{indent}    proxy_pass http://{upstream_name};
{indent}    proxy_set_header Host $host;
{indent}    proxy_set_header X-Real-IP $remote_addr;
{indent}    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
{indent}    proxy_set_header X-Forwarded-Proto $scheme;
{indent}    proxy_set_header X-Forwarded-Host $host;
{indent}    proxy_set_header X-Forwarded-Port $server_port;{websocket_headers}{extra_proxy_directives}

{indent}    # Timeouts
{indent}    proxy_connect_timeout {timeout};
{indent}    proxy_send_timeout {timeout};
{indent}    proxy_read_timeout {timeout};
{indent}}}"""
            location_blocks.append(location_block)

        # Add catch-all 404 for non-allowed paths
        catch_all_block = f"""
{indent}# Block all other paths
{indent}location / {{
{indent}    return 404;
{indent}}}"""
        location_blocks.append(catch_all_block)

        return "\n\n".join(location_blocks)
    else:
        # Original behavior - allow all paths
        return f"""
{indent}# Main application
{indent}location / {{
{indent}    proxy_pass http://{upstream_name};
{indent}    proxy_set_header Host $host;
{indent}    proxy_set_header X-Real-IP $remote_addr;
{indent}    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
{indent}    proxy_set_header X-Forwarded-Proto $scheme;
{indent}    proxy_set_header X-Forwarded-Host $host;
{indent}    proxy_set_header X-Forwarded-Port $server_port;{websocket_headers}{extra_proxy_directives}

{indent}    # Timeouts
{indent}    proxy_connect_timeout {timeout};
{indent}    proxy_send_timeout {timeout};
{indent}    proxy_read_timeout {timeout};
{indent}}}"""


def generate_http_redirect_server(settings: List[Dict[str, Any]]) -> str:
    """Generate HTTP server blocks for redirect or forwarding."""
    # Separate domains by HTTP handling preference
    redirect_domains = [s["domain"] for s in settings if s["type"] == "https-only"]
    forward_settings = [s for s in settings if s["type"] in ["http", "https"]]

    blocks = []

    # HTTP to HTTPS redirect server for domains that don't allow HTTP forwarding
    if redirect_domains:
        domain_list = " ".join(redirect_domains)
        redirect_block = f"""    # HTTP to HTTPS redirect
    server {{
        listen 80;
        server_name {domain_list};

        # Allow Let's Encrypt ACME challenge
        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

        # Redirect all other traffic to HTTPS
        location / {{
            return 301 https://$host$request_uri;
        }}
    }}"""
        blocks.append(redirect_block)

    # HTTP forwarding servers for domains that allow HTTP
    for setting in forward_settings:
        domain = setting["domain"]
        upstream_name = setting["upstream_name"]

        # Security headers
        security_headers = ""
        if setting["security_headers"]:
            csp_header = ""
            if setting["csp_wildcard"] is True:
                csp_header = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; worker-src * 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src *; img-src * data: blob:; frame-src *;"
            elif setting["csp_unsafe_eval"] is True:
                csp_header = "script-src 'self' 'unsafe-eval' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self' https: wss: data:; default-src 'self' http: https: data: blob: 'unsafe-inline'"
            elif setting["csp_unsafe_eval"] is False:
                csp_header = "script-src 'self' 'unsafe-inline'; connect-src 'self' https: wss: data:; default-src 'self' http: https: data: blob: 'unsafe-inline'"

            security_headers = """

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;"""
            if csp_header:
                security_headers += (
                    '''
        add_header Content-Security-Policy "'''
                    + csp_header
                    + """" always;"""
                )

        # WebSocket support
        websocket_headers = ""
        if setting["websocket"]:
            websocket_headers = """
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";"""

        # Extra proxy directives
        extra_proxy_directives = ""
        if setting["proxy_buffering_off"]:
            extra_proxy_directives += "\n            proxy_buffering off;"
        if setting["proxy_cache_off"]:
            extra_proxy_directives += "\n            proxy_cache off;"

        forward_block = f"""    # {domain} - HTTP forwarding to {setting["host"]}:{setting["port"]}
    server {{
        listen 80;
        server_name {domain};

        # Maximum request body size
        client_max_body_size {setting["max_body_size"]};{security_headers}

        # Allow Let's Encrypt ACME challenge
        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

        # Forward traffic to backend{generate_location_blocks(setting, upstream_name, websocket_headers, setting["timeout"])}
    }}"""
        blocks.append(forward_block)

    return "\n\n".join(blocks)


def generate_ssl_server_block(setting: Dict[str, Any]) -> str:
    """Generate SSL server block for a domain."""
    domain = setting["domain"]
    upstream_name = setting["upstream_name"]

    # SSL certificate paths
    if setting["ca_bundle"] and setting["private_key"]:
        ssl_cert = f"/etc/nginx/ssl/{setting['ca_bundle']}"
        ssl_key = f"/etc/nginx/ssl/{setting['private_key']}"
    else:
        # Default Let's Encrypt style paths
        ssl_cert = f"/etc/nginx/ssl/{domain}/fullchain.pem"
        ssl_key = f"/etc/nginx/ssl/{domain}/privkey.pem"

    # Security headers
    security_headers = ""
    if setting["security_headers"]:
        csp_header = ""
        if setting["csp_wildcard"] is True:
            csp_header = "default-src * 'unsafe-inline' 'unsafe-eval'; script-src * 'unsafe-inline' 'unsafe-eval'; connect-src *;"
        elif setting["csp_unsafe_eval"] is True:
            csp_header = "script-src 'self' 'unsafe-eval' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self' https: wss: data:; default-src 'self' http: https: data: blob: 'unsafe-inline'"
        elif setting["csp_unsafe_eval"] is False:
            csp_header = "script-src 'self' 'unsafe-inline'; connect-src 'self' https: wss: data:; default-src 'self' http: https: data: blob: 'unsafe-inline'"

        security_headers = """
        # Security headers
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-XSS-Protection "1; mode=block" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Referrer-Policy "no-referrer-when-downgrade" always;"""
        if csp_header:
            security_headers += (
                '''
        add_header Content-Security-Policy "'''
                + csp_header
                + """" always;"""
            )

    # WebSocket support
    websocket_headers = ""
    if setting["websocket"]:
        websocket_headers = """
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";"""

    # Extra proxy directives
    extra_proxy_directives = ""
    if setting["proxy_buffering_off"]:
        extra_proxy_directives += "\n            proxy_buffering off;"
    if setting["proxy_cache_off"]:
        extra_proxy_directives += "\n            proxy_cache off;"

    # Rate limiting locations
    rate_limit_locations = ""
    if setting["rate_limit"]:
        domain_safe = domain.replace(".", "_").replace("-", "_")
        locations = []

        # Sort paths by specificity (longer/more specific first)
        sorted_paths = sorted(
            setting["rate_limit"].items(), key=lambda x: (-len(x[0]), x[0])
        )

        for path, rate in sorted_paths:
            if rate > 0:
                zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone"
                zone_name = zone_name.replace("__", "_").strip("_")

                # Convert nginx-style wildcards
                nginx_path = path.replace("*", ".*")
                location_type = "~ " if "*" in path else ""

                location_block = f"""
        # Rate limited: {rate} requests/minute for {path}
        location {location_type}{nginx_path} {{
            limit_req zone={zone_name} burst=5 nodelay;

            proxy_pass http://{upstream_name};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;{websocket_headers}{extra_proxy_directives}

            # Timeouts
            proxy_connect_timeout {setting["timeout"]};
            proxy_send_timeout {setting["timeout"]};
            proxy_read_timeout {setting["timeout"]};
        }}"""
                locations.append(location_block)

        rate_limit_locations = "".join(locations)

    # Main location block (only if no rate limiting or no root path rate limit and no allowed-paths restriction)
    main_location = ""
    if not setting["rate_limit"] or "/" not in setting["rate_limit"]:
        if not setting["allowed_paths"]:
            # Only generate default location block if no allowed-paths restriction
            main_location = f"""
        # Main application
        location / {{
            proxy_pass http://{upstream_name};
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;{websocket_headers}{extra_proxy_directives}

            # Timeouts
            proxy_connect_timeout {setting["timeout"]};
            proxy_send_timeout {setting["timeout"]};
            proxy_read_timeout {setting["timeout"]};
        }}"""
        else:
            # Generate allowed-paths location blocks
            main_location = generate_location_blocks(
                setting, upstream_name, websocket_headers, setting["timeout"]
            )

    server_block = f"""    # {domain} - Forward to {setting["host"]}:{setting["port"]}
    server {{
        listen 443 ssl;
        http2 on;
        server_name {domain};

        ssl_certificate {ssl_cert};
        ssl_certificate_key {ssl_key};

        # Maximum request body size
        client_max_body_size {setting["max_body_size"]};{security_headers}{main_location}{rate_limit_locations}
    }}"""

    return server_block


def generate_rate_limit_zones(settings: List[Dict[str, Any]]) -> str:
    """Generate rate limiting zones for nginx."""
    zones = []

    for setting in settings:
        domain_safe = setting["domain"].replace(".", "_").replace("-", "_")

        for path, rate in setting["rate_limit"].items():
            if rate > 0:  # Only create zones for positive rates
                zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone"
                zone_name = zone_name.replace("__", "_").strip("_")
                zones.append(
                    f"    limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={int(rate)}r/m;"
                )

    if zones:
        return "\n    # Rate limiting zones\n" + "\n".join(zones)
    return ""


def generate_nginx_config(settings: List[Dict[str, Any]]) -> str:
    """Generate complete nginx configuration."""

    # Check if compression is enabled for any domain
    compression_enabled = any(s["compression"] for s in settings)

    # Gzip configuration
    gzip_config = ""
    if compression_enabled:
        gzip_config = """
    # Gzip compression
    gzip on;
    gzip_comp_level 6;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/x-javascript application/javascript text/xml application/xml application/rss+xml text/javascript image/svg+xml application/vnd.ms-fontobject application/x-font-ttf font/opentype;"""

    # Rate limiting zones
    rate_limit_zones = generate_rate_limit_zones(settings)

    # Generate upstream blocks
    upstream_blocks = generate_upstream_blocks(settings)

    # Generate HTTP server blocks (redirect or forward)
    http_servers = ""
    if settings:
        http_servers = generate_http_redirect_server(settings)

    # Generate SSL server blocks
    ssl_servers = []
    for setting in settings:
        if setting["type"] in ["https", "https-only"]:
            ssl_servers.append(generate_ssl_server_block(setting))

    # Join SSL servers with double newlines
    ssl_servers_text = "\n\n".join(ssl_servers) if ssl_servers else ""

    # Complete configuration
    config = f"""events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Basic settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_names_hash_bucket_size 128;{gzip_config}{rate_limit_zones}

    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Upstream servers
{upstream_blocks}

{http_servers}

{ssl_servers_text}
}}"""

    return config


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Generate nginx proxy configuration from settings.json"
    )
    parser.add_argument(
        "--input",
        "-i",
        default="settings.json",
        help="Input settings file (default: settings.json)",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="nginx-proxy.conf",
        help="Output nginx config file (default: nginx-proxy.conf)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print configuration to stdout instead of writing to file",
    )

    args = parser.parse_args()

    # Load and validate settings
    settings_data = load_settings(args.input)

    try:
        validated_settings = [validate_setting(setting) for setting in settings_data]
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Generate configuration
    nginx_config = generate_nginx_config(validated_settings)

    if args.dry_run:
        print(nginx_config)
    else:
        # Write to file
        try:
            with open(args.output, "w") as f:
                f.write(nginx_config)
            print(f"✅ Nginx configuration generated successfully: {args.output}")
            print(f"📁 Configured {len(validated_settings)} domain(s):")
            for setting in validated_settings:
                type_status = {
                    "http": "🔓 HTTP only",
                    "https": "🔒 HTTPS + HTTP forwarding",
                    "https-only": "🔒 HTTPS only (HTTP redirects)",
                }[setting["type"]]
                print(
                    f"   - {setting['domain']} → {setting['host']}:{setting['port']} ({type_status})"
                )
        except IOError as e:
            print(f"Error writing to '{args.output}': {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
