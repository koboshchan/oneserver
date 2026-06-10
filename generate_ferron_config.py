#!/usr/bin/env python3
"""
Ferron Proxy Configuration Generator
Converts settings.json to ferron.kdl
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
    rate_limit = setting.get("rate-limit", {})
    if isinstance(rate_limit, (int, float)):
        rate_limit = {"/": rate_limit}
    elif not isinstance(rate_limit, dict):
        rate_limit = {}

    connection_type = setting.get("type", "https-only")
    if connection_type not in ["http", "https", "https-only"]:
        raise ValueError(f"Invalid type '{connection_type}'. Must be 'http', 'https', or 'https-only'")

    # Normalize allowed-paths safely
    allowed_paths = setting.get("allowed-paths", [])
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
        "ca_bundle": setting.get("ca-bundle", ""),
        "private_key": setting.get("private-key", ""),
        "rate_limit": rate_limit,
        "websocket": setting.get("websocket", True),
        "compression": setting.get("compression", True),
        "security_headers": setting.get("security-headers", True),
        "csp_unsafe_eval": setting.get("csp-unsafe-eval") or setting.get("csp_unsafe_eval", False),
        "csp_wildcard": setting.get("csp-wildcard") or setting.get("csp_wildcard", False),
        "timeout": setting.get("timeout", "120s"),
        "max_body_size": setting.get("max-body-size", "10m"),
        "allowed_paths": normalized_paths,
        "proxy_buffering_off": setting.get("proxy-buffering-off", False),
        "proxy_cache_off": setting.get("proxy-cache-off", False),
        "service": setting.get("service", "").strip(),
    }

    # Robust URL/host/port extraction
    forwarding_target = validated["forwarding"]
    if not (forwarding_target.startswith("http://") or forwarding_target.startswith("https://")):
        forwarding_target = f"http://{forwarding_target}"
    
    try:
        parsed_url = urllib.parse.urlparse(forwarding_target)
        validated["host"] = parsed_url.hostname if parsed_url.hostname else "127.0.0.1"
        if ":" in validated["host"] and not validated["host"].startswith("["):
            validated["host"] = f"[{validated['host']}]"
        validated["port"] = parsed_url.port if parsed_url.port else 80
    except Exception:
        raise ValueError(f"Could not parse forwarding target address: {validated['forwarding']}")

    validated["upstream_url"] = f"http://{validated['host']}:{validated['port']}"
    return validated


def generate_security_headers(setting: Dict[str, Any], indent: str = "  ") -> str:
    """Build standardized, robust security headers in KDL format."""
    if not setting["security_headers"]:
        return ""

    headers = [
        f'{indent}header "X-Frame-Options" "SAMEORIGIN"',
        f'{indent}header "X-XSS-Protection" "1; mode=block"',
        f'{indent}header "X-Content-Type-Options" "nosniff"',
        f'{indent}header "Referrer-Policy" "no-referrer-when-downgrade"'
    ]

    csp = ""
    if setting["csp_wildcard"]:
        csp = "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; worker-src * 'unsafe-inline' 'unsafe-eval' data: blob:; connect-src *; img-src * data: blob:; frame-src *;"
    elif setting["csp_unsafe_eval"]:
        csp = "script-src 'self' 'unsafe-eval' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self' https: wss: data: blob:; default-src 'self' http: https: data: blob: 'unsafe-inline';"
    else:
        csp = "script-src 'self' 'unsafe-inline'; connect-src 'self' https: wss: data:; default-src 'self' http: https: data: blob: 'unsafe-inline';"

    if csp:
        headers.append(f'{indent}header "Content-Security-Policy" "{csp}"')

    return "\n" + "\n".join(headers)


def generate_proxy_directives(setting: Dict[str, Any], indent: str = "    ") -> str:
    """Consolidate proxy directives for KDL."""
    lines = [
        f'{indent}proxy "{setting["upstream_url"]}"'
    ]

    # In Ferron, proxy_request_header is used for passing headers
    lines.append(f'{indent}proxy_request_header "Host" "{{header:Host}}"')
    lines.append(f'{indent}proxy_request_header "X-Real-IP" "{{client_ip}}"')
    lines.append(f'{indent}proxy_request_header "X-Forwarded-For" "{{header:X-Forwarded-For}}, {{client_ip}}"')
    lines.append(f'{indent}proxy_request_header "X-Forwarded-Proto" "{{scheme}}"')

    if setting["websocket"]:
        # Ferron usually handles WebSocket headers if proxy_keepalive is on, 
        # but we can explicitly set them if needed.
        lines.append(f'{indent}proxy_request_header "Upgrade" "{{header:Upgrade}}"')
        lines.append(f'{indent}proxy_request_header "Connection" "upgrade"')

    if setting["proxy_buffering_off"]:
        # Based on docs, Ferron doesn't have a direct 'proxy_buffering' toggle in the core, 
        # but we can omit keepalives or use specific modules if they existed. 
        # For now, we'll leave a placeholder comment.
        lines.append(f'{indent}// proxy_buffering off (Not directly supported in core Ferron KDL)')

    return "\n".join(lines)


def generate_ferron_config(settings: List[Dict[str, Any]]) -> str:
    """Compile global unified definitions framework for Ferron KDL."""
    blocks = []

    # Global settings
    blocks.append("globals {")
    blocks.append("  tls_min_version \"TLSv1.2\"")
    blocks.append("  tls_max_version \"TLSv1.3\"")
    blocks.append("}")
    blocks.append("")

    for s in settings:
        domain = s["domain"]
        
        # Handle custom service templates
        if s["service"]:
            template_path = Path("services") / f"{s['service']}.kdl"
            if template_path.exists():
                with open(template_path, "r") as f:
                    template = f.read()
                
                ssl_cert = f"/etc/nginx/ssl/{s['ca_bundle']}" if s['ca_bundle'] else f"/etc/nginx/ssl/{domain}/fullchain.pem"
                ssl_key = f"/etc/nginx/ssl/{s['private_key']}" if s['private_key'] else f"/etc/nginx/ssl/{domain}/privkey.pem"
                
                block = template.replace("{{domain}}", domain) \
                                .replace("{{upstream_url}}", s["upstream_url"]) \
                                .replace("{{ssl_cert}}", ssl_cert) \
                                .replace("{{ssl_key}}", ssl_key) \
                                .replace("{{max_body_size}}", s["max_body_size"])
                blocks.append(f"// Custom Service: {s['service']}\n{block}")
                continue

        # Standard block
        blocks.append(f'"{domain}" {{')
        
        # SSL / TLS
        if s["type"] in ["https", "https-only"]:
            if s["ca_bundle"] and s["private_key"]:
                blocks.append(f'  tls "/etc/nginx/ssl/{s["ca_bundle"]}" "/etc/nginx/ssl/{s["private_key"]}"')
            else:
                # Default to automatic TLS if no manual certs provided
                blocks.append("  auto_tls")
        
        # Security Headers
        blocks.append(generate_security_headers(s))

        # Rate Limiting
        for path, rate in s["rate_limit"].items():
            if rate > 0:
                if path == "/":
                    blocks.append(f'  limit rate={int(rate)} burst={int(rate)//2 + 5}')
                else:
                    # Path specific limits in Ferron use location blocks
                    blocks.append(f'  location "{path}" {{')
                    blocks.append(f'    limit rate={int(rate)} burst={int(rate)//2 + 5}')
                    blocks.append(generate_proxy_directives(s, "    "))
                    blocks.append("  }")

        # Allowed Paths / Whitelisting
        if s["allowed_paths"]:
            for path in s["allowed_paths"]:
                blocks.append(f'  location "{path}" {{')
                blocks.append(generate_proxy_directives(s, "    "))
                blocks.append("  }")
            # Deny everything else
            blocks.append('  location "/" {')
            blocks.append('    status 404 body="Not Found"')
            blocks.append('  }')
        else:
            # Default catch-all proxy if not already defined by rate limits
            if "/" not in s["rate_limit"]:
                blocks.append('  location "/" {')
                blocks.append(generate_proxy_directives(s, "    "))
                blocks.append('  }')

        blocks.append("}")
        blocks.append("")

        # Handle HTTP to HTTPS redirect for https-only
        if s["type"] == "https-only":
            blocks.append(f'"{domain}:80" {{')
            blocks.append(f'  status 301 location="https://{domain}{{path_and_query}}"')
            blocks.append("}")
            blocks.append("")

    return "\n".join(blocks)


def main():
    parser = argparse.ArgumentParser(description="Generate Ferron KDL configurations from settings.json")
    parser.add_argument("--input", "-i", default="settings.json", help="Input settings.json path")
    parser.add_argument("--output", "-o", default="ferron.kdl", help="Output ferron.kdl path")
    parser.add_argument("--dry-run", action="store_true", help="Print to stdout")

    args = parser.parse_args()
    settings_data = load_settings(args.input)

    try:
        validated_settings = [validate_setting(s) for s in settings_data]
    except ValueError as e:
        print(f"Validation Error: {e}")
        sys.exit(1)

    kdl_config = generate_ferron_config(validated_settings)

    if args.dry_run:
        print(kdl_config)
    else:
        try:
            with open(args.output, "w") as f:
                f.write(kdl_config)
            print(f"✔ Ferron configuration generated successfully to: {args.output}")
        except IOError as e:
            print(f"File Error: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
