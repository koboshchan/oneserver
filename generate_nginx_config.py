#!/usr/bin/env python3
"""
Nginx Proxy Configuration Generator
Converts settings.json to nginx-proxy.conf
"""

import os
import subprocess
import json
import argparse
import sys
import urllib.parse
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Set, Optional


# Settings that a `service` template silently ignores (the template only substitutes a
# fixed set of {{placeholder}} tokens - domain, upstream_name, ssl_cert, ssl_key,
# max_body_size, host, port, error_pages, error_locations). Listed as (display name,
# accepted key spellings) so validate_setting() can warn when one is set alongside 'service'.
IGNORED_WHEN_SERVICE = [
    ("timeout", ["timeout"]),
    ("proxy-buffering-off", ["proxy-buffering-off", "proxy_buffering_off"]),
    ("proxy-cache-off", ["proxy-cache-off", "proxy_cache_off"]),
    ("compression", ["compression"]),
    ("csp-unsafe-eval", ["csp-unsafe-eval", "csp_unsafe_eval"]),
    ("csp-wildcard", ["csp-wildcard", "csp_wildcard"]),
    ("security-headers", ["security-headers", "security_headers"]),
    ("websocket", ["websocket"]),
    ("no-x-forwarded-for", ["no-x-forwarded-for", "no_x_forwarded_for"]),
    ("no-x-forwarded-host", ["no-x-forwarded-host", "no_x_forwarded_host"]),
    ("rate-limit", ["rate-limit", "rate_limit"]),
    ("allowed-paths", ["allowed-paths", "allowed_paths"]),
    ("forward-url-path", ["forward-url-path", "forward_url_path"]),
    ("path", ["path"]),
]


def is_wsl() -> bool:
    """Detect if running inside Windows Subsystem for Linux (WSL)."""
    try:
        if os.path.exists("/proc/version"):
            with open("/proc/version", "r") as f:
                if "microsoft" in f.read().lower():
                    return True
    except Exception:
        pass
    return False


def is_wsl_mirrored() -> bool:
    """Detect if WSL2 is running in mirrored networking mode."""
    if not is_wsl():
        return False
    # Check interfaces for Windows-mirrored interface name patterns
    try:
        if os.path.exists("/sys/class/net"):
            interfaces = os.listdir("/sys/class/net")
            for iface in interfaces:
                iface_lower = iface.lower()
                if "pseudo-interface" in iface_lower or "wi-fi" in iface_lower or "ethernet" in iface_lower or "wlan" in iface_lower:
                    return True
    except Exception:
        pass
    
    # Fallback to wslinfo command if available
    try:
        res = subprocess.run(["wslinfo", "--networking-mode"], capture_output=True, text=True, timeout=1)
        if res.returncode == 0 and "mirrored" in res.stdout.lower():
            return True
    except Exception:
        pass
    
    return False



def load_settings(file_path: str) -> List[Dict[str, Any]]:
    """Load settings safely from JSON file, stripping comments outside strings and recording line numbers."""
    try:
        with open(file_path, "r") as f:
            raw_content = f.read()
        
        # Track line numbers of top-level objects in the JSON list
        object_lines = []
        in_str = False
        escape = False
        depth = 0
        for idx, ch in enumerate(raw_content):
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == "\"":
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "{":
                depth += 1
                if depth == 1:
                    line_no = raw_content.count("\n", 0, idx) + 1
                    object_lines.append(line_no)
            elif ch == "}":
                depth -= 1

        # Strip // comments only when NOT inside a string literal
        lines = []
        in_string = False
        for line in raw_content.splitlines():
            out_chars = []
            i = 0
            escaped = False
            while i < len(line):
                c = line[i]
                if escaped:
                    out_chars.append(c)
                    escaped = False
                    i += 1
                    continue
                if c == "\\":
                    out_chars.append(c)
                    escaped = True
                    i += 1
                    continue
                if c == "\"":
                    in_string = not in_string
                    out_chars.append(c)
                    i += 1
                    continue
                if not in_string and c == "/" and i + 1 < len(line) and line[i + 1] == "/":
                    break
                out_chars.append(c)
                i += 1
            lines.append("".join(out_chars))
        
        settings = json.loads("\n".join(lines))

        if not isinstance(settings, list):
            raise ValueError("Settings must be a list of domain configurations")

        # Attach line numbers to top-level dictionary items
        for idx, s in enumerate(settings):
            if isinstance(s, dict):
                s["__line__"] = object_lines[idx] if idx < len(object_lines) else None

        return settings
    except FileNotFoundError:
        print(f"Error: Settings file '{file_path}' not found", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in '{file_path}': {e}", file=sys.stderr)
        sys.exit(1)


def validate_setting(setting: Dict[str, Any]) -> Dict[str, Any]:
    """Validate, normalize, and safely parse domain parameters."""
    line_info = f" (line {setting['__line__']})" if setting.get("__line__") else ""
    connection_type = setting.get("type", "https-only")
    is_default_server = False

    if connection_type == "default-server" or connection_type.startswith("default-server:"):
        is_default_server = True
        domain = "_"
        if connection_type == "default-server":
            if "forwarding" in setting and setting["forwarding"]:
                connection_type = "http"
            elif "path" in setting and setting["path"]:
                has_ssl_certs = bool(setting.get("ca-bundle") or setting.get("ca_bundle"))
                connection_type = "static-https" if has_ssl_certs else "static-http"
            else:
                connection_type = "static-https"
        else:
            type_part = connection_type.split(":", 1)[1].strip()
            valid_target_types = [
                "http", "https", "https-only",
                "redirect-temp", "redirect-perm",
                "static-http", "static-https", "static-https-only"
            ]
            if type_part not in valid_target_types:
                raise ValueError(f"Invalid target type '{type_part}' in default-server type '{connection_type}'{line_info}")
            connection_type = type_part
    elif "domain" not in setting:
        if ":" in connection_type:
            domain = "*"
        else:
            raise ValueError(f"Missing required field 'domain' in domain configuration{line_info}")
    else:
        domain = setting["domain"].strip()
        if not domain:
            raise ValueError(f"Domain name cannot be empty in domain configuration{line_info}")

    error_code = None
    if not is_default_server and ":" in connection_type:
        parts = connection_type.split(":", 1)
        code_str = parts[0].strip()
        type_part = parts[1].strip()
        if not code_str.isdigit():
            raise ValueError(f"Invalid error code format in type '{connection_type}' for domain '{domain}'{line_info}. Note: wildcard '*' catch-alls are no longer supported; use 'default-server' for unknown domain handling.")
        code_int = int(code_str)
        if code_int < 300 or code_int > 599:
            raise ValueError(f"Error code '{code_int}' in type '{connection_type}' for domain '{domain}'{line_info} is out of valid HTTP error range (300-599)")
        error_code = code_int
        
        valid_target_types = [
            "http", "https", "https-only",
            "redirect-temp", "redirect-perm",
            "static-http", "static-https", "static-https-only"
        ]
        if type_part not in valid_target_types:
            raise ValueError(f"Invalid target type '{type_part}' in error handler type '{connection_type}' for domain '{domain}'{line_info}")
        connection_type = type_part
    elif not is_default_server:
        valid_types = [
            "http", "https", "https-only",
            "redirect-temp", "redirect-perm",
            "static-http", "static-https", "static-https-only"
        ]
        if connection_type not in valid_types:
            raise ValueError(f"Invalid type '{connection_type}' in domain configuration for domain '{domain}'{line_info}")

    is_static = connection_type in ["static-http", "static-https", "static-https-only"]
    is_redirect = connection_type in ["redirect-temp", "redirect-perm"]

    service_name_raw = setting.get("service", "").strip()
    if service_name_raw:
        if connection_type not in ["http", "https", "https-only"]:
            raise ValueError(
                f"'service' template '{service_name_raw}' can only be combined with type "
                f"'http', 'https', or 'https-only' (got '{connection_type}') for domain '{domain}'{line_info}"
            )
        template_file = Path("services") / f"{service_name_raw}.conf"
        if not template_file.exists():
            raise ValueError(
                f"Service template '{service_name_raw}.conf' not found in 'services/' directory for domain '{domain}'{line_info}. "
                "Ensure the template file exists before referencing it."
            )

    if not is_static:
        if "forwarding" not in setting or not setting["forwarding"]:
            raise ValueError(f"Missing required field 'forwarding' for type '{connection_type}' in domain '{domain}'{line_info}")

    # Validate and normalize rate-limit format
    raw_rate_limit = setting.get("rate-limit", setting.get("rate_limit", {}))
    if isinstance(raw_rate_limit, (int, float)):
        raw_rate_limit = {"/": raw_rate_limit}
    elif not isinstance(raw_rate_limit, dict):
        raw_rate_limit = {}

    normalized_rate_limit = {}
    for r_path, r_val in raw_rate_limit.items():
        if not isinstance(r_val, (int, float)):
            raise ValueError(f"Rate limit value for path '{r_path}' in domain '{domain}'{line_info} must be a number (got '{r_val}')")
        if r_val <= 0:
            raise ValueError(f"Rate limit for path '{r_path}' in domain '{domain}'{line_info} cannot be 0 or negative (got {r_val}). It must be greater than 0.")
        # Clamp fractional rate limits between 0 and 1 to minimum 1r/m
        clamped_val = max(1, int(round(r_val))) if r_val >= 1 else 1
        normalized_rate_limit[r_path] = clamped_val

    # Validate SSL requirements for redirect types & secure static types
    ca_bundle = setting.get("ca-bundle", setting.get("ca_bundle", "")).strip()
    private_key = setting.get("private-key", setting.get("private_key", "")).strip()

    if error_code is None and not is_default_server:
        if is_redirect or connection_type in ["static-https", "static-https-only"]:
            if not ca_bundle:
                raise ValueError(f"ca-bundle is required for type '{connection_type}' in domain '{domain}'{line_info}")
            if not private_key:
                raise ValueError(f"private-key is required for type '{connection_type}' in domain '{domain}'{line_info}")

    # Normalize allowed-paths safely
    allowed_paths = setting.get("allowed-paths", setting.get("allowed_paths", []))
    if not isinstance(allowed_paths, list):
        raise ValueError(f"'allowed-paths' must be a list of path strings in domain '{domain}'{line_info}")

    normalized_paths = []
    for path in allowed_paths:
        if not isinstance(path, str):
            raise ValueError(f"All entries in 'allowed-paths' must be strings in domain '{domain}'{line_info}")
        p = path.strip()
        if not p.startswith("/"):
            p = "/" + p
        if len(p) > 1 and p.endswith("/"):
            p = p.rstrip("/")
        normalized_paths.append(p)

    # Validate path mappings for static types
    paths = setting.get("path", {})
    if not isinstance(paths, dict):
        raise ValueError(f"'path' must be a dictionary of route mappings in domain '{domain}'{line_info}")
    
    normalized_paths_dict = {}
    for k, v in paths.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError(f"All keys and values in 'path' must be strings in domain '{domain}'{line_info}")
        k_clean = k.strip()
        v_clean = v.strip()
        # Warning if target points to root directory /
        if v_clean in ["/", "", "./"]:
            print(f"Warning: Path mapping target '{v_clean}' for route '{k_clean}' in domain '{domain}' points to the root directory.", file=sys.stderr)
        # Error if source path does not end with / but target path ends with /.
        is_wildcard_key = k_clean.endswith("/*") or k_clean.endswith("/**")
        if not k_clean.endswith("/") and not is_wildcard_key and v_clean.endswith("/"):
            raise ValueError(f"Invalid path mapping '{k_clean}': '{v_clean}' in domain '{domain}'{line_info}. Check if the target path is a directory (ends with '/') when the source path does not end with '/'.")
        normalized_paths_dict[k_clean] = v_clean

    # Check for conflicting wildcard definitions on the same base path
    for k in normalized_paths_dict:
        if k.endswith("/**"):
            base = k[:-3]
            if base + "/*" in normalized_paths_dict:
                raise ValueError(f"Conflicting path mappings: '{k}' and '{base}/*' cannot be used together in domain '{domain}'{line_info}")
        elif k.endswith("/*"):
            base = k[:-2]
            if base + "/**" in normalized_paths_dict:
                raise ValueError(f"Conflicting path mappings: '{k}' and '{base}/**' cannot be used together in domain '{domain}'{line_info}")

    validated = {
        "__line__": setting.get("__line__"),
        "domain": domain,
        "is_default_server": is_default_server,
        "forwarding": setting.get("forwarding", "").strip() if not is_static else "",
        "type": connection_type,
        "error_code": error_code,
        "ca_bundle": ca_bundle,
        "private_key": private_key,
        "rate_limit": normalized_rate_limit,
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
        "proxy_intercept_errors": setting.get("proxy-intercept-errors", setting.get("proxy_intercept_errors", False)),
        "service": service_name_raw,
        "forward_url_path": setting.get("forward-url-path", setting.get("forward_url_path", False)),
        "path": normalized_paths_dict,
        "no_x_forwarded_for": setting.get("no-x-forwarded-for", setting.get("no_x_forwarded_for", False)),
        "no_x_forwarded_host": setting.get("no-x-forwarded-host", setting.get("no_x_forwarded_host", False)),
    }

    # Extract hostname/port if not static and not redirect
    if not is_static and not is_redirect:
        forwarding_target = validated["forwarding"]
        is_upstream_https = forwarding_target.startswith("https://")
        if not (forwarding_target.startswith("http://") or forwarding_target.startswith("https://")):
            forwarding_target = f"http://{forwarding_target}"
        
        try:
            parsed_url = urllib.parse.urlparse(forwarding_target)
            validated["host"] = parsed_url.hostname if parsed_url.hostname else "127.0.0.1"
            if ":" in validated["host"] and not validated["host"].startswith("["):
                validated["host"] = f"[{validated['host']}]"
            default_port = 443 if is_upstream_https else 80
            validated["port"] = parsed_url.port if parsed_url.port else default_port
            validated["upstream_ssl"] = is_upstream_https
        except Exception:
            raise ValueError(f"Could not parse forwarding target address: {validated['forwarding']}{line_info}")
        
        domain_safe = validated["domain"].replace("*", "wildcard").replace(".", "_").replace("-", "_")
        if is_default_server:
            validated["upstream_name"] = "default_server_backend"
        elif error_code is not None:
            lbl = "wildcard" if error_code == "*" else str(error_code)
            validated["upstream_name"] = f"{domain_safe}_error_{lbl}_backend"
        else:
            validated["upstream_name"] = f"{domain_safe}_backend"

    if validated["service"] and (Path("services") / f"{validated['service']}.conf").exists():
        ignored_present = [display for display, keys in IGNORED_WHEN_SERVICE if any(k in setting for k in keys)]
        if ignored_present:
            print(
                f"Warning: domain '{domain}' uses service template '{validated['service']}', "
                f"which ignores: {', '.join(ignored_present)}. Edit services/{validated['service']}.conf "
                "directly to change this behavior.",
                file=sys.stderr
            )

    return validated


def build_proxy_pass_block(setting: Dict[str, Any], indent: str, rate_zone: str = "", has_handlers: bool = False) -> str:
    """Consolidate generation logic to avoid code repetition across routes."""
    proxy_scheme = "https" if setting.get("upstream_ssl", False) else "http"
    lines = [
        f"{indent}proxy_pass {proxy_scheme}://{setting['upstream_name']};",
        f"{indent}proxy_set_header Host $host;"
    ]

    if setting.get("upstream_ssl", False):
        lines.append(f"{indent}proxy_ssl_server_name on;")

    if not setting.get("no_x_forwarded_for", False):
        lines.extend([
            f"{indent}proxy_set_header X-Real-IP $remote_addr;",
            f"{indent}proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"
        ])

    lines.extend([
        f"{indent}proxy_set_header X-Forwarded-Proto $scheme;"
    ])

    if not setting.get("no_x_forwarded_host", False):
        lines.append(f"{indent}proxy_set_header X-Forwarded-Host $host;")

    lines.extend([
        f"{indent}proxy_set_header X-Forwarded-Port $server_port;"
    ])

    if rate_zone:
        lines.insert(0, f"{indent}limit_req zone={rate_zone} burst=5 nodelay;")

    lines.append(f"{indent}proxy_http_version 1.1;")
    if setting["websocket"]:
        lines.extend([
            f"{indent}proxy_set_header Upgrade $http_upgrade;",
            f"{indent}proxy_set_header Connection \"upgrade\";"
        ])
    else:
        lines.append(f"{indent}proxy_set_header Connection \"\";")

    if setting["proxy_buffering_off"]:
        lines.append(f"{indent}proxy_buffering off;")
    if setting["proxy_cache_off"]:
        lines.append(f"{indent}proxy_cache off;")
    if setting.get("proxy_intercept_errors", False):
        lines.append(f"{indent}proxy_intercept_errors on;")

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


def generate_routes(setting: Dict[str, Any], domain_safe: str, indent: str = "        ", has_handlers: bool = False) -> str:
    """Unified path router logic. Evaluates and merges constraints gracefully."""
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
            if path == "/":
                blocks.append(f"{indent}location = / {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone, has_handlers)}\n{indent}}}")
            elif "*" in path:
                clean_path = path.replace("*", ".*")
                blocks.append(f"{indent}location ~ ^{clean_path} {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone, has_handlers)}\n{indent}}}")
            else:
                blocks.append(f"{indent}location ^~ {path}/ {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone, has_handlers)}\n{indent}}}")
                blocks.append(f"{indent}location = {path} {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone, has_handlers)}\n{indent}}}")
        
        # Deny unauthorized access patterns explicitly
        blocks.append(f"{indent}location / {{\n{indent}    return 404;\n{indent}}}")
        return "\n\n".join(blocks)

    # Context B: Standard deployment structure mixed with arbitrary rate-limiting zones
    all_defined_paths: Set[str] = set(processed_limits.keys())
    
    # Sort paths carefully: longest string literal rules take priority structural parsing sequence
    for path in sorted(all_defined_paths, key=lambda x: (-len(x), x)):
        if path == "/":
            continue
        rate_zone = processed_limits[path]
        if "*" in path:
            clean_path = path.replace("*", ".*")
            loc_modifier = "~ ^"
            blocks.append(f"{indent}location {loc_modifier}{clean_path} {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone, has_handlers)}\n{indent}}}")
        else:
            blocks.append(f"{indent}location {path} {{\n{build_proxy_pass_block(setting, indent + '    ', rate_zone, has_handlers)}\n{indent}}}")

    # Fallback primary route block location targeting context root "/"
    root_rate_zone = processed_limits.get("/", "")
    blocks.append(f"{indent}location / {{\n{build_proxy_pass_block(setting, indent + '    ', root_rate_zone, has_handlers)}\n{indent}}}")

    return "\n\n".join(blocks)


def generate_static_routes(setting: Dict[str, Any], domain_safe: str, indent: str = "        ") -> str:
    """Generate Nginx location blocks for serving static files based on path mapping dictionary."""
    blocks = []
    paths = setting.get("path", {})
    rate_limits = setting.get("rate_limit", {})
    
    # Map rate limits to zones
    processed_limits = {}
    for path, rate in rate_limits.items():
        if rate > 0:
            zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone"
            processed_limits[path] = zone_name.replace("__", "_").strip("_")

    exact_blocks = []
    prefix_blocks = []
    regex_blocks = []

    for k, v in paths.items():
        rate_zone = processed_limits.get(k, "")
        rate_limit_line = f"\n{indent}    limit_req zone={rate_zone} burst=5 nodelay;" if rate_zone else ""
        target_path = f"/public/{v}"

        if k.endswith("/**"):
            clean_k = k[:-3]
            if v.strip().endswith("/"):
                alias_base = target_path.rstrip("/")
                regex_blocks.append(f"{indent}location ~ ^{clean_k}(/.*)?$ {{{rate_limit_line}\n{indent}    alias {alias_base}$1;\n{indent}}}")
            else:
                regex_blocks.append(f"{indent}location ~ ^{clean_k}(/.*)?$ {{{rate_limit_line}\n{indent}    alias {target_path};\n{indent}}}")
        elif k.endswith("/*"):
            clean_k = k[:-2]
            # Match one level deep (non-recursive)
            if v.strip().endswith("/"):
                alias_base = target_path.rstrip("/")
                regex_blocks.append(f"{indent}location ~ ^{clean_k}/([^/]+)$ {{{rate_limit_line}\n{indent}    alias {alias_base}/$1;\n{indent}}}")
            else:
                regex_blocks.append(f"{indent}location ~ ^{clean_k}/[^/]+$ {{{rate_limit_line}\n{indent}    alias {target_path};\n{indent}}}")
            # Deeper matches or parent return 404
            if clean_k:
                regex_blocks.append(f"{indent}location ~ ^{clean_k}(/.*)?$ {{\n{indent}    return 404;\n{indent}}}")
            else:
                regex_blocks.append(f"{indent}location ~ ^/[^/]+/.+$ {{\n{indent}    return 404;\n{indent}}}")
                regex_blocks.append(f"{indent}location = / {{\n{indent}    return 404;\n{indent}}}")
        elif k.endswith("/"):
            # Ensure alias has a trailing slash if location has a trailing slash
            alias_target = target_path if target_path.endswith("/") else f"{target_path}/"
            prefix_blocks.append(f"{indent}location {k} {{{rate_limit_line}\n{indent}    alias {alias_target};\n{indent}}}")
        else:
            exact_blocks.append(f"{indent}location = {k} {{{rate_limit_line}\n{indent}    alias {target_path};\n{indent}}}")

    blocks.extend(exact_blocks)
    blocks.extend(prefix_blocks)
    blocks.extend(regex_blocks)

    # Default / fallback location block pointing to /public
    if "/" not in paths:
        root_rate_zone = processed_limits.get("/", "")
        root_rate_line = f"\n{indent}    limit_req zone={root_rate_zone} burst=5 nodelay;" if root_rate_zone else ""
        blocks.append(f"{indent}location / {{{root_rate_line}\n{indent}    root /public;\n{indent}    index index.html index.htm;\n{indent}}}")

    return "\n\n".join(blocks)


def generate_redirect_routes(setting: Dict[str, Any], domain_safe: str, indent: str = "        ") -> str:
    """Generate redirect rules for redirect-temp and redirect-perm connections."""
    blocks = []
    allowed_paths = setting.get("allowed_paths", [])
    rate_limits = setting.get("rate_limit", {})
    redirect_code = 301 if setting["type"] == "redirect-perm" else 302
    target = setting["forwarding"]
    forward_url = setting["forward_url_path"]

    # Map rate limits to zones
    processed_limits = {}
    for path, rate in rate_limits.items():
        if rate > 0:
            zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone"
            processed_limits[path] = zone_name.replace("__", "_").strip("_")

    if forward_url:
        if "?" in target:
            target_base, target_query = target.split("?", 1)
            target_clean = target_base.rstrip("/")
            redirect_target = f"{target_clean}$uri?{target_query}&$args"
        else:
            target_clean = target.rstrip("/")
            redirect_target = f"{target_clean}$request_uri"
    else:
        redirect_target = target

    if allowed_paths:
        for path in allowed_paths:
            rate_zone = processed_limits.get(path, "")
            rate_limit_line = f"\n{indent}    limit_req zone={rate_zone} burst=5 nodelay;" if rate_zone else ""
            
            if path == "/":
                blocks.append(f"{indent}location = / {{{rate_limit_line}\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")
            elif "*" in path:
                clean_path = path.replace("*", ".*")
                blocks.append(f"{indent}location ~ ^{clean_path} {{{rate_limit_line}\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")
            else:
                blocks.append(f"{indent}location ^~ {path}/ {{{rate_limit_line}\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")
                blocks.append(f"{indent}location = {path} {{{rate_limit_line}\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")
        
        blocks.append(f"{indent}location / {{\n{indent}    return 404;\n{indent}}}")
    else:
        for path, rate_zone in sorted(processed_limits.items(), key=lambda x: (-len(x[0]), x[0])):
            if path == "/":
                continue
            if "*" in path:
                clean_path = path.replace("*", ".*")
                blocks.append(f"{indent}location ~ ^{clean_path} {{\n{indent}    limit_req zone={rate_zone} burst=5 nodelay;\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")
            else:
                blocks.append(f"{indent}location {path} {{\n{indent}    limit_req zone={rate_zone} burst=5 nodelay;\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")
        
        root_rate_zone = processed_limits.get("/", "")
        root_rate_line = f"\n{indent}    limit_req zone={root_rate_zone} burst=5 nodelay;" if root_rate_zone else ""
        blocks.append(f"{indent}location / {{{root_rate_line}\n{indent}    return {redirect_code} {redirect_target};\n{indent}}}")

    return "\n\n".join(blocks)


def generate_error_page_directives(handlers: List[Dict[str, Any]], indent: str = "        ") -> str:
    """Generate Nginx error_page directives based on custom handlers."""
    directives = []
    for h in handlers:
        if h.get("error_code") and h["error_code"] != "*":
            directives.append(f"{indent}error_page {h['error_code']} @error_{h['error_code']};")
    return "\n" + "\n".join(directives) if directives else ""


def generate_error_handlers_locations(handlers: List[Dict[str, Any]], indent: str = "        ") -> str:
    """Generate Nginx location blocks for custom error handlers."""
    blocks = []
    for h in handlers:
        if not h.get("error_code") or h["error_code"] == "*":
            continue
        lbl = str(h["error_code"])
        
        loc_lines = []
        if h["type"] in ["redirect-temp", "redirect-perm"]:
            redirect_code = 301 if h["type"] == "redirect-perm" else 302
            target = h["forwarding"]
            if h["forward_url_path"]:
                if "?" in target:
                    target_base, target_query = target.split("?", 1)
                    target_clean = target_base.rstrip("/")
                    redirect_target = f"{target_clean}$uri?{target_query}&$args"
                else:
                    target_clean = target.rstrip("/")
                    redirect_target = f"{target_clean}$request_uri"
            else:
                redirect_target = target
            loc_lines.append(f"{indent}    return {redirect_code} {redirect_target};")
        elif h["type"] in ["static-http", "static-https", "static-https-only"]:
            file_target = h["path"].get("/", "")
            if not file_target and h["path"]:
                file_target = list(h["path"].values())[0]
            if not file_target:
                file_target = f"{lbl}.html"
            
            file_target = file_target.lstrip("/")
            loc_lines.append(f"{indent}    root /public;")
            loc_lines.append(f"{indent}    error_page 405 =200 $uri;")
            loc_lines.append(f"{indent}    rewrite ^ /{file_target} break;")
        elif h["type"] in ["http", "https", "https-only"]:
            proxy_pass_code = build_proxy_pass_block(h, indent + "    ")
            loc_lines.append(proxy_pass_code)
        
        blocks.append(f"{indent}location @error_{lbl} {{\n" + "\n".join(loc_lines) + f"\n{indent}}}")
    return "\n\n".join(blocks)


def generate_upstream_blocks(settings: List[Dict[str, Any]]) -> str:
    """Generate independent upstream server block allocations."""
    seen_upstreams = set()
    upstream_blocks = []
    for s in settings:
        is_static = s["type"] in ["static-http", "static-https", "static-https-only"]
        is_redirect = s["type"] in ["redirect-temp", "redirect-perm"]
        if not is_static and not is_redirect:
            upstream_name = s.get("upstream_name")
            if upstream_name and upstream_name not in seen_upstreams:
                seen_upstreams.add(upstream_name)
                upstream_blocks.append(
                    f"    upstream {upstream_name} {{\n        server {s['host']}:{s['port']};\n        keepalive 32;\n    }}"
                )

    return "\n\n".join(upstream_blocks)


def generate_rate_limit_zones(settings: List[Dict[str, Any]]) -> str:
    """Build shared memory limits allocating proportional slots directly based on rulesets."""
    zones = []
    seen_zones = set()
    for s in settings:
        domain_safe = s["domain"].replace("*", "wildcard").replace(".", "_").replace("-", "_")
        for path, rate in s["rate_limit"].items():
            if rate > 0:
                zone_name = f"{domain_safe}_{path.replace('/', '_').replace('*', 'wildcard')}_zone".replace("__", "_").strip("_")
                if zone_name not in seen_zones:
                    seen_zones.add(zone_name)
                    zones.append(f"    limit_req_zone $binary_remote_addr zone={zone_name}:10m rate={int(rate)}r/m;")
    return "\n    # Rate limiting zones\n" + "\n".join(zones) if zones else ""


def generate_http_redirect_server(grouped_settings: Dict[str, List[Dict[str, Any]]]) -> str:
    """Generate universal port 80 routing behaviors supporting structural certificate lifecycle requests."""
    redirect_domains = []
    http_domains = []

    for dom, group in grouped_settings.items():
        main_entry = next((s for s in group if s["error_code"] is None), None)
        if not main_entry:
            continue
        
        secure_types = ["https", "https-only", "redirect-temp", "redirect-perm", "static-https", "static-https-only"]
        if main_entry["type"] in secure_types:
            redirect_domains.append(dom)
        else:
            handlers = [s for s in group if s["error_code"] is not None]
            http_domains.append((main_entry, handlers))

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

    for main_entry, handlers in http_domains:
        dom = main_entry["domain"]
        domain_safe = dom.replace("*", "wildcard").replace(".", "_").replace("-", "_")
        gzip_toggle = "\n        gzip off;" if not main_entry["compression"] else ""
        
        error_directives = generate_error_page_directives(handlers, indent="        ")
        error_locations = generate_error_handlers_locations(handlers, indent="        ")
        error_locations_str = f"\n\n{error_locations}" if error_locations else ""

        is_static = main_entry["type"] == "static-http"
        has_handlers = len(handlers) > 0

        if is_static:
            routes_content = generate_static_routes(main_entry, domain_safe, indent="        ")
        else:
            routes_content = generate_routes(main_entry, domain_safe, indent="        ", has_handlers=has_handlers)

        blocks.append(f"""    # {dom} - HTTP Core Forwarding
    server {{
        listen 80;
        server_name {dom};
        client_max_body_size {main_entry['max_body_size']};{generate_security_headers(main_entry)}{gzip_toggle}{error_directives}

        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}

{routes_content}{error_locations_str}
    }}""")

    return "\n\n".join(blocks)


def generate_default_http_server(default_server: Optional[Dict[str, Any]] = None) -> str:
    """Generate default catch-all server block on port 80 for unmatched domains."""
    content_lines = []
    location_blocks = []

    if default_server:
        if default_server["type"] in ["redirect-temp", "redirect-perm"]:
            redirect_code = 301 if default_server["type"] == "redirect-perm" else 302
            target = default_server["forwarding"]
            if default_server.get("forward_url_path"):
                if "?" in target:
                    target_base, target_query = target.split("?", 1)
                    target_clean = target_base.rstrip("/")
                    redirect_target = f"{target_clean}$uri?{target_query}&$args"
                else:
                    target_clean = target.rstrip("/")
                    redirect_target = f"{target_clean}$request_uri"
            else:
                redirect_target = target
            location_blocks.append(f"        location / {{\n            return {redirect_code} {redirect_target};\n        }}")
        elif default_server["type"] in ["http", "https", "https-only"]:
            proxy_block = build_proxy_pass_block(default_server, indent="            ")
            location_blocks.append(f"        location / {{\n{proxy_block}\n        }}")
        else:  # static types (static-http, static-https, static-https-only)
            file_target = default_server.get("path", {}).get("/", "")
            if not file_target and default_server.get("path"):
                file_target = list(default_server["path"].values())[0]
            if not file_target:
                file_target = "404.html"
            file_target = file_target.lstrip("/")

            content_lines.append("        error_page 404 @default_error;")
            location_blocks.append("        location / {\n            return 404;\n        }")
            location_blocks.append(
                f"        location @default_error {{\n"
                f"            root /public;\n"
                f"            error_page 405 =200 $uri;\n"
                f"            rewrite ^ /{file_target} break;\n"
                f"        }}"
            )
    else:
        location_blocks.append("        location / {\n            return 404;\n        }")

    error_directives_str = ("\n" + "\n".join(content_lines)) if content_lines else ""
    locations_str = "\n\n".join(location_blocks)

    return f"""    # Default Server - HTTP (unknown domains)
    server {{
        listen 80 default_server;
        server_name _;

        location /.well-known/acme-challenge/ {{
            root /var/www/certbot;
        }}{error_directives_str}

{locations_str}
    }}"""


def generate_default_ssl_server(default_server: Optional[Dict[str, Any]], actual_settings: List[Dict[str, Any]]) -> str:
    """Generate default catch-all server block on port 443 for unmatched domains."""
    default_ca = ""
    default_key = ""
    if default_server:
        default_ca = default_server.get("ca_bundle", "")
        default_key = default_server.get("private_key", "")
    
    if not default_ca:
        default_ca = next((s["ca_bundle"] for s in actual_settings if s.get("ca_bundle")), "")
    if not default_key:
        default_key = next((s["private_key"] for s in actual_settings if s.get("private_key")), "")

    default_ssl_cert = f"/etc/nginx/ssl/{default_ca}" if default_ca else "/etc/nginx/ssl/fullchain.pem"
    default_ssl_key = f"/etc/nginx/ssl/{default_key}" if default_key else "/etc/nginx/ssl/privkey.pem"

    content_lines = []
    location_blocks = []

    if default_server:
        if default_server["type"] in ["redirect-temp", "redirect-perm"]:
            redirect_code = 301 if default_server["type"] == "redirect-perm" else 302
            target = default_server["forwarding"]
            if default_server.get("forward_url_path"):
                if "?" in target:
                    target_base, target_query = target.split("?", 1)
                    target_clean = target_base.rstrip("/")
                    redirect_target = f"{target_clean}$uri?{target_query}&$args"
                else:
                    target_clean = target.rstrip("/")
                    redirect_target = f"{target_clean}$request_uri"
            else:
                redirect_target = target
            location_blocks.append(f"        location / {{\n            return {redirect_code} {redirect_target};\n        }}")
        elif default_server["type"] in ["http", "https", "https-only"]:
            proxy_block = build_proxy_pass_block(default_server, indent="            ")
            location_blocks.append(f"        location / {{\n{proxy_block}\n        }}")
        else:  # static types (static-http, static-https, static-https-only)
            file_target = default_server.get("path", {}).get("/", "")
            if not file_target and default_server.get("path"):
                file_target = list(default_server["path"].values())[0]
            if not file_target:
                file_target = "404.html"
            file_target = file_target.lstrip("/")

            content_lines.append("        error_page 404 @default_error;")
            location_blocks.append("        location / {\n            return 404;\n        }")
            location_blocks.append(
                f"        location @default_error {{\n"
                f"            root /public;\n"
                f"            error_page 405 =200 $uri;\n"
                f"            rewrite ^ /{file_target} break;\n"
                f"        }}"
            )
    else:
        location_blocks.append("        location / {\n            return 404;\n        }")

    error_directives_str = ("\n" + "\n".join(content_lines)) if content_lines else ""
    locations_str = "\n\n".join(location_blocks)

    return f"""    # Default Server - HTTPS (unknown domains)
    server {{
        listen 443 ssl default_server;
        http2 on;
        server_name _;

        ssl_certificate {default_ssl_cert};
        ssl_certificate_key {default_ssl_key};{error_directives_str}

{locations_str}
    }}"""


def generate_ssl_server_block(main_entry: Dict[str, Any], handlers: List[Dict[str, Any]]) -> str:
    """Generate comprehensive production-hardened TLS context configuration parameters."""
    domain = main_entry["domain"]
    domain_safe = domain.replace("*", "wildcard").replace(".", "_").replace("-", "_")
    
    ssl_cert = f"/etc/nginx/ssl/{main_entry['ca_bundle']}" if main_entry["ca_bundle"] else f"/etc/nginx/ssl/{domain}/fullchain.pem"
    ssl_key = f"/etc/nginx/ssl/{main_entry['private_key']}" if main_entry["private_key"] else f"/etc/nginx/ssl/{domain}/privkey.pem"

    gzip_toggle = "\n        gzip off;" if not main_entry["compression"] else ""
    
    error_directives = generate_error_page_directives(handlers, indent="        ")
    error_locations = generate_error_handlers_locations(handlers, indent="        ")
    error_locations_str = f"\n\n{error_locations}" if error_locations else ""

    has_handlers = len(handlers) > 0
    is_static = main_entry["type"] in ["static-http", "static-https", "static-https-only"]
    is_redirect = main_entry["type"] in ["redirect-temp", "redirect-perm"]

    if is_static:
        routes_content = generate_static_routes(main_entry, domain_safe, indent="        ")
    elif is_redirect:
        routes_content = generate_redirect_routes(main_entry, domain_safe, indent="        ")
    else:
        routes_content = generate_routes(main_entry, domain_safe, indent="        ", has_handlers=has_handlers)

    return f"""    # {domain} - Production TLS Context
    server {{
        listen 443 ssl;
        http2 on;
        server_name {domain};

        ssl_certificate {ssl_cert};
        ssl_certificate_key {ssl_key};
        client_max_body_size {main_entry['max_body_size']};{generate_security_headers(main_entry, is_ssl=True)}{gzip_toggle}{error_directives}

{routes_content}{error_locations_str}
    }}"""


def generate_nginx_config(settings: List[Dict[str, Any]]) -> str:
    """Compile global unified definitions framework orchestrating secondary modular dependencies."""
    # Find default-server setting if present
    default_server_settings = [s for s in settings if s.get("is_default_server")]
    if len(default_server_settings) > 1:
        line_nums = [str(s["__line__"]) for s in default_server_settings if s.get("__line__")]
        lines_str = f" (at line(s): {', '.join(line_nums)})" if line_nums else ""
        raise ValueError(f"More than one 'default-server' configuration block defined{lines_str}")
    
    default_server_setting = default_server_settings[0] if default_server_settings else None

    # Filter out default-server from actual domain settings
    actual_settings = [s for s in settings if not s.get("is_default_server")]
    
    # Check for duplicate main configuration entries for the same domain
    main_entries_by_domain: Dict[str, List[Dict[str, Any]]] = {}
    for s in actual_settings:
        if s.get("error_code") is None:
            main_entries_by_domain.setdefault(s["domain"], []).append(s)

    for dom, entries in main_entries_by_domain.items():
        if len(entries) > 1:
            line_nums = [str(e["__line__"]) for e in entries if e.get("__line__") is not None]
            lines_str = f" (found at line(s): {', '.join(line_nums)})" if line_nums else ""
            raise ValueError(
                f"Duplicate main configuration entries found for domain '{dom}'{lines_str}. "
                "Each domain can only have one primary configuration block."
            )

    domains_map = {}
    for s in actual_settings:
        dom = s["domain"]
        if dom not in domains_map:
            domains_map[dom] = []
        domains_map[dom].append(s)

    for dom, group in domains_map.items():
        main_entry = next((s for s in group if s["error_code"] is None), None)
        if not main_entry:
            line_info = f" (defined near line {group[0]['__line__']})" if group and group[0].get('__line__') else ""
            raise ValueError(f"No main configuration entry (without error code prefix) defined for domain '{dom}'{line_info}")
        
        handlers = [s for s in group if s["error_code"] is not None]
        
        code_counts = Counter(h["error_code"] for h in handlers)
        duplicate_codes = [code for code, count in code_counts.items() if count > 1]
        if duplicate_codes:
            conflicting_handlers = [h for h in handlers if h["error_code"] in duplicate_codes]
            line_nums = [str(h["__line__"]) for h in conflicting_handlers if h.get("__line__") is not None]
            line_info = f" (at line(s): {', '.join(line_nums)})" if line_nums else ""
            raise ValueError(f"More than one error handler defined for code(s) {duplicate_codes} for domain '{dom}'{line_info}")

    gzip_config = ""
    has_compression = any(s["compression"] for s in actual_settings if s["error_code"] is None)
    if has_compression:
        gzip_config = """
    # Gzip compression
    gzip on;
    gzip_comp_level 6;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/x-javascript application/javascript text/xml application/xml application/rss+xml text/javascript image/svg+xml application/vnd.ms-fontobject application/x-font-ttf font/opentype;"""

    service_blocks = []
    ssl_servers = []

    for dom, group in domains_map.items():
        main_entry = next(s for s in group if s["error_code"] is None)
        handlers = [s for s in group if s["error_code"] is not None]
        
        if main_entry["service"]:
            template_path = Path("services") / f"{main_entry['service']}.conf"
            if template_path.exists():
                with open(template_path, "r") as f:
                    template = f.read()
                
                ssl_cert = f"/etc/nginx/ssl/{main_entry['ca_bundle']}" if main_entry['ca_bundle'] else f"/etc/nginx/ssl/{dom}/fullchain.pem"
                ssl_key = f"/etc/nginx/ssl/{main_entry['private_key']}" if main_entry['private_key'] else f"/etc/nginx/ssl/{dom}/privkey.pem"
                
                host_val = main_entry.get("host", "127.0.0.1")
                port_val = str(main_entry.get("port", 80))

                error_directives = generate_error_page_directives(handlers, indent="    ")
                error_locations = generate_error_handlers_locations(handlers, indent="    ")
                error_locations_str = f"\n\n{error_locations}" if error_locations else ""

                block = template.replace("{{domain}}", dom) \
                                .replace("{{upstream_name}}", main_entry.get("upstream_name", "")) \
                                .replace("{{ssl_cert}}", ssl_cert) \
                                .replace("{{ssl_key}}", ssl_key) \
                                .replace("{{max_body_size}}", main_entry["max_body_size"]) \
                                .replace("{{host}}", host_val) \
                                .replace("{{port}}", port_val) \
                                .replace("{{error_pages}}", error_directives) \
                                .replace("{{error_locations}}", error_locations_str)
                service_blocks.append(f"    # Custom Service: {main_entry['service']}\n{block}")
        else:
            secure_types = ["https", "https-only", "redirect-temp", "redirect-perm", "static-https", "static-https-only"]
            if main_entry["type"] in secure_types:
                ssl_servers.append(generate_ssl_server_block(main_entry, handlers))

    ssl_servers_text = "\n\n".join(ssl_servers) if ssl_servers else ""
    service_servers_text = "\n\n".join(service_blocks) if service_blocks else ""
    http_servers_text = generate_http_redirect_server(domains_map)

    default_http_server = generate_default_http_server(default_server_setting)
    http_blocks = [default_http_server]
    if http_servers_text:
        http_blocks.append(http_servers_text)
    http_section = "\n\n".join(http_blocks)

    has_ssl = any(s["type"] in ["https", "https-only", "redirect-temp", "redirect-perm", "static-https", "static-https-only"] for s in actual_settings if s.get("error_code") is None)
    if not has_ssl and default_server_setting:
        has_ssl = default_server_setting["type"] in ["https", "https-only", "redirect-temp", "redirect-perm", "static-https", "static-https-only"]

    ssl_blocks = []
    if has_ssl:
        ssl_blocks.append(generate_default_ssl_server(default_server_setting, actual_settings))
    if ssl_servers:
        ssl_blocks.append(ssl_servers_text)
    if service_blocks:
        ssl_blocks.append(service_servers_text)
    ssl_section = "\n\n".join(ssl_blocks)

    server_sections = [http_section]
    if ssl_section:
        server_sections.append(ssl_section)
    servers_text = "\n\n".join(server_sections)

    all_active_settings = actual_settings + ([default_server_setting] if default_server_setting else [])

    return f"""events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" host="$host"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    server_names_hash_bucket_size 128;{gzip_config}{generate_rate_limit_zones(all_active_settings)}

    # Real IP resolution (Trust Docker internal and private networks)
    set_real_ip_from 127.0.0.1;
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    # Production SSL Hardening Context Parameters
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Upstream Definitions
{generate_upstream_blocks(all_active_settings)}

{servers_text}
}}"""


def main():
    parser = argparse.ArgumentParser(description="Generate production nginx proxy configurations safely from standard settings schema matrices.")
    parser.add_argument("--input", "-i", default="settings.json", help="Input parameters schema source path mapping.")
    parser.add_argument("--output", "-o", default="nginx-proxy.conf", help="Target assembly destination file output path.")
    parser.add_argument("--dry-run", action="store_true", help="Output stream raw string asset evaluation dumps to standard stdout instead.")

    args = parser.parse_args()
    
    if is_wsl() and not is_wsl_mirrored():
        print(
            "\033[93m⚠️ WARNING: WSL2 detected running in default NAT network mode.\n"
            "In NAT mode, Nginx inside Docker cannot see the real public client IP directly.\n"
            "To fix this, we recommend enabling 'mirrored' networking in WSL2:\n"
            "1. Create or edit '%USERPROFILE%\\.wslconfig' in Windows.\n"
            "2. Add the following to your .wslconfig:\n"
            "   [wsl2]\n"
            "   networkingMode=mirrored\n"
            "3. Restart WSL by running 'wsl --shutdown' in PowerShell.\033[0m",
            file=sys.stderr
        )

    settings_data = load_settings(args.input)

    try:
        validated_settings = [validate_setting(s) for s in settings_data]
        nginx_config = generate_nginx_config(validated_settings)
    except ValueError as e:
        print(f"Validation Operational Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.dry_run:
        print(nginx_config)
    else:
        try:
            with open(args.output, "w") as f:
                f.write(nginx_config)
            print(f"\033[92m\u2714 Nginx proxy mapping generated successfully to: {args.output}\033[0m")
        except IOError as e:
            print(f"Disk Write Operational Error payload anomaly observed on out-stream: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
