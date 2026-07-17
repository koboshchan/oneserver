#!/usr/bin/env python3
"""
Ferron Proxy Configuration Generator (DEPRECATED)
"""

import sys

def main():
    print(
        "Error: generate_ferron_config.py is deprecated and no longer supported.\n"
        "oneserver has transitioned to an Nginx-only reverse proxy setup.\n"
        "Please use generate_nginx_config.py instead.",
        file=sys.stderr
    )
    sys.exit(1)

if __name__ == "__main__":
    main()
