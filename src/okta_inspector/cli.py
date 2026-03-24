"""Command-line interface for okta-inspector."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from okta_inspector import __version__
from okta_inspector.analyzers import available_frameworks


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="okta-inspector",
        description=f"Okta Multi-Framework Compliance Audit Tool v{__version__}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  okta-inspector -d your-org.okta.com -t YOUR_API_TOKEN
  okta-inspector -d your-org.okta.com -t YOUR_API_TOKEN --frameworks stig,cmmc
  OKTA_DOMAIN=your-org.okta.com OKTA_API_TOKEN=xxx okta-inspector
""",
    )

    parser.add_argument(
        "-d",
        "--domain",
        default=os.environ.get("OKTA_DOMAIN"),
        help="Okta domain (e.g. your-org.okta.com).  Env: OKTA_DOMAIN",
    )
    parser.add_argument(
        "-t",
        "--token",
        default=os.environ.get("OKTA_API_TOKEN"),
        help="Okta API token.  Env: OKTA_API_TOKEN",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        help="Custom output directory (default: timestamped)",
    )
    parser.add_argument(
        "-p",
        "--page-size",
        type=int,
        default=200,
        help="Items per API page (default: 200)",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Max pages to retrieve per endpoint (default: 10)",
    )
    parser.add_argument(
        "--oauth",
        action="store_true",
        help="Token is OAuth 2.0 Bearer (default: SSWS)",
    )
    parser.add_argument(
        "--frameworks",
        help=f"Comma-separated list of frameworks to run (default: all).  Available: {', '.join(available_frameworks()) or 'loading...'}",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args(argv)

    if not args.domain:
        parser.error("--domain is required (or set OKTA_DOMAIN)")
    if not args.token:
        parser.error("--token is required (or set OKTA_API_TOKEN)")

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Lazy imports to keep --help fast
    from okta_inspector.client import OktaClient
    from okta_inspector.engine import AuditEngine
    from okta_inspector.output import OutputManager

    # Prepare token
    token = args.token
    if args.oauth and not token.startswith("Bearer "):
        token = f"Bearer {token}"

    client = OktaClient(
        domain=args.domain,
        token=token,
        page_size=args.page_size,
        max_pages=args.max_pages,
    )

    output_dir = Path(args.output_dir) if args.output_dir else None
    output = OutputManager(base_dir=output_dir)

    frameworks = [f.strip() for f in args.frameworks.split(",")] if args.frameworks else None

    if not client.test_connection():
        logging.getLogger(__name__).error("Failed to connect to Okta API. Verify domain and token.")
        sys.exit(1)

    engine = AuditEngine(client, output, frameworks=frameworks)

    try:
        engine.run()
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Audit interrupted by user")
        sys.exit(1)
    except Exception as e:
        logging.getLogger(__name__).error("Audit failed: %s", e)
        sys.exit(1)
