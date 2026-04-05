from __future__ import annotations

import argparse
import logging
import sys

from smtp_audit.core import SMTPAuditConfig, load_values, run_selected_checks

BASE_BODY = (
    "This email is part of an approved security assessment. "
    "Please forward this message to the security testing contact."
)


def configure_logging(debug: bool, logfile: str = "smtp_audit.log") -> None:
    logger = logging.getLogger("smtp_audit")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(stream_handler)

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
    logger.addHandler(file_handler)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="smtp-vrfy-relay-audit",
        description="SMTP security auditing CLI for relay, spoofing, and VRFY exposure checks.",
    )
    parser.add_argument("--targets", required=True, help="SMTP host or path to a file containing one host per line")
    parser.add_argument("--port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("--tester", required=True, help="Recipient used during relay tests")

    parser.add_argument("--from-addr", "--fromaddr", dest="from_addr", help="Sender used for spoof/relay tests")
    parser.add_argument("--to-addr", "--toaddr", dest="to_addr", help="Recipient used for internal spoofing tests")
    parser.add_argument("--subject", default="SMTP Security Audit", help="Subject for test emails")
    parser.add_argument("--body", default=BASE_BODY, help="Body text for generated test emails")

    parser.add_argument(
        "--vrfy-addresses",
        "--address",
        dest="vrfy_addresses",
        help="Single address or file containing addresses used in VRFY checks",
    )
    parser.add_argument("--mode", choices=["full", "external", "internal", "vrfy"], default="full")

    # Backward-compatible flags from the original script.
    parser.add_argument("-e", "--external", action="store_true", help="Legacy alias for --mode external")
    parser.add_argument("-i", "--internal", action="store_true", help="Legacy alias for --mode internal")
    parser.add_argument("-v", "--vrfy", action="store_true", help="Legacy alias for --mode vrfy")

    parser.add_argument("--debug", action="store_true", help="Enable SMTP and application debug logs")
    return parser.parse_args(argv)


def resolve_mode(args: argparse.Namespace) -> str:
    selected_legacy_modes = [
        (args.external, "external"),
        (args.internal, "internal"),
        (args.vrfy, "vrfy"),
    ]
    active = [name for enabled, name in selected_legacy_modes if enabled]
    if len(active) > 1:
        raise ValueError("Select only one of -e/--external, -i/--internal, or -v/--vrfy.")
    if active:
        return active[0]
    return args.mode


def build_config(args: argparse.Namespace, mode: str) -> SMTPAuditConfig:
    targets = load_values(args.targets)
    vrfy_addresses = load_values(args.vrfy_addresses) if args.vrfy_addresses else []

    return SMTPAuditConfig(
        targets=targets,
        port=args.port,
        tester_address=args.tester,
        from_address=args.from_addr,
        to_address=args.to_addr,
        body=f"{args.body}\n\nAudit contact: {args.tester}",
        subject=args.subject,
        vrfy_addresses=vrfy_addresses,
        debug=args.debug,
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(debug=args.debug)

    try:
        mode = resolve_mode(args)
        config = build_config(args, mode)
        run_selected_checks(config, mode)
        return 0
    except ValueError as exc:
        logging.getLogger("smtp_audit").error("Input validation failed: %s", exc)
        return 2
    except KeyboardInterrupt:
        logging.getLogger("smtp_audit").warning("Execution interrupted by user")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
