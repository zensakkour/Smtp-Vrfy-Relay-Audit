"""Legacy entrypoint kept for backward compatibility.

Use `python -m smtp_audit --help` for the maintained CLI.
"""

from smtp_audit.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
