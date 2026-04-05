# smtp-vrfy-relay-audit

Named after the exact SMTP controls it validates: `VRFY` exposure and relay/spoofing behavior.

A focused SMTP security assessment CLI for authorized penetration tests. The toolkit validates three common SMTP exposure classes:

- External relay acceptance
- Internal spoofing acceptance
- User enumeration via `VRFY`

## Engineering Highlights
This repository is a maintainable, production-style SMTP security auditing toolkit focused on engineering quality:

- Modular Python package instead of a single script
- Stronger input validation and execution modes
- Structured logging with file + console output
- Backward-compatible legacy entrypoint (`SMTPHAK.py`)
- Basic automated tests for core I/O behavior

## Technology Stack

- Language: Python 3.10+
- Standard libraries: `argparse`, `smtplib`, `email`, `logging`, `unittest`
- Packaging: `pyproject.toml` (PEP 621 + setuptools)

## Repository Structure

```text
.
|-- smtp_audit/
|   |-- __init__.py
|   |-- __main__.py
|   |-- cli.py
|   `-- core.py
|-- tests/
|   `-- test_io.py
|-- SMTPHAK.py
|-- pyproject.toml
`-- README.md
```

## Installation

```bash
python -m pip install -e .
```

## Usage

```bash
python -m smtp_audit --targets <smtp-host-or-file> --tester <email>
```

### Common Examples

Run full audit (external + internal):

```bash
python -m smtp_audit --targets 10.10.10.15 --tester sec-team@example.com --from-addr admin@example.com --to-addr user@example.com
```

Run external relay checks only:

```bash
python -m smtp_audit --targets targets.txt --tester sec-team@example.com --from-addr admin@example.com --mode external
```

Run VRFY checks only:

```bash
python -m smtp_audit --targets smtp.example.com --tester sec-team@example.com --vrfy-addresses users.txt --mode vrfy
```

Legacy compatibility is preserved:

```bash
python SMTPHAK.py --targets smtp.example.com --tester sec-team@example.com -e --fromaddr admin@example.com
```

## Quality Controls

Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Responsible Use
Use this tool only on systems you are explicitly authorized to test. The project is designed for defensive security assessments and audit validation.

## License
MIT License
