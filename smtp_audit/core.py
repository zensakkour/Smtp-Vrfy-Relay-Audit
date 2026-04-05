from __future__ import annotations

from dataclasses import dataclass
from email.mime.text import MIMEText
import logging
from pathlib import Path
import smtplib
from typing import Iterable, Sequence

LOGGER = logging.getLogger("smtp_audit")
FAKE_SENDER = "does-not-exist@invalid.local"


@dataclass(frozen=True)
class SMTPAuditConfig:
    targets: Sequence[str]
    port: int
    tester_address: str
    from_address: str | None
    to_address: str | None
    body: str
    subject: str
    vrfy_addresses: Sequence[str]
    debug: bool


def load_values(raw: str) -> list[str]:
    """Load one value or many values from a text file path."""
    candidate = Path(raw)
    if candidate.exists() and candidate.is_file():
        return [line.strip() for line in candidate.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [raw.strip()]


def build_message(subject: str, sender: str, recipient: str, body: str) -> str:
    message = MIMEText(body)
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    return message.as_string()


def run_external_relay_test(config: SMTPAuditConfig, sender: str, recipient: str) -> None:
    if not sender or not recipient:
        raise ValueError("External relay test requires both sender and recipient addresses.")

    body = f"{config.body}\n\nTest type: external relay/spoofing"
    for target in config.targets:
        LOGGER.info("Testing external relay on %s:%s", target, config.port)
        try:
            with smtplib.SMTP(target, config.port, timeout=15) as smtp:
                if config.debug:
                    smtp.set_debuglevel(1)
                smtp.ehlo_or_helo_if_needed()
                payload = build_message(config.subject, sender, recipient, f"{body}\nTarget: {target}")
                smtp.sendmail(sender, recipient, payload)
                LOGGER.critical(
                    "VULNERABLE: %s accepted external relay (from=%s, to=%s)",
                    target,
                    sender,
                    recipient,
                )
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPResponseException) as exc:
            LOGGER.error("Not vulnerable or blocked by policy on %s: %s", target, exc)
        except OSError as exc:
            LOGGER.error("Connection issue with %s: %s", target, exc)


def run_internal_spoof_test(config: SMTPAuditConfig) -> None:
    if not config.from_address or not config.to_address:
        raise ValueError("Internal spoof test requires --from-addr and --to-addr.")

    sender_domain = config.from_address.split("@")[-1].lower()
    recipient_domain = config.to_address.split("@")[-1].lower()
    if sender_domain != recipient_domain:
        raise ValueError("Internal spoofing test requires sender and recipient to share the same domain.")

    body = f"{config.body}\n\nTest type: internal spoofing"
    for target in config.targets:
        LOGGER.info("Testing internal spoofing on %s:%s", target, config.port)
        try:
            with smtplib.SMTP(target, config.port, timeout=15) as smtp:
                if config.debug:
                    smtp.set_debuglevel(1)
                smtp.ehlo_or_helo_if_needed()
                payload = build_message(config.subject, config.from_address, config.to_address, f"{body}\nTarget: {target}")
                smtp.sendmail(config.from_address, config.to_address, payload)
                LOGGER.critical("VULNERABLE: %s accepted internal spoofing (from=%s)", target, config.from_address)
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused, smtplib.SMTPResponseException) as exc:
            LOGGER.error("Not vulnerable or blocked by policy on %s: %s", target, exc)
        except OSError as exc:
            LOGGER.error("Connection issue with %s: %s", target, exc)


def run_vrfy_test(config: SMTPAuditConfig) -> None:
    if not config.vrfy_addresses:
        raise ValueError("VRFY mode requires at least one address via --vrfy-addresses.")

    for target in config.targets:
        LOGGER.info("Testing VRFY user enumeration on %s:%s", target, config.port)
        try:
            with smtplib.SMTP(target, config.port, timeout=15) as smtp:
                if config.debug:
                    smtp.set_debuglevel(1)
                smtp.ehlo_or_helo_if_needed()
                for address in config.vrfy_addresses:
                    try:
                        response_code, _ = smtp.verify(address)
                        if response_code in (250, 251, 252):
                            LOGGER.warning("Possible enumeration leak: %s on %s (code=%s)", address, target, response_code)
                        else:
                            LOGGER.info("VRFY blocked/failed for %s on %s (code=%s)", address, target, response_code)
                    except smtplib.SMTPResponseException as exc:
                        LOGGER.info("VRFY blocked for %s on %s: %s", address, target, exc)
        except OSError as exc:
            LOGGER.error("Connection issue with %s: %s", target, exc)


def run_full_audit(config: SMTPAuditConfig) -> None:
    if not config.from_address:
        raise ValueError("Full audit requires --from-addr for relay/spoof checks.")

    run_external_relay_test(config, config.from_address, config.tester_address)
    run_external_relay_test(config, FAKE_SENDER, config.tester_address)
    run_internal_spoof_test(config)


def run_selected_checks(config: SMTPAuditConfig, mode: str) -> None:
    if mode == "external":
        if not config.from_address:
            raise ValueError("External mode requires --from-addr.")
        run_external_relay_test(config, config.from_address, config.tester_address)
        run_external_relay_test(config, FAKE_SENDER, config.tester_address)
        return

    if mode == "internal":
        run_internal_spoof_test(config)
        return

    if mode == "vrfy":
        run_vrfy_test(config)
        return

    run_full_audit(config)
