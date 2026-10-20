#!/usr/bin/env python3
"""Command-line interface for the AI phishing detector.

Examples
--------
    python cli.py url https://paypal.com@secure-login-verify.tk/account
    python cli.py url suspicious.txt
    python cli.py email email.txt
    python cli.py email --subject "Verify now" --body "Click https://x.tk/login"
    python cli.py demo
"""

from __future__ import annotations

import argparse
import os
import sys

from phishing_detector.explainer import build_email_report, build_url_report
from phishing_detector.model import ModelStore

# Pretty console colours (disabled when not a TTY / on Windows without ANSI)
_COLORS = {
    "danger": "\033[91m",
    "warning": "\033[93m",
    "safe": "\033[92m",
    "dim": "\033[90m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

SEVERITY_MARK = {"high": "!!", "medium": " !", "low": "  "}


def _configure_console() -> None:
    """Make stdout UTF-8 so box/bar glyphs never crash a legacy console.

    Windows terminals default to a code page (e.g. cp1252) that cannot encode
    the progress-bar characters; switching the stream to UTF-8 with a safe
    fallback keeps output portable.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):  # pragma: no cover
            pass


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def render_report(report) -> str:
    lines: list[str] = []
    bar_len = 30
    filled = int(round(report.probability * bar_len))
    bar = "#" * filled + "-" * (bar_len - filled)

    lines.append("")
    lines.append(_c("=" * 66, "dim"))
    lines.append(f"{_c('VERDICT', 'bold')}: "
                 f"{_c(report.verdict_label.upper(), report.risk_class)}")
    lines.append(f"Phishing probability: [{bar}] {report.probability * 100:5.1f}%")
    lines.append(f"  ML model: {report.ml_probability * 100:5.1f}%   "
                 f"Rule score: {report.rule_score}/100")
    lines.append(_c("=" * 66, "dim"))

    lines.append("\nWHY — main reasons")
    if report.summary:
        for item in report.summary:
            lines.append(f"  * {item}")

    if report.warnings:
        lines.append("\nWARNING SIGNS")
        ordered = sorted(report.warnings, key=lambda f: {"high": 0, "medium": 1, "low": 2}[f.severity])
        for f in ordered:
            mark = SEVERITY_MARK.get(f.severity, " ")
            color = {"high": "danger", "medium": "warning", "low": "dim"}[f.severity]
            lines.append(f"  {_c('[' + f.severity.upper() + ']', color)} {f.title}")
            lines.append(f"        {_c(f.detail, 'dim')}")

    if report.ml_signs:
        lines.append("\nWHAT THE MODEL NOTICED")
        for sign in report.ml_signs:
            lines.append(f"  + {sign}")

    if report.trust_signs:
        lines.append("\nEVIDENCE OF LEGITIMACY")
        for sign in report.trust_signs:
            lines.append(f"  - {sign}")

    lines.append("\nRECOMMENDATION")
    if report.verdict == "phishing":
        lines.append(_c("  Do NOT click, reply or enter any credentials. "
                        "Report and delete the message.", "danger"))
    elif report.verdict == "suspicious":
        lines.append(_c("  Treat as untrusted. Verify the sender through an "
                        "official channel you already know.", "warning"))
    else:
        lines.append(_c("  No strong indicators found — still verify before "
                        "sharing sensitive data.", "safe"))

    if report.kind == "email" and report.meta:
        lines.append(_c("\nHEADER SUMMARY", "dim"))
        meta = report.meta
        lines.append(f"  From        : {meta.get('sender_name', '')} <{meta.get('sender_addr', '')}>")
        for key in ("return_path", "reply_to"):
            if meta.get(key):
                lines.append(f"  {key.replace('_', ' ').title():<12}: {meta[key]}")
        lines.append(f"  SPF/DKIM/DMARC: {meta.get('spf')} / {meta.get('dkim')} / {meta.get('dmarc')}")
        if meta.get("links"):
            lines.append(f"  Links found : {len(meta['links'])}")
        if meta.get("attachments"):
            lines.append(f"  Attachments : {', '.join(meta['attachments'])}")

    lines.append("")
    return "\n".join(lines)


def _read_source(value: str) -> str:
    """Return file contents when *value* is an existing path, else the value."""
    if os.path.isfile(value):
        with open(value, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return value


def main(argv: list[str] | None = None) -> int:
    _configure_console()
    parser = argparse.ArgumentParser(
        prog="cli.py", description="AI-based phishing detection (URLs and emails).")
    sub = parser.add_subparsers(dest="command", required=True)

    url_p = sub.add_parser("url", help="analyse a URL (or a file of URLs)")
    url_p.add_argument("target", help="URL string, or path to a file with one URL per line")
    url_p.add_argument("--threshold", type=float, default=None,
                       help="override phishing probability threshold (0-1)")

    email_p = sub.add_parser("email", help="analyse a raw email (or subject/body)")
    email_p.add_argument("target", nargs="?", default="",
                         help="raw email text or path to a .eml/.txt file")
    email_p.add_argument("--subject", default="")
    email_p.add_argument("--body", default="")

    sub.add_parser("demo", help="run built-in example samples")
    sub.add_parser("status", help="show model file status")

    args = parser.parse_args(argv)
    store = ModelStore("models")

    if args.command == "status":
        print(store.status())
        return 0

    if args.command == "demo":
        _demo(store)
        return 0

    store.ensure()

    if args.command == "url":
        source = _read_source(args.target)
        targets = [t.strip() for t in source.splitlines() if t.strip()] if os.path.isfile(args.target) else [args.target]
        for target in targets:
            report = build_url_report(target, store.url_model)
            if args.threshold is not None:
                from phishing_detector.explainer import verdict_for
                report.verdict, report.verdict_label = verdict_for(args.threshold)
            print(render_report(report))
        return 0

    raw = _read_source(args.target) if args.target else ""
    body = _read_source(args.body) if args.body else ""
    report = build_email_report(raw_email=raw, subject=args.subject, body=body, model=store.email_model)
    print(render_report(report))
    return 0


def _demo(store: ModelStore) -> None:
    store.ensure()
    print(_c("\n### DEMO 1 — credential-stealing URL", "bold"))
    print(render_report(build_url_report(
        "http://paypal.com@secure-login-verify.tk/account/verify?session=8831&email=a%40b.com",
        store.url_model)))

    print(_c("\n### DEMO 2 — legitimate URL", "bold"))
    print(render_report(build_url_report("https://docs.python.org/3/library/email.html",
                                        store.url_model)))

    print(_c("\n### DEMO 3 — spoofed delivery email", "bold"))
    demo_email = (
        "Return-Path: <bounce@mail-random-host.xyz>\n"
        "From: \"DHL Express\" <delivery@mail-random-host.xyz>\n"
        "Reply-To: recover@another-host.tk\n"
        "Subject: Urgent: your package is on hold - confirm your address immediately\n"
        "Authentication-Results: mx.example; spf=fail; dkim=none; dmarc=fail\n"
        "Message-ID: <20260101@mail-random-host.xyz>\n"
        "Content-Type: text/html; charset=utf-8\n"
        "\n"
        "<html><body><p>Dear customer, your parcel could not be delivered. "
        "Confirm your address and pay the redelivery fee within 24 hours.</p>"
        "<p><a href=\"http://track-dhl-secure.xyz/track?id=7788\">dhl.com/tracking</a></p>"
        "<form action=\"http://track-dhl-secure.xyz/collect\"><input name=\"card\"></form>"
        "</body></html>\n"
    )
    print(render_report(build_email_report(raw_email=demo_email, model=store.email_model)))


if __name__ == "__main__":
    sys.exit(main())
