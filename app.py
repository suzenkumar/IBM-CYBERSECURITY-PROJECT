#!/usr/bin/env python3
"""Flask web application for the AI-based phishing detector.

Run:
    python app.py
then open http://127.0.0.1:5000

Endpoints
---------
GET  /            HTML dashboard
POST /api/analyze-url    JSON { url } -> full report
POST /api/analyze-email  JSON { raw_email | subject | body | file } -> full report
GET  /api/health   model status
GET  /api/examples built-in demo samples
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, render_template, request

from phishing_detector.explainer import build_email_report, build_url_report
from phishing_detector.model import ModelStore

MAX_PAYLOAD_BYTES = 512 * 1024  # 512 KB is plenty for a pasted email

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_PAYLOAD_BYTES

#: Models live next to this file in ``models/``.
STORE = ModelStore(os.path.join(os.path.dirname(os.path.abspath(__file__)), "models"))


# --------------------------------------------------------------------------
# Serialisation helpers
# --------------------------------------------------------------------------

def _finding(finding) -> dict:
    return {
        "code": finding.code,
        "title": finding.title,
        "detail": finding.detail,
        "severity": finding.severity,
        "points": finding.points,
    }


def _report_payload(report) -> dict:
    return {
        "kind": report.kind,
        "target": report.target,
        "verdict": report.verdict,
        "verdict_label": report.verdict_label,
        "risk_class": report.risk_class,
        "probability": round(report.probability, 4),
        "ml_probability": round(report.ml_probability, 4),
        "rule_score": report.rule_score,
        "summary": report.summary,
        "warnings": [_finding(f) for f in report.warnings],
        "trust": [_finding(f) for f in report.trust],
        "ml_signs": report.ml_signs,
        "trust_signs": report.trust_signs,
        "meta": report.meta,
    }


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/robots.txt")
def robots():
    """Crawl directives; API routes are excluded from indexing."""
    from flask import Response
    body = ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /api/\n\n"
            "Sitemap: {base}/sitemap.xml\n")
    return Response(body.format(base=request.host_url.rstrip("/")),
                    mimetype="text/plain")


@app.get("/sitemap.xml")
def sitemap():
    """Single-page sitemap for search engines."""
    from flask import Response
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
           '  <url>\n'
           f'    <loc>{request.host_url}</loc>\n'
           '    <changefreq>monthly</changefreq>\n'
           '    <priority>1.0</priority>\n'
           '  </url>\n'
           '</urlset>\n')
    return Response(xml, mimetype="application/xml")


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

@app.get("/api/health")
def health():
    status = STORE.status()
    status["ok"] = True
    return jsonify(status)


@app.get("/api/examples")
def examples():
    """Built-in demo samples so the UI is usable without real data."""
    return jsonify({
        "url_phishing": "http://paypal.com@secure-login-verify.tk/account/verify"
                        "?session=8831&email=user%40mail.com",
        "url_shortener": "https://bit.ly/3xYzAbC",
        "url_legit": "https://docs.python.org/3/library/email.html",
        "email_phishing": (
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
            "</body></html>\n"
        ),
        "email_legit": (
            "Return-Path: <notifications@github.com>\n"
            "From: \"GitHub\" <notifications@github.com>\n"
            "Subject: [myorg/repo] Pull request #42 merged\n"
            "Authentication-Results: mx.example; spf=pass; dkim=pass; dmarc=pass\n"
            "Message-ID: <abc123@github.com>\n"
            "Received: from github.com (github.com [140.82.112.3]) by mx.example;\n"
            "\n"
            "Hi Alex,\n\nThe pull request has been merged into main. "
            "Tests are green. See https://github.com/myorg/repo/pull/42 for details.\n\n"
            "-- GitHub\n"
        ),
    })


@app.post("/api/analyze-url")
def analyze_url_endpoint():
    payload = request.get_json(silent=True) or {}
    target = (payload.get("url") or "").strip()
    if not target:
        return jsonify({"error": "Provide a 'url' field."}), 400
    if len(target) > 8000:
        return jsonify({"error": "URL too long (max 8000 characters)."}), 400

    STORE.ensure()
    try:
        report = build_url_report(target, STORE.url_model)
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(_report_payload(report))


@app.post("/api/analyze-email")
def analyze_email_endpoint():
    payload = request.get_json(silent=True) or {}
    raw = payload.get("raw_email") or payload.get("email") or ""
    subject = payload.get("subject") or ""
    body = payload.get("body") or ""

    if not (raw.strip() or subject.strip() or body.strip()):
        return jsonify({"error": "Provide 'raw_email' or 'subject'/'body'."}), 400

    STORE.ensure()
    try:
        report = build_email_report(raw_email=raw, subject=subject, body=body,
                                    model=STORE.email_model)
    except Exception as exc:  # pragma: no cover - defensive
        return jsonify({"error": f"Analysis failed: {exc}"}), 500
    return jsonify(_report_payload(report))


@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "Payload too large (max 512 KB)."}), 413


if __name__ == "__main__":
    # Warm the models up on first launch so the first request is fast.
    try:
        STORE.ensure()
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[warn] could not load/train models: {exc}")

    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=bool(os.environ.get("FLASK_DEBUG")))
