# PhishGuard — AI-Based Phishing Detection Tool

> **Made by Er-Suzen Kumar Mohanty** · **IBM Cyber Security Project**

A beginner-to-intermediate **defensive security** project that analyses suspicious
**emails and URLs**, classifies them with **machine learning**, and **explains every
warning sign** in language a non-expert can act on.

> **Defensive use only.** PhishGuard performs *static* analysis — it never opens,
> fetches, or executes a link, and never stores the samples you paste.

---

## Table of contents

1. [What it does](#what-it-does)
2. [Step-by-step usage](#step-by-step-usage)
3. [Screenshots & sample output](#sample-output)
4. [Architecture](#architecture)
5. [Quick start](#quick-start)
6. [How the detection works](#how-the-detection-works)
7. [Project layout](#project-layout)
8. [Web API](#web-api)
9. [CLI usage](#cli-usage)
10. [Training on real datasets](#training-on-real-datasets)
11. [Testing](#testing)
12. [Skills demonstrated](#skills-demonstrated)
13. [Limitations & responsible use](#limitations--responsible-use)
14. [Roadmap / extensions](#roadmap--extensions)
15. [Credits](#credits)

---

## What it does

| Capability | Details |
|---|---|
| **URL inspection** | 27 lexical/structural features: length, subdomain depth, hyphens, digits, entropy, `@` userinfo trick, raw-IP hosts, punycode, high-abuse TLDs, shorteners, ports, HTTPS, credential vocabulary |
| **Email header analysis** | SPF / DKIM / DMARC results, display-name spoofing, `Return-Path` / `Reply-To` mismatches, `Message-ID` domain, routing hops, attachments |
| **Email content analysis** | urgency wording, credential-theft phrasing, link-vs-sender mismatch, anchor-text-vs-href mismatch, embedded HTML forms, HTML-only messages |
| **Machine learning** | Two scikit-learn pipelines (URL: hand-crafted features + char n-grams; Email: word n-grams) with logistic regression |
| **Explainability** | Rule findings with severities **plus** the exact model features that moved the decision (`coefficient × value`), and the evidence *for* legitimacy |
| **Interfaces** | Flask web dashboard (URL + email tabs) and a colour CLI (`demo`, `url`, `email`, `status`) |

---

## Step-by-step usage

### Path A — Web app (recommended for beginners)

**Step 1 · Install Python & dependencies**

Open a terminal in the `phishing-detector` folder:

```bash
cd phishing-detector
python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

**Step 2 · Train the machine-learning models** (once)

```bash
python train_model.py
```

This creates `models/url_model.joblib` and `models/email_model.joblib`.
If you skip this, the app trains them automatically on first launch.

**Step 3 · Start the web app**

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser. The badge in the top-right
turns green with **"models ready"** when everything is loaded.

**Step 4 · Check a suspicious URL**

1. Click the **URL Check** tab.
2. Paste the complete link (include `http://` / `https://` if you have it).
3. Press **Analyze URL**.

```
http://paypal.com@secure-login-verify.tk/account/verify
```

**Step 5 · Check a suspicious email**

1. Click the **Email Check** tab.
2. Paste the **raw email** — headers *and* body.
   * Gmail → open message → **⋮** → **Show original** → copy everything.
   * Outlook → open message → **⋯** → **View** → **View message source**.
3. Press **Analyze Email**.
   * No headers handy? Expand **"Or enter subject / body separately"** instead.

**Step 6 · Understand the result**

Every analysis shows the same structure:

| Section | What it tells you |
|---|---|
| **Verdict pill** | `Likely phishing` / `Suspicious` / `Looks legitimate` |
| **Gauge + scores** | Overall risk %, plus the ML score and the rule score separately |
| **Why this verdict** | The top three reasons in one line each |
| **Warning signs** | Every finding, colour-coded by severity, with a plain-language explanation |
| **What the model noticed** | The exact features that pushed the ML decision toward "phishing" |
| **Evidence of legitimacy** | Counter-evidence, so you can weigh both sides |
| **Recommended action** | What to do next |
| **Technical details** | Raw feature values and parsed header metadata |

**Step 7 · Act on the advice**

* **Likely phishing** → do **not** click, reply, or enter credentials. Report and delete.
* **Suspicious** → verify the sender through an official channel you already know.
* **Looks legitimate** → no strong indicators, but still confirm before sharing data.

### Path B — Command line (optional, same engine)

```bash
python cli.py demo                                         # built-in examples
python cli.py url "http://bit.ly/3xYzAbC"                  # analyse a URL
python cli.py url urls.txt                                 # a file of URLs, one per line
python cli.py email suspicious.eml                         # analyse a raw email
python cli.py email --subject "Verify now" --body "..."    # subject + body only
python cli.py status                                       # which model files exist
```

### Golden rule of phishing defence

> **Never trust a link you did not type yourself.** If a message pressures you to
> act fast, open the official website manually in a new tab and verify there.

---

## Sample output

```
==================================================================
VERDICT: LIKELY PHISHING
Phishing probability: [##########################----]  86.3%
  ML model: 100.0%   Rule score: 61/100
==================================================================

WHY — main reasons
  * Deceptive '@' in the link
  * High-abuse top-level domain '.tk'
  * Unencrypted http:// link

WARNING SIGNS
  [HIGH] Deceptive '@' in the link
        Browsers display only the text *before* '@' for some links, so
        'https://paypal.com@evil.example' actually goes to evil.example.
  [MEDIUM] Credential-theft vocabulary in the link
        Found 'account', 'login', 'secure', 'session', 'verify' — wording designed
        to push victims toward a fake login or verification page.

WHAT THE MODEL NOTICED
  + 5 credential-theft keyword(s) in the link  (+4.85)
  + Sits on a TLD with a known abuse reputation  (+3.45)

RECOMMENDATION
  Do NOT click, reply or enter any credentials. Report and delete the message.
```

---

## Architecture

```
              ┌──────────────────────────── Flask (app.py) ────────────────────────────┐
              │   /            dashboard (templates/index.html + static/)              │
              │   /api/analyze-url     /api/analyze-email     /api/health  /examples   │
              └───────────────────────────────┬────────────────────────────────────────┘
                                              │
                       ┌──────────────────────┴───────────────────────┐
                       │                                              │
            ┌──────────▼──────────┐                       ┌───────────▼───────────┐
            │  url_analyzer.py    │                       │  email_analyzer.py    │
            │  rule findings      │                       │  header + body rules  │
            └──────────┬──────────┘                       └───────────┬───────────┘
                       │  features.py                                 │
                       │  (27 URL features)                           │
                       └──────────────────────┬───────────────────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │   model.py        │  ← joblib persistence
                                    │  sklearn pipelines│
                                    └─────────┬─────────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  explainer.py     │
                                    │  blended verdict  │
                                    │  + human reasons  │
                                    └───────────────────┘
                    training.py + synthetic.py  →  train_model.py  →  models/*.joblib
```

**Verdict blending.** The final probability mixes the ML score with the rule score
(URL: 65 % ML / 35 % rules, Email: 55 % ML / 45 % headers+content). Rules provide
auditability, the model provides generalisation; together they reduce both
false negatives and unexplainable verdicts.

| Blended probability | Verdict |
|---|---|
| ≥ 0.65 | **Likely phishing** |
| 0.40 – 0.65 | **Suspicious** |
| < 0.40 | **Looks legitimate** |

---

## Quick start

### 1. Requirements

**System requirements**

| Item | Requirement |
|---|---|
| Operating system | Windows / macOS / Linux |
| Python | **3.10 or newer** (developed on 3.14.7) |
| RAM | ~512 MB free (models are tiny) |
| Disk | ~60 MB including dependencies |
| Browser | Any modern browser (Chrome, Edge, Firefox, Safari) |
| Internet | **Not required** — everything runs locally |

**Python packages** — all listed in [`requirements.txt`](requirements.txt):

| Package | Version | Purpose |
|---|---|---|
| `Flask` | ≥ 3.0, < 4.0 | Web dashboard + JSON API |
| `scikit-learn` | ≥ 1.4 | ML pipelines, TF-IDF, logistic regression |
| `numpy` | ≥ 1.26 | Feature vectors |
| `scipy` | ≥ 1.11 | Sparse matrices from TF-IDF |
| `joblib` | ≥ 1.3 | Model persistence (`.joblib` files) |

> On Windows you may need to run Python as `py -3` instead of `python`
> if Python is not on your PATH.

### 2. Install

```bash
cd phishing-detector
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Train the models (first run)

```bash
python train_model.py
```

Expected output:

```
Training phishing models ...
  [URL] hold-out accuracy=1.000  f1=1.000  (train=640, test=160)
  [Email] hold-out accuracy=1.000  f1=1.000  (train=560, test=140)
Saved models to 'models/' (1.4s)
```

> The synthetic corpus mirrors the rule heuristics, so 100 % is expected here.
> Real-world accuracy is covered in [Training on real datasets](#training-on-real-datasets).

### 4. Run the web app

```bash
python app.py
# open http://127.0.0.1:5000
```

If `models/` is empty, the app trains the models automatically on first launch.

### 5. Or use the CLI

```bash
python cli.py demo            # three built-in examples
python cli.py url "http://paypal.com@secure-login-verify.tk/account/verify?session=8831"
python cli.py email email.eml
python cli.py email --subject "Verify now" --body "Click http://x.tk/login"
python cli.py status
```

---

## How the detection works

### URL features (`features.py`)

| Group | Features |
|---|---|
| Length | `url_length`, `host_length`, `path_length`, `query_length` |
| Structure | `num_dots`, `num_subdomains`, `num_hyphens`, `num_digits`, `digit_ratio`, `num_slashes`, `path_depth` |
| Obfuscation | `num_at`, `num_question`, `num_equals`, `num_percent`, `num_ampersand`, `non_ascii`, `host_entropy` |
| Host tricks | `has_ip`, `has_userinfo`, `has_punycode`, `unusual_port`, `has_https` |
| Reputation | `keyword_count`, `brand_in_host`, `suspicious_tld`, `is_shortener` |

The model also sees **character 3–5-grams** of the raw URL, which capture
tokens like `login-`, `-verify`, `/wp-admin`, `.tk/`.

### Email features (`email_analyzer.py`)

* **Authentication:** `spf`, `dkim`, `dmarc` results parsed from
  `Authentication-Results` / `Received-SPF`.
* **Identity:** display name vs. address, `From` vs. `Return-Path` vs. `Reply-To`
  vs. `Message-ID` domains.
* **Links:** IP hosts, `http://`, shorteners, bad TLDs, brand-in-host-but-wrong-domain,
  anchor text ≠ href, links disagreeing with the sender's domain.
* **Content:** urgency phrases, credential requests, HTML-only body, embedded forms.
* **Attachments:** risky extensions (`.exe`, `.scr`, `.docm`, `.zip`, `.html`, …).

### Explainability (`explainer.py`)

For every prediction the model exposes:

```
contribution = logistic_coefficient × feature_value
```

The largest positive contributions become *"What the model noticed"*, the largest
negative ones *"Evidence of legitimacy"*. This makes an ML verdict auditable
instead of a black box — a core requirement for security tooling.

---

## Project layout

```
phishing-detector/                 ← C:\Users\suzen\Documents\Default Project\phishing-detector
├── app.py                     # Flask app + JSON API + /robots.txt + /sitemap.xml
├── cli.py                     # command-line interface
├── train_model.py             # training entry point
├── requirements.txt           # Python dependencies
├── README.md                  # this file
├── .gitignore
├── phishing_detector/         # the importable package (core logic)
│   ├── __init__.py
│   ├── features.py            # 27 URL features + threat vocabularies
│   ├── url_analyzer.py        # URL rule engine → Finding objects
│   ├── email_analyzer.py      # email header/body rule engine
│   ├── synthetic.py           # seeded training corpora
│   ├── model.py               # sklearn pipelines + PhishingModel/ModelStore
│   ├── training.py            # train + evaluate + persist
│   └── explainer.py           # blended verdict + human explanations
├── templates/
│   └── index.html             # responsive dashboard (SEO + mobile friendly)
├── static/
│   ├── style.css              # styling + 6-tier responsive system
│   ├── app.js                 # tab UI + API calls
│   └── robots.txt             # crawler directives
├── tests/
│   ├── test_detector.py       # 20 unit tests
│   └── smoke_ui.py            # UI/CSS/responsive smoke checks
├── models/                    # generated: url_model.joblib, email_model.joblib, metrics.json
└── data/                      # optional: drop real datasets here
```

---

## Web API

All endpoints return JSON.

### `POST /api/analyze-url`

```bash
curl -X POST http://127.0.0.1:5000/api/analyze-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal.com@secure-login-verify.tk/account/verify"}'
```

Response (abridged):

```json
{
  "kind": "url",
  "verdict": "phishing",
  "verdict_label": "Likely phishing",
  "risk_class": "danger",
  "probability": 0.863,
  "ml_probability": 1.0,
  "rule_score": 61,
  "summary": ["Deceptive '@' in the link", "High-abuse top-level domain '.tk'"],
  "warnings": [
    { "code": "userinfo", "title": "Deceptive '@' in the link",
      "detail": "Browsers display only the text before '@' …",
      "severity": "high", "points": 20 }
  ],
  "trust": [...],
  "ml_signs": ["5 credential-theft keyword(s) in the link  (+4.85)"],
  "trust_signs": ["Link uses HTTPS (encrypted transport)"],
  "meta": { "host": "secure-login-verify.tk", "features": { "...": 0 } }
}
```

### `POST /api/analyze-email`

Accept either a raw email or separate parts:

```json
{ "raw_email": "From: ...\nSubject: ...\n\nBody" }
```
```json
{ "subject": "Urgent: verify", "body": "Click http://x.tk/login" }
```

### `GET /api/health` · `GET /api/examples`

Model status and built-in demo samples used by the UI buttons.

---

## CLI usage

```
python cli.py url <URL or file>       # analyse one URL or a file of URLs
python cli.py email <file|text>       # analyse a raw email
       --subject "…" --body "…"       #   or just subject/body
python cli.py demo                    # built-in examples
python cli.py status                  # which model files exist
```

---

## Training on real datasets

The bundled synthetic corpus makes the project runnable offline, but for realistic
evaluation use real, publicly available data. Two paths are supported:

### A. Retrain from CSV (recommended)

`urls.csv` — columns `url,label`
```csv
url,label
https://www.google.com/search?q=test,0
http://paypal-secure.tk/login,1
```

`emails.csv` — columns `text,label` (text = subject + "\n" + body)

```bash
python train_model.py --urls-csv data/urls.csv --emails-csv data/emails.csv
```

### B. Suggested public sources

| Data | Source | Notes |
|---|---|---|
| Phishing URLs | [PhishTank](https://phishtank.org/developer_info.php), [OpenPhish](https://openphish.com/), [APWG / Kaggle "Phishing Site URLs"](https://www.kaggle.com/datasets) | label 1 |
| Legitimate URLs | [Tranco](https://tranco-list.eu/) top-1M, Alexa/Cisco lists | label 0 |
| Phishing emails | [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) (spam), Nazario phishing corpus | label 1 |
| Legitimate emails | [Enron email dataset](https://www.cs.cmu.edu/~enron/), SpamAssassin "ham" | label 0 |

**Report honestly.** On real data you should expect roughly:

| Metric | Reasonable target |
|---|---|
| URL accuracy | 0.93 – 0.97 |
| Email accuracy | 0.95 – 0.99 |
| Phishing recall | ≥ 0.95 (missing phishing is the costly error) |

Track **precision, recall and F1 per class** (`sklearn.classification_report`),
because with imbalanced security data accuracy alone is misleading. Swap in
`RandomForestClassifier` / `GradientBoostingClassifier` for a fair comparison —
`model.py` only requires a scikit-learn `Pipeline`.

---

## Testing

```bash
python -m unittest discover -s tests -v
# or:  python -m pytest -q
```

20 tests cover feature extraction, URL rules (userinfo, IP, punycode, shortener,
legit TLDs), email rules (SPF/DMARC, display-name spoof, anchor mismatch, HTML form),
model class separation, and report blending.

---

## Skills demonstrated

`Python` · `machine learning` (scikit-learn pipelines, logistic regression,
feature engineering) · `NLP` (char + word n-grams, TF-IDF) · `Flask` (REST API +
SPA dashboard) · `defensive security` (SPF/DKIM/DMARC, URL/header forensics,
security-focused UX) · `testing` · `explainable AI`.

---

## Limitations & responsible use

* **Synthetic training data** mirrors the rule heuristics — perfect scores are
  expected. Evaluate on real corpora before drawing conclusions.
* **Static analysis only.** No live reputation checks (Google Safe Browsing,
  VirusTotal); a brand-new phishing domain may look structurally clean.
* **Legitimate mail behind marketing platforms** (Mailchimp, SendGrid, tracking
  domains, link shorteners) can look suspicious and will trigger medium findings.
* **English-centric** vocabulary; add locales by extending the word lists in
  `features.py` / `email_analyzer.py`.
* Model files are only as fresh as the last training run — phishing tactics drift,
  so schedule periodic retraining.
* Use this tool to **protect** people. Never deploy it to generate, host, or
  distribute phishing content.

---

## Roadmap / extensions

1. **Live reputation enrichment** — Safe Browsing / VirusTotal / WHOIS age (behind a flag).
2. **`.eml` / `.msg` upload** with attachment hashing.
3. **URL expansion** — resolve shorteners in a sandboxed fetcher.
4. **Model comparison notebook** — LR vs. Random Forest vs. linear SVM vs. gradient boosting.
5. **Confidence calibration** — Platt scaling / isotonic regression.
6. **Docker + REST deployment** with rate limiting.
7. **Browser extension** — POST the current tab URL to `/api/analyze-url`.
8. **Feedback loop** — "was this correct?" button that appends labelled samples
   to `data/` for retraining.

---

## Credits

| | |
|---|---|
| **Author** | **Er-Suzen Kumar Mohanty** |
| **Project** | PhishGuard — AI-Based Phishing Detection Tool |
| **Programme** | **IBM Cyber Security Project** |
| **Stack** | Python · scikit-learn · Flask · HTML/CSS/JS |
| **Purpose** | Defensive security · Educational use only |
| **Version** | 1.0 |

The web interface footer displays:

```
Made by  Er-Suzen Kumar Mohanty
         IBM Cyber Security Project
```

---

*Educational project — Level: Beginner–Intermediate.*
