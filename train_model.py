#!/usr/bin/env python3
"""Train (or retrain) the phishing detection models.

Usage
-----
    python train_model.py                 # train both models on synthetic data
    python train_model.py --seed 7        # different random corpus
    python train_model.py --quick         # smaller, faster corpus
    python train_model.py --urls-csv urls.csv --emails-csv emails.csv

CSV format (optional real data):
    urls.csv     -> columns: url,label          (label: 1 phishing, 0 legitimate)
    emails.csv   -> columns: text,label         (text = subject + body)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys

from phishing_detector.model import (
    PhishingModel,
    build_email_pipeline,
    build_url_pipeline,
)
from phishing_detector.training import train_and_save


def _load_urls_csv(path: str) -> tuple[list[str], list[int]]:
    urls, labels = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            urls.append(row["url"].strip())
            labels.append(int(row["label"]))
    return urls, labels


def _load_emails_csv(path: str) -> tuple[list[str], list[int]]:
    texts, labels = [], []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            texts.append(row["text"])
            labels.append(int(row["label"]))
    return texts, labels


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train the phishing detector models.")
    parser.add_argument("--model-dir", default="models", help="where to store .joblib files")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--quick", action="store_true", help="smaller corpus (fast)")
    parser.add_argument("--urls-csv", help="real URL dataset (url,label)")
    parser.add_argument("--emails-csv", help="real email dataset (text,label)")
    args = parser.parse_args(argv)

    if not args.urls_csv and not args.emails_csv:
        report = train_and_save(args.model_dir, seed=args.seed, verbose=True)
        print(json.dumps(report, indent=2))
        return 0

    # --- real-data path ---------------------------------------------------
    import os
    from sklearn.metrics import accuracy_score, f1_score

    os.makedirs(args.model_dir, exist_ok=True)
    if args.urls_csv:
        urls, labels = _load_urls_csv(args.urls_csv)
        print(f"Training URL model on {len(urls)} real samples ...")
        model = PhishingModel("url", build_url_pipeline()).train(urls, labels)
        preds = [1 if model.probability(u) >= 0.5 else 0 for u in urls]
        print(f"  train accuracy={accuracy_score(labels, preds):.3f} "
              f"f1={f1_score(labels, preds):.3f}")
        model.save(os.path.join(args.model_dir, "url_model.joblib"))
    if args.emails_csv:
        texts, labels = _load_emails_csv(args.emails_csv)
        print(f"Training email model on {len(texts)} real samples ...")
        model = PhishingModel("email", build_email_pipeline()).train(texts, labels)
        preds = [1 if model.probability(t) >= 0.5 else 0 for t in texts]
        print(f"  train accuracy={accuracy_score(labels, preds):.3f} "
              f"f1={f1_score(labels, preds):.3f}")
        model.save(os.path.join(args.model_dir, "email_model.joblib"))
    print("Done. Restart the web app to pick up the new models.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
