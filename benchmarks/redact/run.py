"""REDACT benchmark runner for veil.

Downloads the locked 1,000-record REDACT sample, runs veil's default
detectors against each record, and produces a markdown results report.

Usage:
    python -m benchmarks.redact.run                  # run + print report
    python -m benchmarks.redact.run --out results.md  # save to file
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Ensure the repo root is on sys.path so veil is importable.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))

from veil import Scrubber, default_detectors  # noqa: E402
from veil.types import Finding  # noqa: E402

from .entity_map import (  # noqa: E402
    MAPPED_REDACT_TYPES,
    MAPPED_VEIL_TYPES,
    UNMAPPED_REDACT_TYPES,
    redact_to_veil,
)
from .metrics import BenchmarkResults, Span, evaluate, exact_match, partial_match  # noqa: E402

# ---------------------------------------------------------------------------
# Dataset handling
# ---------------------------------------------------------------------------

_SAMPLE_URL = (
    "https://media.githubusercontent.com/media/guneeshvats/"
    "REDACT-PII-Benchmark/main/data/pii_benchmark_sample1000.json"
)
_DATA_DIR = Path(__file__).resolve().parent / "data"
_SAMPLE_PATH = _DATA_DIR / "pii_benchmark_sample1000.json"


def _download_sample() -> Path:
    if _SAMPLE_PATH.exists():
        return _SAMPLE_PATH
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading REDACT sample to {_SAMPLE_PATH} ...")
    urllib.request.urlretrieve(_SAMPLE_URL, _SAMPLE_PATH)
    print("Done.")
    return _SAMPLE_PATH


def _load_records(path: Path) -> list[dict]:
    with open(path) as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "records" in data:
        return data["records"]
    raise ValueError(f"Unexpected REDACT format in {path}")


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def _run_veil(records: list[dict]) -> list[tuple[list[Span], list[Span]]]:
    """Run veil detectors on every record, return (gold, pred) span pairs."""
    scrubber = Scrubber(detectors=default_detectors())
    results: list[tuple[list[Span], list[Span]]] = []
    mapped_gold_total = 0
    unmapped_gold_total = 0

    for rec in records:
        text = rec["text"]
        entities = rec.get("entities", [])

        # Build gold spans (only mapped types).
        gold_spans: list[Span] = []
        for ent in entities:
            redact_type = ent["entity_type"]
            veil_type = redact_to_veil(redact_type)
            if veil_type is None:
                unmapped_gold_total += 1
                continue
            mapped_gold_total += 1
            gold_spans.append(Span(
                entity_type=veil_type,
                start=ent["start"],
                end=ent["end"],
                sensitivity_tier=ent.get("sensitivity_tier", "UNKNOWN"),
            ))

        # Run veil detectors.
        all_findings: list[Finding] = []
        for d in scrubber.detectors:
            try:
                all_findings.extend(d.detect(text))
            except Exception:
                pass

        # Only keep predictions whose veil type maps back to a REDACT type,
        # so we don't penalise veil for detecting real patterns (JWT, IBAN, …)
        # that fall outside REDACT's taxonomy.
        pred_spans: list[Span] = [
            Span(entity_type=f.entity_type, start=f.start, end=f.end)
            for f in all_findings
            if f.entity_type in MAPPED_VEIL_TYPES
        ]

        results.append((gold_spans, pred_spans))

    return results


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

_PRESIDIO_BASELINE = {
    "partial_micro_f1": 0.195,
    "macro_f1": 0.063,
    "exact_micro_f1": 0.145,
    "high_recall": 0.07,
    "medium_recall": None,
    "low_recall": 0.23,
}


def _format_pct(v: float) -> str:
    return f"{v:.1%}" if v > 0 else "0.0%"


def _generate_report(
    partial: BenchmarkResults,
    exact: BenchmarkResults,
    elapsed_s: float,
    num_records: int,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# REDACT Benchmark Results — veil Tier 1",
        "",
        f"**Date:** {now}  ",
        f"**Records evaluated:** {num_records}  ",
        f"**Elapsed:** {elapsed_s:.1f}s  ",
        f"**Gold spans (mapped):** {partial.mapped_gold_spans}  ",
        f"**Gold spans (unmapped / Tier 2+):** {partial.unmapped_gold_spans}  ",
        f"**Predicted spans:** {partial.total_pred_spans}  ",
        "",
        "---",
        "",
        "## Aggregate metrics",
        "",
        "| Metric | veil (Tier 1) | Presidio baseline |",
        "|---|---|---|",
        f"| Partial micro-F1 | **{_format_pct(partial.micro.f1)}** | {_format_pct(_PRESIDIO_BASELINE['partial_micro_f1'])} |",
        f"| Macro F1 | **{_format_pct(partial.macro_f1)}** | {_format_pct(_PRESIDIO_BASELINE['macro_f1'])} |",
        f"| Exact micro-F1 | **{_format_pct(exact.micro.f1)}** | {_format_pct(_PRESIDIO_BASELINE['exact_micro_f1'])} |",
        f"| Micro precision | {_format_pct(partial.micro.precision)} | — |",
        f"| Micro recall | {_format_pct(partial.micro.recall)} | — |",
        "",
        "---",
        "",
        "## Per-type results (partial overlap)",
        "",
        "| Entity type | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|",
    ]

    for etype in sorted(partial.per_type):
        m = partial.per_type[etype]
        lines.append(
            f"| {etype} | {m.tp} | {m.fp} | {m.fn} "
            f"| {_format_pct(m.precision)} | {_format_pct(m.recall)} | {_format_pct(m.f1)} |"
        )

    lines += [
        "",
        "---",
        "",
        "## Recall by GDPR sensitivity tier",
        "",
        "| Tier | Recall | Gold spans | Presidio baseline |",
        "|---|---|---|---|",
    ]

    for tier in ("HIGH", "MEDIUM", "LOW"):
        hits, total = partial.per_tier_recall.get(tier, (0, 0))
        recall = hits / total if total else 0.0
        presidio = _PRESIDIO_BASELINE.get(f"{tier.lower()}_recall")
        presidio_str = _format_pct(presidio) if presidio is not None else "—"
        lines.append(f"| {tier} | {_format_pct(recall)} | {total} | {presidio_str} |")

    lines += [
        "",
        "---",
        "",
        "## Coverage gap (unmapped REDACT types)",
        "",
        "These REDACT entity types have no veil Tier 1 detector. They represent",
        "the gap that NER (Tier 2) and LLM classifier (Tier 3) detectors are",
        "designed to fill.",
        "",
    ]

    for t in sorted(UNMAPPED_REDACT_TYPES):
        lines.append(f"- {t}")

    lines += [
        "",
        "---",
        "",
        "*Generated by `python -m benchmarks.redact.run`*",
        "",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Run REDACT benchmark on veil")
    parser.add_argument("--out", type=str, default=None, help="Write report to file")
    parser.add_argument("--data", type=str, default=None, help="Path to REDACT JSON sample")
    args = parser.parse_args()

    # Load data.
    if args.data:
        data_path = Path(args.data)
    else:
        data_path = _download_sample()
    records = _load_records(data_path)
    print(f"Loaded {len(records)} REDACT records.")

    # Run detection.
    print("Running veil detectors ...")
    t0 = time.perf_counter()
    span_pairs = _run_veil(records)
    elapsed = time.perf_counter() - t0
    print(f"Detection complete in {elapsed:.1f}s.")

    # Count mapped/unmapped for reporting.
    mapped_gold = sum(len(g) for g, _ in span_pairs)
    unmapped_gold = 0
    for rec in records:
        for ent in rec.get("entities", []):
            if redact_to_veil(ent["entity_type"]) is None:
                unmapped_gold += 1

    # Evaluate.
    partial_results = evaluate(span_pairs, match_fn=partial_match)
    exact_results = evaluate(span_pairs, match_fn=exact_match)

    partial_results.mapped_gold_spans = mapped_gold
    partial_results.unmapped_gold_spans = unmapped_gold

    # Generate report.
    report = _generate_report(partial_results, exact_results, elapsed, len(records))

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(report)
        print(f"Report written to {out_path}")
    else:
        print()
        print(report)


if __name__ == "__main__":
    main()
