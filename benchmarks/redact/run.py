"""REDACT benchmark runner for veil.

Downloads the locked 1,000-record REDACT sample, runs veil's default
detectors against each record, and produces a markdown results report.

Usage:
    python -m benchmarks.redact.run                   # Tier 1 only
    python -m benchmarks.redact.run --ner              # Tier 1 + Tier 2 NER
    python -m benchmarks.redact.run --ner --model de_core_news_sm
    python -m benchmarks.redact.run --out results.md   # save to file
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_SRC_DIR = str(_REPO_ROOT / "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from veil import Scrubber, default_detectors  # noqa: E402
from veil.types import Finding  # noqa: E402

from .entity_map import (  # noqa: E402
    MAPPED_REDACT_TYPES,
    MAPPED_VEIL_TYPES,
    UNMAPPED_REDACT_TYPES,
    redact_to_veil,
)
from .metrics import BenchmarkResults, Span, evaluate, exact_match, partial_match  # noqa: E402

# Prediction types that should be treated as equivalent for benchmark matching.
# Tier 1's DATE_OF_BIRTH and NER's DATE_TIME both detect dates; when REDACT's
# Date_of_Birth is mapped to DATE_OF_BIRTH, an NER DATE_TIME at the same span
# should still count as a match.
_PRED_TYPE_ALIASES: dict[str, str] = {
    "DATE_TIME": "DATE_OF_BIRTH",
}

# ---------------------------------------------------------------------------
# Dataset handling
# ---------------------------------------------------------------------------

_PINNED_COMMIT = "34c78df19edbbf3b8605284f275592d52825cc5e"
_SAMPLE_URL = (
    "https://media.githubusercontent.com/media/guneeshvats/"
    f"REDACT-PII-Benchmark/{_PINNED_COMMIT}/data/pii_benchmark_sample1000.json"
)
_EXPECTED_SHA256 = "754f562ce9c3c5b7b663f1ba6127c38a31d93f5631d38364341cb727936234c6"
_DATA_DIR = Path(__file__).resolve().parent / "data"
_SAMPLE_PATH = _DATA_DIR / "pii_benchmark_sample1000.json"


def _download_sample() -> Path:
    if _SAMPLE_PATH.exists():
        digest = hashlib.sha256(_SAMPLE_PATH.read_bytes()).hexdigest()
        if digest == _EXPECTED_SHA256:
            return _SAMPLE_PATH
        print(f"Checksum mismatch (got {digest[:12]}…), re-downloading.")
        _SAMPLE_PATH.unlink()
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Downloading REDACT sample to {_SAMPLE_PATH} ...")
    urllib.request.urlretrieve(_SAMPLE_URL, _SAMPLE_PATH)
    digest = hashlib.sha256(_SAMPLE_PATH.read_bytes()).hexdigest()
    if digest != _EXPECTED_SHA256:
        _SAMPLE_PATH.unlink()
        raise RuntimeError(
            f"REDACT sample checksum mismatch: expected {_EXPECTED_SHA256[:12]}…, "
            f"got {digest[:12]}…. The upstream file may have changed."
        )
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


def _dedup_gold_spans(spans: list[Span]) -> list[Span]:
    """Remove gold spans that are fully contained within a larger same-type span.

    REDACT annotates "Rajesh Mehta" as three overlapping spans (Full_Name,
    First_Given_Name, Last_Family_Name) that all map to PERSON_NAME.  Keeping
    all three penalises a detector that correctly finds the full name, since
    the greedy 1:1 matching counts 1 TP + 2 FN.  Dedup keeps only the largest
    non-contained span per group, preserving the sensitivity tier of the
    longest span.
    """
    if not spans:
        return spans

    by_type: dict[str, list[Span]] = {}
    for s in spans:
        by_type.setdefault(s.entity_type, []).append(s)

    kept: list[Span] = []
    for etype, group in by_type.items():
        group.sort(key=lambda s: (s.start, -(s.end - s.start)))
        for i, span in enumerate(group):
            contained = False
            for j, other in enumerate(group):
                if i == j:
                    continue
                if other.start <= span.start and other.end >= span.end:
                    contained = True
                    break
            if not contained:
                kept.append(span)
    return kept


def _run_veil(
    records: list[dict],
    use_ner: bool = False,
    ner_model: str | list[str] = "en_core_web_sm",
) -> list[tuple[list[Span], list[Span]]]:
    """Run veil detectors on every record, return (gold, pred) span pairs."""
    detectors = default_detectors()
    if use_ner:
        from veil.detectors.ner import ner_detectors

        models = ner_model if isinstance(ner_model, list) else [ner_model]
        detectors = detectors + ner_detectors(model=models if len(models) > 1 else models[0])
    scrubber = Scrubber(detectors=detectors)
    results: list[tuple[list[Span], list[Span]]] = []
    mapped_gold_total = 0
    unmapped_gold_total = 0

    for rec in records:
        text = rec["text"]
        entities = rec.get("entities", [])

        # Build gold spans (only mapped types with valid offsets).
        gold_spans_raw: list[Span] = []
        for ent in entities:
            redact_type = ent["entity_type"]
            veil_type = redact_to_veil(redact_type)
            if veil_type is None:
                unmapped_gold_total += 1
                continue
            start, end = ent.get("start"), ent.get("end")
            if start is None or end is None:
                unmapped_gold_total += 1
                continue
            mapped_gold_total += 1
            gold_spans_raw.append(Span(
                entity_type=veil_type,
                start=start,
                end=end,
                sensitivity_tier=ent.get("sensitivity_tier", "UNKNOWN"),
            ))

        # De-duplicate overlapping gold spans of the same type.  REDACT
        # annotates Full_Name, First_Given_Name, and Last_Family_Name as
        # separate entities that all map to PERSON_NAME.  Without dedup,
        # a single correct detection is counted as 1 TP + N FN.
        gold_spans = _dedup_gold_spans(gold_spans_raw)

        # Run veil detectors.
        all_findings: list[Finding] = []
        for d in scrubber.detectors:
            try:
                all_findings.extend(d.detect(text))
            except Exception:
                detector_name = getattr(d, "name", type(d).__name__)
                record_id = rec.get("record_id", "?")
                logging.error(
                    "Detector %s failed on record %s", detector_name, record_id,
                    exc_info=True,
                )
                raise RuntimeError(
                    f"Detector {detector_name!r} raised on record {record_id}; "
                    "fix the detector or exclude the record with --data"
                )

        # Only keep predictions whose veil type maps back to a REDACT type,
        # so we don't penalise veil for detecting real patterns (JWT, IBAN, …)
        # that fall outside REDACT's taxonomy.  Also emit aliased copies so
        # e.g. a DATE_TIME prediction can match a DATE_OF_BIRTH gold span.
        pred_spans: list[Span] = []
        for f in all_findings:
            if f.entity_type in MAPPED_VEIL_TYPES:
                pred_spans.append(
                    Span(entity_type=f.entity_type, start=f.start, end=f.end)
                )
            alias = _PRED_TYPE_ALIASES.get(f.entity_type)
            if alias and alias in MAPPED_VEIL_TYPES:
                pred_spans.append(
                    Span(entity_type=alias, start=f.start, end=f.end)
                )

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
    tier_label: str = "Tier 1",
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# REDACT Benchmark Results — veil {tier_label}",
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
    parser.add_argument("--ner", action="store_true", help="Include Tier 2 NER detectors")
    parser.add_argument("--model", type=str, nargs="+", default=["en_core_web_sm"], help="spaCy model(s) for NER")
    args = parser.parse_args()

    # Load data.
    if args.data:
        data_path = Path(args.data)
    else:
        data_path = _download_sample()
    records = _load_records(data_path)
    print(f"Loaded {len(records)} REDACT records.")

    tier_label = "Tier 1 + 2" if args.ner else "Tier 1"

    # Run detection.
    print(f"Running veil detectors ({tier_label}) ...")
    t0 = time.perf_counter()
    span_pairs = _run_veil(records, use_ner=args.ner, ner_model=args.model)
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
    report = _generate_report(
        partial_results, exact_results, elapsed, len(records),
        tier_label=tier_label,
    )

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(report)
        print(f"Report written to {out_path}")
    else:
        print()
        print(report)


if __name__ == "__main__":
    main()
