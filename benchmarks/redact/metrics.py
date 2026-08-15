"""Span-matching and metric computation for the REDACT benchmark.

Two matching modes, following the REDACT paper:
  - **Partial overlap**: a prediction matches a ground-truth span if they
    share the same (mapped) entity type and overlap by at least 50% of the
    shorter span's length.
  - **Exact overlap**: start, end, and entity type must all match exactly.

Metrics produced:
  - Per-type precision, recall, F1
  - Micro-averaged precision, recall, F1 (over all mapped types)
  - Macro-averaged F1 (mean of per-type F1 values)
  - Per-sensitivity-tier recall (LOW / MEDIUM / HIGH)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Span:
    entity_type: str
    start: int
    end: int
    sensitivity_tier: str = "UNKNOWN"

    @property
    def length(self) -> int:
        return self.end - self.start


def _overlap(a: Span, b: Span) -> int:
    return max(0, min(a.end, b.end) - max(a.start, b.start))


def partial_match(pred: Span, gold: Span) -> bool:
    """50%-of-shorter-span partial overlap + type match."""
    if pred.entity_type != gold.entity_type:
        return False
    ov = _overlap(pred, gold)
    threshold = min(pred.length, gold.length) * 0.5
    return ov >= threshold


def exact_match(pred: Span, gold: Span) -> bool:
    return (
        pred.entity_type == gold.entity_type
        and pred.start == gold.start
        and pred.end == gold.end
    )


@dataclass
class TypeMetrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


@dataclass
class BenchmarkResults:
    per_type: dict[str, TypeMetrics] = field(default_factory=dict)
    per_tier_recall: dict[str, tuple[int, int]] = field(default_factory=dict)
    total_records: int = 0
    total_gold_spans: int = 0
    total_pred_spans: int = 0
    mapped_gold_spans: int = 0
    unmapped_gold_spans: int = 0

    @property
    def micro(self) -> TypeMetrics:
        m = TypeMetrics()
        for t in self.per_type.values():
            m.tp += t.tp
            m.fp += t.fp
            m.fn += t.fn
        return m

    @property
    def macro_f1(self) -> float:
        scores = [t.f1 for t in self.per_type.values() if (t.tp + t.fn) > 0]
        return sum(scores) / len(scores) if scores else 0.0

    def tier_recall(self, tier: str) -> float:
        hits, total = self.per_tier_recall.get(tier, (0, 0))
        return hits / total if total else 0.0


def evaluate(
    records: list[tuple[list[Span], list[Span]]],
    match_fn=partial_match,
) -> BenchmarkResults:
    """Compute metrics over a list of (gold_spans, pred_spans) per record.

    Gold spans should already have their entity_type mapped to veil types
    (unmapped types should be excluded before calling this).
    """
    results = BenchmarkResults(total_records=len(records))

    for gold_spans, pred_spans in records:
        results.total_gold_spans += len(gold_spans)
        results.total_pred_spans += len(pred_spans)

        gold_matched = [False] * len(gold_spans)
        pred_matched = [False] * len(pred_spans)

        # Greedy matching: iterate predictions, match to best unmatched gold.
        for pi, pred in enumerate(pred_spans):
            best_overlap = 0
            best_gi = -1
            for gi, gold in enumerate(gold_spans):
                if gold_matched[gi]:
                    continue
                if match_fn(pred, gold):
                    ov = _overlap(pred, gold)
                    if ov > best_overlap:
                        best_overlap = ov
                        best_gi = gi
            if best_gi >= 0:
                gold_matched[best_gi] = True
                pred_matched[pi] = True
                etype = gold_spans[best_gi].entity_type
                results.per_type.setdefault(etype, TypeMetrics()).tp += 1

        for gi, gold in enumerate(gold_spans):
            if not gold_matched[gi]:
                results.per_type.setdefault(gold.entity_type, TypeMetrics()).fn += 1
            # Track per-tier recall
            tier = gold.sensitivity_tier
            hits, total = results.per_tier_recall.get(tier, (0, 0))
            results.per_tier_recall[tier] = (
                hits + (1 if gold_matched[gi] else 0),
                total + 1,
            )

        for pi, pred in enumerate(pred_spans):
            if not pred_matched[pi]:
                results.per_type.setdefault(pred.entity_type, TypeMetrics()).fp += 1

    return results
