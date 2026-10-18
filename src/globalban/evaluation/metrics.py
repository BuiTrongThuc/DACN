"""Reproducible binary detection metrics without inventing labels."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectionMetrics:
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float


def evaluate_binary(expected: list[bool], predicted: list[bool]) -> DetectionMetrics:
    if len(expected) != len(predicted):
        raise ValueError("expected and predicted must have equal length")
    true_positive = sum(actual and result for actual, result in zip(expected, predicted))
    false_positive = sum(not actual and result for actual, result in zip(expected, predicted))
    false_negative = sum(actual and not result for actual, result in zip(expected, predicted))
    true_negative = sum(not actual and not result for actual, result in zip(expected, predicted))
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    return DetectionMetrics(
        true_positive, false_positive, false_negative, true_negative,
        precision, recall, f1, false_positive_rate,
    )