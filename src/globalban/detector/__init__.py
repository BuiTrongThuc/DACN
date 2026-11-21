"""
globalban.detector
==================
Module phát hiện và tính điểm lệch chuẩn hành vi người dùng (UEBA Anomaly Scoring).
"""
from globalban.detector.ueba_scorer import UEBAScorer, UEBAAnomalyResult

__all__ = ["UEBAScorer", "UEBAAnomalyResult"]
