from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from io import StringIO
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any


DEFAULT_GLOBALBAN_ROOT = Path(r"C:\Users\Admin\Desktop\globalban")


def ensure_globalban_importable(globalban_root: str | Path = DEFAULT_GLOBALBAN_ROOT) -> Path:
    """Add GlobalBan's src directory to sys.path so we can import globalban modules directly."""
    root = Path(globalban_root).resolve()
    src_dir = root / "src"
    if not src_dir.is_dir():
        raise FileNotFoundError(f"Không tìm thấy thư mục GlobalBan src tại: {src_dir}")
    src_str = str(src_dir)
    if src_str not in sys.path:
        sys.path.insert(0, src_str)
    return root


@dataclass(slots=True)
class DetailedEvaluationReport:
    jsonl_path: Path
    xml_path: Path | None
    total_events: int
    malicious_events: int
    benign_events: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    rule_match_accuracy: float
    mitre_technique_counts: dict[str, int]
    mitre_signal_recall_by_technique: dict[str, float]
    triggered_rule_counts: dict[str, int] = field(default_factory=dict)
    auth_burst_level1_count: int = 0
    auth_burst_level2_count: int = 0
    persistence_correlator_count: int = 0
    expected_signal_events: int = 0
    precursor_attack_events: int = 0
    sample_detections: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "jsonl_path": str(self.jsonl_path),
            "xml_path": str(self.xml_path) if self.xml_path else None,
            "total_events": self.total_events,
            "malicious_events": self.malicious_events,
            "expected_signal_events": self.expected_signal_events,
            "precursor_attack_events": self.precursor_attack_events,
            "benign_events": self.benign_events,
            "confusion_matrix": {
                "TP": self.true_positive,
                "FP": self.false_positive,
                "FN": self.false_negative,
                "TN": self.true_negative,
            },
            "metrics": {
                "precision": round(self.precision, 6),
                "recall": round(self.recall, 6),
                "f1_score": round(self.f1, 6),
                "false_positive_rate": round(self.false_positive_rate, 6),
                "rule_match_accuracy": round(self.rule_match_accuracy, 6),
            },
            "mitre_technique_counts": self.mitre_technique_counts,
            "mitre_signal_recall_by_technique": self.mitre_signal_recall_by_technique,
            "triggered_rule_counts": self.triggered_rule_counts,
            "total_alerts_and_signals": sum(self.triggered_rule_counts.values()),
            "auth_burst_levels": {
                "level_1": self.auth_burst_level1_count,
                "level_2": self.auth_burst_level2_count,
            },
            "persistence_correlator_count": self.persistence_correlator_count,
        }


def run_globalban_evaluation(
    jsonl_path: str | Path,
    xml_path: str | Path | None = None,
    globalban_root: str | Path = DEFAULT_GLOBALBAN_ROOT,
) -> DetailedEvaluationReport:
    """
    Push the generated .jsonl dataset into GlobalBan's evaluate_windows_dataset
    and inspect the exact alerts/signals emitted by EventAggregator,
    WindowsSequenceDetector, and WindowsBehaviorDetectors.
    """
    root = ensure_globalban_importable(globalban_root)
    from globalban.detection.aggregator import EventAggregator
    from globalban.detection.baseline import BehaviorBaseline, LocalBaseline
    from globalban.detection.behavior import WindowsBehaviorDetectors
    from globalban.detection.sequence import WindowsSequenceDetector
    from globalban.evaluation.metrics import evaluate_windows_dataset
    from globalban.ingestion.parser import parse_windows_event_xml

    techniques_csv = root / "datasets" / "attack_techniques.csv"
    eval_result = evaluate_windows_dataset(
        jsonl_path,
        techniques_csv if techniques_csv.is_file() else None,
    )

    j_path = Path(jsonl_path)
    rows = [
        json.loads(line)
        for line in j_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    malicious_count = sum(1 for r in rows if r.get("is_malicious"))
    expected_signal_count = sum(1 for r in rows if r.get("expected_signal"))
    precursor_count = sum(
        1 for r in rows if r.get("is_malicious") and not r.get("expected_signal")
    )
    benign_count = len(rows) - malicious_count

    # Run a parallel inspection pass to collect per-rule & Level 1/Level 2 breakdown
    aggregator = EventAggregator(
        threshold=5,
        window_seconds=300,
        baseline=LocalBaseline(None),
        level_two_threshold=10,
        multi_account_threshold=2,
    )
    sequence = WindowsSequenceDetector(
        window_seconds=300,
        baseline=BehaviorBaseline(None, warmup_events=20),
    )
    behavior = WindowsBehaviorDetectors(window_seconds=300)

    rule_counter: Counter[str] = Counter()
    level1_count = 0
    level2_count = 0
    persistence_count = 0
    sample_detections: list[dict[str, Any]] = []

    for row in rows:
        event = parse_windows_event_xml(row["xml"])
        if event is None:
            continue

        alert = aggregator.ingest(event)
        if alert is not None:
            rule_counter[alert.rule_id] += 1
            if alert.response_level == 1:
                level1_count += 1
            elif alert.response_level == 2:
                level2_count += 1
            if len(sample_detections) < 50:
                sample_detections.append(
                    {
                        "event_id": row["event_id"],
                        "detector": "EventAggregator",
                        "rule_id": f"{alert.rule_id} (Level {alert.response_level})",
                        "target": alert.source_ip,
                        "scenario": row.get("scenario", ""),
                        "explanation": alert.explanation,
                    }
                )

        seq_sig = sequence.add(event)
        if seq_sig is not None:
            seq_rule_id = seq_sig.rule_id or (
                "WINDOWS-" + "-".join(map(str, seq_sig.event_ids))
            )
            rule_counter[seq_rule_id] += 1
            if "logon, process creation, and persistence events correlated" in seq_sig.reasons:
                persistence_count += 1
            if len(sample_detections) < 50:
                sample_detections.append(
                    {
                        "event_id": row["event_id"],
                        "detector": "WindowsSequenceDetector",
                        "rule_id": seq_rule_id,
                        "target": seq_sig.host,
                        "scenario": row.get("scenario", ""),
                        "explanation": seq_sig.explanation,
                    }
                )

        for beh_sig in behavior.add(event):
            if beh_sig.rule_id:
                rule_counter[beh_sig.rule_id] += 1
                if len(sample_detections) < 50:
                    sample_detections.append(
                        {
                            "event_id": row["event_id"],
                            "detector": "WindowsBehaviorDetectors",
                            "rule_id": beh_sig.rule_id,
                            "target": beh_sig.host,
                            "scenario": row.get("scenario", ""),
                            "explanation": beh_sig.explanation,
                        }
                    )

    m = eval_result.signal_detection_metrics
    return DetailedEvaluationReport(
        jsonl_path=j_path,
        xml_path=Path(xml_path) if xml_path else None,
        total_events=len(rows),
        malicious_events=malicious_count,
        benign_events=benign_count,
        true_positive=m.true_positive,
        false_positive=m.false_positive,
        false_negative=m.false_negative,
        true_negative=m.true_negative,
        precision=m.precision,
        recall=m.recall,
        f1=m.f1,
        false_positive_rate=m.false_positive_rate,
        rule_match_accuracy=eval_result.rule_match_accuracy,
        mitre_technique_counts=eval_result.mitre_technique_counts,
        mitre_signal_recall_by_technique=eval_result.mitre_signal_recall_by_technique,
        triggered_rule_counts=dict(sorted(rule_counter.items())),
        auth_burst_level1_count=level1_count,
        auth_burst_level2_count=level2_count,
        persistence_correlator_count=persistence_count,
        expected_signal_events=expected_signal_count,
        precursor_attack_events=precursor_count,
        sample_detections=sample_detections,
    )


def push_xml_to_globalban_cli(
    xml_path: str | Path,
    globalban_root: str | Path = DEFAULT_GLOBALBAN_ROOT,
) -> list[dict[str, Any]]:
    """
    Push an exported Windows Event XML file directly into GlobalBan's main CLI entrypoint
    (globalban.main.main(["--windows-xml", ...])) and return the parsed JSON alert records.
    """
    root = ensure_globalban_importable(globalban_root)
    from globalban.main import main as globalban_main

    demo_config = root / "config" / "demo.config.json"
    argv = ["--windows-xml", str(Path(xml_path).resolve())]
    if demo_config.is_file():
        argv = ["--config", str(demo_config)] + argv

    buf = StringIO()
    with redirect_stdout(buf):
        globalban_main(argv)

    alerts_and_signals: list[dict[str, Any]] = []
    for line in buf.getvalue().splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                alerts_and_signals.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return alerts_and_signals


def format_report_text(report: DetailedEvaluationReport) -> str:
    """Format a human-readable Vietnamese & English cybersecurity evaluation report."""
    lines = [
        "=" * 78,
        "   BÁO CÁO ĐÁNH GIÁ HIỆU QUẢ PHÁT HIỆN TẤN CÔNG CỦA GLOBALBAN (WINDOWS XML)",
        "=" * 78,
        f"File Dataset (.jsonl) : {report.jsonl_path}",
        f"File Export  (.xml)   : {report.xml_path or 'N/A'}",
        f"Tổng số sự kiện sinh  : {report.total_events:,} logs "
        f"(Tấn công: {report.malicious_events:,} [Kích hoạt: {report.expected_signal_events:,}, Tiền đề: {report.precursor_attack_events:,}] | Bình thường/Benign: {report.benign_events:,})",
        "-" * 78,
        "1. MA TRẬN NHẦM LẪN (CONFUSION MATRIX - SIGNAL DETECTION):",
        f"   - True Positive  (TP - Bắt đúng tín hiệu tấn công) : {report.true_positive:,}",
        f"   - False Positive (FP - Báo động giả trên log sạch) : {report.false_positive:,}",
        f"   - False Negative (FN - Bỏ lọt tín hiệu tấn công)   : {report.false_negative:,}",
        f"   - True Negative  (TN - Bỏ qua đúng log không báo)  : {report.true_negative:,}",
        "-" * 78,
        "2. CÁC CHỈ SỐ ĐO LƯỜNG CHÍNH (EVALUATION METRICS):",
        f"   - Precision (Độ chính xác)          : {report.precision * 100:6.2f}% ({report.precision:.4f})",
        f"   - Recall    (Độ phủ / Tỷ lệ bắt)    : {report.recall * 100:6.2f}% ({report.recall:.4f})",
        f"   - F1-Score  (Trung bình điều hòa)   : {report.f1 * 100:6.2f}% ({report.f1:.4f})",
        f"   - False Positive Rate (Tỷ lệ báo giả): {report.false_positive_rate * 100:6.2f}% ({report.false_positive_rate:.4f})",
        f"   - Rule Match Accuracy (Khớp nhãn Rule): {report.rule_match_accuracy * 100:6.2f}% ({report.rule_match_accuracy:.4f})",
        "-" * 78,
        f"3. THỐNG KÊ CÁC RULE GLOBALBAN ĐÃ KÍCH HOẠT (Tổng: {sum(report.triggered_rule_counts.values()):,} tín hiệu):",
    ]
    if report.triggered_rule_counts:
        for rule_id, cnt in report.triggered_rule_counts.items():
            extra = ""
            if rule_id == "AUTH-FAILURE-BURST":
                extra = f" (Level 1: {report.auth_burst_level1_count:,} | Level 2: {report.auth_burst_level2_count:,})"
            lines.append(f"   - {rule_id:<42}: {cnt:,} lần{extra}")
        if report.persistence_correlator_count:
            lines.append(
                f"   * Chuỗi tương quan logon-process-persistence: {report.persistence_correlator_count:,} lần"
            )
    else:
        lines.append("   (Không có rule nào được kích hoạt)")

    lines.append("-" * 78)
    lines.append("4. ĐỘ PHỦ THEO KỸ THUẬT MITRE ATT&CK (RECALL BY TECHNIQUE):")
    for tech_id, count in report.mitre_technique_counts.items():
        rec_val = report.mitre_signal_recall_by_technique.get(tech_id)
        rec_str = f"{rec_val * 100:6.2f}%" if rec_val is not None else "N/A (Context event)"
        lines.append(f"   - {tech_id:<12} | Số sự kiện: {count:>5,} | Signal Recall: {rec_str}")

    lines.append("=" * 78)
    return "\n".join(lines)

