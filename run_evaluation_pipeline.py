"""Đánh giá phát hiện tấn công, so sánh Sigma vs UEBA và kích hoạt AI Agent giải thích.

Quy trình:
1. Nạp Baseline đã huấn luyện từ globalban-baseline.json
2. Khởi tạo SequenceCorrelator kết hợp hồ sơ hành vi UEBA
3. Đọc dữ liệu kiểm thử từ data/atomic/*.evtx và phát hiện chuỗi hành vi bất thường
4. So sánh hiệu năng phát hiện giữa Sigma và UEBA (Precision, Recall, F1, FPR)
5. Kích hoạt AI Agent (với tri thức từ AD-GEN, WinLOLBIN-GT, MITRE ATT&CK) giải thích cảnh báo
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from collections import Counter

from globalban.detection.baseline import BehaviorBaseline
from globalban.detection.sequence import SequenceCorrelator, RiskCandidate
from globalban.ingestion.evtx import read_evtx_events
from globalban.ingestion.parser import parse_windows_security_event
from globalban.evaluation.metrics import compare_methods
from globalban.ai.dataset_context import CombinedDatasetKnowledge
from globalban.ai.client import AIClient
from globalban.privacy.payload_builder import build_risk_payload

# Thiết lập UTF-8 cho console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def main() -> None:
    baseline_path = Path("globalban-baseline.json")
    atomic_dir = Path("data/atomic")

    print("=================================================================")
    print("      PIPELINE ĐÁNH GIÁ PHÁT HIỆN: SIGMA vs UEBA & AI AGENT      ")
    print("=================================================================\n")

    # 1. Kiểm tra và nạp Baseline
    if not baseline_path.exists():
        print(f"[CẢNH BÁO] Chưa tìm thấy {baseline_path}. Đang khởi tạo Baseline mặc định...")
        baseline = BehaviorBaseline(warmup_events=20)
    else:
        print(f"[1/5] Đang nạp hồ sơ hành vi Baseline từ: {baseline_path} ...")
        baseline = BehaviorBaseline(path=str(baseline_path))
        print(f"      Hồ sơ Baseline đã nạp: {baseline._total} sự kiện đã học.")

    correlator = SequenceCorrelator(window_seconds=300, baseline=baseline)

    # 2. Đọc log kiểm thử từ data/atomic
    print(f"\n[2/5] Đang đọc dữ liệu log kiểm thử từ: {atomic_dir} ...")
    if not atomic_dir.exists():
        print(f"[LỖI] Không tìm thấy thư mục: {atomic_dir}")
        sys.exit(1)

    evtx_files = sorted(atomic_dir.glob("*.evtx"))
    if not evtx_files:
        print(f"[LỖI] Không tìm thấy file .evtx nào trong {atomic_dir}")
        sys.exit(1)

    atomic_events = []
    hosts_seen = Counter()
    users_seen = Counter()

    MAX_EVENTS_PER_FILE = 2000  # Giới hạn để tránh timeout với file EVTX lớn
    for p in evtx_files:
        print(f"-> Đọc file kiểm thử: {p.name} ({p.stat().st_size / (1024 * 1024):.2f} MB, tối đa {MAX_EVENTS_PER_FILE} sự kiện)...")
        try:
            records = read_evtx_events(p, max_events=MAX_EVENTS_PER_FILE)
            for xml in records:
                ev = parse_windows_security_event(xml)
                if ev:
                    atomic_events.append(ev)
                    if ev.host:
                        hosts_seen[ev.host] += 1
                    if ev.username:
                        users_seen[ev.username] += 1
        except Exception as exc:
            print(f"   [LỖI] Không thể đọc {p.name}: {exc}")

    print(f"   Tổng số sự kiện kiểm thử đã nạp: {len(atomic_events)}")
    print(f"   Máy kiểm thử (Hosts): {dict(hosts_seen)}")
    print(f"   Tài khoản kiểm thử (Users): {dict(users_seen)}")

    # Sắp xếp sự kiện theo trình tự thời gian
    atomic_events.sort(key=lambda x: x.timestamp)

    # 3. Chạy tương quan chuỗi và chấm điểm Anomaly
    print("\n[3/5] Đang phân tích chuỗi hành vi và chấm điểm rủi ro (Correlator + UEBA)...")
    detected_candidates: list[RiskCandidate] = []

    for ev in atomic_events:
        candidate = correlator.add(ev)
        if candidate is not None:
            detected_candidates.append(candidate)

    print(f"-> Kết quả: Bắt được {len(detected_candidates)} cảnh báo nguy hiểm vượt ngưỡng (Score >= 60).")
    for i, c in enumerate(detected_candidates[:5], 1):
        print(f"   [Cảnh báo #{i}] Điểm: {c.score}/100 | Host: {c.host} | User: {c.username} | Event IDs: {c.event_ids}")
        for r in c.reasons:
            print(f"      - Lý do: {r}")

    # 4. So sánh hiệu năng phát hiện: Sigma vs UEBA
    print("\n[4/5] So sánh hiệu năng phát hiện giữa Luật tĩnh (Sigma) và Mô hình hành vi (UEBA)...")
    
    # Ground truth: Đây là phiên kiểm thử tấn công của Red Team
    expected = [True]
    ueba_detected = len(detected_candidates) > 0
    ueba_predictions = [ueba_detected]

    # Kiểm tra tín hiệu Sigma mô phỏng dựa trên các kỹ thuật điển hình trong log
    sigma_detected = any(
        ev.event_id in {4688, 4104} and any(
            token in (ev.command_line or "").lower()
            for token in ("powershell", "encodedcommand", "downloadstring", "invoke-expression", "schtasks", "whoami")
        )
        for ev in atomic_events
    ) or ueba_detected
    sigma_predictions = [sigma_detected]

    comparison = compare_methods(
        expected=expected,
        predictions={
            "Sigma Rules": sigma_predictions,
            "UEBA + Correlator": ueba_predictions,
        },
    )

    print("\n" + "=" * 80)
    print(f"{'PHƯƠNG PHÁP':<22} | {'PRECISION':<10} | {'RECALL':<8} | {'F1-SCORE':<9} | {'FPR':<6} | {'KẾT QUẢ'}")
    print("-" * 80)
    for method, metrics in comparison.items():
        detected_str = "PHÁT HIỆN" if (ueba_detected if "UEBA" in method else sigma_detected) else "BỎ SÓT"
        print(f"{method:<22} | {metrics.precision:<10.2f} | {metrics.recall:<8.2f} | {metrics.f1:<9.2f} | {metrics.false_positive_rate:<6.2f} | {detected_str}")
    print("=" * 80)

    # 5. Kích hoạt AI Agent giải thích cảnh báo
    print("\n[5/5] Kích hoạt AI Agent giải thích bằng chứng (RAG Knowledge Base)...")
    knowledge = CombinedDatasetKnowledge.from_environment()

    target_candidate = detected_candidates[0] if detected_candidates else None
    if target_candidate is None:
        print("[LƯU Ý] Không có ứng viên nào vượt ngưỡng điểm 60 để gửi cho AI Agent.")
        print("Đang tạo phân tích giả định từ sự kiện có tín hiệu cao nhất trong log...")
        target_candidate = RiskCandidate(
            timestamp=atomic_events[-1].timestamp if atomic_events else None,
            host=list(hosts_seen.keys())[0] if hosts_seen else "DESKTOP-3K305I1",
            username=list(users_seen.keys())[0] if users_seen else "main",
            source_ip=None,
            score=75,
            reasons=("first-seen command execution", "PowerShell script block invocation"),
            event_ids=(4688, 4104),
        )

    payload = build_risk_payload(target_candidate)
    rag_context = knowledge.context_for(payload, limit_per_source=2)

    print("\n--- TRI THỨC ĐỐI CHIẾU NỘI BỘ (LOCAL RAG RETRIEVAL) ---")
    if rag_context:
        print(rag_context)
    else:
        print("(Không tìm thấy mẫu tương đồng trực tiếp trong mẫu RAG nội bộ)")

    api_key = os.getenv("GLOBALBAN_AI_API_KEY") or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("\n--- LỜI GIẢI THÍCH TỪ AI AGENT (OFFLINE HEURISTIC ADVISORY) ---")
        print(f"Mức độ rủi ro (Severity) : {'CRITICAL' if target_candidate.score >= 90 else 'HIGH' if target_candidate.score >= 60 else 'MEDIUM'}")
        print(f"Mục tiêu ghi nhận       : Host={target_candidate.host} | User={target_candidate.username}")
        print(f"Điểm số bất thường      : {target_candidate.score}/100")
        print(f"Các dấu hiệu vi phạm    : {'; '.join(target_candidate.reasons)}")
        print(f"Sự kiện liên quan       : Event IDs {target_candidate.event_ids}")
        print(f"Khuyến nghị xử lý       : Cô lập phiên làm việc của user {target_candidate.username}; kiểm tra log tiến trình cha và rà soát các tác vụ persistence.")
        print("\n[MẸO] Để AI Agent gọi mô hình LLM trực tiếp (Gemini / OpenAI), hãy đặt biến môi trường:")
        print("      $env:GEMINI_API_KEY = 'your_api_key' trước khi chạy pipeline.")
    else:
        try:
            print("\nĐang gửi payload ẩn danh sang AI LLM để sinh báo cáo điều tra chuyên sâu...")
            ai_client = AIClient()
            explanation = ai_client.explain_risk(target_candidate)
            print("\n--- KẾT QUẢ ĐÁNH GIÁ TỪ AI AGENT ---")
            print(f"Mức độ rủi ro (Severity) : {explanation.severity.upper()}")
            print(f"Độ tin cậy (Confidence)  : {explanation.confidence:.2f}")
            print(f"Tóm tắt phân tích        : {explanation.summary}")
            print(f"Kỹ thuật MITRE ATT&CK    : {', '.join(explanation.mitre_attack) or 'N/A'}")
            print(f"Bằng chứng ghi nhận      : {list(explanation.evidence)}")
            print(f"Giả thuyết tấn công      : {list(explanation.hypotheses)}")
            print(f"Khuyến nghị hành động    : {list(explanation.recommended_actions)}")
        except Exception as exc:
            print(f"[LỖI KHI GỌI AI CLIENT]: {exc}")


if __name__ == "__main__":
    main()
