#!/usr/bin/env python3
"""
redteam_gui.py
==============
GlobalBan Red Team Studio — MITRE ATT&CK Attack Console
Giao diện đồ họa tối (SOC-style) để thực thi từng kỹ thuật tấn công hoặc
toàn bộ chiến dịch Red Team nhắm vào máy Blue Team (192.168.52.136).

Yêu cầu: PySide6 >= 6.5, Python 3.12
Chạy:    python C:\\redteam-harness\\redteam_gui.py
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# Đảm bảo import được run_campaign và các thư viện liên quan
# ---------------------------------------------------------------------------
HARNESS_DIR = Path(__file__).parent
sys.path.insert(0, str(HARNESS_DIR))

# Thêm đường dẫn src để load mô-đun phân tích
for _extra in [
    HARNESS_DIR / "src",
    Path(r"C:\attack-globalban\src"),
    Path(r"C:\DACN\src"),
]:
    if _extra.exists() and str(_extra) not in sys.path:
        sys.path.insert(0, str(_extra))

from PySide6.QtCore import (
    QObject,
    QRunnable,
    QThreadPool,
    Qt,
    Signal,
    Slot,
)
from PySide6.QtGui import QFont, QTextCursor
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QDoubleSpinBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QStatusBar,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Màu sắc SOC-style
# ---------------------------------------------------------------------------
C_BG       = "#0a0e1a"
C_PANEL    = "#0f1526"
C_CARD     = "#141c30"
C_BORDER   = "#1e2d4a"
C_ACCENT   = "#EF4444"       # đỏ — Red Team
C_ACCENT2  = "#3B82F6"       # xanh dương nhạt
C_GOLD     = "#F59E0B"
C_GREEN    = "#22C55E"
C_TEXT     = "#E2E8F0"
C_MUTED    = "#64748B"
C_WAIT     = "#64748B"       # badge Waiting
C_RUN      = "#F59E0B"       # badge Running
C_DONE     = "#22C55E"       # badge Done
C_FAIL     = "#EF4444"       # badge Failed

BADGE_WAIT = "🔵"
BADGE_RUN  = "🟡"
BADGE_DONE = "🟢"
BADGE_FAIL = "🔴"

MONOSPACE_FONT = QFont("Consolas", 9)
MONOSPACE_FONT.setStyleHint(QFont.StyleHint.Monospace)


# ===========================================================================
# Worker — chạy từng case trong QThreadPool
# ===========================================================================
class WorkerSignals(QObject):
    log_line   = Signal(str)          # một dòng log mới
    status_upd = Signal(str, str)     # (step_id, "running" | "done" | "failed" | "waiting")
    finished   = Signal(str, bool)    # (step_id, success)
    all_done   = Signal()             # chiến dịch kết thúc


class AttackWorker(QRunnable):
    """Chạy một hàm case_* của run_campaign trong thread riêng."""

    def __init__(self, step_id: str, fn, fn_kwargs: dict):
        super().__init__()
        self.step_id   = step_id
        self.fn        = fn
        self.fn_kwargs = fn_kwargs
        self.signals   = WorkerSignals()
        self.setAutoDelete(True)

    @Slot()
    def run(self):
        self.signals.status_upd.emit(self.step_id, "running")
        self.signals.log_line.emit(
            f"\n{'='*60}\n[►] BẮT ĐẦU: {self.step_id}\n{'='*60}"
        )
        try:
            result = self.fn(**self.fn_kwargs)
            for line in str(result).splitlines():
                self.signals.log_line.emit(line)
            self.signals.status_upd.emit(self.step_id, "done")
            self.signals.finished.emit(self.step_id, True)
        except Exception as exc:
            self.signals.log_line.emit(f"[!] LỖI: {exc}")
            self.signals.log_line.emit(traceback.format_exc())
            self.signals.status_upd.emit(self.step_id, "failed")
            self.signals.finished.emit(self.step_id, False)
        finally:
            self.signals.all_done.emit()


class SubprocessWorker(QRunnable):
    """Chạy một lệnh phụ bằng subprocess, stream từng dòng stdout."""

    def __init__(self, step_id: str, cmd: list[str], env: dict | None = None):
        super().__init__()
        self.step_id = step_id
        self.cmd     = cmd
        self.env     = env or os.environ.copy()
        self.signals = WorkerSignals()
        self.setAutoDelete(True)
        self.proc: subprocess.Popen | None = None

    @Slot()
    def run(self):
        self.signals.status_upd.emit(self.step_id, "running")
        self.signals.log_line.emit(
            f"\n{'='*60}\n[►] BẮT ĐẦU: {self.step_id}\n{'='*60}"
        )
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self.env,
            )
            for line in self.proc.stdout:
                self.signals.log_line.emit(line.rstrip())
            self.proc.wait()
            ok = self.proc.returncode == 0
            self.signals.status_upd.emit(self.step_id, "done" if ok else "failed")
            self.signals.finished.emit(self.step_id, ok)
        except Exception as exc:
            self.signals.log_line.emit(f"[!] LỖI subprocess: {exc}")
            self.signals.status_upd.emit(self.step_id, "failed")
            self.signals.finished.emit(self.step_id, False)
        finally:
            self.signals.all_done.emit()


class CampaignWorker(QRunnable):
    """Chạy toàn bộ chiến dịch tuần tự — gọi từng fn một, hỗ trợ dừng ngay lập tức."""

    def __init__(self, steps: list[tuple[str, callable, dict]], cooldown: float = 2.0):
        super().__init__()
        self.steps     = steps
        self.cooldown  = cooldown
        self.signals   = WorkerSignals()
        self.setAutoDelete(True)
        self._is_stopped = False

    def stop(self):
        """Yêu cầu dừng khẩn cấp chiến dịch."""
        self._is_stopped = True

    @Slot()
    def run(self):
        self.signals.log_line.emit(
            f"\n{'#'*60}\n🚀 TOÀN BỘ CHIẾN DỊCH BẮT ĐẦU\n{'#'*60}"
        )
        all_ok = True
        executed_count = 0

        for step_id, fn, kwargs in self.steps:
            if self._is_stopped:
                self.signals.log_line.emit(
                    f"\n{'='*60}\n⛔ CHIẾN DỊCH ĐÃ BỊ DỪNG BỞI NGƯỜI DÙNG!\n{'='*60}"
                )
                self.signals.status_upd.emit(step_id, "waiting")
                break

            self.signals.status_upd.emit(step_id, "running")
            self.signals.log_line.emit(
                f"\n{'='*55}\n[►] {step_id}\n{'='*55}"
            )
            try:
                result = fn(**kwargs)
                for line in str(result).splitlines():
                    self.signals.log_line.emit(line)
                self.signals.status_upd.emit(step_id, "done")
                self.signals.finished.emit(step_id, True)
                executed_count += 1
            except Exception as exc:
                self.signals.log_line.emit(f"[!] LỖI: {exc}")
                self.signals.log_line.emit(traceback.format_exc())
                self.signals.status_upd.emit(step_id, "failed")
                self.signals.finished.emit(step_id, False)
                all_ok = False

            # Nghỉ theo cooldown, kiểm tra ngắt dừng mỗi 0.1s
            sleep_ticks = int(max(0.5, self.cooldown) * 10)
            for _ in range(sleep_ticks):
                if self._is_stopped:
                    break
                time.sleep(0.1)

        if self._is_stopped:
            self.signals.log_line.emit(
                f"\n[⛔] Chiến dịch đã dừng thành công sau khi chạy {executed_count}/{len(self.steps)} bài kiểm thử.\n"
            )
        else:
            self.signals.log_line.emit(
                f"\n{'#'*60}\n{'✅ CHIẾN DỊCH HOÀN TẤT' if all_ok else '⚠️  CHIẾN DỊCH KẾT THÚC (CÓ LỖI)'}\n{'#'*60}"
            )

        self.signals.all_done.emit()


# ===========================================================================
# Nút kỹ thuật (TechniqueButton) — hiển thị badge trạng thái
# ===========================================================================
class TechniqueButton(QWidget):
    clicked = Signal(str)   # emits step_id

    def __init__(self, step_id: str, label: str, parent=None):
        super().__init__(parent)
        self.step_id = step_id

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 2, 0, 2)
        layout.setSpacing(6)

        self.badge = QLabel(BADGE_WAIT)
        self.badge.setFixedWidth(22)
        self.badge.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.btn = QPushButton(label)
        self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.btn.setMinimumHeight(32)
        self.btn.setStyleSheet(f"""
            QPushButton {{
                background: {C_CARD};
                color: {C_TEXT};
                border: 1px solid {C_BORDER};
                border-radius: 4px;
                padding: 4px 10px;
                text-align: left;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background: #1a2540;
                border-color: {C_ACCENT2};
                color: #FFFFFF;
            }}
            QPushButton:pressed {{
                background: #0f1a35;
            }}
        """)
        self.btn.clicked.connect(lambda: self.clicked.emit(self.step_id))

        layout.addWidget(self.badge)
        layout.addWidget(self.btn)

    def set_status(self, status: str):
        mapping = {
            "waiting": (BADGE_WAIT, C_WAIT),
            "running": (BADGE_RUN,  C_RUN),
            "done":    (BADGE_DONE, C_DONE),
            "failed":  (BADGE_FAIL, C_FAIL),
        }
        badge_char, _color = mapping.get(status, (BADGE_WAIT, C_WAIT))
        self.badge.setText(badge_char)


# ===========================================================================
# Cửa sổ chính
# ===========================================================================
class RedTeamStudio(QMainWindow):

    def __init__(self):
        super().__init__()
        # Import run_campaign động (đảm bảo đường dẫn đúng)
        try:
            import run_campaign as rc
            self.rc = rc
            self._import_ok = True
        except Exception as exc:
            self._import_ok = False
            self._import_err = str(exc)

        self.setWindowTitle("🔴 GlobalBan Red Team Studio — MITRE ATT&CK Attack Console")
        self.resize(1300, 840)
        self._apply_dark_palette()

        self.pool = QThreadPool.globalInstance()
        self.pool.setMaxThreadCount(4)

        # Lưu widget nút theo step_id
        self._btn_map: dict[str, TechniqueButton] = {}
        self._running: set[str] = set()
        self._current_campaign_worker: CampaignWorker | None = None

        self._build_ui()

        if not self._import_ok:
            self._log(f"[!] CẢNH BÁO: Không import được run_campaign.py\n    {self._import_err}")
            self._log("    Hãy chạy script từ thư mục C:\\redteam-harness\\")
        else:
            self._log("✅ run_campaign.py đã được nạp thành công.")
            self._log(f"📁 Thư mục artifacts: {Path(self.rc.ROOT_DIR)}")
            self._log("─" * 60)

    # ------------------------------------------------------------------
    # Màu nền tối
    # ------------------------------------------------------------------
    def _apply_dark_palette(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background-color: {C_BG};
                color: {C_TEXT};
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }}
            QSplitter::handle {{
                background: {C_BORDER};
                width: 2px;
            }}
            QScrollBar:vertical {{
                background: {C_PANEL};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {C_BORDER};
                border-radius: 4px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            QLineEdit, QSpinBox, QDoubleSpinBox {{
                background: {C_CARD};
                color: {C_TEXT};
                border: 1px solid {C_BORDER};
                border-radius: 4px;
                padding: 4px 8px;
                font-size: 12px;
            }}
            QCheckBox {{
                color: {C_TEXT};
                spacing: 6px;
            }}
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {C_ACCENT};
                border-radius: 3px;
                background: {C_CARD};
            }}
            QCheckBox::indicator:checked {{
                background: {C_ACCENT};
            }}
            QLabel {{
                color: {C_TEXT};
            }}
            QStatusBar {{
                background: {C_PANEL};
                color: {C_MUTED};
                border-top: 1px solid {C_BORDER};
            }}
        """)

    # ------------------------------------------------------------------
    # Xây dựng giao diện
    # ------------------------------------------------------------------
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Thanh tiêu đề ──────────────────────────────────────────────
        root_layout.addWidget(self._build_title_bar())

        # ── Thanh cấu hình ─────────────────────────────────────────────
        root_layout.addWidget(self._build_config_bar())

        # ── Nội dung chính (splitter) ───────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([350, 950])
        root_layout.addWidget(splitter, 1)

        # ── Thanh dưới (bottom bar) ─────────────────────────────────────
        root_layout.addWidget(self._build_bottom_bar())

        # ── Status bar ──────────────────────────────────────────────────
        self.setStatusBar(QStatusBar())
        self.statusBar().showMessage("Sẵn sàng  |  Red Team: 192.168.52.134  →  Blue Team: 192.168.52.136")

    def _build_title_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"""
            QWidget {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #1a0608, stop:0.5 #0f1526, stop:1 #0a0e1a);
                border-bottom: 2px solid {C_ACCENT};
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 0, 16, 0)

        icon = QLabel("🎯")
        icon.setStyleSheet("font-size: 24px; background: transparent;")

        title = QLabel("GlobalBan Red Team Studio")
        title.setStyleSheet(f"""
            font-size: 18px;
            font-weight: bold;
            color: {C_ACCENT};
            background: transparent;
            letter-spacing: 1px;
        """)

        sub = QLabel("MITRE ATT&CK Attack Console  |  Purple Team Lab")
        sub.setStyleSheet(f"color: {C_MUTED}; background: transparent; font-size: 11px;")

        layout.addWidget(icon)
        layout.addSpacing(8)
        layout.addWidget(title)
        layout.addSpacing(16)
        layout.addWidget(sub)
        layout.addStretch()

        version = QLabel("v2.0 — DACN 2026")
        version.setStyleSheet(f"color: {C_MUTED}; background: transparent; font-size: 10px;")
        layout.addWidget(version)

        return bar

    def _build_config_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"""
            QWidget {{
                background: {C_PANEL};
                border-bottom: 1px solid {C_BORDER};
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 6, 16, 6)
        layout.setSpacing(14)

        # Target IP
        lbl_ip = QLabel("🎯 Target IP:")
        lbl_ip.setStyleSheet("font-weight: bold; color: #94A3B8; background: transparent;")
        self.inp_ip = QLineEdit("192.168.52.136")
        self.inp_ip.setFixedWidth(145)
        self.inp_ip.setToolTip("IP máy Blue Team — chỉ cho phép dải 192.168.52.*")

        # Cooldown
        lbl_cd = QLabel("⏱ Cooldown (s):")
        lbl_cd.setStyleSheet("font-weight: bold; color: #94A3B8; background: transparent;")
        self.spn_cooldown = QDoubleSpinBox()
        self.spn_cooldown.setRange(0.5, 60)
        self.spn_cooldown.setValue(2.0)
        self.spn_cooldown.setSingleStep(0.5)
        self.spn_cooldown.setFixedWidth(68)
        self.spn_cooldown.setToolTip("Thời gian nghỉ (giây) giữa các bài kiểm thử trong chiến dịch")

        # Approved checkbox
        self.chk_approved = QCheckBox("✓ ĐÃ ĐƯỢC PHÊ DUYỆT (--approved)")
        self.chk_approved.setStyleSheet(f"""
            QCheckBox {{
                font-weight: bold;
                color: {C_GOLD};
                background: transparent;
            }}
            QCheckBox::indicator {{ border-color: {C_GOLD}; }}
            QCheckBox::indicator:checked {{ background: {C_GOLD}; }}
        """)
        self.chk_approved.setToolTip("Bắt buộc tích để kích hoạt các nút tấn công")

        # Clear log
        btn_clear = QPushButton("🗑 Xóa Log")
        btn_clear.setFixedHeight(32)
        btn_clear.setFixedWidth(85)
        btn_clear.setStyleSheet(f"""
            QPushButton {{
                background: {C_CARD};
                color: {C_MUTED};
                border: 1px solid {C_BORDER};
                border-radius: 4px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background: #1e2a40; color: {C_TEXT}; }}
        """)
        btn_clear.clicked.connect(self._clear_log)

        layout.addWidget(lbl_ip)
        layout.addWidget(self.inp_ip)
        layout.addWidget(lbl_cd)
        layout.addWidget(self.spn_cooldown)
        layout.addSpacing(12)
        layout.addWidget(self.chk_approved)
        layout.addStretch()
        layout.addWidget(btn_clear)

        return bar

    def _build_left_panel(self) -> QWidget:
        container = QWidget()
        container.setMinimumWidth(320)
        container.setMaximumWidth(390)
        container.setStyleSheet(f"""
            QWidget {{
                background: {C_PANEL};
                border-right: 1px solid {C_BORDER};
            }}
        """)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(4)

        # Tiêu đề panel
        header = QLabel("⚔  KỸ THUẬT MITRE ATT&CK")
        header.setStyleSheet(f"""
            font-size: 11px;
            font-weight: bold;
            color: {C_ACCENT};
            padding: 4px 0;
            border-bottom: 1px solid {C_BORDER};
            background: transparent;
        """)
        layout.addWidget(header)
        layout.addSpacing(4)

        # Danh sách các kỹ thuật
        self._steps: list[tuple[str, str, callable | None]] = [
            ("baseline",       "📋 5-Day Normal Baseline",           None),
            ("T1082",          "T1082 — System Info Discovery",      None),
            ("T1033",          "T1033 — User Discovery",             None),
            ("T1016/T1049",    "T1016/49 — Network Discovery",       None),
            ("T1560.001",      "T1560.001 — Archive Staging",        None),
            ("T1053.005",      "T1053.005 — Scheduled Task",         None),
            ("T1071.001",      "T1071.001 — C2 Beaconing",          None),
            ("T1110.001",      "T1110.001 — Brute Force",            None),
            ("T1110.003",      "T1110.003 — Password Spray",         None),
            ("T1059.001",      "T1059.001 — Encoded PowerShell",     None),
            ("T1087.001",      "T1087.001 — Account Discovery",      None),
            ("ContextDev",     "🔸 Context Deviation (LotL)",        None),
        ]

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setContentsMargins(0, 0, 0, 0)
        scroll_layout.setSpacing(3)

        for step_id, label, _ in self._steps:
            tb = TechniqueButton(step_id, label)
            tb.clicked.connect(self._on_technique_click)
            self._btn_map[step_id] = tb
            scroll_layout.addWidget(tb)

        scroll_layout.addStretch()
        scroll_area.setWidget(scroll_content)
        layout.addWidget(scroll_area, 1)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"color: {C_BORDER}; background: {C_BORDER}; max-height: 1px;")
        layout.addWidget(sep)
        layout.addSpacing(4)

        # ── KHỐI ĐIỀU KHIỂN CHIẾN DỊCH: CHẠY & DỪNG ──────────────────
        btn_action_layout = QHBoxLayout()
        btn_action_layout.setSpacing(8)

        # Nút RUN ALL
        self.btn_run_all = QPushButton("🚀  CHẠY TOÀN BỘ")
        self.btn_run_all.setMinimumHeight(44)
        self.btn_run_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_run_all.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #7f1d1d, stop:1 #991b1b);
                color: #FEF2F2;
                border: 2px solid {C_ACCENT};
                border-radius: 6px;
                font-size: 12px;
                font-weight: bold;
                letter-spacing: 0.5px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C_ACCENT}, stop:1 #dc2626);
                color: #FFFFFF;
            }}
            QPushButton:disabled {{
                background: #1e2430;
                color: #4b5563;
                border-color: #2b3548;
            }}
        """)
        self.btn_run_all.clicked.connect(self._on_run_all)

        # Nút DỪNG CHIẾN DỊCH
        self.btn_stop = QPushButton("⏹  DỪNG")
        self.btn_stop.setMinimumHeight(44)
        self.btn_stop.setFixedWidth(105)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_stop.setToolTip("Dừng ngay lập tức chiến dịch đang chạy")
        self.btn_stop.setStyleSheet(f"""
            QPushButton {{
                background: #450a0a;
                color: #FCA5A5;
                border: 2px solid {C_ACCENT};
                border-radius: 6px;
                font-size: 12px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: {C_ACCENT};
                color: #FFFFFF;
            }}
            QPushButton:disabled {{
                background: #161c28;
                color: #475569;
                border-color: #243048;
            }}
        """)
        self.btn_stop.clicked.connect(self._on_stop_campaign)

        btn_action_layout.addWidget(self.btn_run_all, 1)
        btn_action_layout.addWidget(self.btn_stop)
        layout.addLayout(btn_action_layout)

        return container

    def _build_right_panel(self) -> QWidget:
        container = QWidget()
        container.setStyleSheet(f"background: {C_BG};")
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        # Header log
        log_header = QLabel("📄 NHẬT KÝ THỰC CHIẾN (Real-time Telemetry Stream)")
        log_header.setStyleSheet(f"""
            font-size: 11px;
            font-weight: bold;
            color: {C_ACCENT2};
            padding: 2px 0;
        """)
        layout.addWidget(log_header)

        # Vùng log chính
        self.log_edit = QPlainTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(MONOSPACE_FONT)
        self.log_edit.setStyleSheet(f"""
            QPlainTextEdit {{
                background: #060b14;
                color: #A8D8A8;
                border: 1px solid {C_BORDER};
                border-radius: 6px;
                padding: 10px;
                selection-background-color: #1e3a5f;
            }}
        """)
        self.log_edit.setPlaceholderText(
            "Nhật ký hoạt động Red Team sẽ xuất hiện ở đây...\n"
            "Hãy chọn kỹ thuật từ panel bên trái hoặc nhấn [🚀 CHẠY TOÀN BỘ] / [⏹ DỪNG]."
        )
        layout.addWidget(self.log_edit, 1)

        return container

    def _build_bottom_bar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"""
            QWidget {{
                background: {C_PANEL};
                border-top: 1px solid {C_BORDER};
            }}
        """)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(10)

        def _make_bottom_btn(icon_label: str, color: str, tooltip: str) -> QPushButton:
            btn = QPushButton(icon_label)
            btn.setFixedHeight(34)
            btn.setMinimumWidth(180)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolTip(tooltip)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: {C_CARD};
                    color: {color};
                    border: 1px solid {color};
                    border-radius: 5px;
                    font-size: 11px;
                    font-weight: bold;
                    padding: 0 12px;
                }}
                QPushButton:hover {{
                    background: {color};
                    color: #000;
                }}
            """)
            return btn

        btn_validate = _make_bottom_btn(
            "📋  Kiểm tra Handoff (Validate)", C_GOLD,
            "Chạy validate_handoff.py — kiểm tra toàn vẹn SHA-256 của gói bằng chứng"
        )
        btn_evaluate = _make_bottom_btn(
            "📊  So sánh Sigma vs UEBA", C_ACCENT2,
            "Chạy bridge_evaluate.py — xuất bảng đối sánh Precision / Recall / F1"
        )
        btn_artifacts = _make_bottom_btn(
            "📂  Mở Thư mục Artifacts", C_GREEN,
            "Mở thư mục C:\\redteam-harness\\artifacts trong Windows Explorer"
        )
        btn_reset = _make_bottom_btn(
            "🔄  Reset Trạng thái", C_MUTED,
            "Đặt lại tất cả badge kỹ thuật về trạng thái ban đầu"
        )

        btn_validate.clicked.connect(self._on_validate)
        btn_evaluate.clicked.connect(self._on_evaluate)
        btn_artifacts.clicked.connect(self._on_open_artifacts)
        btn_reset.clicked.connect(self._on_reset_badges)

        layout.addWidget(btn_validate)
        layout.addWidget(btn_evaluate)
        layout.addWidget(btn_artifacts)
        layout.addStretch()
        layout.addWidget(btn_reset)

        return bar

    # ------------------------------------------------------------------
    # Tiện ích log
    # ------------------------------------------------------------------
    def _log(self, text: str):
        """Thêm dòng text vào log panel (thread-safe từ main thread)."""
        self.log_edit.appendPlainText(text)
        self.log_edit.moveCursor(QTextCursor.MoveOperation.End)

    @Slot(str)
    def _append_log(self, line: str):
        """Slot nhận signal từ worker thread."""
        self.log_edit.appendPlainText(line)
        self.log_edit.moveCursor(QTextCursor.MoveOperation.End)

    def _clear_log(self):
        self.log_edit.clear()

    # ------------------------------------------------------------------
    # Tiện ích lấy target IP và kiểm tra
    # ------------------------------------------------------------------
    def _get_target_ip(self) -> str:
        return self.inp_ip.text().strip()

    def _check_approved(self) -> bool:
        if not self.chk_approved.isChecked():
            self._log("[!] Phải tích ô [✓ ĐÃ ĐƯỢC PHÊ DUYỆT] trước khi thực thi!")
            return False
        ip = self._get_target_ip()
        if not ip.startswith("192.168.52."):
            self._log(f"[!] IP không hợp lệ: {ip} — Chỉ cho phép dải mạng lab 192.168.52.*")
            return False
        return True

    # ------------------------------------------------------------------
    # Mapping step_id → hàm trong run_campaign
    # ------------------------------------------------------------------
    def _resolve_fn(self, step_id: str) -> tuple[callable, dict] | None:
        if not self._import_ok:
            self._log("[!] run_campaign chưa được nạp. Không thể thực thi.")
            return None
        rc = self.rc
        ip = self._get_target_ip()
        mapping = {
            "baseline":     (rc.case_baseline_normal,              {}),
            "T1082":        (rc.case_t1082_system_info_discovery,  {}),
            "T1033":        (rc.case_t1033_user_discovery,         {}),
            "T1016/T1049":  (rc.case_t1016_t1049_network_discovery,{}),
            "T1560.001":    (rc.case_t1560_001_archive_staging,    {}),
            "T1053.005":    (rc.case_t1053_005_scheduled_task,     {}),
            "T1071.001":    (rc.case_t1071_001_c2_beaconing,       {"target_ip": ip}),
            "T1110.001":    (rc.case_t1110_001_bruteforce,         {"target_ip": ip}),
            "T1110.003":    (rc.case_t1110_003_password_spray,     {"target_ip": ip}),
            "T1059.001":    (rc.case_t1059_001_encoded_powershell, {}),
            "T1087.001":    (rc.case_t1087_001_local_account_discovery, {}),
            "ContextDev":   (rc.case_context_deviation_off_hours,  {}),
        }
        return mapping.get(step_id)

    # ------------------------------------------------------------------
    # Signal routing từ worker → UI
    # ------------------------------------------------------------------
    def _connect_worker_signals(self, worker):
        worker.signals.log_line.connect(self._append_log)
        worker.signals.status_upd.connect(self._on_status_update)
        worker.signals.all_done.connect(self._on_all_workers_finished)

    @Slot(str, str)
    def _on_status_update(self, step_id: str, status: str):
        if step_id in self._btn_map:
            self._btn_map[step_id].set_status(status)
        if status == "running":
            self._running.add(step_id)
            self.statusBar().showMessage(f"⏳ Đang chạy: {step_id}  |  Target: {self._get_target_ip()}")
        else:
            self._running.discard(step_id)
            if not self._running:
                self.statusBar().showMessage(f"✅ Hoàn tất  |  Target: {self._get_target_ip()}")

    @Slot()
    def _on_all_workers_finished(self):
        """Khôi phục trạng thái nút bấm khi tất cả tác vụ kết thúc."""
        self._current_campaign_worker = None
        self.btn_run_all.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.statusBar().showMessage(f"Sẵn sàng  |  Target: {self._get_target_ip()}")

    # ------------------------------------------------------------------
    # Event handlers — các nút kỹ thuật
    # ------------------------------------------------------------------
    @Slot(str)
    def _on_technique_click(self, step_id: str):
        if not self._check_approved():
            return
        result = self._resolve_fn(step_id)
        if result is None:
            self._log(f"[!] Không tìm thấy hàm cho step: {step_id}")
            return
        fn, kwargs = result
        self.btn_run_all.setEnabled(False)
        self.btn_stop.setEnabled(True)
        worker = AttackWorker(step_id, fn, kwargs)
        self._connect_worker_signals(worker)
        self.pool.start(worker)

    # ------------------------------------------------------------------
    # Event handler — Run All Campaign & Stop Campaign
    # ------------------------------------------------------------------
    @Slot()
    def _on_run_all(self):
        if not self._check_approved():
            return
        if not self._import_ok:
            self._log("[!] run_campaign chưa được nạp.")
            return

        cooldown = self.spn_cooldown.value()
        campaign_steps = []
        for step_id, _, _ in self._steps:
            result = self._resolve_fn(step_id)
            if result:
                fn, kwargs = result
                campaign_steps.append((step_id, fn, kwargs))

        worker = CampaignWorker(campaign_steps, cooldown=cooldown)
        self._current_campaign_worker = worker
        self._connect_worker_signals(worker)

        self.btn_run_all.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.statusBar().showMessage(f"🚀 Đang chạy toàn bộ chiến dịch ({len(campaign_steps)} bài) → {self._get_target_ip()}...")
        self.pool.start(worker)

    @Slot()
    def _on_stop_campaign(self):
        """Dừng khẩn cấp toàn bộ chiến dịch đang chạy."""
        if self._current_campaign_worker:
            self._log("\n[⛔] ĐÃ NHẤN NÚT DỪNG CHIẾN DỊCH! Đang hủy các bước tiếp theo...")
            self.statusBar().showMessage("⛔ Đang dừng chiến dịch khẩn cấp...")
            self._current_campaign_worker.stop()
            self.btn_stop.setEnabled(False)
            self.btn_run_all.setEnabled(True)
        else:
            self._log("[ℹ] Không có chiến dịch nào đang chạy.")
            self.btn_stop.setEnabled(False)
            self.btn_run_all.setEnabled(True)

    # ------------------------------------------------------------------
    # Bottom bar handlers
    # ------------------------------------------------------------------
    @Slot()
    def _on_validate(self):
        script = str(HARNESS_DIR / "validate_handoff.py")
        worker = SubprocessWorker(
            "validate_handoff",
            [sys.executable, script]
        )
        self.btn_run_all.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._connect_worker_signals(worker)
        self.pool.start(worker)

    @Slot()
    def _on_evaluate(self):
        # Đảm bảo PYTHONPATH chứa đầy đủ các thư mục src cần thiết
        env = os.environ.copy()
        extra_paths = [
            str(HARNESS_DIR / "src"),
            r"C:\attack-globalban\src",
            r"C:\DACN\src",
        ]
        curr_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join(extra_paths + ([curr_pp] if curr_pp else []))

        script_harness = HARNESS_DIR / "bridge_evaluate.py"
        script_dacn    = Path(r"C:\DACN\bridge_evaluate.py")
        script = str(script_harness) if script_harness.exists() else str(script_dacn)

        worker = SubprocessWorker(
            "bridge_evaluate",
            [sys.executable, script],
            env=env,
        )
        self.btn_run_all.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self._connect_worker_signals(worker)
        self.pool.start(worker)

    @Slot()
    def _on_open_artifacts(self):
        artifacts_path = str(HARNESS_DIR / "artifacts")
        subprocess.Popen(["explorer.exe", artifacts_path])
        self._log(f"📂 Mở Explorer: {artifacts_path}")

    @Slot()
    def _on_reset_badges(self):
        for tb in self._btn_map.values():
            tb.set_status("waiting")
        self._log("🔄 Đã reset tất cả badge về Waiting.")
        self._running.clear()
        self._current_campaign_worker = None
        self.btn_run_all.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.statusBar().showMessage(f"Sẵn sàng  |  Target: {self._get_target_ip()}")


# ===========================================================================
# Entry point
# ===========================================================================
def main():
    # Đảm bảo encoding UTF-8
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    app = QApplication(sys.argv)
    app.setApplicationName("GlobalBan Red Team Studio")
    app.setOrganizationName("DACN-2026")

    # High DPI
    app.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    window = RedTeamStudio()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
