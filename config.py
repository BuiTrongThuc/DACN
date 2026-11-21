"""
config.py
=========
Gom các hằng số cấu hình mặc định cho GlobalBan Red-Team Studio.
"""

from __future__ import annotations

from pathlib import Path

BASE_DIR: Path = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR: Path = BASE_DIR / "output"
DEFAULT_SCRIPTS_DIR: Path = BASE_DIR / "scripts"
DEFAULT_METADATA_DIR: Path = BASE_DIR / "metadata"

# Tham số sinh dữ liệu kiểm chuẩn mặc định
DEFAULT_SEED: int = 42
DEFAULT_CAMPAIGNS_PER_SCENARIO: int = 25
DEFAULT_BENIGN_COUNT: int = 600
DEFAULT_FP_NOISE_COUNT: int = 30
DETECTION_WINDOW_SECONDS: int = 300

# Cấu hình IP Lab & C2 giả lập
ATTACKER_IP_PREFIX: str = "91"
INTERNAL_SUBNET_PREFIX: str = "10.10.1"
PUBLIC_C2_IPS: tuple[str, ...] = (
    "45.33.32.156",
    "185.199.108.153",
    "104.16.132.229",
    "151.101.1.69",
    "172.67.74.226",
    "198.41.200.113",
    "140.82.121.4",
    "13.107.42.14",
    "34.117.59.81",
    "52.84.150.11",
    "103.224.182.210",
    "91.189.91.39",
)
