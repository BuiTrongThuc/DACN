"""Chuẩn bị dataset cho dự án agent phát hiện nguy hiểm trên log Windows.

1) AD-GEN (JSONL -> CSV cân bằng theo mức rủi ro):
   git clone https://github.com/namhop88/AD-GEN.git
   python prepare_dataset.py adgen --files AD-GEN/LAB/LAB.jsonl AD-GEN/REAL/REAL.jsonl --per-level 500 --out datasets/adgen_sample.csv

2) MITRE ATT&CK (STIX -> CSV tri thức cho RAG):
   python prepare_dataset.py stix --file datasets/enterprise-attack.json --out datasets/attack_techniques.csv --windows-only
"""
import argparse
import csv
import json
import os
import random
import re
import sys

# Thiết lập UTF-8 cho console Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")


def flat(x):
    if isinstance(x, list):
        return ";".join(map(str, x))
    return "" if x is None else str(x)


def adgen(a):
    random.seed(a.seed)
    pools, seen = {}, {}  # reservoir sampling theo mức rủi ro (xử lý file rất lớn)
    total_processed = 0

    # Tự động nhận diện nếu người dùng truyền nhầm LAB/NEW_LAB
    files_to_read = []
    for p in a.files:
        if os.path.exists(p):
            files_to_read.append(p)
        else:
            # Kiểm tra tên thay thế (ví dụ NEW_LAB -> LAB hoặc ngược lại)
            alt_p = p.replace("NEW_", "") if "NEW_" in p else p.replace("LAB.jsonl", "NEW_LAB.jsonl").replace("REAL.jsonl", "NEW_REAL.jsonl")
            if os.path.exists(alt_p):
                print(f"[Lưu ý] Đổi đường dẫn '{p}' sang file thực tế '{alt_p}'")
                files_to_read.append(alt_p)
            else:
                print(f"[Cảnh báo] Không tìm thấy file: {p}")

    if not files_to_read:
        print("[Lỗi] Không có file JSONL hợp lệ nào để xử lý!")
        sys.exit(1)

    for path in files_to_read:
        print(f"Đang đọc dữ liệu từ: {path} ...")
        # Kiểm tra nếu file chỉ là Git LFS pointer
        try:
            with open(path, "rb") as f_check:
                header = f_check.read(128)
                if b"git-lfs" in header:
                    print(f"[Cảnh báo] File '{path}' là Git LFS pointer (chưa tải dữ liệu thật, kích thước ~ {os.path.getsize(path)} bytes). Hãy cài git-lfs và chạy 'git lfs pull' trước!")
                    continue
        except OSError:
            pass

        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except Exception:
                    continue
                lab = r.get("label") or {}
                lvl = lab.get("risk_level", "Unknown")
                seen[lvl] = seen.get(lvl, 0) + 1
                total_processed += 1
                pool = pools.setdefault(lvl, [])
                if len(pool) < a.per_level:
                    pool.append(r)
                else:
                    j = random.randrange(seen[lvl])
                    if j < a.per_level:
                        pool[j] = r
                if total_processed % 50000 == 0:
                    print(f"  -> Đã duyệt {total_processed} dòng... Phân bố hiện tại: {seen}")

    cols = [
        "sample_id",
        "environment",
        "narrative",
        "risk_level",
        "verdict",
        "mitre_tactics",
        "mitre_techniques",
        "sysmon_hints",
        "recommended_actions",
        "summary",
        "analyst_rationale",
    ]
    n = 0
    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for lvl, pool in pools.items():
            for r in pool:
                lab = r.get("label") or {}
                raw_actions = lab.get("recommended_actions", [])
                acts = [
                    x.get("tool_name", "") if isinstance(x, dict) else str(x)
                    for x in raw_actions
                ]
                w.writerow([
                    r.get("sample_id"),
                    r.get("environment"),
                    r.get("narrative"),
                    lvl,
                    lab.get("verdict"),
                    flat(lab.get("mitre_tactics")),
                    flat(lab.get("mitre_techniques")),
                    flat(r.get("sysmon_hints")),
                    flat(acts),
                    lab.get("summary"),
                    lab.get("analyst_rationale"),
                ])
                n += 1

    print("\n--- KẾT QUẢ AD-GEN ---")
    print("Phân bố gốc toàn bộ dataset:", seen)
    print(f"Đã xuất {n} mẫu cân bằng rủi ro (tối đa {a.per_level}/mức) ra file: {a.out}")


def stix(a):
    if not os.path.exists(a.file):
        print(f"[Lỗi] File STIX không tồn tại: {a.file}")
        sys.exit(1)

    print(f"Đang phân tích MITRE ATT&CK STIX từ: {a.file} ...")
    with open(a.file, encoding="utf-8") as f:
        data = json.load(f)

    objs = data.get("objects", [])
    rows = []
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if a.windows_only and "Windows" not in o.get("x_mitre_platforms", []):
            continue
        tid = next(
            (
                r["external_id"]
                for r in o.get("external_references", [])
                if r.get("source_name") == "mitre-attack" and "external_id" in r
            ),
            "",
        )
        tactics = [p.get("phase_name", "") for p in o.get("kill_chain_phases", []) if p.get("phase_name")]
        desc_raw = o.get("description") or ""
        desc = re.sub(r"\(Citation:[^)]*\)", "", desc_raw)
        desc = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", desc)
        rows.append([tid, o.get("name") or "", flat(tactics), " ".join(desc.split())])

    rows.sort(key=lambda x: x[0])
    out_dir = os.path.dirname(a.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "name", "tactics", "description"])
        w.writerows(rows)

    print("\n--- KẾT QUẢ MITRE ATT&CK ---")
    print(f"Đã trích xuất {len(rows)} kỹ thuật ATT&CK (Windows-only: {a.windows_only}) ra file: {a.out}")


def main():
    p = argparse.ArgumentParser(description="Công cụ chuẩn bị dữ liệu cho AI Agent giám sát log Windows")
    s = p.add_subparsers(dest="cmd", required=True)

    x = s.add_parser("adgen", help="Trích xuất mẫu cân bằng từ AD-GEN JSONL")
    x.add_argument("--files", nargs="+", required=True, help="Đường dẫn đến các file JSONL")
    x.add_argument("--per-level", type=int, default=500, help="Số mẫu tối đa mỗi mức rủi ro (Low, Medium, High, Critical)")
    x.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên")
    x.add_argument("--out", default="datasets/adgen_sample.csv", help="Đường dẫn file CSV đầu ra")
    x.set_defaults(fn=adgen)

    y = s.add_parser("stix", help="Chuyển đổi STIX enterprise-attack.json sang CSV kỹ thuật cho RAG")
    y.add_argument("--file", required=True, help="Đường dẫn file enterprise-attack.json")
    y.add_argument("--out", default="datasets/attack_techniques.csv", help="Đường dẫn file CSV đầu ra")
    y.add_argument("--windows-only", action="store_true", help="Chỉ lọc kỹ thuật trên Windows")
    y.set_defaults(fn=stix)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
