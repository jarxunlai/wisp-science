#!/usr/bin/env python3
"""
百度网盘与本地/服务器目录增量同步比对工具
"""

import argparse
import json
import os
import re
import subprocess
import sys


def parse_pcs_ls_output(raw_output):
    """
    解析 BaiduPCS-Go ls 输出
    输出格式通常为:
       0           - 2026-09-06 21:58:47 01-spatial-platforms/
       1    100.25KB 2026-09-06 21:58:48 test.tsv
    """
    items = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^\s*(\d+)\s+([\w\.\-]+)\s+(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+(.+)$", line)
        if m:
            idx, size_str, date_str, time_str, name = m.groups()
            name = name.strip()
            is_dir = name.endswith("/")
            item_name = name.rstrip("/")
            items.append({
                "name": item_name,
                "is_dir": is_dir,
                "size_str": size_str,
                "datetime": f"{date_str} {time_str}"
            })
    return items


def scan_remote_pcs(pcs_bin, remote_base):
    """
    通过 BaiduPCS-Go 递归遍历网盘指定路径下的所有文件
    返回相对路径 -> 元数据字典
    """
    files = {}
    stack = [""]
    
    while stack:
        rel = stack.pop()
        curr = (remote_base.rstrip("/") + "/" + rel).rstrip("/") if rel else remote_base
        cmd = [pcs_bin, "ls", curr]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            output = res.stdout
        except Exception as e:
            print(f"[WARN] Failed to ls remote path {curr}: {e}", file=sys.stderr)
            continue

        items = parse_pcs_ls_output(output)
        for item in items:
            item_rel = (rel + "/" + item["name"]).lstrip("/")
            if item["is_dir"]:
                stack.append(item_rel)
            else:
                files[item_rel] = {
                    "size_str": item["size_str"],
                    "datetime": item["datetime"]
                }
    return files


def scan_local_dir(local_base):
    """
    递归遍历本地目录
    返回相对路径 -> 文件大小 (int)
    """
    local_files = {}
    if not os.path.exists(local_base):
        return local_files

    for root, _, files in os.walk(local_base):
        for f in files:
            full_p = os.path.join(root, f)
            rel_p = os.path.relpath(full_p, local_base).replace("\\", "/")
            try:
                local_files[rel_p] = os.path.getsize(full_p)
            except OSError:
                continue
    return local_files


def compare_manifests(remote_manifest, local_manifest):
    """
    比对网盘端和本地端
    返回: missing_in_local, exist_in_both, extra_in_local
    """
    remote_keys = set(remote_manifest.keys())
    local_keys = set(local_manifest.keys())

    missing = sorted(list(remote_keys - local_keys))
    both = sorted(list(remote_keys & local_keys))
    extra = sorted(list(local_keys - remote_keys))

    return missing, both, extra


def main():
    parser = argparse.ArgumentParser(description="Compare Baidu PCS files with local directory for incremental sync.")
    parser.add_argument(
        "--pcs-bin",
        default=os.environ.get("PCS_BIN", os.path.expanduser("~/bin/BaiduPCS-Go")),
        help="Path to BaiduPCS-Go binary (override with --pcs-bin or PCS_BIN)",
    )
    parser.add_argument("--remote-base", required=True, help="Remote directory path in Baidu PCS")
    parser.add_argument("--local-base", required=True, help="Local directory path")
    parser.add_argument("--output-json", help="Path to save comparison JSON result")
    
    args = parser.parse_args()

    print(f"Scanning remote: {args.remote_base} ...")
    remote_files = scan_remote_pcs(args.pcs_bin, args.remote_base)
    print(f"Found {len(remote_files)} files on Baidu PCS.")

    print(f"Scanning local: {args.local_base} ...")
    local_files = scan_local_dir(args.local_base)
    print(f"Found {len(local_files)} files in local directory.")

    missing, both, extra = compare_manifests(remote_files, local_files)
    print(f"\n[Comparison Summary]")
    print(f"  Already exists locally: {len(both)}")
    print(f"  Missing locally (need download): {len(missing)}")
    print(f"  Only exists locally: {len(extra)}")

    result = {
        "remote_base": args.remote_base,
        "local_base": args.local_base,
        "remote_count": len(remote_files),
        "local_count": len(local_files),
        "missing_in_local": missing,
        "exist_in_both": both,
        "extra_in_local": extra,
        "remote_manifest": remote_files
    }

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        print(f"Comparison report saved to {args.output_json}")


if __name__ == "__main__":
    main()
