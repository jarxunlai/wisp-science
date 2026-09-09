#!/usr/bin/env python3
"""Offline structural verification for the baidupcs-transfer-sync Skill."""

from __future__ import annotations

import argparse
import ast
import importlib.util
import os
import re
import sys
from pathlib import Path, PurePosixPath

SKILL_NAME = "baidupcs-transfer-sync"
REQUIRED_FILES = {
    "SKILL.md",
    "scripts/login.sh",
    "scripts/compare_manifest.py",
    "scripts/incremental_download.py",
    "scripts/verify_skill.py",
    "references/best_practices.md",
    "references/directory_schema.md",
}
FORBIDDEN_SUFFIXES = {".pyc", ".pyo"}
FORBIDDEN_PARTS = {"__pycache__", ".git"}
PATH_REFERENCE_RE = re.compile(r"`((?:references|scripts)/[A-Za-z0-9._/-]+)`")
PRIVATE_PATH_RE = re.compile(
    r"(?i)(/home/data/\w+|C:\\Users\\|/Users/\w+|BDUSS=[A-Za-z0-9_\-~]+)"
)


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md must start with YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise ValueError("SKILL.md frontmatter is not closed")
    values: dict[str, str] = {}
    for raw_line in text[4:end].splitlines():
        if not raw_line.strip():
            continue
        if ":" not in raw_line:
            raise ValueError(f"invalid frontmatter line: {raw_line!r}")
        key, value = raw_line.split(":", 1)
        values[key.strip()] = value.strip()
    return values, text[end + 5 :]


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validate_python_scripts(root: Path) -> None:
    for path in sorted((root / "scripts").glob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _validate_parser_fixture() -> None:
    compare_path = Path(__file__).resolve().parent / "compare_manifest.py"
    module = _load_module(compare_path, "compare_manifest")
    sample = (
        "   0           - 2026-09-06 21:58:47 01-spatial-platforms/\n"
        "   1    100.25KB 2026-09-06 21:58:48 test.tsv\n"
    )
    items = module.parse_pcs_ls_output(sample)
    if len(items) != 2:
        raise ValueError(f"expected 2 parsed items, got {len(items)}")
    if not items[0]["is_dir"] or items[0]["name"] != "01-spatial-platforms":
        raise ValueError("directory line was not parsed correctly")
    if items[1]["is_dir"] or items[1]["name"] != "test.tsv":
        raise ValueError("file line was not parsed correctly")

    missing, both, extra = module.compare_manifests(
        {"a.txt": {}, "b.txt": {}},
        {"b.txt": 1, "c.txt": 2},
    )
    if missing != ["a.txt"] or both != ["b.txt"] or extra != ["c.txt"]:
        raise ValueError("compare_manifests returned unexpected sets")


def _validate_tree(root: Path) -> None:
    if root.name != SKILL_NAME:
        raise ValueError(f"folder name must be {SKILL_NAME!r}")
    skill_md = root / "SKILL.md"
    text = skill_md.read_text(encoding="utf-8")
    frontmatter, body = _frontmatter(text)
    if set(frontmatter) != {"name", "description"}:
        raise ValueError("frontmatter must contain only name and description")
    if frontmatter["name"] != SKILL_NAME:
        raise ValueError("frontmatter name does not match folder")
    description = frontmatter["description"]
    if "BaiduPCS-Go" not in description or "增量" not in description:
        raise ValueError("description must state BaiduPCS-Go transfer/sync capability")
    if "## 安全边界" not in body:
        raise ValueError("SKILL.md is missing the safety section")

    missing = sorted(relative for relative in REQUIRED_FILES if not (root / relative).is_file())
    if missing:
        raise ValueError(f"missing required files: {', '.join(missing)}")

    for reference in PATH_REFERENCE_RE.findall(text):
        pure = PurePosixPath(reference)
        if pure.is_absolute() or ".." in pure.parts:
            raise ValueError(f"unsafe local reference: {reference}")
        if not (root / Path(*pure.parts)).is_file():
            raise ValueError(f"broken local reference: {reference}")

    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in FORBIDDEN_PARTS for part in relative.parts):
            raise ValueError(f"forbidden path in Skill tree: {relative}")
        if path.is_file() and path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise ValueError(f"forbidden compiled file: {relative}")
        if path.is_symlink():
            raise ValueError(f"symlinks are not allowed: {relative}")
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            if PRIVATE_PATH_RE.search(content):
                raise ValueError(f"possible personal path or cookie payload in {relative}")

    login_sh = (root / "scripts" / "login.sh").read_text(encoding="utf-8")
    if "login -bduss=" not in login_sh or "stoken" not in login_sh.lower():
        raise ValueError("login.sh must use -bduss/-stoken rather than -cookies")

    _validate_python_scripts(root)
    _validate_parser_fixture()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "skill_directory",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args(argv)
    root = args.skill_directory.expanduser().resolve()
    try:
        _validate_tree(root)
    except (OSError, UnicodeError, TypeError, ValueError, SyntaxError) as exc:
        print(f"Skill verification failed: {exc}", file=sys.stderr)
        return 1
    files = sum(1 for path in root.rglob("*") if path.is_file())
    print(f"Skill verification passed: {root} ({files} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
