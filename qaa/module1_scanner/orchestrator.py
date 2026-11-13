"""
Module 1 orchestrator.

Walks a target directory, routes every file to the correct surface detector,
and returns a single unified list of Findings for Module 2.

Routing rules
-------------
    .py                         -> AST scanner (falls back to regex on SyntaxError)
    other source extensions     -> regex scanner
    known config names/exts     -> config scanner
    known manifest names        -> dependency scanner
    .pcap / .pcapng / .cap      -> network scanner
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from qaa.config import (
    CONFIG_EXTENSIONS,
    CONFIG_FILENAMES,
    DEPENDENCY_FILENAMES,
    MAX_FILE_BYTES,
    PCAP_EXTENSIONS,
    SOURCE_EXTENSIONS,
)
from qaa.schema import Finding

from .ast_scanner import scan_python_file
from .config_scanner import scan_config_file
from .dependency_scanner import scan_dependency_file
from .regex_scanner import scan_text_source

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "env",
             "dist", "build", ".idea", ".vscode", "target", "vendor",
             "site-packages", ".mypy_cache", ".pytest_cache", "models"}


class ScanStats:
    def __init__(self) -> None:
        self.files_seen = 0
        self.files_scanned = 0
        self.files_skipped = 0
        self.by_surface: dict[str, int] = {}
        self.elapsed_sec = 0.0
        self.errors: list[str] = []

    def as_dict(self) -> dict:
        return {
            "files_seen": self.files_seen,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings_by_surface": dict(self.by_surface),
            "elapsed_sec": round(self.elapsed_sec, 3),
            "errors": self.errors[:20],
        }


def classify_file(path: Path) -> str | None:
    """Return the surface a file belongs to, or None if it should be skipped."""
    name = path.name.lower()
    suffix = path.suffix.lower()

    if name in DEPENDENCY_FILENAMES or path.name in DEPENDENCY_FILENAMES:
        return "dependency"
    if suffix in PCAP_EXTENSIONS:
        return "network"
    if name in CONFIG_FILENAMES or path.name in CONFIG_FILENAMES:
        return "config"
    if suffix == ".py":
        return "python_source"
    if suffix in SOURCE_EXTENSIONS:
        return "source"
    if suffix in CONFIG_EXTENSIONS:
        return "config"
    if name.startswith(".env"):
        return "config"
    return None


def scan_target(
    target: str | Path,
    include_pcap: bool = True,
    progress: Callable[[str, int, int], None] | None = None,
) -> tuple[list[Finding], ScanStats]:
    """
    Scan a file or directory across every supported surface.

    Returns (findings, stats).
    """
    target = Path(target)
    stats = ScanStats()
    started = time.perf_counter()

    if target.is_file():
        candidates = [target]
    else:
        candidates = [
            p for p in target.rglob("*")
            if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
        ]

    total = len(candidates)
    findings: list[Finding] = []

    for i, path in enumerate(candidates, start=1):
        stats.files_seen += 1
        surface = classify_file(path)
        if surface is None:
            stats.files_skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES and surface != "network":
                stats.files_skipped += 1
                continue
        except OSError:
            stats.files_skipped += 1
            continue

        if progress:
            progress(str(path), i, total)

        try:
            if surface == "python_source":
                got = scan_python_file(path)
                if not got:
                    # AST found nothing: either genuinely clean, or unparseable.
                    # Regex acts as the safety net for the second case.
                    got = scan_text_source(path, language="python")
            elif surface == "source":
                got = scan_text_source(path)
            elif surface == "config":
                got = scan_config_file(path)
            elif surface == "dependency":
                got = scan_dependency_file(path)
            elif surface == "network":
                if not include_pcap:
                    stats.files_skipped += 1
                    continue
                from .network_scanner import scan_pcap
                got = scan_pcap(path)
            else:
                got = []
        except Exception as exc:                       # noqa: BLE001
            stats.errors.append(f"{path}: {type(exc).__name__}: {exc}")
            continue

        stats.files_scanned += 1
        for f in got:
            stats.by_surface[f.surface] = stats.by_surface.get(f.surface, 0) + 1
        findings.extend(got)

    stats.elapsed_sec = time.perf_counter() - started
    return findings, stats
