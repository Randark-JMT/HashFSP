from __future__ import annotations

import ntpath


ROOT = "\\"


def normalize_mount_path(file_name: str) -> str:
    raw = str(file_name or "").replace("/", "\\").strip()
    if raw in {"", "\\", "."}:
        return ROOT

    if not raw.startswith("\\"):
        raw = "\\" + raw

    parts: list[str] = []
    for part in raw.split("\\"):
        if part in {"", "."}:
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)

    if not parts:
        return ROOT
    return "\\" + "\\".join(parts)


def parent_and_name(path: str) -> tuple[str, str]:
    path = normalize_mount_path(path)
    if path == ROOT:
        return ROOT, ""

    parent = ntpath.dirname(path) or ROOT
    if parent == "":
        parent = ROOT
    return normalize_mount_path(parent), ntpath.basename(path)


def join_child(parent: str, child: str) -> str:
    parent = normalize_mount_path(parent)
    child = child.replace("/", "\\").strip("\\")
    if parent == ROOT:
        return normalize_mount_path("\\" + child)
    return normalize_mount_path(parent + "\\" + child)


def wildcard_for_directory(path: str) -> str:
    path = normalize_mount_path(path)
    if path == ROOT:
        return "\\*"
    return path.rstrip("\\") + "\\*"
