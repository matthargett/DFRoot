from __future__ import annotations

import posixpath
import json
import re
import struct
from collections import Counter
from pathlib import Path, PurePosixPath

from .adb import Adb, output


POLICY_PATH = (
    Path(__file__).resolve().parents[2]
    / "app/src/main/assets/runtime-discovery-policy.json"
)


def _policy() -> dict[str, object]:
    policy = json.loads(POLICY_PATH.read_text())
    if policy.get("schema_version") != 1:
        raise ValueError("unsupported runtime discovery policy")
    return policy


_POLICY = _policy()

# These are deliberately structural.  A new system is searched using the same
# directory grammar and content tests; no build fingerprint or device name is
# involved in candidate selection.
PREFIXES = tuple(str(value) for value in _POLICY["prefixes"])
SUFFIXES = tuple(str(value) for value in _POLICY["suffixes"])
FILE_NAMES = tuple(str(value) for value in _POLICY["file_names"])
FIXED_EVIDENCE_PATHS = tuple(
    str(value) for value in _POLICY["fixed_evidence_paths"]
)
CONTENT_TERMS = tuple(str(value) for value in _POLICY["content_terms"])

SYMBOL_TERMS = (
    "basic_ostream",
    "sentry",
    "property_set",
    "finit_module",
    "init_module",
    "android::",
)

MODULE_ANCHORS = set(
    str(value) for value in _POLICY["module_relocation_anchors"]
)


def parse_elf64_relocations(
    raw: bytes, wanted: set[str]
) -> tuple[list[dict[str, object]], dict[str, dict[str, int]]]:
    """Return wanted ELF64 relocations and useful section file ranges."""
    if len(raw) < 64 or raw[:5] != b"\x7fELF\x02" or raw[5] != 1:
        return [], {}
    try:
        section_offset = struct.unpack_from("<Q", raw, 0x28)[0]
        section_size = struct.unpack_from("<H", raw, 0x3A)[0]
        section_count = struct.unpack_from("<H", raw, 0x3C)[0]
        section_names_index = struct.unpack_from("<H", raw, 0x3E)[0]
    except struct.error:
        return [], {}
    if section_size < 64 or section_count == 0:
        return [], {}

    sections: list[dict[str, int]] = []
    for index in range(section_count):
        offset = section_offset + index * section_size
        if offset + 64 > len(raw):
            return [], {}
        values = struct.unpack_from("<IIQQQQIIQQ", raw, offset)
        sections.append(
            {
                "name_offset": values[0],
                "type": values[1],
                "file_offset": values[4],
                "size": values[5],
                "link": values[6],
                "entry_size": values[9],
            }
        )
    if section_names_index >= len(sections):
        return [], {}

    def bytes_at(section: dict[str, int]) -> bytes:
        start = section["file_offset"]
        end = start + section["size"]
        return raw[start:end] if 0 <= start <= end <= len(raw) else b""

    def cstring(table: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(table):
            return ""
        end = table.find(b"\0", offset)
        if end < 0:
            end = len(table)
        return table[offset:end].decode(errors="replace")

    section_names = bytes_at(sections[section_names_index])
    for section in sections:
        section["name"] = cstring(section_names, section["name_offset"])

    useful = {
        str(section["name"]): {
            "file_offset": section["file_offset"],
            "size": section["size"],
        }
        for section in sections
        if section.get("name") in {
            ".text", ".init.text", ".exit.text", ".init_array", ".fini_array"
        }
    }
    relocations: list[dict[str, object]] = []
    for section in sections:
        if section["type"] not in {4, 9} or section["link"] >= len(sections):
            continue
        symtab = sections[section["link"]]
        if symtab["link"] >= len(sections):
            continue
        strings = bytes_at(sections[symtab["link"]])
        symbols = bytes_at(symtab)
        symbol_size = symtab["entry_size"] or 24
        entries = bytes_at(section)
        relocation_size = section["entry_size"] or (24 if section["type"] == 4 else 16)
        for offset in range(0, len(entries) - relocation_size + 1, relocation_size):
            relocation_offset, info = struct.unpack_from("<QQ", entries, offset)
            symbol_index = info >> 32
            symbol_offset = symbol_index * symbol_size
            if symbol_offset + 4 > len(symbols):
                continue
            name_offset = struct.unpack_from("<I", symbols, symbol_offset)[0]
            name = cstring(strings, name_offset)
            if name not in wanted:
                continue
            relocations.append(
                {
                    "section": section.get("name", ""),
                    "offset": relocation_offset,
                    "type": info & 0xFFFFFFFF,
                    "symbol": name,
                }
            )
    return relocations, useful


def candidate_directories(
    prefixes: tuple[str, ...] = PREFIXES,
    suffixes: tuple[str, ...] = SUFFIXES,
) -> list[str]:
    return sorted(
        {
            posixpath.normpath(posixpath.join(prefix, suffix))
            for prefix in prefixes
            for suffix in suffixes
        }
    )


def exact_candidate_paths(
    prefixes: tuple[str, ...] = PREFIXES,
    suffixes: tuple[str, ...] = SUFFIXES,
    names: tuple[str, ...] = FILE_NAMES,
) -> list[str]:
    return sorted(
        {
            posixpath.join(directory, name)
            for directory in candidate_directories(prefixes, suffixes)
            for name in names
        }
    )


def classify_path(path: str) -> str | None:
    name = PurePosixPath(path).name.lower()
    parts = PurePosixPath(path).parts
    if path in FIXED_EVIDENCE_PATHS:
        return "runtime_evidence"
    if path.startswith("/dev/"):
        return "device_node"
    if name.endswith(".ko"):
        return "kernel_module"
    if name.endswith(".rc") or name.endswith(".cfg") or name in {
        "modules.load", "modules.dep"
    }:
        return "boot_config"
    if name.endswith(".so") or ".so." in name:
        return "shared_library"
    if "bin" in parts or name in FILE_NAMES:
        return "executable"
    return None


def _visible_directories(adb: Adb) -> list[str]:
    quoted = " ".join(candidate_directories())
    script = f"for p in {quoted}; do [ -d \"$p\" ] && printf '%s\\n' \"$p\"; done"
    result = adb.script(script)
    return sorted(
        set(
            line.strip()
            for line in result.stdout.decode(errors="replace").splitlines()
            if line.startswith("/")
        )
    )


def _enumerate_paths(adb: Adb, directories: list[str], limit: int) -> list[str]:
    files = adb.files(tuple(directories), 1) if directories else []
    selected = {path for path in files if classify_path(path)}

    # APEX payloads are one level below their versioned mount.  Search only the
    # conventional payload directories and keep the same global bound.
    apex = adb.script(
        "for p in /apex/*/bin /apex/*/lib /apex/*/lib64 /apex/*/etc/init; do "
        "[ -d \"$p\" ] && find \"$p\" -maxdepth 1 -type f 2>/dev/null; done"
    )
    for line in apex.stdout.decode(errors="replace").splitlines():
        path = line.strip()
        if path.startswith("/") and classify_path(path):
            selected.add(path)

    # Exact names are checked even when a directory listing is restricted.
    exact = exact_candidate_paths()
    for start in range(0, len(exact), 200):
        batch = " ".join(exact[start:start + 200])
        result = adb.script(
            f"for p in {batch}; do [ -e \"$p\" ] && printf '%s\\n' \"$p\"; done"
        )
        selected.update(
            line.strip()
            for line in result.stdout.decode(errors="replace").splitlines()
            if line.startswith("/")
        )

    selected.update(
        path for path in FIXED_EVIDENCE_PATHS
        if adb.path(path).get("state") == "visible"
    )
    quotas = {
        "runtime_evidence": 16,
        "kernel_module": 48,
        "boot_config": 32,
        "executable": 24,
        "shared_library": 32,
        "device_node": 8,
    }
    grouped: dict[str, list[str]] = {}
    for path in selected:
        category = classify_path(path)
        if category:
            grouped.setdefault(category, []).append(path)
    chosen: list[str] = []
    for category, quota in quotas.items():
        chosen.extend(sorted(grouped.get(category, []), key=_priority)[:quota])
    if len(chosen) < limit:
        chosen_set = set(chosen)
        chosen.extend(
            path for path in sorted(selected, key=_priority)
            if path not in chosen_set
        )
    return chosen[:limit]


def _priority(path: str) -> tuple[int, str]:
    category = classify_path(path)
    rank = {
        "runtime_evidence": 0,
        "kernel_module": 1,
        "boot_config": 2,
        "executable": 3,
        "shared_library": 4,
        "device_node": 5,
    }.get(category, 9)
    name = PurePosixPath(path).name.lower()
    exact = 0 if name in FILE_NAMES else 1
    return rank * 10 + exact, path


def _probe(adb: Adb, path: str, category: str, kernel_release: str) -> dict[str, object]:
    metadata = adb.path(path)
    record: dict[str, object] = {
        "path": path,
        "category": category,
        "state": metadata.get("state"),
        "metadata": metadata.get("detail", ""),
    }
    if metadata.get("state") != "visible" or category == "device_node":
        return record

    file_result = adb.run("shell", "file", "-L", path)
    record["file"] = output(file_result)
    stat_result = adb.run("shell", "stat", "-c", "%s", path)
    stat_text = output(stat_result).strip()
    record["size"] = int(stat_text) if stat_text.isdigit() else None
    digest = adb.run("shell", "sha256sum", path)
    match = re.match(r"^([0-9a-fA-F]{64})\s", output(digest))
    if match:
        # This digest is evidence for the bytes just discovered.  It is never a
        # selector and is not part of the repository policy.
        record["integrity_sha256"] = match.group(1).lower()

    if category == "kernel_module":
        info = output(adb.run("shell", "modinfo", path))
        vermagic = re.search(r"^vermagic:[ \t]*(.+)$", info, re.M)
        depends = re.search(r"^depends:[ \t]*(.*)$", info, re.M)
        record["vermagic"] = vermagic.group(1).strip() if vermagic else None
        record["vermagic_matches_running_kernel"] = bool(
            vermagic and vermagic.group(1).split()[0] == kernel_release
        )
        record["depends"] = depends.group(1).strip() if depends else None

    if category in {"kernel_module", "shared_library", "executable"}:
        header = output(adb.run("shell", "readelf", "-h", path))
        record["elf64"] = "ELF64" in header
        record["aarch64"] = bool(re.search(r"Machine:\s*(AArch64|arm64)\b", header, re.I))
        terms = "|".join(CONTENT_TERMS)
        strings = adb.script(
            f"strings -a '{path}' 2>/dev/null | grep -E -i -m 32 '{terms}'"
        )
        hits = sorted(
            {
                term
                for line in strings.stdout.decode(errors="replace").splitlines()
                for term in CONTENT_TERMS
                if term.lower() in line.lower()
            }
        )
        record["content_terms"] = hits
        if category == "kernel_module":
            record["anchor_terms"] = sorted(set(hits) & MODULE_ANCHORS)
            if record["anchor_terms"]:
                byte_probe, raw = adb.read_bytes(path)
                if raw is not None:
                    relocations, sections = parse_elf64_relocations(raw, MODULE_ANCHORS)
                    record["relocations"] = relocations
                    record["relocation_anchors"] = sorted(
                        {str(item["symbol"]) for item in relocations}
                    )
                    record["sections"] = sections
                    record["integrity_sha256"] = byte_probe["sha256"]
                else:
                    record["relocation_probe"] = byte_probe
                    record["relocation_anchors"] = []
            else:
                record["relocation_anchors"] = []
        elif record["elf64"] and record["aarch64"]:
            terms = "|".join(SYMBOL_TERMS)
            symbols = adb.script(
                f"readelf -s '{path}' 2>/dev/null | grep -E -i -m 24 '{terms}'"
            )
            record["symbol_terms"] = sorted(
                term
                for line in symbols.stdout.decode(errors="replace").splitlines()
                for term in SYMBOL_TERMS
                if term.lower() in line.lower()
            )

    if category == "boot_config":
        terms = (
            "^[[:space:]]*(service|on|import)[[:space:]]|"
            "(^|[[:space:]|])(modprobe|insmod|ctl\\.(start|restart)|finit_module)"
            "([[:space:]|]|$)"
        )
        excerpt = adb.script(
            f"grep -E -i -m 40 '{terms}' '{path}' 2>/dev/null"
        )
        lines = [
            line.strip()
            for line in excerpt.stdout.decode(errors="replace").splitlines()
            if line.strip()
        ]
        found: set[str] = set()
        for line in lines:
            if re.match(r"^\s*service\s+", line, re.I):
                found.add("service")
            for term in ("modprobe", "insmod", "ctl.start", "ctl.restart"):
                if re.search(rf"(^|[\s|]){re.escape(term)}([\s|]|$)", line, re.I):
                    found.add(term)
        record["content_terms"] = sorted(found)
        record["excerpt"] = lines[:12]
        byte_probe, raw = adb.read_bytes(path)
        if raw is not None and len(raw) <= 1024 * 1024:
            windows: list[dict[str, object]] = []
            offset = 0
            for line in raw.splitlines(keepends=True):
                content = line.rstrip(b"\r\n")
                stripped = content.lstrip()
                if len(content) >= 32 and stripped and not stripped.startswith(b"#"):
                    verb = stripped.split(b"|", 1)[0].split(None, 1)[0]
                    windows.append(
                        {
                            "offset": offset,
                            "length": len(line),
                            "verb": verb.decode(errors="replace"),
                            "preview": content[:80].decode(errors="replace"),
                        }
                    )
                offset += len(line)
            record["replacement_windows"] = windows[:16]
            record["integrity_sha256"] = byte_probe["sha256"]
    return record


def _symbol_sources(adb: Adb) -> list[dict[str, object]]:
    sources: list[dict[str, object]] = []
    for path in ("/proc/kallsyms", "/sys/kernel/btf/vmlinux"):
        probe = adb.path(path)
        item: dict[str, object] = {
            "path": path,
            "kind": "symbol_addresses" if path == "/proc/kallsyms" else "type_layout",
            "state": probe.get("state"),
        }
        if probe.get("state") == "visible":
            read = adb.run("exec-out", "dd", f"if={path}", "bs=4096", "count=1")
            item["readable"] = read.returncode == 0 and bool(read.stdout)
            if path == "/proc/kallsyms" and item["readable"]:
                text = read.stdout.decode(errors="replace")
                addresses = [
                    int(match.group(1), 16)
                    for match in re.finditer(r"^([0-9a-fA-F]+)\s", text, re.M)
                ]
                wanted = "|".join(sorted(MODULE_ANCHORS))
                matches = adb.script(
                    f"grep -E ' ({wanted})$' /proc/kallsyms 2>/dev/null | head -n 64"
                )
                item["symbols"] = [
                    line.strip()
                    for line in matches.stdout.decode(errors="replace").splitlines()
                    if re.match(r"^[0-9a-fA-F]+\s", line)
                ]
                selected_addresses = [
                    int(str(line).split()[0], 16) for line in item["symbols"]
                ]
                item["addresses_redacted"] = (
                    not selected_addresses or all(value == 0 for value in selected_addresses)
                )
                item["usable"] = not item["addresses_redacted"]
            elif path == "/sys/kernel/btf/vmlinux":
                item["usable"] = bool(item["readable"])
        sources.append(item)

    sections = adb.script(
        "for p in $(find /sys/module -path '*/sections/*' -type f -readable 2>/dev/null | head -n 32); do "
        "printf '%s=' \"$p\"; cat \"$p\" 2>/dev/null; done"
    )
    section_values = [
        line.strip()
        for line in sections.stdout.decode(errors="replace").splitlines()
        if re.match(r"^/[^=]+=0x[0-9a-fA-F]+$", line.strip())
    ]
    section_addresses = [
        int(line.rsplit("=", 1)[1], 16) for line in section_values
    ]
    sources.append(
        {
            "path": "/sys/module/*/sections/*",
            "kind": "module_addresses",
            "state": "visible" if section_values else "unavailable",
            "readable_count_sample": len(section_values),
            "addresses_redacted": not section_addresses or all(
                value == 0 for value in section_addresses
            ),
            "usable": bool(section_addresses) and any(
                value != 0 for value in section_addresses
            ),
            "values": section_values,
        }
    )
    return sources


def build_probe_plan(discovery: dict[str, object], runtime: dict[str, object]) -> dict[str, object]:
    candidates = discovery.get("candidates", [])
    assert isinstance(candidates, list)
    by_category: dict[str, list[dict[str, object]]] = {}
    for item in candidates:
        if isinstance(item, dict):
            by_category.setdefault(str(item.get("category")), []).append(item)

    modules = by_category.get("kernel_module", [])
    exact_modules = [m for m in modules if m.get("vermagic_matches_running_kernel")]
    anchored_modules = [m for m in exact_modules if m.get("relocation_anchors")]
    carrier_modules = [
        module for module in anchored_modules
        if module.get("sections", {}).get(".init.text")
        and any(
            str(item.get("section")) == ".rela.init.text"
            for item in module.get("relocations", [])
            if isinstance(item, dict)
        )
    ]
    configs = [c for c in by_category.get("boot_config", []) if c.get("content_terms")]
    loaders = [
        c for c in by_category.get("executable", [])
        if PurePosixPath(str(c.get("path"))).name in {"insmod", "modprobe"}
    ]
    symbols = discovery.get("symbol_sources", [])
    assert isinstance(symbols, list)
    address_sources = [
        source for source in symbols
        if isinstance(source, dict)
        and source.get("kind") in {"symbol_addresses", "module_addresses"}
        and source.get("usable")
    ]
    type_sources = [
        source for source in symbols
        if isinstance(source, dict)
        and source.get("kind") == "type_layout"
        and source.get("usable")
    ]
    module_examples = [
        {
            "path": module.get("path"),
            "size": module.get("size"),
            "depends": module.get("depends"),
            "vermagic": module.get("vermagic"),
            "relocations": module.get("relocations", [])[:8],
            "sections": module.get("sections", {}),
        }
        for module in sorted(
            carrier_modules,
            key=lambda item: (
                len([part for part in str(item.get("depends") or "").split(",") if part]),
                int(item.get("size") or 1 << 62),
                str(item.get("path")),
            ),
        )[:5]
    ]
    config_examples = [
        {
            "path": config.get("path"),
            "size": config.get("size"),
            "terms": config.get("content_terms", []),
            "replacement_windows": config.get("replacement_windows", []),
        }
        for config in sorted(
            configs,
            key=lambda item: (
                0 if "modprobe" in item.get("content_terms", []) else 1,
                str(item.get("path")),
            ),
        )[:5]
    ]

    steps: list[dict[str, object]] = [
        {
            "id": "runtime_inventory",
            "state": "proved",
            "safety": "read_only",
            "evidence": f"{len(candidates)} structurally classified candidates",
        },
        {
            "id": "scratch_write_restore",
            "state": "needed",
            "safety": "reversible_scratch_write",
            "evidence": "presence of XFRM and filemap interfaces is not a vulnerability proof",
            "requires": ["write only an app-owned scratch inode", "read back exact bytes", "restore and verify the original digest"],
        },
        {
            "id": "module_carrier_analysis",
            "state": "ready" if carrier_modules else "ambiguous",
            "safety": "read_only",
            "evidence": f"exact_vermagic={len(exact_modules)} relocation_anchor_candidates={len(anchored_modules)} init_section_candidates={len(carrier_modules)} loaders={len(loaders)} configs={len(configs)}",
            "requires": [] if carrier_modules else ["an exact-vermagic module with a usable imported relocation anchor in an init section"],
            "candidates": module_examples,
        },
        {
            "id": "kernel_symbol_resolution",
            "state": "ready" if address_sources else "ambiguous",
            "safety": "read_only",
            "evidence": (
                "addresses=" + (
                    ",".join(str(source.get("path")) for source in address_sources)
                    or "none"
                ) + "; type_layout=" + (
                    ",".join(str(source.get("path")) for source in type_sources)
                    or "none"
                )
            ),
            "requires": [] if address_sources else [
                "unredacted kernel or module addresses, or an offline exact kernel image with symbols"
            ],
            "sources": symbols,
        },
        {
            "id": "privileged_trigger_analysis",
            "state": "ready" if configs and by_category.get("shared_library") else "ambiguous",
            "safety": "read_only",
            "evidence": f"configs={len(configs)} shared_libraries={len(by_category.get('shared_library', []))}",
            "requires": [] if configs else ["a runtime service or property trigger parsed from boot configuration"],
            "candidates": config_examples,
        },
    ]

    if int(runtime.get("uid", -1)) == 0:
        next_probe = "preserve_current_root_evidence"
        reason = "ADB is already UID 0; do not rerun a live exploit on this boot"
    else:
        next_item = next((step for step in steps if step["state"] in {"needed", "ready"} and step["id"] != "runtime_inventory"), None)
        next_probe = str(next_item["id"]) if next_item else "collect_missing_evidence"
        reason = str(next_item.get("evidence", "")) if next_item else "no safe derived step is ready"

    return {
        "next_probe": next_probe,
        "reason": reason,
        "live_exploit_state": "blocked_until_invariants_proved",
        "steps": steps,
    }


def collect_runtime_discovery(
    adb: Adb,
    kernel_release: str,
    runtime: dict[str, object],
    limit: int = 160,
) -> dict[str, object]:
    directories = _visible_directories(adb)
    paths = _enumerate_paths(adb, directories, limit)
    candidates = [
        _probe(adb, path, category, kernel_release)
        for path in paths
        if (category := classify_path(path)) is not None
    ]
    counts = Counter(str(item["category"]) for item in candidates)
    discovery: dict[str, object] = {
        "selection": "runtime_structure_and_content",
        "visibility_uid": runtime.get("uid"),
        "visibility_context": runtime.get("context"),
        "candidate_limit": limit,
        "visible_directories": directories,
        "candidate_counts": dict(sorted(counts.items())),
        "candidates": candidates,
        "symbol_sources": _symbol_sources(adb),
    }
    discovery["probe_plan"] = build_probe_plan(discovery, runtime)
    return discovery
