from __future__ import annotations
import gzip
import hashlib
import re


CONFIG_KEYS = (
    "XFRM",
    "INET_ESP",
    "MODULES",
    "MODULE_UNLOAD",
    "MODVERSIONS",
    "MODULE_SIG",
    "MODULE_SIG_FORCE",
    "KALLSYMS",
    "KALLSYMS_ALL",
    "PERF_EVENTS",
    "HW_PERF_EVENTS",
    "ARM_PMU",
    "UNMAP_KERNEL_AT_EL0",
    "RANDOMIZE_BASE",
    "DEBUG_RODATA",
    "STRICT_KERNEL_RWX",
    "STRICT_MODULE_RWX",
    "SECURITY_SELINUX",
    "SECURITY_SELINUX_DEVELOP",
    "KPROBES",
    "DEVMEM",
    "DEVKMEM",
    "RKP",
    "KDIUP",
)

CPU_EVENT_CANDIDATES = {
    "cycles": ("cpu-cycles", "raw-cpu-cycles"),
    "instructions": ("instructions", "raw-inst-retired"),
    "l1d_access": ("L1-dcache-loads", "raw-l1-dcache", "cache-references"),
    "l1d_refill": ("L1-dcache-load-misses", "raw-l1-dcache-refill", "cache-misses"),
    "branches": ("branch-instructions", "branches", "raw-br-pred"),
    "branch_misses": ("branch-misses", "raw-br-mis-pred"),
}

CPU_EVENT_GROUPS = (
    ("core", ("cycles", "instructions")),
    ("cache", ("l1d_access", "l1d_refill")),
    ("branch", ("branches", "branch_misses")),
)


def parse_config(raw: bytes | None) -> dict[str, str] | None:
    if raw is None:
        return None
    try:
        text = gzip.decompress(raw).decode(errors="replace")
    except (gzip.BadGzipFile, EOFError):
        return None
    options = {key: "not_declared" for key in CONFIG_KEYS}
    for line in text.splitlines():
        enabled = re.fullmatch(r"CONFIG_([A-Z0-9_]+)=(.+)", line)
        disabled = re.fullmatch(r"# CONFIG_([A-Z0-9_]+) is not set", line)
        if enabled and enabled.group(1) in options:
            options[enabled.group(1)] = enabled.group(2)
        elif disabled and disabled.group(1) in options:
            options[disabled.group(1)] = "n"
    return options

def parse_zoneinfo(probe: dict[str, object]) -> dict[str, object]:
    if probe["state"] != "readable":
        return {"state": probe["state"], "detail": probe.get("detail")}
    zones: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for raw in str(probe["text"]).splitlines():
        zone = re.fullmatch(r"Node\s+(\d+),\s+zone\s+(.+)", raw.strip())
        if zone:
            current = {"node": int(zone.group(1)), "name": zone.group(2).strip()}
            zones.append(current)
            continue
        value = re.fullmatch(
            r"(start_pfn|spanned|present|managed)\s*:?\s*(\d+)", raw.strip()
        )
        if current is not None and value:
            current[value.group(1)] = int(value.group(2))
    populated = [
        zone for zone in zones if int(zone.get("spanned", 0)) > 0 and "start_pfn" in zone
    ]
    if not populated:
        return {"state": "invalid", "zones": zones, "detail": "no populated zones"}
    start = min(int(zone["start_pfn"]) for zone in populated)
    end = max(int(zone["start_pfn"]) + int(zone["spanned"]) for zone in populated)
    present = sum(int(zone.get("present", 0)) for zone in populated)
    spanned = sum(int(zone.get("spanned", 0)) for zone in populated)
    return {
        "state": "measured",
        "start": start,
        "end": end,
        "present_pages": present,
        "spanned_pages": spanned,
        "sparse": present < spanned,
        "zones": populated,
    }

def parse_iomem(probe: dict[str, object]) -> dict[str, object]:
    if probe["state"] != "readable":
        return {"state": probe["state"], "detail": probe.get("detail")}
    ranges: list[dict[str, object]] = []
    for raw in str(probe["text"]).splitlines():
        match = re.fullmatch(r"(\s*)([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.+)", raw)
        if not match or match.group(4).strip() != "System RAM":
            continue
        start = int(match.group(2), 16)
        end = int(match.group(3), 16) + 1
        if start == 0 and end <= 1:
            continue
        ranges.append(
            {
                "start": start,
                "end": end,
                "start_pfn": start // 4096,
                "end_pfn": (end + 4095) // 4096,
                "bytes": end - start,
                "indent": len(match.group(1)),
            }
        )
    if not ranges:
        state = "redacted" if "00000000-00000000" in str(probe["text"]) else "unavailable"
        return {"state": state, "ranges": []}
    return {
        "state": "measured",
        "ranges": ranges,
        "bytes": sum(int(item["bytes"]) for item in ranges),
    }

def merge_memory_blocks(indices: list[int], block_size: int) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    for index in sorted(set(indices)):
        start = index * block_size
        end = start + block_size
        if ranges and ranges[-1]["end"] == start:
            ranges[-1]["end"] = end
            ranges[-1]["end_pfn"] = end // 4096
        else:
            ranges.append(
                {
                    "start": start,
                    "end": end,
                    "start_pfn": start // 4096,
                    "end_pfn": end // 4096,
                }
            )
    return ranges

def canonical_identity_sha256(
    fingerprint: str, incremental: str, security_patch: str, kernel_release: str
) -> str:
    canonical = "\n".join(
        (fingerprint, incremental, security_patch, kernel_release)
    ) + "\n"
    return hashlib.sha256(canonical.encode()).hexdigest()

def parse_kmi(release: str) -> str | None:
    match = re.search(r"android(\d+)-(\d+\.\d+)", release)
    return f"android{match.group(1)}-{match.group(2)}" if match else None

def value(probe: dict[str, object]) -> str | None:
    if probe.get("state") != "readable":
        return None
    return str(probe.get("text", "")).strip()

def advertised_events(detail: str) -> set[str]:
    return {
        line.strip().split()[0]
        for line in detail.splitlines()
        if line.strip()
    }

def choose_cpu_events(available: set[str]) -> tuple[dict[str, str], list[str]]:
    selected: dict[str, str] = {}
    missing: list[str] = []
    for metric, candidates in CPU_EVENT_CANDIDATES.items():
        event = next((candidate for candidate in candidates if candidate in available), None)
        if event is None:
            missing.append(metric)
        else:
            selected[metric] = event
    return selected, missing

def parse_event_counts(detail: str, selected: dict[str, str]) -> dict[str, int]:
    by_event = {event: metric for metric, event in selected.items()}
    counts: dict[str, int] = {}
    for line in detail.splitlines():
        columns = line.strip().split()
        if len(columns) < 2 or columns[1] not in by_event:
            continue
        try:
            counts[by_event[columns[1]]] = int(columns[0].replace(",", ""))
        except ValueError:
            continue
    return counts

def hex_range(physical: dict[str, object]) -> str:
    if physical.get("state") != "measured":
        return str(physical.get("state"))
    return f"[{int(physical['start']):#x},{int(physical['end']):#x})"

def byte_range(item: dict[str, object]) -> str:
    return f"[{int(item['start']):#x},{int(item['end']):#x})"

def format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f}MiB"
    return f"{size / 1024:.1f}KiB"
