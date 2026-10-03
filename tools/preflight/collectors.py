from __future__ import annotations
import re
from pathlib import Path

from .adb import Adb, output
from .discovery import collect_runtime_discovery
from .parsers import (
    CPU_EVENT_GROUPS,
    advertised_events,
    choose_cpu_events,
    merge_memory_blocks,
    parse_config,
    parse_event_counts,
    parse_iomem,
    parse_kmi,
    parse_zoneinfo,
    value,
)

ROOT = Path(__file__).resolve().parents[2]


def collect_memory(adb: Adb) -> dict[str, object]:
    memory = parse_zoneinfo(adb.read("/proc/zoneinfo"))
    memory["iomem"] = parse_iomem(adb.read("/proc/iomem"))
    block_size_probe = adb.read("/sys/devices/system/memory/block_size_bytes")
    block_size_text = value(block_size_probe)
    block_size = int(block_size_text, 16) if block_size_text else None
    states = adb.script(
        "for f in /sys/devices/system/memory/memory*/state; do "
        "n=${f%/state}; n=${n##*memory}; printf '%s %s\\n' \"$n\" \"$(cat \"$f\" 2>/dev/null)\"; done",
    )
    online = []
    for line in states.stdout.decode(errors="replace").splitlines():
        match = re.fullmatch(r"(\d+)\s+online", line.strip())
        if match:
            online.append(int(match.group(1)))
    memory["sysfs"] = {
        "state": "measured" if block_size and online else "unavailable",
        "block_size": block_size,
        "online_blocks": online,
        "ranges": merge_memory_blocks(online, block_size) if block_size else [],
    }
    return memory

def collect_identity(adb: Adb) -> dict[str, object]:
    release = adb.text("shell", "uname", "-r")
    version = adb.text("shell", "uname", "-v")
    return {
        "serial": adb.serial,
        "model": adb.property("ro.product.model"),
        "device": adb.property("ro.product.device"),
        "board": adb.property("ro.board.platform"),
        "soc_manufacturer": adb.property("ro.soc.manufacturer"),
        "soc_model": adb.property("ro.soc.model"),
        "egl_hardware": adb.property("ro.hardware.egl"),
        "vulkan_hardware": adb.property("ro.hardware.vulkan"),
        "fingerprint": adb.property("ro.build.fingerprint"),
        "incremental": adb.property("ro.build.version.incremental"),
        "security_patch": adb.property("ro.build.version.security_patch"),
        "android": adb.property("ro.build.version.release"),
        "api": int(adb.property("ro.build.version.sdk")),
        "kernel_release": release,
        "kernel_version": version,
        "kmi": parse_kmi(release),
    }

def status_fields(probe: dict[str, object]) -> dict[str, str | None]:
    text = str(probe.get("text", ""))
    names = ("Uid", "Gid", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
             "NoNewPrivs", "Seccomp", "Seccomp_filters")
    return {
        name: (match.group(1).strip() if (match := re.search(
            rf"^{name}:\s*(.+)$", text, re.M
        )) else None)
        for name in names
    }

def collect_process(adb: Adb, name: str) -> dict[str, object]:
    pid_result = adb.run("shell", "pidof", name)
    pids = re.findall(r"\d+", pid_result.stdout.decode(errors="replace"))
    if not pids:
        return {"state": "absent", "name": name}
    pid = pids[0]
    status = adb.read(f"/proc/{pid}/status")
    context = value(adb.read(f"/proc/{pid}/attr/current"))
    command = adb.read(f"/proc/{pid}/cmdline")
    command_text = value(command)
    return {
        "state": "measured" if status.get("state") == "readable" else status["state"],
        "name": name,
        "pid": int(pid),
        "status": status_fields(status),
        "context": context.replace("\x00", "") if context else None,
        "command": command_text.replace("\x00", " ").strip() if command_text else None,
    }

def collect_runtime(adb: Adb) -> dict[str, object]:
    identity = adb.text("shell", "id")
    context = adb.text("shell", "id", "-Z").removeprefix("context=")
    status = adb.read("/proc/self/status")
    uid = re.search(r"uid=(\d+)", identity)
    fields = status_fields(status)
    return {
        "id": identity,
        "uid": int(uid.group(1)) if uid else None,
        "context": context,
        "selinux": adb.text("shell", "getenforce"),
        "seccomp": fields["Seccomp"],
        "no_new_privs": fields["NoNewPrivs"],
        "cap_eff": fields["CapEff"],
        "perf_event_paranoid": value(adb.read("/proc/sys/kernel/perf_event_paranoid")),
        "perf_harden": adb.property("security.perf_harden"),
        "adbd": collect_process(adb, "adbd"),
        "ro_secure": adb.property("ro.secure"),
        "ro_debuggable": adb.property("ro.debuggable"),
        "verified_boot": adb.property("ro.boot.verifiedbootstate"),
        "bootloader_state": adb.property("ro.boot.vbmeta.device_state"),
    }

def collect_repository() -> dict[str, object]:
    gradle = (ROOT / "app/build.gradle.kts").read_text()
    minimum = re.search(r"\bminSdk\s*=\s*(\d+)", gradle)
    modules = sorted(path.name for path in (ROOT / "app/src/main/jni/ko").glob("*.ko"))
    return {
        "min_api": int(minimum.group(1)) if minimum else None,
        "modules": modules,
    }

def collect_module_state(adb: Adb, config: dict[str, str] | None) -> dict[str, object]:
    loaded = adb.read("/proc/modules")
    module_roots = (
        "/vendor_dlkm/lib/modules",
        "/odm_dlkm/lib/modules",
        "/vendor/lib/modules",
        "/odm/lib/modules",
        "/system_dlkm/lib/modules",
        "/system/lib/modules",
    )
    module_files = [
        path for path in adb.files(module_roots, 1) if path.endswith(".ko")
    ]
    sample = module_files[0] if module_files else None
    vermagic = None
    if sample:
        info = output(adb.run("shell", "modinfo", sample))
        match = re.search(r"^vermagic:\s*(.+)$", info, re.M)
        vermagic = match.group(1).strip() if match else None
    return {
        "config": config,
        "modules_disabled": value(adb.read("/proc/sys/kernel/modules_disabled")),
        "loaded": str(loaded.get("text", "")).splitlines()
        if loaded.get("state") == "readable"
        else None,
        "loaders": {
            path: adb.path(path)
            for path in (
                "/system/bin/insmod",
                "/vendor/bin/insmod",
                "/system/bin/modprobe",
                "/vendor/bin/modprobe",
            )
        },
        "shipped": {
            "roots": sorted({str(Path(path).parent) for path in module_files}),
            "count": len(module_files),
            "sample": sample,
            "sample_vermagic": vermagic,
        },
    }

def collect_exploit_primitives(adb: Adb) -> dict[str, object]:
    paths = (
        "/dev/ion",
        "/dev/dma_heap/system",
        "/sys/kernel/tracing/events/filemap",
        "/sys/kernel/tracing/events/filemap/mm_filemap_add_to_page_cache/id",
        "/sys/kernel/tracing/events/filemap/mm_filemap_delete_from_page_cache/id",
        "/vendor/etc/init.insmod.cfg",
        "/system/lib64/libandroid_servers.so",
    )
    return {
        "paths": {path: adb.path(path) for path in paths},
        "kptr_restrict": value(adb.read("/proc/sys/kernel/kptr_restrict")),
        "dmesg_restrict": value(adb.read("/proc/sys/kernel/dmesg_restrict")),
        "unprivileged_userfaultfd": value(
            adb.read("/proc/sys/vm/unprivileged_userfaultfd")
        ),
        "unprivileged_bpf_disabled": value(
            adb.read("/proc/sys/kernel/unprivileged_bpf_disabled")
        ),
        "xfrm_stats": adb.path("/proc/net/xfrm_stat"),
    }

def collect_graphics(adb: Adb) -> dict[str, object]:
    features = adb.text("shell", "pm", "list", "features").splitlines()
    surface = adb.run("shell", "dumpsys", "SurfaceFlinger")
    gles = next(
        (line.strip() for line in output(surface).splitlines() if "GLES:" in line), None
    )
    executable_roots = (
        "/system/bin",
        "/system_ext/bin",
        "/vendor/bin",
        "/product/bin",
        "/odm/bin",
    )
    library_roots = (
        "/vendor/lib64",
        "/system/lib64",
        "/system_ext/lib64",
        "/product/lib64",
        "/odm/lib64",
    )
    executable_files = adb.files(executable_roots, 1)
    tool_paths = [
        path for path in executable_files
        if Path(path).name in {"simpleperf", "perfetto"}
        or re.search(r"(gpu|perf|trace|vulkan|render|adreno)", Path(path).name, re.I)
    ]
    library_files = adb.files(library_roots, 2)
    driver_paths = [
        path for path in library_files
        if path.endswith(".so") and (
            Path(path).name.startswith("vulkan.")
            or Path(path).name.startswith("libvulkan")
            or Path(path).name.startswith("libVkLayer")
            or "adreno" in Path(path).name.lower()
        )
    ]
    perfetto = next(
        (path for path in tool_paths if Path(path).name == "perfetto"), None
    )
    perfetto_query = output(adb.run("shell", perfetto, "--query")) if perfetto else ""
    gpu_sources = sorted(set(re.findall(r"^(gpu\.[^\s]+)", perfetto_query, re.M)))
    services = output(adb.run("shell", "service", "list"))
    return {
        "kgsl": adb.path("/dev/kgsl-3d0"),
        "gpu_model": value(adb.read("/sys/class/kgsl/kgsl-3d0/gpu_model")),
        "gpu_frequencies": value(
            adb.read("/sys/class/kgsl/kgsl-3d0/gpu_available_frequencies")
        ),
        "gpu_busy": value(adb.read("/sys/class/kgsl/kgsl-3d0/gpubusy")),
        "gles": gles,
        "features": [
            line for line in features if "vulkan" in line.lower() or "opengles" in line.lower()
        ],
        "tools": {path: adb.path(path) for path in tool_paths},
        "drivers": {path: adb.path(path, digest=True) for path in driver_paths},
        "perfetto_gpu_sources": gpu_sources,
        "services": [line for line in services.splitlines() if "gpu" in line.lower()],
    }

def collect_live_cpu(adb: Adb, enabled: bool) -> dict[str, object]:
    if not enabled:
        return {"state": "not_requested"}
    event_list = adb.run("shell", "simpleperf", "list")
    event_detail = output(event_list)
    if event_list.returncode:
        return {
            "state": "failed",
            "phase": "event_discovery",
            "exit": event_list.returncode,
            "detail": event_detail,
        }
    selected, missing = choose_cpu_events(advertised_events(event_detail))
    if not {"cycles", "instructions"}.issubset(selected):
        return {
            "state": "unsupported",
            "phase": "event_selection",
            "selected": selected,
            "missing": missing,
            "detail": "simpleperf did not advertise both cycle and instruction events",
        }
    groups: list[dict[str, object]] = []
    counts: dict[str, int] = {}
    details: list[str] = []
    for name, metrics in CPU_EVENT_GROUPS:
        events = {metric: selected[metric] for metric in metrics if metric in selected}
        if not events:
            continue
        result = adb.run(
            "shell", "simpleperf", "stat", "-a", "--duration", "0.25",
            "-e", ",".join(events.values()),
        )
        detail = output(result)
        counts.update(parse_event_counts(detail, events))
        groups.append(
            {
                "name": name,
                "events": list(events.values()),
                "exit": result.returncode,
                "detail": detail,
            }
        )
        details.append(f"[{name}]\n{detail}")
    measured = all(group["exit"] == 0 for group in groups) and all(
        counts.get(metric, 0) > 0 for metric in ("cycles", "instructions")
    )
    return {
        "state": "measured" if measured else "failed",
        "phase": "measurement",
        "exit": 0 if measured else next(
            (int(group["exit"]) for group in groups if group["exit"] != 0), 1
        ),
        "selected": selected,
        "missing": missing,
        "counts": counts,
        "groups": groups,
        "detail": "\n".join(details),
    }

def collect(serial: str, timeout: int, live_cpu: bool) -> dict[str, object]:
    adb = Adb(serial, timeout)
    config_probe, config_raw = adb.read_bytes("/proc/config.gz")
    config = parse_config(config_raw)
    identity = collect_identity(adb)
    runtime = collect_runtime(adb)
    snapshot = {
        "identity": identity,
        "runtime": runtime,
        "repository": collect_repository(),
        "config_probe": config_probe,
        "config": config,
        "physical_memory": collect_memory(adb),
        "modules": collect_module_state(adb, config),
        "exploit_primitives": collect_exploit_primitives(adb),
        "graphics": collect_graphics(adb),
        "live_cpu": collect_live_cpu(adb, live_cpu),
    }
    snapshot["runtime_discovery"] = collect_runtime_discovery(
        adb, str(identity["kernel_release"]), runtime
    )
    return snapshot
