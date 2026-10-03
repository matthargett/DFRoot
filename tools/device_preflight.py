#!/usr/bin/env python3
"""Read-only exploitation and profiling preflight for an ADB Android device."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
DIRECT_TARGETS = ROOT / "app/src/main/assets/direct-kernel-targets.json"


@dataclass(frozen=True)
class Finding:
    state: str
    topic: str
    observed: str
    next_step: str | None = None


@dataclass(frozen=True)
class Report:
    verdict: str
    snapshot: dict[str, object]
    findings: list[Finding]


class Adb:
    def __init__(self, serial: str, timeout: int) -> None:
        self.serial = serial
        self.timeout = timeout

    def run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["adb", "-s", self.serial, *args],
            capture_output=True,
            check=False,
            timeout=self.timeout,
        )

    def text(self, *args: str) -> str:
        result = self.run(*args)
        if result.returncode:
            raise RuntimeError(output(result) or f"command exited {result.returncode}")
        return result.stdout.decode(errors="replace").strip()

    def property(self, name: str) -> str:
        return self.text("shell", "getprop", name)

    def read(self, path: str) -> dict[str, object]:
        result = self.run("exec-out", "cat", path)
        if result.returncode:
            detail = output(result)
            return {"state": classify_error(detail), "detail": detail}
        return {
            "state": "readable",
            "text": result.stdout.decode(errors="replace"),
            "size": len(result.stdout),
            "sha256": hashlib.sha256(result.stdout).hexdigest(),
        }

    def read_bytes(self, path: str) -> tuple[dict[str, object], bytes | None]:
        result = self.run("exec-out", "cat", path)
        if result.returncode:
            detail = output(result)
            return {"state": classify_error(detail), "detail": detail}, None
        return {
            "state": "readable",
            "size": len(result.stdout),
            "sha256": hashlib.sha256(result.stdout).hexdigest(),
        }, result.stdout

    def path(self, path: str) -> dict[str, object]:
        result = self.run("shell", "ls", "-ldZ", path)
        detail = output(result)
        if result.returncode:
            return {"state": classify_error(detail), "path": path, "detail": detail}
        return {"state": "visible", "path": path, "detail": detail}


def output(result: subprocess.CompletedProcess[bytes]) -> str:
    return "\n".join(
        stream.decode(errors="replace").strip()
        for stream in (result.stdout, result.stderr)
        if stream.strip()
    )


def classify_error(detail: str) -> str:
    lowered = detail.lower()
    if "permission denied" in lowered or "operation not permitted" in lowered:
        return "permission_denied"
    if "no such file" in lowered or "not found" in lowered:
        return "absent"
    return "probe_failed"


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
    return {"state": "measured", "start": start, "end": end, "zones": populated}


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


def parse_kmi(release: str) -> str | None:
    match = re.search(r"android(\d+)-(\d+\.\d+)", release)
    return f"android{match.group(1)}-{match.group(2)}" if match else None


def collect_runtime(adb: Adb) -> dict[str, object]:
    identity = adb.text("shell", "id")
    context = adb.text("shell", "id", "-Z").removeprefix("context=")
    status = adb.read("/proc/self/status")
    uid = re.search(r"uid=(\d+)", identity)
    status_text = str(status.get("text", ""))
    scalar = lambda name: (re.search(rf"^{name}:\s*(.+)$", status_text, re.M) or [None, None])[1]
    return {
        "id": identity,
        "uid": int(uid.group(1)) if uid else None,
        "context": context,
        "selinux": adb.text("shell", "getenforce"),
        "seccomp": scalar("Seccomp"),
        "no_new_privs": scalar("NoNewPrivs"),
        "perf_event_paranoid": value(adb.read("/proc/sys/kernel/perf_event_paranoid")),
        "perf_harden": adb.property("security.perf_harden"),
    }


def value(probe: dict[str, object]) -> str | None:
    if probe.get("state") != "readable":
        return None
    return str(probe.get("text", "")).strip()


def collect_repository() -> dict[str, object]:
    gradle = (ROOT / "app/build.gradle.kts").read_text()
    minimum = re.search(r"\bminSdk\s*=\s*(\d+)", gradle)
    modules = sorted(path.name for path in (ROOT / "app/src/main/jni/ko").glob("*.ko"))
    targets = json.loads(DIRECT_TARGETS.read_text()).get("targets", [])
    return {
        "min_api": int(minimum.group(1)) if minimum else None,
        "modules": modules,
        "direct_targets": targets,
    }


def collect_module_state(adb: Adb, config: dict[str, str] | None) -> dict[str, object]:
    loaded = adb.read("/proc/modules")
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
    }


def collect_graphics(adb: Adb) -> dict[str, object]:
    board = adb.property("ro.board.platform")
    features = adb.text("shell", "pm", "list", "features").splitlines()
    surface = adb.run("shell", "dumpsys", "SurfaceFlinger")
    gles = next(
        (line.strip() for line in output(surface).splitlines() if "GLES:" in line), None
    )
    tool_paths = (
        "/system/bin/simpleperf",
        "/system/bin/perfetto",
        "/system/bin/gpuprofserver",
        "/system/bin/ovrgpuprofiler",
        "/system/bin/gprobe",
    )
    driver_paths = (
        f"/vendor/lib64/hw/vulkan.{board}.so",
        "/vendor/lib64/egl/libGLESv2_adreno.so",
    )
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
        "drivers": {path: adb.path(path) for path in driver_paths},
        "services": [line for line in services.splitlines() if "gpu" in line.lower()],
    }


CPU_EVENT_CANDIDATES = {
    "cycles": ("cpu-cycles", "raw-cpu-cycles"),
    "instructions": ("instructions", "raw-inst-retired"),
    "l1d_access": ("L1-dcache-loads", "raw-l1-dcache", "cache-references"),
    "l1d_refill": ("L1-dcache-load-misses", "raw-l1-dcache-refill", "cache-misses"),
    "branches": ("branch-instructions", "branches", "raw-br-pred"),
    "branch_misses": ("branch-misses", "raw-br-mis-pred"),
}


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
    result = adb.run(
        "shell",
        "simpleperf",
        "stat",
        "-a",
        "--duration",
        "0.25",
        "-e",
        ",".join(selected.values()),
    )
    detail = output(result)
    counts = parse_event_counts(detail, selected)
    measured = result.returncode == 0 and all(
        counts.get(metric, 0) > 0 for metric in ("cycles", "instructions")
    )
    return {
        "state": "measured" if measured else "failed",
        "phase": "measurement",
        "exit": result.returncode,
        "selected": selected,
        "missing": missing,
        "counts": counts,
        "detail": detail,
    }


def collect(serial: str, timeout: int, live_cpu: bool) -> dict[str, object]:
    adb = Adb(serial, timeout)
    config_probe, config_raw = adb.read_bytes("/proc/config.gz")
    config = parse_config(config_raw)
    return {
        "identity": collect_identity(adb),
        "runtime": collect_runtime(adb),
        "repository": collect_repository(),
        "config_probe": config_probe,
        "config": config,
        "physical_memory": parse_zoneinfo(adb.read("/proc/zoneinfo")),
        "modules": collect_module_state(adb, config),
        "graphics": collect_graphics(adb),
        "live_cpu": collect_live_cpu(adb, live_cpu),
    }


def find_direct_target(snapshot: dict[str, object]) -> dict[str, object] | None:
    identity = snapshot["identity"]
    assert isinstance(identity, dict)
    repository = snapshot["repository"]
    assert isinstance(repository, dict)
    for target in repository["direct_targets"]:
        if all(
            (
                target["device"] == identity["device"],
                target["build_fingerprint"] == identity["fingerprint"],
                target["security_patch"] == identity["security_patch"],
                target["build_incremental"] == identity["incremental"],
                target["kernel_release"] == identity["kernel_release"],
            )
        ):
            return target
    return None


def runtime_identity(runtime: dict[str, object]) -> str:
    identity = str(runtime["id"])
    context = str(runtime["context"])
    return identity if context in identity else f"{identity}; context={context}"


def check_privilege(snapshot: dict[str, object]) -> Finding:
    runtime = snapshot["runtime"]
    assert isinstance(runtime, dict)
    if runtime["uid"] == 0:
        return Finding(
            "pass",
            "Fresh ADB privilege",
            f"{runtime_identity(runtime)}; SELinux={runtime['selinux']}",
            "preserve this command output with the exploit holder PID; do not rerun the exploit while root remains active",
        )
    return Finding(
        "info",
        "Fresh ADB privilege",
        f"{runtime_identity(runtime)}; SELinux={runtime['selinux']}",
        "treat any provider success line as provisional until a new ADB command reports UID 0",
    )


def check_api(snapshot: dict[str, object]) -> Finding:
    identity = snapshot["identity"]
    repository = snapshot["repository"]
    assert isinstance(identity, dict) and isinstance(repository, dict)
    observed, minimum = int(identity["api"]), int(repository["min_api"])
    state = "pass" if observed >= minimum else "block"
    step = None if state == "pass" else f"build a separate APK variant with minSdk <= {observed}"
    return Finding(state, "APK API", f"device API={observed}, minSdk={minimum}", step)


def check_direct(snapshot: dict[str, object]) -> Finding:
    physical = snapshot["physical_memory"]
    runtime = snapshot["runtime"]
    assert isinstance(physical, dict) and isinstance(runtime, dict)
    target = find_direct_target(snapshot)
    if target is None:
        return Finding(
            "block",
            "Direct-kernel route",
            f"no exact descriptor matches the full runtime identity; observed PFN={hex_range(physical)}",
            "add a descriptor only after a dry provider probe reports exact offsets and a live run proves a fresh UID 0 shell",
        )
    expected = target.get("physical_pfn_range")
    if expected and physical.get("state") == "measured":
        start = int(str(expected["observed_start"]), 0)
        end = int(str(expected["observed_unaligned_end"]), 0)
        if (physical.get("start"), physical.get("end")) != (start, end):
            return Finding(
                "block",
                "Direct-kernel route",
                f"target={target['id']} but PFN envelope changed to {hex_range(physical)}",
                "re-derive the physical range; do not widen the descriptor blindly",
            )
    provider = target["payload"]
    path = ROOT / "app/src/main/jniLibs/arm64-v8a" / provider["file"]
    if not path.is_file():
        return Finding(
            "candidate",
            "Direct-kernel route",
            f"exact target={target['id']}; provider is not packaged; expected SHA-256={provider['sha256']}",
            "obtain the exact provider under compatible terms, verify its hash, then run the app's read-only probe",
        )
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != provider["sha256"]:
        return Finding(
            "block",
            "Direct-kernel route",
            f"target={target['id']}; provider hash mismatch observed={observed}",
            "remove the mismatched provider; never substitute a different build",
        )
    run = target["run"]
    configured = ""
    if expected:
        configured = (
            f" configured=[{int(str(expected['observed_start']), 0):#x},"
            f"{int(str(expected['configured_end']), 0):#x})"
            f" groups={expected['groups']}x{expected['segment_pages']}"
        )
    next_step = (
        "preserve this command output with the exploit holder PID; do not rerun the exploit while root remains active"
        if runtime["uid"] == 0
        else "run the read-only app probe first; use only the generated launcher and require a fresh ADB UID 0 proof"
    )
    return Finding(
        "pass",
        "Direct-kernel route",
        f"target={target['id']}; provider_sha256={observed}; "
        f"execution_domain={run['execution_domain']}; PFN observed={hex_range(physical)}{configured}",
        next_step,
    )


def check_native_module(snapshot: dict[str, object]) -> Finding:
    identity = snapshot["identity"]
    repository = snapshot["repository"]
    config = snapshot["config"]
    assert isinstance(identity, dict) and isinstance(repository, dict)
    kmi = identity["kmi"]
    if kmi is None:
        return Finding(
            "block",
            "Bundled module route",
            "kernel release has no Android KMI tag",
            "require an exact-release module or use another exact strategy; a same-version GKI module is not compatible evidence",
        )
    filename = f"dirtyfrag-{kmi}.ko"
    if filename not in repository["modules"]:
        return Finding(
            "block",
            "Bundled module route",
            f"no bundled module matches {kmi}",
            f"build an exact {kmi} module and validate vermagic, symbol CRCs, and CFI expectations",
        )
    prerequisites = config and config["XFRM"] == "y" and config["INET_ESP"] in {"y", "m"}
    state = "candidate" if prerequisites else "block"
    return Finding(
        state,
        "Bundled module route",
        f"module={filename}; XFRM={config and config['XFRM']}; INET_ESP={config and config['INET_ESP']}",
        "run the app's read-only selector; this KMI match does not replace exact carrier and trigger checks",
    )


def check_modules(snapshot: dict[str, object]) -> Finding:
    modules = snapshot["modules"]
    config = snapshot["config"]
    assert isinstance(modules, dict)
    if config is None:
        return Finding("unknown", "Kernel modules", "/proc/config.gz unavailable")
    loaders = [
        path for path, probe in modules["loaders"].items()
        if probe["state"] == "visible"
    ]
    loaded = modules["loaded"]
    observed = (
        f"MODULES={config['MODULES']}, MODVERSIONS={config['MODVERSIONS']}, "
        f"SIG={config['MODULE_SIG']}, SIG_FORCE={config['MODULE_SIG_FORCE']}, "
        f"modules_disabled={modules['modules_disabled']}, loaded="
        f"{len(loaded) if isinstance(loaded, list) else 'unreadable'}, "
        f"loaders={','.join(loaders) or 'none'}"
    )
    if config["MODULES"] != "y" or modules["modules_disabled"] != "0":
        return Finding("block", "Kernel modules", observed)
    if config["MODULE_SIG_FORCE"] == "y":
        return Finding(
            "block",
            "Kernel modules",
            observed,
            "use a correctly signed exact-build module or a non-module route",
        )
    step = (
        "CONFIG_MODVERSIONS=y requires exact symbol CRCs; record finit_module errno from an exact-build benign module before claiming load support"
        if config["MODVERSIONS"] == "y"
        else "runtime acceptance remains unproven until an exact-build benign module loads"
    )
    return Finding("candidate", "Kernel modules", observed, step)


def check_selinux(snapshot: dict[str, object]) -> Finding:
    runtime = snapshot["runtime"]
    config = snapshot["config"]
    assert isinstance(runtime, dict)
    detail = f"mode={runtime['selinux']}, context={runtime['context']}"
    if config:
        detail += f", SELINUX={config['SECURITY_SELINUX']}, DEVELOP={config['SECURITY_SELINUX_DEVELOP']}"
    return Finding(
        "info",
        "SELinux",
        detail,
        "kernel permissive mode does not disable userspace property-service or service-manager allowlists; use and record the required process domain",
    )


def check_cpu(snapshot: dict[str, object]) -> Finding:
    runtime = snapshot["runtime"]
    config = snapshot["config"]
    live = snapshot["live_cpu"]
    assert isinstance(runtime, dict) and isinstance(live, dict)
    support = config and config["HW_PERF_EVENTS"] == "y" and config["ARM_PMU"] == "y"
    selected = live.get("selected", {})
    counts = live.get("counts", {})
    event_summary = (
        ",".join(str(event) for event in selected.values())
        if isinstance(selected, dict) else ""
    )
    count_summary = (
        ",".join(f"{metric}={count}" for metric, count in counts.items())
        if isinstance(counts, dict) else ""
    )
    observed = (
        f"HW_PERF_EVENTS={config and config['HW_PERF_EVENTS']}, ARM_PMU={config and config['ARM_PMU']}, "
        f"perf_event_paranoid={runtime['perf_event_paranoid']}, perf_harden={runtime['perf_harden']}, "
        f"live={live['state']}"
    )
    if event_summary:
        observed += f", events={event_summary}"
    if count_summary:
        observed += f", counts={count_summary}"
    if live["state"] == "measured":
        missing = live.get("missing", [])
        step = (
            f"hardware counts are live; this simpleperf lacks aliases for {','.join(missing)}"
            if missing else None
        )
        return Finding("pass", "CPU PMU", observed, step)
    if live["state"] == "not_requested":
        step = "run with --live-cpu and require nonzero cycle and instruction counts before claiming PMU access"
    else:
        first_line = str(live.get("detail", "no diagnostic")).splitlines()[0]
        step = f"simpleperf {live.get('phase', 'probe')} failed: {first_line}"
    return Finding(
        "candidate" if support else "unknown",
        "CPU PMU",
        observed,
        step,
    )


def check_graphics(snapshot: dict[str, object]) -> Finding:
    graphics = snapshot["graphics"]
    assert isinstance(graphics, dict)
    kgsl = graphics["kgsl"]
    assert isinstance(kgsl, dict)
    profilers = [
        path for path, probe in graphics["tools"].items()
        if "gpu" in path and probe["state"] == "visible"
    ]
    observed = (
        f"model={graphics['gpu_model']}, KGSL={kgsl['state']}, "
        f"profilers={','.join(profilers) or 'none'}"
    )
    if kgsl["state"] != "visible":
        return Finding("block", "Adreno/KGSL", observed)
    return Finding(
        "candidate",
        "Adreno/KGSL",
        observed,
        "device-node mode is not counter proof; run the unchanged profiler with the required UID, capabilities, and SELinux domain, then require changing hardware values under a GPU workload",
    )


def check_vulkan(snapshot: dict[str, object]) -> Finding:
    graphics = snapshot["graphics"]
    assert isinstance(graphics, dict)
    drivers = [path for path, probe in graphics["drivers"].items() if probe["state"] == "visible"]
    observed = (
        f"features={','.join(graphics['features']) or 'none'}; "
        f"drivers={','.join(drivers) or 'none'}; {graphics['gles'] or 'GLES string unavailable'}"
    )
    state = "candidate" if drivers and graphics["features"] else "unknown"
    return Finding(
        state,
        "Vulkan/GLES",
        observed,
        "driver presence is not detailed-counter proof; capture a rendering workload and require named counter or render-stage output",
    )


def check_hardening(snapshot: dict[str, object]) -> Finding:
    config = snapshot["config"]
    if config is None:
        return Finding("unknown", "Kernel hardening", "kernel config unavailable")
    observed = (
        f"KPTI={config['UNMAP_KERNEL_AT_EL0']}, KASLR={config['RANDOMIZE_BASE']}, "
        f"DEBUG_RODATA={config['DEBUG_RODATA']}, STRICT_KERNEL_RWX={config['STRICT_KERNEL_RWX']}, "
        f"RKP={config['RKP']}, KDIUP={config['KDIUP']}"
    )
    return Finding("info", "Kernel hardening", observed)


CHECKS: tuple[Callable[[dict[str, object]], Finding], ...] = (
    check_privilege,
    check_api,
    check_direct,
    check_native_module,
    check_modules,
    check_selinux,
    check_cpu,
    check_graphics,
    check_vulkan,
    check_hardening,
)


def hex_range(physical: dict[str, object]) -> str:
    if physical.get("state") != "measured":
        return str(physical.get("state"))
    return f"[{int(physical['start']):#x},{int(physical['end']):#x})"


def evaluate(snapshot: dict[str, object]) -> Report:
    findings = [check(snapshot) for check in CHECKS]
    runtime = snapshot["runtime"]
    assert isinstance(runtime, dict)
    route_states = {
        finding.state
        for finding in findings
        if finding.topic in {"Direct-kernel route", "Bundled module route"}
    }
    if runtime["uid"] == 0:
        verdict = "already_privileged"
    elif "pass" in route_states or "candidate" in route_states:
        verdict = "runtime_probe_available"
    elif "unknown" in route_states:
        verdict = "inconclusive"
    else:
        verdict = "no_exact_route"
    return Report(verdict, snapshot, findings)


def render(report: Report) -> str:
    identity = report.snapshot["identity"]
    runtime = report.snapshot["runtime"]
    physical = report.snapshot["physical_memory"]
    assert isinstance(identity, dict) and isinstance(runtime, dict)
    assert isinstance(physical, dict)
    soc = " ".join(
        str(identity[key]) for key in ("soc_manufacturer", "soc_model")
        if identity[key]
    ) or "unreported"
    egl = identity["egl_hardware"] or "unreported"
    vulkan = identity["vulkan_hardware"] or "unreported"
    lines = [
        f"DFRoot device preflight: {report.verdict}",
        f"identity: {identity['model']} / {identity['device']} / {identity['board']}",
        f"SoC / graphics HAL: {soc} / EGL={egl} Vulkan={vulkan}",
        f"build: {identity['fingerprint']}",
        f"incremental / patch: {identity['incremental']} / {identity['security_patch']}",
        f"Android/API: {identity['android']} / {identity['api']}",
        f"kernel: {identity['kernel_release']} {identity['kernel_version']}",
        f"ADB: {runtime['id']}",
        f"SELinux / seccomp: {runtime['selinux']} / {runtime['seccomp']}",
        f"physical PFNs: {hex_range(physical)} source=/proc/zoneinfo state={physical['state']}",
        "",
        "Findings",
    ]
    for finding in report.findings:
        lines.append(f"  {finding.state.upper():9} {finding.topic}: {finding.observed}")
    zones = physical.get("zones", [])
    if zones:
        lines.extend(("", "Physical zones"))
        for zone in zones:
            lines.append(
                "  node={node} name={name} start={start_pfn:#x} spanned={spanned:#x} "
                "present={present:#x} managed={managed:#x}".format(**zone)
            )
    steps = list(
        dict.fromkeys(finding.next_step for finding in report.findings if finding.next_step)
    )
    if steps:
        lines.extend(("", "Next steps"))
        lines.extend(f"  {index}. {step}" for index, step in enumerate(steps, 1))
    lines.extend(
        (
            "",
            "This preflight performs no exploit, module load, property write, or SELinux change.",
            "--live-cpu adds only a 0.25-second simpleperf measurement.",
        )
    )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("serial", help="ADB device serial")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--live-cpu", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = evaluate(collect(args.serial, args.timeout, args.live_cpu))
    print(
        json.dumps(
            {
                "schema_version": 1,
                "verdict": report.verdict,
                "snapshot": report.snapshot,
                "findings": [asdict(finding) for finding in report.findings],
            },
            indent=2,
            sort_keys=True,
        )
        if args.format == "json"
        else render(report)
    )
    return 0 if report.verdict in {"already_privileged", "runtime_probe_available"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
