from __future__ import annotations
import re
from pathlib import Path
from typing import Callable

from .model import Finding, Report
from .parsers import hex_range


def runtime_identity(runtime: dict[str, object]) -> str:
    identity = str(runtime["id"])
    context = str(runtime["context"])
    return identity if context in identity else f"{identity}; context={context}"

def check_privilege(snapshot: dict[str, object]) -> Finding:
    runtime = snapshot["runtime"]
    assert isinstance(runtime, dict)
    adbd = runtime.get("adbd", {})
    daemon = ""
    if isinstance(adbd, dict) and adbd.get("state") == "measured":
        status = adbd.get("status", {})
        daemon = (
            f"; adbd_pid={adbd.get('pid')} adbd_uid={status.get('Uid')} "
            f"adbd_context={adbd.get('context')} adbd_cap_eff={status.get('CapEff')} "
            f"adbd_seccomp={status.get('Seccomp')}"
        )
    if runtime["uid"] == 0:
        return Finding(
            "pass",
            "Fresh ADB privilege",
            f"{runtime_identity(runtime)}; SELinux={runtime['selinux']}{daemon}",
            "preserve this command output with the exploit holder PID; do not rerun the exploit while root remains active",
        )
    return Finding(
        "info",
        "Fresh ADB privilege",
        f"{runtime_identity(runtime)}; SELinux={runtime['selinux']}{daemon}",
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

def check_memory(snapshot: dict[str, object]) -> Finding:
    memory = snapshot["physical_memory"]
    assert isinstance(memory, dict)
    iomem = memory.get("iomem", {})
    sysfs = memory.get("sysfs", {})
    ranges = iomem.get("ranges", []) if isinstance(iomem, dict) else []
    observed = (
        f"zone_envelope={hex_range(memory)}, present_pages={memory.get('present_pages')}, "
        f"spanned_pages={memory.get('spanned_pages')}, iomem={iomem.get('state') if isinstance(iomem, dict) else 'unknown'} "
        f"segments={len(ranges)}, sysfs={sysfs.get('state') if isinstance(sysfs, dict) else 'unknown'}"
    )
    if memory.get("state") != "measured":
        return Finding(
            "unknown", "Physical memory topology", observed,
            "collect at least two independent sources before configuring a physical scan range",
        )
    if memory.get("sparse") or len(ranges) > 1:
        return Finding(
            "info", "Physical memory topology", observed,
            "preserve the disjoint RAM segments and reserved gaps; never treat the zone envelope as one contiguous provider range",
        )
    return Finding("pass", "Physical memory topology", observed)

def check_direct(snapshot: dict[str, object]) -> Finding:
    discovery = snapshot["runtime_discovery"]
    assert isinstance(discovery, dict)
    plan = discovery.get("probe_plan", {})
    counts = discovery.get("candidate_counts", {})
    assert isinstance(plan, dict) and isinstance(counts, dict)
    steps = plan.get("steps", [])
    assert isinstance(steps, list)
    ready = [
        str(step.get("id")) for step in steps
        if isinstance(step, dict) and step.get("state") == "ready"
    ]
    ambiguous = [
        str(step.get("id")) for step in steps
        if isinstance(step, dict) and step.get("state") == "ambiguous"
    ]
    state = "candidate" if ready else "unknown"
    return Finding(
        state,
        "Adaptive route discovery",
        f"selection={discovery.get('selection')}; candidates={sum(int(v) for v in counts.values())}; "
        f"ready={','.join(ready) or 'none'}; ambiguous={','.join(ambiguous) or 'none'}; "
        f"next={plan.get('next_probe')}",
        str(plan.get("reason")),
    )

def check_native_module(snapshot: dict[str, object]) -> Finding:
    identity = snapshot["identity"]
    repository = snapshot["repository"]
    config = snapshot["config"]
    assert isinstance(identity, dict) and isinstance(repository, dict)
    kmi = identity["kmi"]
    discovery = snapshot.get("runtime_discovery", {})
    candidates = discovery.get("candidates", []) if isinstance(discovery, dict) else []
    exact_release_modules = [
        item for item in candidates
        if isinstance(item, dict)
        and item.get("category") == "kernel_module"
        and item.get("vermagic_matches_running_kernel")
    ]
    relocation_carriers = [
        item for item in exact_release_modules if item.get("relocation_anchors")
    ]
    if kmi is None:
        modules = snapshot["modules"]
        shipped = modules.get("shipped", {}) if isinstance(modules, dict) else {}
        vermagic = shipped.get("sample_vermagic") if isinstance(shipped, dict) else None
        exact_release = bool(vermagic and str(vermagic).split()[0] == identity["kernel_release"])
        state = "candidate" if relocation_carriers else "block"
        return Finding(
            state,
            "Module route",
            f"kernel release has no Android KMI tag; shipped_vermagic={vermagic or 'unavailable'}; "
            f"exact_release_anchor={int(exact_release)}; discovered_exact_modules={len(exact_release_modules)}; "
            f"relocation_carriers={len(relocation_carriers)}",
            (
                "runtime modules prove carrier ABI and relocation candidates; a payload still needs exact symbol CRCs and accepted loader semantics"
                if relocation_carriers
                else "require an exact-release module or use another derived strategy; a same-version GKI module is not compatibility evidence"
            ),
        )
    filename = f"dirtyfrag-{kmi}.ko"
    if filename not in repository["modules"]:
        return Finding(
            "block",
            "Module route",
            f"no bundled module matches {kmi}",
            f"build an exact {kmi} module and validate vermagic, symbol CRCs, and CFI expectations",
        )
    prerequisites = config and config["XFRM"] == "y" and config["INET_ESP"] in {"y", "m"}
    state = "candidate" if prerequisites else "block"
    return Finding(
        state,
        "Module route",
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
    shipped = modules.get("shipped", {})
    observed = (
        f"MODULES={config['MODULES']}, MODVERSIONS={config['MODVERSIONS']}, "
        f"SIG={config['MODULE_SIG']}, SIG_FORCE={config['MODULE_SIG_FORCE']}, "
        f"modules_disabled={modules['modules_disabled']}, loaded="
        f"{len(loaded) if isinstance(loaded, list) else 'unreadable'}, "
        f"loaders={','.join(loaders) or 'none'}, shipped={shipped.get('count')}, "
        f"sample_vermagic={shipped.get('sample_vermagic')}"
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

def check_exploit_primitives(snapshot: dict[str, object]) -> Finding:
    config = snapshot["config"]
    primitives = snapshot["exploit_primitives"]
    assert isinstance(primitives, dict)
    paths = primitives["paths"]
    trace = paths["/sys/kernel/tracing/events/filemap"]
    ion = paths["/dev/ion"]
    dma = paths["/dev/dma_heap/system"]
    xfrm = primitives["xfrm_stats"]
    observed = (
        f"XFRM={config and config['XFRM']}, INET_ESP={config and config['INET_ESP']}, "
        f"xfrm_stats={xfrm['state']}, filemap_tracepoints={trace['state']}, "
        f"ion={ion['state']}, dma_heap={dma['state']}, "
        f"userfaultfd={primitives['unprivileged_userfaultfd']}, "
        f"unpriv_bpf_disabled={primitives['unprivileged_bpf_disabled']}"
    )
    candidate = bool(
        config and config["XFRM"] == "y" and config["INET_ESP"] in {"y", "m"}
        and xfrm["state"] == "visible"
    )
    return Finding(
        "candidate" if candidate else "unknown",
        "Exploit primitives",
        observed,
        "capability presence is not vulnerability proof; require a scratch-file write/readback probe and an exact restoration check before selecting a live chain",
    )

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
        if re.search(r"(prof|counter|gprobe)", Path(path).name, re.I)
        and probe["state"] == "visible"
    ]
    observed = (
        f"model={graphics['gpu_model']}, KGSL={kgsl['state']}, "
        f"profilers={','.join(profilers) or 'none'}, "
        f"perfetto_gpu_sources={','.join(graphics['perfetto_gpu_sources']) or 'none'}"
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
    drivers = [
        path for path, probe in graphics["drivers"].items()
        if probe["state"] == "visible" and (
            Path(path).name.startswith("vulkan.")
            or Path(path).name == "libGLESv2_adreno.so"
            or Path(path).name == "libVkLayer_ADRENO_qprofiler.so"
        )
    ]
    digests = [
        f"{Path(path).name}:{probe.get('sha256')}"
        for path, probe in graphics["drivers"].items()
        if path in drivers and probe.get("sha256")
    ]
    observed = (
        f"features={','.join(graphics['features']) or 'none'}; "
        f"drivers={','.join(drivers) or 'none'}; hashes={','.join(digests) or 'unavailable'}; "
        f"{graphics['gles'] or 'GLES string unavailable'}"
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
    primitives = snapshot["exploit_primitives"]
    observed = (
        f"KPTI={config['UNMAP_KERNEL_AT_EL0']}, KASLR={config['RANDOMIZE_BASE']}, "
        f"DEBUG_RODATA={config['DEBUG_RODATA']}, STRICT_KERNEL_RWX={config['STRICT_KERNEL_RWX']}, "
        f"STRICT_MODULE_RWX={config['STRICT_MODULE_RWX']}, kptr_restrict={primitives['kptr_restrict']}, "
        f"dmesg_restrict={primitives['dmesg_restrict']}, RKP={config['RKP']}, KDIUP={config['KDIUP']}"
    )
    return Finding("info", "Kernel hardening", observed)

def evaluate(snapshot: dict[str, object]) -> Report:
    findings = [check(snapshot) for check in CHECKS]
    runtime = snapshot["runtime"]
    assert isinstance(runtime, dict)
    route_states = {
        finding.state
        for finding in findings
        if finding.topic in {"Adaptive route discovery", "Module route"}
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

CHECKS: tuple[Callable[[dict[str, object]], Finding], ...] = (
    check_privilege,
    check_api,
    check_memory,
    check_direct,
    check_native_module,
    check_modules,
    check_exploit_primitives,
    check_selinux,
    check_cpu,
    check_graphics,
    check_vulkan,
    check_hardening,
)
