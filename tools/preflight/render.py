from __future__ import annotations
from .model import Report
from .parsers import byte_range, format_size, hex_range


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
    discovery = report.snapshot.get("runtime_discovery", {})
    if isinstance(discovery, dict):
        counts = discovery.get("candidate_counts", {})
        plan = discovery.get("probe_plan", {})
        lines.extend(("", "Runtime structural discovery"))
        if isinstance(counts, dict):
            lines.append("  candidates: " + ", ".join(
                f"{name}={count}" for name, count in counts.items()
            ))
        if isinstance(plan, dict):
            lines.append(f"  next probe: {plan.get('next_probe')} ({plan.get('reason')})")
            for step in plan.get("steps", []):
                if not isinstance(step, dict):
                    continue
                required = step.get("requires", [])
                suffix = f"; missing={'; '.join(required)}" if required else ""
                lines.append(
                    f"  {str(step.get('state')).upper():9} {step.get('id')}: "
                    f"{step.get('evidence')}{suffix}"
                )
                for candidate in step.get("candidates", [])[:3]:
                    if not isinstance(candidate, dict):
                        continue
                    relocations = candidate.get("relocations", [])
                    offsets = ",".join(
                        f"{item.get('symbol')}@{int(item.get('offset', 0)):#x}"
                        for item in relocations[:6]
                        if isinstance(item, dict)
                    )
                    lines.append(
                        f"             candidate={candidate.get('path')} "
                        f"size={candidate.get('size', 'unknown')} "
                        f"depends={candidate.get('depends', 'unknown') or 'none'} "
                        f"relocations={offsets or 'none'}"
                    )
                    windows = candidate.get("replacement_windows", [])
                    if windows:
                        lines.append(
                            "             replacement_windows=" + ",".join(
                                f"{item.get('verb')}@{int(item.get('offset', 0)):#x}+{item.get('length')}"
                                for item in windows[:8]
                                if isinstance(item, dict)
                            )
                        )
                for source in step.get("sources", [])[:3]:
                    if not isinstance(source, dict) or not source.get("symbols"):
                        continue
                    lines.append(
                        f"             source={source.get('path')} symbols="
                        + " | ".join(str(item) for item in source["symbols"][:6])
                    )
    zones = physical.get("zones", [])
    if zones:
        lines.extend(("", "Physical zones"))
        for zone in zones:
            lines.append(
                "  node={node} name={name} start={start_pfn:#x} spanned={spanned:#x} "
                "present={present:#x} managed={managed:#x}".format(**zone)
            )
    iomem = physical.get("iomem", {})
    ram_ranges = iomem.get("ranges", []) if isinstance(iomem, dict) else []
    if ram_ranges:
        lines.extend(("", "System RAM segments from /proc/iomem"))
        for item in ram_ranges:
            lines.append(
                f"  bytes={byte_range(item)} PFNs=[{item['start_pfn']:#x},{item['end_pfn']:#x}) "
                f"size={format_size(int(item['bytes']))}"
            )
    sysfs = physical.get("sysfs", {})
    block_ranges = sysfs.get("ranges", []) if isinstance(sysfs, dict) else []
    if block_ranges:
        lines.extend(("", "Online memory blocks from sysfs"))
        for item in block_ranges:
            lines.append(
                f"  bytes={byte_range(item)} PFNs=[{item['start_pfn']:#x},{item['end_pfn']:#x})"
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
            "--live-cpu adds three 0.25-second simpleperf groups to avoid PMU multiplexing.",
        )
    )
    return "\n".join(lines)
