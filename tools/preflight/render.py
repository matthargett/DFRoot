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
        f"identity SHA-256: {identity['canonical_sha256']}",
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
