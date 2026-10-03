#!/usr/bin/env python3
"""Host-only checks for runtime parsing and structural discovery."""

from __future__ import annotations

import sys
import subprocess
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from preflight.discovery import (
    build_probe_plan,
    candidate_directories,
    classify_path,
    exact_candidate_paths,
    parse_elf64_relocations,
    _probe,
)
from preflight.parsers import (
    merge_memory_blocks,
    parse_iomem,
)


class PreflightTest(unittest.TestCase):
    def test_iomem_preserves_disjoint_system_ram(self) -> None:
        parsed = parse_iomem(
            {
                "state": "readable",
                "text": (
                    "811d0000-819fffff : System RAM\n"
                    "  811d0000-811dffff : reserved\n"
                    "81cf5000-81cfefff : System RAM\n"
                ),
            }
        )

        self.assertEqual("measured", parsed["state"])
        self.assertEqual(
            [(0x811D0000, 0x81A00000), (0x81CF5000, 0x81CFF000)],
            [(item["start"], item["end"]) for item in parsed["ranges"]],
        )

    def test_online_blocks_merge_only_adjacent_indices(self) -> None:
        self.assertEqual(
            [
                {
                    "start": 0x80000000,
                    "end": 0x90000000,
                    "start_pfn": 0x80000,
                    "end_pfn": 0x90000,
                },
                {
                    "start": 0x98000000,
                    "end": 0xA0000000,
                    "start_pfn": 0x98000,
                    "end_pfn": 0xA0000,
                },
            ],
            merge_memory_blocks([16, 17, 19], 0x8000000),
        )

    def test_candidate_paths_are_composed_from_generic_parts(self) -> None:
        directories = candidate_directories(("/vendor", "/usr"), ("bin", "lib/modules"))
        self.assertEqual(
            ["/usr/bin", "/usr/lib/modules", "/vendor/bin", "/vendor/lib/modules"],
            directories,
        )
        paths = exact_candidate_paths(("/var",), ("", "bin"), ("modprobe",))
        self.assertEqual(["/var/bin/modprobe", "/var/modprobe"], paths)

    def test_path_classification_uses_structure(self) -> None:
        self.assertEqual("kernel_module", classify_path("/future/lib/modules/carrier.ko"))
        self.assertEqual("boot_config", classify_path("/future/etc/init/runtime.rc"))
        self.assertEqual("shared_library", classify_path("/future/lib64/runtime.so"))
        self.assertEqual("device_node", classify_path("/dev/example"))

    def test_probe_plan_reports_missing_symbol_evidence(self) -> None:
        discovery = {
            "candidates": [
                {
                    "path": "/vendor/lib/modules/example.ko",
                    "category": "kernel_module",
                    "vermagic_matches_running_kernel": True,
                    "anchor_terms": [],
                    "relocation_anchors": [],
                },
                {
                    "path": "/vendor/bin/modprobe",
                    "category": "executable",
                },
            ],
            "symbol_sources": [
                {
                    "path": "/proc/kallsyms",
                    "state": "visible",
                    "readable": True,
                    "addresses_redacted": True,
                }
            ],
        }
        plan = build_probe_plan(discovery, {"uid": 2000})
        steps = {step["id"]: step for step in plan["steps"]}
        self.assertEqual("ambiguous", steps["module_carrier_analysis"]["state"])
        self.assertEqual("ambiguous", steps["kernel_symbol_resolution"]["state"])
        self.assertEqual("scratch_write_restore", plan["next_probe"])

    def test_elf_parser_rejects_non_elf_input(self) -> None:
        self.assertEqual(([], {}), parse_elf64_relocations(b"not an elf", {"symbol"}))

    def test_unreadable_candidate_still_returns_evidence(self) -> None:
        class FakeAdb:
            def path(self, path: str) -> dict[str, object]:
                return {"state": "visible", "detail": path}

            def run(self, *args: str) -> subprocess.CompletedProcess[bytes]:
                return subprocess.CompletedProcess(args, 1, b"", b"permission denied")

            def script(self, source: str) -> subprocess.CompletedProcess[bytes]:
                return subprocess.CompletedProcess((source,), 1, b"", b"permission denied")

            def read_bytes(self, path: str):
                return ({"state": "permission_denied"}, None)

        candidate = _probe(  # type: ignore[arg-type]
            FakeAdb(), "/system/bin/modprobe", "executable", "kernel"
        )
        self.assertEqual("executable", candidate["category"])
        self.assertFalse(candidate["elf64"])


if __name__ == "__main__":
    unittest.main()
