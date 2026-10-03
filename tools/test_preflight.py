#!/usr/bin/env python3
"""Host-only checks for preflight parsing and identity matching."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from preflight.checks import find_direct_target
from preflight.parsers import (
    canonical_identity_sha256,
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

    def test_digest_descriptor_matches_without_raw_identity(self) -> None:
        digest = canonical_identity_sha256("fingerprint", "incremental", "patch", "kernel")
        target = {"identity_sha256": digest}
        snapshot = {
            "identity": {
                "canonical_sha256": digest,
                "device": "observed-device",
                "fingerprint": "fingerprint",
                "security_patch": "patch",
                "incremental": "incremental",
                "kernel_release": "kernel",
            },
            "repository": {"direct_targets": [target]},
        }

        self.assertIs(target, find_direct_target(snapshot))


if __name__ == "__main__":
    unittest.main()
