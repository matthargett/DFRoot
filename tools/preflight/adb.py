from __future__ import annotations
import hashlib
import re
import shlex
import subprocess


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

    def path(self, path: str, digest: bool = False) -> dict[str, object]:
        result = self.run("shell", "ls", "-ldZ", path)
        detail = output(result)
        if result.returncode:
            return {"state": classify_error(detail), "path": path, "detail": detail}
        probe = {"state": "visible", "path": path, "detail": detail}
        if digest:
            hashed = self.run("shell", "sha256sum", path)
            match = re.match(r"^([0-9a-fA-F]{64})\s", output(hashed))
            probe["sha256"] = match.group(1).lower() if match else None
            probe["sha256_state"] = "measured" if match else classify_error(output(hashed))
        return probe

    def files(self, roots: tuple[str, ...], max_depth: int) -> list[str]:
        result = self.run(
            "shell", "find", *roots, "-maxdepth", str(max_depth), "-type", "f"
        )
        return sorted(
            line.strip()
            for line in result.stdout.decode(errors="replace").splitlines()
            if line.startswith("/")
        )

    def script(self, source: str) -> subprocess.CompletedProcess[bytes]:
        return self.run("shell", "sh", "-c", shlex.quote(source))

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
