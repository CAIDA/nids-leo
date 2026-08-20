"""Command construction for the heavyweight LTE decoder stages.

The notebook defaults to cached artifacts because a complete 151-second PHY
decode is slow.  Setting ``RUN_FULL_DECODERS=True`` makes these helpers invoke
the same checked-in decoder scripts.  Patched LTEsniffer and an srsRAN 4G build
remain system dependencies; they are deliberately not bundled as binaries.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess


@dataclass
class DecoderEnvironment:
    core: Path
    runtime: Path
    ltesniffer: Path | None = None
    ul_probe: Path | None = None

    @classmethod
    def discover(cls, core: Path, runtime: Path) -> "DecoderEnvironment":
        ltesniffer_text = os.environ.get("LTESNIFFER_BIN")
        probe_text = os.environ.get("UL_GRANT_PROBE_BIN")
        return cls(
            core=core.resolve(),
            runtime=runtime.resolve(),
            ltesniffer=Path(ltesniffer_text).resolve() if ltesniffer_text else None,
            ul_probe=Path(probe_text).resolve() if probe_text else None,
        )

    def prerequisites(self) -> dict[str, bool]:
        return {
            "tshark": shutil.which("tshark") is not None,
            "patched LTESniffer": bool(self.ltesniffer and self.ltesniffer.is_file()),
            "ul_grant_probe": bool(self.ul_probe and self.ul_probe.is_file()),
        }

    def run(self, command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
        self.runtime.mkdir(parents=True, exist_ok=True)
        print(" ".join(command))
        return subprocess.run(command, cwd=cwd, text=True, check=True)

    def ul_command(
        self,
        *,
        paired_iq: Path,
        grant_log: Path,
        burst_audit: Path,
        pci: int,
        output_dir: Path,
        radius_ms: float = 5.0,
        timing_candidates: int = 4,
        rrc_pcaps: list[Path] | None = None,
    ) -> list[str]:
        if self.ul_probe is None:
            probe = "${UL_GRANT_PROBE_BIN}"
        else:
            probe = str(self.ul_probe)
        command = [
            "python3",
            str(self.core / "scripts" / "grant_directed_wide_timing.py"),
            "--input", str(paired_iq),
            "--grant-log", str(grant_log),
            "--burst-audit", str(burst_audit),
            "--pci", str(pci),
            "--output-dir", str(output_dir),
            "--radius-ms", str(radius_ms),
            "--timing-candidates", str(timing_candidates),
            "--probe", probe,
        ]
        for pcap in rrc_pcaps or []:
            command.extend(["--rrc-pcap", str(pcap)])
        return command


def display_command(command: list[str]) -> str:
    return " ".join(command)
