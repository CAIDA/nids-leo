#!/usr/bin/env python3
"""Check every runtime dependency before an expensive notebook decode."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess


def check_setup(tutorial: Path | None = None, *, require_gnuradio: bool = True) -> list[str]:
    tutorial = (tutorial or Path(__file__).resolve().parent).resolve()
    core_build = tutorial / "utils" / "decoder_core" / "build"
    missing: list[str] = []
    for command in ("tshark", "mergecap"):
        if shutil.which(command) is None:
            missing.append(f"command: {command}")
    for name in ("LTESniffer", "align_duplex_lte", "ul_grant_probe"):
        path = core_build / name
        if not path.is_file() or not path.stat().st_mode & 0o111:
            missing.append(f"local decoder: {path}")
    if require_gnuradio:
        probe = subprocess.run(
            ["/usr/bin/python3", "-c", "import gnuradio"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode:
            missing.append("system Python module: gnuradio")
    for module in ("numpy", "matplotlib", "IPython"):
        if importlib.util.find_spec(module) is None:
            missing.append(f"Python module: {module}")
    return missing


def require_setup(tutorial: Path | None = None, *, require_gnuradio: bool = True) -> None:
    missing = check_setup(tutorial, require_gnuradio=require_gnuradio)
    if missing:
        details = "\n".join(f"  - {item}" for item in missing)
        raise RuntimeError(
            "Tutorial setup is incomplete:\n"
            f"{details}\n\n"
            "From the repository root run:\n"
            "  bash Tutorial/setup_ubuntu.sh\n"
            "Then restart the Jupyter kernel and run the notebook again."
        )


if __name__ == "__main__":
    missing = check_setup()
    if missing:
        print("Setup incomplete:")
        print("\n".join(f"  - {item}" for item in missing))
        raise SystemExit(1)
    print("Setup complete: all notebook runtime dependencies are available.")
