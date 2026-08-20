#!/usr/bin/env python3
"""Run a true LTEsniffer DL-mode pass on duplex-aligned offline IQ."""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

import numpy as np


DEFAULT_DECODER = Path(
    "/home/morty/Desktop/LTEsniffer_offline/tools/bin/LTESniffer"
)
SAMPLE_RATE = 5_760_000


def extract_downlink(source_path: Path, output_path: Path, subframes: int) -> None:
    source = np.memmap(source_path, dtype="<c8", mode="r")
    wanted = min(source.size // 2, subframes * (SAMPLE_RATE // 1000))
    chunk = 1_000_000
    with output_path.open("wb") as output:
        for start in range(0, wanted, chunk):
            end = min(wanted, start + chunk)
            np.asarray(source[2 * start : 2 * end : 2], dtype="<c8").tofile(output)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--pci", type=int, required=True)
    parser.add_argument("--subframes", type=int, required=True)
    parser.add_argument("--ports", type=int, default=1)
    parser.add_argument("--prb", type=int, default=25)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--rnti", type=int,
                        help="restrict dedicated traffic decoding to this RNTI")
    parser.add_argument("--debug", action="store_true",
                        help="enable LTEsniffer per-candidate decode diagnostics")
    parser.add_argument("--decoder", type=Path, default=DEFAULT_DECODER)
    args = parser.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"pci{args.pci}-dl-") as temporary:
        downlink_iq = Path(temporary) / f"pci{args.pci}_downlink.fc32"
        extract_downlink(args.input.resolve(), downlink_iq, args.subframes)
        command = [
            str(args.decoder),
            "-A",
            "1",
            "-W",
            str(args.workers),
            "-i",
            str(downlink_iq),
            "-P",
            str(args.ports),
            "-c",
            str(args.pci),
            "-p",
            str(args.prb),
            "-x",
            "1/6",
            "-X",
            "normal",
            "-K",
            "normal",
            "-m",
            "0",
            "-n",
            str(args.subframes),
            "-D",
            "dci.txt",
            "-E",
            "stats.txt",
        ]
        if args.rnti is not None:
            command.extend(["-r", str(args.rnti)])
        if args.debug:
            command.append("-d")
        result = subprocess.run(
            command,
            cwd=args.output_dir,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        (args.output_dir / "decode.log").write_text(result.stdout)

    pcap = args.output_dir / "ltesniffer_dl_mode.pcap"
    if not pcap.is_file():
        raise SystemExit(
            f"decoder did not create {pcap}; exit={result.returncode}"
        )
    # LTEsniffer returns 1 after a normal finite-file shutdown in this build.
    if result.returncode not in (0, 1):
        raise SystemExit(f"decoder failed with exit={result.returncode}")
    print(pcap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
