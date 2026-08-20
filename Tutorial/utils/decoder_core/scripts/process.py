#!/usr/bin/python3
"""Find LTE cells in raw DL and build synchronized duplex LTEsniffer files."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import struct
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT.parent / "tools"
PAIR_RESAMPLER = ROOT / "scripts" / "channelize_pair.py"
CELL_SEARCH = TOOLS / "bin" / "cell_search_file"
MIB_DECODER = TOOLS / "bin" / "mib_decode_file"
ALIGNER = ROOT / "build" / "align_duplex_lte"
LTESNIFFER = TOOLS / "bin" / "LTESniffer"
PRB_RATES = {
    6: 1_920_000,
    15: 3_840_000,
    25: 5_760_000,
    50: 11_520_000,
    75: 15_360_000,
    100: 23_040_000,
}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def last_json(text: str) -> dict[str, Any] | None:
    for line in reversed(text.splitlines()):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return None


def run(
    cmd: list[str],
    log: Path,
    commands: Path,
    *,
    cwd: Path | None = None,
    timeout: int = 60,
    accepted: tuple[int, ...] = (0,),
) -> tuple[int, str]:
    log.parent.mkdir(parents=True, exist_ok=True)
    with commands.open("a") as handle:
        rendered = shlex.join(cmd)
        if cwd:
            rendered = f"(cd {shlex.quote(str(cwd))} && {rendered})"
        handle.write(rendered + "\n")
    print("+", shlex.join(cmd), flush=True)
    child_env = os.environ.copy()
    private_lib = str(TOOLS / "lib")
    old_library_path = child_env.get("LD_LIBRARY_PATH")
    child_env["LD_LIBRARY_PATH"] = (
        f"{private_lib}:{old_library_path}" if old_library_path else private_lib
    )
    if Path(cmd[0]).name == "LTESniffer":
        child_env["LTESNIFFER_UL_DIAGNOSTICS"] = "1"
        child_env["LTESNIFFER_DISABLE_PRACH"] = "1"
    try:
        completed = subprocess.run(
            cmd,
            cwd=cwd,
            env=child_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )
        status, output = completed.returncode, completed.stdout
    except subprocess.TimeoutExpired as error:
        raw = error.stdout or ""
        output = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        output += f"\nTIMEOUT after {timeout}s\n"
        status = 124
    log.write_text(output)
    if status not in accepted:
        raise RuntimeError(f"command exited {status}; inspect {log}")
    return status, output


def count_pcap(path: Path) -> int:
    if not path.exists() or path.stat().st_size < 24:
        return 0
    data = path.read_bytes()
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"M<\xb2\xa1") else ">"
    offset = 24
    count = 0
    while offset + 16 <= len(data):
        included = struct.unpack_from(endian + "I", data, offset + 8)[0]
        offset += 16 + included
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture", type=Path, default=ROOT / "runs" / "latest")
    parser.add_argument(
        "--results-dir", type=Path,
        help="write derived files here instead of CAPTURE/offline",
    )
    parser.add_argument("--pci", type=int, help="only process this detected PCI")
    parser.add_argument("--threads", type=int, default=1)
    args = parser.parse_args()

    capture_dir = args.capture.resolve()
    manifest_path = capture_dir / "capture.json"
    manifest = json.loads(manifest_path.read_text())
    capture = manifest["capture"]
    raw_rate = int(round(capture["sample_rate_hz"]))
    sample_count = int(capture["sample_count_per_channel"])
    duration = sample_count / raw_rate
    results = (args.results_dir.resolve() if args.results_dir else capture_dir / "offline")
    commands = results / "commands.sh"
    commands.parent.mkdir(parents=True, exist_ok=True)
    commands.write_text("#!/usr/bin/env bash\nset -Eeuo pipefail\n\n")

    sync_dir = results / "sync_search"
    sync_dl = sync_dir / "downlink_1p92Msps.fc32"
    sync_ul = sync_dir / "uplink_1p92Msps.fc32"
    _, resample_output = run(
        [
            "/usr/bin/python3",
            str(PAIR_RESAMPLER),
            "--manifest",
            str(manifest_path),
            "--dl-output",
            str(sync_dl),
            "--ul-output",
            str(sync_ul),
            "--output-rate",
            "1920000",
        ],
        sync_dir / "resample.log",
        commands,
        timeout=max(120, int(math.ceil(duration * 4))),
    )

    sync_samples = sync_dl.stat().st_size // 8
    offsets = [0]
    if duration >= 1.5:
        offsets.append(int(sync_samples / 2))
    searches: list[dict[str, Any]] = []
    hits: dict[int, list[dict[str, Any]]] = {}
    for offset in offsets:
        for nid2 in range(3):
            _, output = run(
                [
                    str(CELL_SEARCH),
                    "--input",
                    str(sync_dl),
                    "--nid2",
                    str(nid2),
                    "--max-frames",
                    "200",
                    "--valid-frames",
                    "4",
                    "--offset-samples",
                    str(offset),
                ],
                results / "cell_search" / f"offset{offset}_nid2_{nid2}.log",
                commands,
                accepted=(0, 1),
                timeout=20,
            )
            found = last_json(output) or {"found": False, "error": "no JSON"}
            found["offset_samples"] = offset
            searches.append(found)
            if found.get("found"):
                hits.setdefault(int(found["pci"]), []).append(found)
    write_json(results / "cell_search_results.json", searches)

    confirmed: dict[int, dict[str, Any]] = {}
    mib_results: list[dict[str, Any]] = []
    for pci, pci_hits in sorted(hits.items()):
        if args.pci is not None and pci != args.pci:
            continue
        for index, hit in enumerate(pci_hits):
            _, output = run(
                [
                    str(MIB_DECODER),
                    "--input",
                    str(sync_dl),
                    "--pci",
                    str(pci),
                    "--frame-type",
                    str(hit.get("frame_type", "FDD")),
                    "--cp",
                    str(hit.get("cp", "normal")),
                    "--cfo-hz",
                    str(hit.get("cfo_hz", 0.0)),
                    "--offset-samples",
                    str(hit["offset_samples"]),
                    "--max-frames",
                    "100",
                ],
                results / "mib" / f"pci{pci}_hit{index}.log",
                commands,
                accepted=(0, 1, 124),
                timeout=8,
            )
            mib = last_json(output) or {"mib_found": False, "error": "no JSON"}
            mib["search"] = hit
            mib_results.append(mib)
            if mib.get("mib_found") and mib.get("frame_type") == "FDD":
                confirmed.setdefault(
                    pci,
                    {
                        **mib,
                        "cfo_hz": float(hit.get("cfo_hz", 0.0)),
                    },
                )
    write_json(results / "mib_results.json", mib_results)

    cell_results: list[dict[str, Any]] = []
    resampled_by_rate: dict[int, tuple[Path, Path]] = {}
    for pci, cell in sorted(confirmed.items()):
        prb = int(cell["nof_prb"])
        if prb not in PRB_RATES:
            continue
        rate = PRB_RATES[prb]
        if rate not in resampled_by_rate:
            rate_dir = results / "lte_rate" / f"{rate}Sps"
            dl_rate = rate_dir / "downlink.fc32"
            ul_rate = rate_dir / "uplink.fc32"
            run(
                [
                    "/usr/bin/python3",
                    str(PAIR_RESAMPLER),
                    "--manifest",
                    str(manifest_path),
                    "--dl-output",
                    str(dl_rate),
                    "--ul-output",
                    str(ul_rate),
                    "--output-rate",
                    str(rate),
                ],
                rate_dir / "resample.log",
                commands,
                timeout=max(180, int(math.ceil(duration * 5))),
            )
            resampled_by_rate[rate] = (dl_rate, ul_rate)

        dl_rate, ul_rate = resampled_by_rate[rate]
        cell_dir = results / "cells" / f"pci_{pci}"
        paired = cell_dir / "ltesniffer_duplex_aligned.fc32"
        _, align_output = run(
            [
                str(ALIGNER),
                "--dl",
                str(dl_rate),
                "--ul",
                str(ul_rate),
                "--output",
                str(paired),
                "--pci",
                str(pci),
                "--prb",
                str(prb),
                "--cfo-hz",
                str(cell["cfo_hz"]),
            ],
            cell_dir / "alignment.log",
            commands,
            accepted=(0, 3),
            timeout=max(120, int(math.ceil(duration * 4))),
        )
        alignment = last_json(align_output) or {"started": False}
        cell_result = {"pci": pci, "mib": cell, "alignment": alignment}
        written = int(alignment.get("written_subframes", 0))
        if alignment.get("started") and written:
            decode_dir = cell_dir / "ltesniffer"
            decode_dir.mkdir(parents=True, exist_ok=True)
            decode_status, decode_output = run(
                [
                    str(LTESNIFFER),
                    "-A",
                    "2",
                    "-W",
                    str(args.threads),
                    "-i",
                    str(paired),
                    "-P",
                    str(cell["nof_ports"]),
                    "-c",
                    str(pci),
                    "-p",
                    str(prb),
                    "-x",
                    str(cell["phich_resources"]),
                    "-X",
                    str(cell["phich_length"]),
                    "-K",
                    str(cell.get("cp", "normal")),
                    "-m",
                    "1",
                    "-n",
                    str(written),
                    "-D",
                    "dci.txt",
                    "-E",
                    "stats.txt",
                ],
                decode_dir / "decode.log",
                commands,
                cwd=decode_dir,
                # Some LTEsniffer builds abort during final PRACH cleanup after
                # closing an otherwise readable PCAP. Preserve and report that
                # per-cell result instead of discarding all other cells.
                accepted=(0, 1, -6, -11),
                timeout=max(180, int(math.ceil(duration * 6))),
            )
            pcap = decode_dir / "ltesniffer_ul_mode.pcap"
            rntis = sorted(
                set(
                    re.findall(
                        r"(?m)^\s*\d+\s+(\d+)\s+(?:Unknown|16QAM|64QAM|256QAM)",
                        decode_output,
                    )
                )
            )
            ul_attempts = [
                dict(re.findall(r"(\w+)=([^ ]+)", line))
                for line in decode_output.splitlines()
                if "[UL-TRY]" in line
            ]
            cell_result["ltesniffer"] = {
                "return_code": decode_status,
                "clean_exit": decode_status in (0, 1),
                "mib_decoded": "Decoded MIB" in decode_output,
                "pcap": str(pcap),
                "pcap_packets": count_pcap(pcap),
                "pcap_bytes": pcap.stat().st_size if pcap.exists() else 0,
                "observed_rntis": rntis,
                "ul_grant_attempts": len(ul_attempts),
                "validated_nonzero_ul_packets": sum(
                    attempt.get("crc") == "1"
                    and attempt.get("all_zero") == "0"
                    for attempt in ul_attempts
                ),
                "rejected_all_zero_crc_passes": sum(
                    attempt.get("crc") == "1"
                    and attempt.get("all_zero") == "1"
                    for attempt in ul_attempts
                ),
                "skipped_subframes": (
                    int(match.group(1))
                    if (match := re.search(r"Skipped subframe:\s*(\d+)", decode_output))
                    else None
                ),
            }
        cell_results.append(cell_result)

    summary = {
        "capture": str(capture_dir),
        "source_duration_seconds": duration,
        "source_sample_rate_hz": raw_rate,
        "source_frequencies_hz": {
            "downlink": capture["dl_frequency_hz"],
            "uplink": capture["ul_frequency_hz"],
        },
        "cell_search_candidates": sorted(hits),
        "mib_confirmed_pcis": sorted(confirmed),
        "cells": cell_results,
    }
    write_json(results / "summary.json", summary)
    commands.chmod(0o755)
    print(json.dumps(summary, indent=2))
    return 0 if confirmed else 4


if __name__ == "__main__":
    raise SystemExit(main())
