#!/usr/bin/env python3
"""Re-decode fixed DMRS associations with merged DL-derived RRC/UCI state."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
from pathlib import Path
from types import SimpleNamespace

from burst_first_ul_decode_v2 import decode_grant, rrc_hypotheses
from probe_ul_grants import extract_rrc_configs_many


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--associations", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--rrc-pcap", action="append", default=[], type=Path)
    parser.add_argument("--probe", type=Path, default=(
        Path(__file__).resolve().parents[1] / "build" / "ul_grant_probe"))
    parser.add_argument("--radius-ms", type=float, default=0.35)
    parser.add_argument("--workers", type=int, default=4)
    return parser.parse_args()


def main() -> int:
    args = arguments()
    associations = [
        json.loads(line) for line in args.associations.read_text().splitlines()
        if line.strip()
    ]
    configs = extract_rrc_configs_many(args.rrc_pcap)
    hypothesis_args = SimpleNamespace(unknown_uci="both")
    probe_args = SimpleNamespace(
        input=args.input, probe=args.probe, radius_ms=args.radius_ms,
    )

    tasks = []
    for index, association in enumerate(associations):
        burst = {"burst_sf": int(association["burst_sf"])}
        acquisition = {
            "allocation": association["allocation"],
            "pci": int(association["pci"]),
        }
        grant = association["grant"]
        expected = association["dmrs_expected"]
        for uci in rrc_hypotheses(grant, configs, hypothesis_args):
            tasks.append((index, burst, acquisition, grant, expected, uci))

    attempts = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(
                decode_grant, probe_args, burst, acquisition, grant,
                expected, uci,
            ): (index, burst, acquisition, expected)
            for index, burst, acquisition, grant, expected, uci in tasks
        }
        for future in concurrent.futures.as_completed(future_map):
            index, burst, acquisition, expected = future_map[future]
            attempt = future.result()
            attempts.append({
                "association_index": index,
                "burst_sf": burst["burst_sf"],
                "pci": acquisition["pci"],
                "allocation": acquisition["allocation"],
                "dmrs": expected,
                **attempt,
            })

    attempts.sort(key=lambda item: (
        int(item["burst_sf"]), int(item["grant"]["tti"]),
        str(item["uci"]["cqi_type"]),
    ))
    valid = [item for item in attempts if item["crc_valid"]]

    # At most one validated representation is retained per physical grant and
    # payload. This keeps the output directly compatible with the packager.
    unique = {}
    for item in valid:
        key = (
            int(item["burst_sf"]), int(item["pci"]),
            int(item["grant"]["rnti"]), item["decode"]["payload_hex"],
        )
        unique.setdefault(key, item)
    valid = list(unique.values())

    args.output_dir.mkdir(parents=True, exist_ok=True)
    attempts_path = args.output_dir / "rrc_redecode_attempts.jsonl"
    valid_path = args.output_dir / "crc_valid_ul.jsonl"
    with attempts_path.open("w") as output:
        for item in attempts:
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    with valid_path.open("w") as output:
        for item in valid:
            output.write(json.dumps(item, separators=(",", ":")) + "\n")

    associated_rntis = sorted({
        int(item["grant"]["rnti"]) for item in associations
    })
    summary = {
        "input": str(args.input),
        "associations": len(associations),
        "decode_attempts": len(attempts),
        "crc_valid_packets": len(valid),
        "associated_rntis": associated_rntis,
        "rrc_pcaps": [str(path) for path in args.rrc_pcap],
        "rrc_configured_associated_rntis": [
            rnti for rnti in associated_rntis if rnti in configs
        ],
        "rrc_configs": {
            str(rnti): configs[rnti]
            for rnti in associated_rntis if rnti in configs
        },
        "attempts_output": str(attempts_path),
        "crc_valid_output": str(valid_path),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
