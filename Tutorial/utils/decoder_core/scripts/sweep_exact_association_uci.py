#!/usr/bin/env python3
"""Sweep bounded LTE UCI hypotheses on already-acquired PUSCH associations."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
from pathlib import Path
from types import SimpleNamespace

from burst_first_ul_decode_v2 import decode_grant


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--associations", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--probe", type=Path, default=(
        Path(__file__).resolve().parents[1] / "build" / "ul_grant_probe"))
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--radius-ms", type=float, default=0.35)
    return parser.parse_args()


def hypotheses(grant: dict) -> list[dict]:
    ack_values = range(16) if int(grant["nof_ack"]) else (7,)
    values = []
    for ack in ack_values:
        # No periodic UCI; beta offsets are inert except ACK when present.
        values.append({
            "source": "bounded_uci_sweep", "known_rnti": False,
            "cqi_due": False, "cqi_type": "none", "ri_len": 0,
            "offset_ack": ack, "offset_cqi": 7, "offset_ri": 1,
        })
        # Periodic wideband CQI with all standardized beta-offset indices.
        for cqi in range(16):
            values.append({
                "source": "bounded_uci_sweep", "known_rnti": False,
                "cqi_due": True, "cqi_type": "wideband", "ri_len": 0,
                "offset_ack": ack, "offset_cqi": cqi, "offset_ri": 1,
            })
        # Periodic rank indication without simultaneous CQI.
        for ri in range(16):
            values.append({
                "source": "bounded_uci_sweep", "known_rnti": False,
                "cqi_due": False, "cqi_type": "none", "ri_len": 1,
                "offset_ack": ack, "offset_cqi": 7, "offset_ri": ri,
            })
    unique = {}
    for value in values:
        key = tuple(value[name] for name in (
            "cqi_type", "ri_len", "offset_ack", "offset_cqi", "offset_ri"
        ))
        unique[key] = value
    return list(unique.values())


def main() -> int:
    args = arguments()
    associations = [
        json.loads(line) for line in args.associations.read_text().splitlines()
        if line.strip()
    ]
    tasks = []
    probe_args = SimpleNamespace(
        input=args.input, probe=args.probe, radius_ms=args.radius_ms,
    )
    for index, association in enumerate(associations):
        burst = {"burst_sf": int(association["burst_sf"])}
        acquisition = {
            "allocation": association["allocation"],
            "pci": int(association["pci"]),
        }
        grant = association["grant"]
        expected = association["dmrs_expected"]
        for uci in hypotheses(grant):
            tasks.append((index, burst, acquisition, grant, expected, uci))

    valid = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(decode_grant, probe_args, burst, acquisition,
                        grant, expected, uci): (index, uci)
            for index, burst, acquisition, grant, expected, uci in tasks
        }
        for future in concurrent.futures.as_completed(future_map):
            index, uci = future_map[future]
            attempt = future.result()
            if attempt["crc_valid"]:
                valid.append({
                    "association_index": index,
                    "burst_sf": associations[index]["burst_sf"],
                    "pci": associations[index]["pci"],
                    "allocation": associations[index]["allocation"],
                    "dmrs": associations[index]["dmrs_expected"],
                    **attempt,
                })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    valid.sort(key=lambda item: (int(item["burst_sf"]),
                                 int(item["grant"]["tti"])))
    with args.output.open("w") as output:
        for item in valid:
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    summary = {
        "associations": len(associations), "decode_attempts": len(tasks),
        "crc_valid_attempts": len(valid),
        "crc_valid_associations": len({item["association_index"] for item in valid}),
        "output": str(args.output),
    }
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
