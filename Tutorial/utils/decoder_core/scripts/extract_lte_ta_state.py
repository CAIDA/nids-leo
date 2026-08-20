#!/usr/bin/env python3
"""Extract per-C-RNTI LTE timing-advance state from a DL MAC PCAP.

RAR timing advance is an absolute 11-bit command in units of 16 Ts. Later
MAC timing-advance control elements are signed updates encoded as A - 31 and
become usable for UL prediction six subframes after their DL reception.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--decode-log", required=True, type=Path)
    parser.add_argument("--pci", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--apply-delay-sf", type=int, default=6)
    return parser.parse_args()


def parse_tti0(log: Path) -> int:
    text = log.read_text(errors="replace")
    match = re.search(r"Decoded MIB\. SFN: (\d+), offset: (\d+)", text)
    if not match:
        raise ValueError(f"no decoded MIB timing in {log}")
    sfn, offset = map(int, match.groups())
    return ((sfn + offset) % 1024) * 10


def split_values(value: str) -> list[str]:
    return [part for part in value.split(",") if part]


def main() -> int:
    args = arguments()
    for path in (args.pcap, args.decode_log):
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    tti0 = parse_tti0(args.decode_log)
    command = [
        "tshark", "-r", str(args.pcap),
        "-Y", "mac-lte.direction == 1 && (mac-lte.rar || mac-lte.control.timing-advance)",
        "-T", "fields", "-E", "separator=|", "-E", "occurrence=a",
        "-E", "aggregator=,",
        "-e", "frame.number", "-e", "mac-lte.sfn",
        "-e", "mac-lte.subframe", "-e", "mac-lte.rnti",
        "-e", "mac-lte.rar.rapid", "-e", "mac-lte.rar.ta",
        "-e", "mac-lte.rar.temporary-crnti",
        "-e", "mac-lte.control.timing-advance.command",
    ]
    run = subprocess.run(command, text=True, capture_output=True, check=True)
    events = []
    last_file_sf = -1
    for line in run.stdout.splitlines():
        fields = (line.split("|") + [""] * 8)[:8]
        frame, sfn, subframe, context_rnti, rapids, rar_tas, temporary_rntis, adjustment = fields
        if not sfn or not subframe:
            continue
        tti = int(sfn) * 10 + int(subframe)
        file_sf = (tti - tti0) % 10240
        while file_sf < last_file_sf - 100:
            file_sf += 10240
        last_file_sf = max(last_file_sf, file_sf)
        ta_values = split_values(rar_tas)
        crnti_values = split_values(temporary_rntis)
        rapid_values = split_values(rapids)
        for index, (ta_value, crnti_value) in enumerate(zip(ta_values, crnti_values)):
            events.append({
                "kind": "initial_rar", "pci": args.pci,
                "frame": int(frame), "file_sf": file_sf, "tti": tti,
                "effective_file_sf": file_sf + args.apply_delay_sf,
                "ra_rnti": int(context_rnti),
                "rapid": int(rapid_values[index], 0) if index < len(rapid_values) else None,
                "rnti": int(crnti_value, 0), "ta_raw": int(ta_value, 0),
                "lag_samples_5p76": -3 * int(ta_value, 0),
            })
        if adjustment:
            command_value = int(split_values(adjustment)[0], 0)
            events.append({
                "kind": "adjustment", "pci": args.pci,
                "frame": int(frame), "file_sf": file_sf, "tti": tti,
                "effective_file_sf": file_sf + args.apply_delay_sf,
                "rnti": int(context_rnti), "command": command_value,
                "delta_raw": command_value - 31,
                "delta_samples_5p76": -3 * (command_value - 31),
            })

    events.sort(key=lambda item: (item["file_sf"], item["frame"], item["kind"]))
    states: dict[int, list[dict]] = defaultdict(list)
    current: dict[int, int] = {}
    for event in sorted(events, key=lambda item: (
            item["effective_file_sf"], item["frame"], item["kind"])):
        rnti = int(event["rnti"])
        if event["kind"] == "initial_rar":
            current[rnti] = int(event["ta_raw"])
        elif rnti not in current:
            event["ignored_without_initial_rar"] = True
            continue
        else:
            current[rnti] += int(event["delta_raw"])
        states[rnti].append({
            "effective_file_sf": int(event["effective_file_sf"]),
            "ta_raw": current[rnti],
            "lag_samples_5p76": -3 * current[rnti],
            "source_frame": int(event["frame"]),
            "source_kind": event["kind"],
        })

    result = {
        "pcap": str(args.pcap), "decode_log": str(args.decode_log),
        "pci": args.pci, "tti0": tti0,
        "apply_delay_sf": args.apply_delay_sf,
        "events": events,
        "states": {str(rnti): values for rnti, values in sorted(states.items())},
        "summary": {
            "initial_rars": sum(e["kind"] == "initial_rar" for e in events),
            "adjustments": sum(e["kind"] == "adjustment" for e in events),
            "rntis_with_initial_ta": len(states),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
