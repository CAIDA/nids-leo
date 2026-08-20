#!/usr/bin/env python3
"""Write tentative UL decoder bytes as CRC-failed MAC-LTE PCAP records."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import json
import struct
import time
from pathlib import Path


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path,
                        help="probe_ul_grants.py JSONL output")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--all-hypotheses",
        action="store_true",
        help="retain alternate TBS/modulation hypotheses for the same burst",
    )
    parser.add_argument(
        "--crc-valid-only",
        action="store_true",
        help="write only records whose independent transport-block CRC passed",
    )
    parser.add_argument(
        "--capture-manifest",
        type=Path,
        help=(
            "use capture_utc plus grant file_sf for capture-aligned packet "
            "timestamps instead of synthetic current-time timestamps"
        ),
    )
    parser.add_argument(
        "--file-sf-offset",
        type=int,
        default=0,
        help=(
            "add this many subframes to each JSONL file_sf when assigning "
            "capture timestamps (for an aligned segment cut from a longer capture)"
        ),
    )
    return parser.parse_args()


def mac_lte_record(payload: bytes, rnti: int, tti: int, crc_ok: bool) -> bytes:
    # Wireshark MAC-LTE framing from srsRAN pcap.c:
    # FDD, uplink, C-RNTI, tagged RNTI/UEID/SFN+SF/CRC/carrier/NB mode.
    frame_subframe = ((tti // 10) << 4) | (tti % 10)
    return b"".join((
        bytes((1, 0, 3, 0x02)),
        struct.pack("!H", rnti),
        bytes((0x03, 0, 0, 0x04)),
        struct.pack("!H", frame_subframe),
        bytes((0x07, int(crc_ok), 0x0A, 0, 0x0F, 0, 0x01)),
        payload,
    ))


def main() -> int:
    args = arguments()
    records = []
    seen: set[tuple[int, int, int]] = set()
    for line in args.input.read_text(errors="replace").splitlines():
        item = json.loads(line)
        grant = item.get("grant") or {}
        decoded = item.get("decode") or {}
        payload_hex = decoded.get("payload_hex", "")
        if not payload_hex:
            continue
        if args.crc_valid_only and not bool(decoded.get("crc", False)):
            continue
        physical_key = (
            int(grant["file_sf"]), int(grant["tti"]), int(grant["rnti"])
        )
        if not args.all_hypotheses and physical_key in seen:
            continue
        seen.add(physical_key)
        records.append((
            int(grant["file_sf"]) + args.file_sf_offset,
            mac_lte_record(
                bytes.fromhex(payload_hex),
                int(grant["rnti"]),
                int(grant["tti"]),
                bool(decoded.get("crc", False)),
            ),
        ))

    # Burst-first decoding is parallel, so JSONL completion order is not
    # necessarily radio-time order.  PCAP readers expect monotonically ordered
    # timestamps.
    records.sort(key=lambda entry: entry[0])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.capture_manifest:
        manifest = json.loads(args.capture_manifest.read_text())
        capture_start = datetime.strptime(
            manifest["capture_utc"], "%Y%m%dT%H%M%SZ"
        ).replace(tzinfo=timezone.utc)
        base_us = int(capture_start.timestamp() * 1_000_000)
        timestamp_method = (
            "capture_utc plus grant file_sf plus file_sf_offset="
            f"{args.file_sf_offset}"
        )
    else:
        base_us = int(time.time() * 1_000_000)
        timestamp_method = "synthetic current time"
    occurrences: dict[int, int] = defaultdict(int)
    with args.output.open("wb") as pcap:
        pcap.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147))
        for index, (file_sf, record) in enumerate(records):
            if args.capture_manifest:
                timestamp_us = base_us + file_sf * 1000 + occurrences[file_sf]
                occurrences[file_sf] += 1
            else:
                timestamp_us = base_us + index
            pcap.write(struct.pack(
                "<IIII",
                timestamp_us // 1_000_000,
                timestamp_us % 1_000_000,
                len(record),
                len(record),
            ))
            pcap.write(record)
    print(json.dumps({
        "input": str(args.input),
        "output": str(args.output),
        "packets": len(records),
        "timestamp_method": timestamp_method,
        "crc_status": (
            "all records valid" if args.crc_valid_only
            else "copied from each source decode record"
        ),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
