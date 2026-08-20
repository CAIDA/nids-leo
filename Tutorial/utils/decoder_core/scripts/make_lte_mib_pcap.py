#!/usr/bin/env python3
"""Create a one-packet USER1 PCAP carrying an LTE BCCH-BCH MIB."""

from __future__ import annotations

import argparse
import json
import struct
import time
from pathlib import Path


BANDWIDTH_ENUM = {6: 0, 15: 1, 25: 2, 50: 3, 75: 4, 100: 5}
PHICH_DURATION_ENUM = {"normal": 0, "extended": 1}
PHICH_RESOURCE_ENUM = {"1/6": 0, "1/2": 1, "1": 2, "2": 3}


def encode_mib(prb: int, phich_duration: str, phich_resource: str, sfn: int) -> bytes:
    # 3GPP TS 36.331 unaligned PER layout:
    # dl-Bandwidth(3), phich-Duration(1), phich-Resource(2),
    # systemFrameNumber MSB 8 bits, spare(10).
    value = (
        (BANDWIDTH_ENUM[prb] << 21)
        | (PHICH_DURATION_ENUM[phich_duration] << 20)
        | (PHICH_RESOURCE_ENUM[phich_resource] << 18)
        | (((sfn >> 2) & 0xFF) << 10)
    )
    return value.to_bytes(3, "big")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-output", type=Path)
    parser.add_argument("--pci", type=int, required=True)
    parser.add_argument("--prb", type=int, choices=sorted(BANDWIDTH_ENUM), required=True)
    parser.add_argument("--ports", type=int, required=True)
    parser.add_argument("--phich-duration", choices=PHICH_DURATION_ENUM, required=True)
    parser.add_argument("--phich-resource", choices=PHICH_RESOURCE_ENUM, required=True)
    parser.add_argument("--sfn", type=int, required=True)
    parser.add_argument("--timestamp", type=float, default=time.time())
    args = parser.parse_args()

    payload = encode_mib(
        args.prb, args.phich_duration, args.phich_resource, args.sfn
    )
    seconds = int(args.timestamp)
    microseconds = int((args.timestamp - seconds) * 1_000_000)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as handle:
        # Classic little-endian PCAP, DLT_USER1 (148).
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 148))
        handle.write(
            struct.pack("<IIII", seconds, microseconds, len(payload), len(payload))
        )
        handle.write(payload)

    metadata = {
        "pci": args.pci,
        "nof_prb": args.prb,
        "nof_ports": args.ports,
        "phich_duration": args.phich_duration,
        "phich_resource": args.phich_resource,
        "decoded_sfn": args.sfn,
        "encoded_system_frame_number_msb8": args.sfn >> 2,
        "bcch_bch_payload_hex": payload.hex(),
        "pcap_linktype": "DLT_USER1 (148)",
        "wireshark_decode_as": "lte-rrc.bcch.bch",
    }
    metadata_output = args.metadata_output or args.output.with_suffix(".json")
    metadata_output.write_text(json.dumps(metadata, indent=2) + "\n")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
