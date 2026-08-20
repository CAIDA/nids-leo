#!/usr/bin/env python3
"""Add a decoded LTE MIB to a DL-mode MAC trace as a second PCAPNG interface."""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
from pathlib import Path

from make_lte_mib_pcap import encode_mib


def first_pcap_timestamp(path: Path) -> float:
    with path.open("rb") as handle:
        header = handle.read(24)
        packet = handle.read(16)
    if len(header) != 24 or len(packet) != 16:
        raise ValueError(f"no packet timestamp in {path}")
    magic = header[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian, divisor = "<", 1_000_000
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian, divisor = ">", 1_000_000
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian, divisor = "<", 1_000_000_000
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian, divisor = ">", 1_000_000_000
    else:
        raise ValueError(f"unsupported PCAP magic {magic.hex()} in {path}")
    seconds, fraction = struct.unpack(f"{endian}II", packet[:8])
    return seconds + fraction / divisor


def parse_mib(log_path: Path) -> dict:
    text = log_path.read_text(errors="replace")
    patterns = {
        "frame_type": r"- Type:\s+(\S+)",
        "pci": r"- PCI:\s+(\d+)",
        "nof_ports": r"- Nof ports:\s+(\d+)",
        "cp": r"- CP:\s+(\S+)",
        "nof_prb": r"- PRB:\s+(\d+)",
        "phich_duration": r"- PHICH Length:\s+(\S+)",
        "phich_resource": r"- PHICH Resources:\s+(\S+)",
        "sfn": r"Decoded MIB\. SFN:\s+(\d+)",
    }
    result = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, text)
        if not match:
            raise ValueError(f"{key} not found in {log_path}")
        result[key] = match.group(1)
    for key in ("pci", "nof_ports", "nof_prb", "sfn"):
        result[key] = int(result[key])
    result["phich_duration"] = result["phich_duration"].lower()
    return result


def write_mib_pcap(path: Path, payload: bytes, timestamp: float) -> None:
    seconds = int(timestamp)
    microseconds = int((timestamp - seconds) * 1_000_000)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 148))
        handle.write(
            struct.pack("<IIII", seconds, microseconds, len(payload), len(payload))
        )
        handle.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-dir", type=Path, required=True)
    args = parser.parse_args()

    trace_dir = args.trace_dir.resolve()
    dl_pcap = trace_dir / "ltesniffer_dl_mode.pcap"
    decode_log = trace_dir / "decode.log"
    mib = parse_mib(decode_log)
    payload = encode_mib(
        mib["nof_prb"],
        mib["phich_duration"],
        mib["phich_resource"],
        mib["sfn"],
    )
    mib_pcap = trace_dir / "mib_bcch_bch.pcap"
    write_mib_pcap(mib_pcap, payload, first_pcap_timestamp(dl_pcap))

    metadata = {
        **mib,
        "bcch_bch_payload_hex": payload.hex(),
        "mib_interface": {
            "linktype": "DLT_USER1 (148)",
            "wireshark_payload": "lte-rrc.bcch.bch",
        },
        "mac_lte_interface": {
            "linktype": "DLT_USER0 (147)",
            "wireshark_payload": "mac-lte-framed",
        },
        "interpretation": (
            "The MIB is PBCH/BCCH-BCH rather than a MAC PDU, so the complete "
            "PCAPNG uses a separate interface for it."
        ),
    }
    (trace_dir / "mib.json").write_text(json.dumps(metadata, indent=2) + "\n")

    complete = trace_dir / "complete_dl_with_mib.pcapng"
    subprocess.run(
        ["mergecap", "-w", str(complete), str(mib_pcap), str(dl_pcap)],
        check=True,
    )
    print(complete)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
