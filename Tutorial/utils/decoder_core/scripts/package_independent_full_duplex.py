#!/usr/bin/env python3
"""Package full DL-mode output with independently CRC-valid UL packets."""

from __future__ import annotations

import argparse
import json
import struct
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from failed_ul_jsonl_to_pcap import mac_lte_record
from make_lte_mib_pcap import encode_mib
from package_complete_dl_trace import parse_mib


TAG_LENGTHS = {0x02: 2, 0x03: 2, 0x04: 2, 0x07: 1, 0x0A: 1, 0x0F: 1}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def read_pcap(path: Path) -> list[bytes]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError(f"truncated PCAP: {path}")
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif data[:4] == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError(f"unsupported PCAP magic in {path}")
    linktype = struct.unpack_from(endian + "I", data, 20)[0]
    if linktype != 147:
        raise ValueError(f"expected DLT_USER0/147, got {linktype} in {path}")
    records = []
    offset = 24
    while offset + 16 <= len(data):
        included = struct.unpack_from(endian + "I", data, offset + 8)[0]
        offset += 16
        if offset + included > len(data):
            raise ValueError(f"truncated packet in {path}")
        records.append(data[offset : offset + included])
        offset += included
    return records


def mac_context(record: bytes) -> tuple[int, int]:
    if len(record) < 4:
        raise ValueError("short MAC-LTE framed record")
    direction = record[1]
    frame_subframe = None
    offset = 3
    while offset < len(record):
        tag = record[offset]
        offset += 1
        if tag == 0x01:
            break
        length = TAG_LENGTHS.get(tag)
        if length is None or offset + length > len(record):
            raise ValueError(f"unsupported MAC-LTE context tag 0x{tag:02x}")
        if tag == 0x04:
            frame_subframe = struct.unpack("!H", record[offset : offset + 2])[0]
        offset += length
    if frame_subframe is None:
        raise ValueError("MAC-LTE record has no SFN/subframe tag")
    sfn, subframe = frame_subframe >> 4, frame_subframe & 0x0F
    return direction, sfn * 10 + subframe


def write_pcap(path: Path, records: list[tuple[int, bytes]], base_us: int) -> None:
    occurrence = defaultdict(int)
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 147))
        for file_sf, record in records:
            extra_us = occurrence[file_sf]
            occurrence[file_sf] += 1
            timestamp_us = base_us + file_sf * 1000 + extra_us
            output.write(struct.pack(
                "<IIII", timestamp_us // 1_000_000, timestamp_us % 1_000_000,
                len(record), len(record),
            ))
            output.write(record)


def write_mib(path: Path, payload: bytes, base_us: int) -> None:
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 148))
        output.write(struct.pack(
            "<IIII", base_us // 1_000_000, base_us % 1_000_000,
            len(payload), len(payload),
        ))
        output.write(payload)


def main() -> int:
    args = arguments()
    capture_dir = args.capture_dir.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    cell_dir = capture_dir / "offline/cells/pci_1"
    dl_dir = cell_dir / "full_dl"
    dl_source = dl_dir / "ltesniffer_dl_mode.pcap"
    probe_source = cell_dir / "ltesniffer/independent_ul_probe.jsonl"

    valid_ul = []
    seen = set()
    for line in probe_source.read_text(errors="replace").splitlines():
        item = json.loads(line)
        grant = item.get("grant") or {}
        decoded = item.get("decode") or {}
        if not decoded.get("crc") or decoded.get("all_zero"):
            continue
        key = (int(grant["file_sf"]), int(grant["tti"]), int(grant["rnti"]))
        if key in seen:
            continue
        seen.add(key)
        valid_ul.append((
            int(grant["file_sf"]),
            mac_lte_record(
                bytes.fromhex(decoded["payload_hex"]),
                int(grant["rnti"]), int(grant["tti"]), True,
            ),
        ))
    if not valid_ul:
        raise ValueError("no independently CRC-valid UL packets")

    reference_file_sf = valid_ul[0][0]
    _, reference_tti = mac_context(valid_ul[0][1])
    tti_offset = (reference_tti - reference_file_sf) % 10240

    dl_records = []
    last_file_sf = -1
    for record in read_pcap(dl_source):
        direction, tti = mac_context(record)
        if direction != 1:
            continue
        file_sf = (tti - tti_offset) % 10240
        while file_sf < last_file_sf - 100:
            file_sf += 10240
        last_file_sf = max(last_file_sf, file_sf)
        dl_records.append((file_sf, record))

    combined = [(sf, 0, record) for sf, record in dl_records]
    combined.extend((sf, 1, record) for sf, record in valid_ul)
    combined.sort(key=lambda item: (item[0], item[1]))

    manifest = json.loads((capture_dir / "capture.json").read_text())
    capture_utc = manifest["capture_utc"]
    start = datetime.strptime(capture_utc, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    base_us = int(start.timestamp() * 1_000_000)

    mac_pcap = output_dir / "full_dl_plus_independent_crc_valid_ul.pcap"
    write_pcap(mac_pcap, [(sf, record) for sf, _, record in combined], base_us)

    mib = parse_mib(dl_dir / "decode.log")
    mib_payload = encode_mib(
        mib["nof_prb"], mib["phich_duration"], mib["phich_resource"], mib["sfn"]
    )
    mib_pcap = output_dir / "mib_bcch_bch.pcap"
    write_mib(mib_pcap, mib_payload, base_us)
    complete = output_dir / "complete_duplex_with_mib.pcapng"
    subprocess.run(["mergecap", "-w", str(complete), str(mib_pcap), str(mac_pcap)], check=True)

    metadata = {
        "capture": str(capture_dir),
        "pci": 1,
        "timing": {
            "method": "synthetic capture-relative timestamps from LTE SFN/subframe and independent UL file_sf",
            "tti_minus_file_sf_mod_10240": tti_offset,
        },
        "packets": {
            "mib": 1,
            "downlink_mac": len(dl_records),
            "independent_crc_valid_uplink_mac": len(valid_ul),
            "total_pcapng": 1 + len(dl_records) + len(valid_ul),
        },
        "outputs": {
            "mac_lte_dl_ul_pcap": str(mac_pcap),
            "complete_with_mib_pcapng": str(complete),
        },
        "mib": mib,
    }
    metadata_path = output_dir / "summary.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
