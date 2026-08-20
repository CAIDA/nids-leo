#!/usr/bin/env python3
"""Package segmented LTE DL traces with independently CRC-valid UL packets."""

from __future__ import annotations

import argparse
import json
import re
import struct
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from failed_ul_jsonl_to_pcap import mac_lte_record
from make_lte_mib_pcap import encode_mib
from package_independent_full_duplex import TAG_LENGTHS, mac_context, read_pcap


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--ul-jsonl", action="append", default=[], metavar="LABEL=PATH",
        help=(
            "override or add the UL JSONL for a segment label; repeat for "
            "multiple cells"
        ),
    )
    return parser.parse_args()


def context_offsets(record: bytes) -> tuple[int, int]:
    rnti_offset = None
    ueid_offset = None
    offset = 3
    while offset < len(record):
        tag = record[offset]
        offset += 1
        if tag == 0x01:
            break
        length = TAG_LENGTHS.get(tag)
        if length is None or offset + length > len(record):
            raise ValueError(f"unsupported MAC-LTE context tag 0x{tag:02x}")
        if tag == 0x02:
            rnti_offset = offset
        elif tag == 0x03:
            ueid_offset = offset
        offset += length
    if rnti_offset is None or ueid_offset is None:
        raise ValueError("MAC-LTE record lacks RNTI or UEID context")
    return rnti_offset, ueid_offset


def isolate_context(record: bytes, pci: int,
                    context_ids: dict[tuple[int, int], int]) -> bytes:
    rnti_offset, ueid_offset = context_offsets(record)
    rnti = struct.unpack_from("!H", record, rnti_offset)[0]
    key = (pci, rnti)
    if key not in context_ids:
        context_ids[key] = len(context_ids) + 1
    rewritten = bytearray(record)
    struct.pack_into("!H", rewritten, ueid_offset, context_ids[key])
    return bytes(rewritten)


def parse_mib(log: Path) -> dict:
    text = log.read_text(errors="replace")
    match = re.search(r"Decoded MIB\. SFN: (\d+), offset: (\d+)", text)
    if not match:
        raise ValueError(f"no decoded MIB in {log}")
    phich_length = re.search(r"PHICH Length:\s+(\w+)", text)
    phich_resources = re.search(r"PHICH Resources:\s+(\S+)", text)
    sfn, offset = map(int, match.groups())
    return {
        "sfn": sfn, "sfn_offset": offset,
        "tti0": ((sfn + offset) % 1024) * 10,
        "phich_length": phich_length.group(1).lower() if phich_length else "normal",
        "phich_resources": phich_resources.group(1) if phich_resources else "1/6",
    }


def unwrap_downlink(records: list[bytes], tti0: int) -> list[tuple[int, bytes]]:
    result = []
    last = -1
    for record in records:
        direction, tti = mac_context(record)
        if direction != 1:
            continue
        file_sf = (tti - tti0) % 10240
        while file_sf < last - 100:
            file_sf += 10240
        last = max(last, file_sf)
        result.append((file_sf, record))
    return result


def write_pcap(path: Path, linktype: int,
               records: list[tuple[int, bytes]]) -> None:
    occurrences = defaultdict(int)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4,
                                 0, 0, 65535, linktype))
        for timestamp_us, payload in sorted(records, key=lambda item: item[0]):
            timestamp_us += occurrences[timestamp_us]
            occurrences[timestamp_us] += 1
            output.write(struct.pack(
                "<IIII", timestamp_us // 1_000_000,
                timestamp_us % 1_000_000, len(payload), len(payload)))
            output.write(payload)


def main() -> int:
    args = arguments()
    run = args.run.resolve()
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    spec = json.loads(args.spec.read_text())
    ul_overrides = {}
    for value in args.ul_jsonl:
        if "=" not in value:
            raise SystemExit(f"invalid --ul-jsonl value: {value}")
        label, path = value.split("=", 1)
        if not label or not path:
            raise SystemExit(f"invalid --ul-jsonl value: {value}")
        ul_overrides[label] = path
    manifest = json.loads((run / "capture.json").read_text())
    start = datetime.strptime(manifest["capture_utc"], "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc)
    base_us = int(start.timestamp() * 1_000_000)

    context_ids: dict[tuple[int, int], int] = {}
    all_mac = []
    all_ul = []
    all_mib = []
    per_segment = []
    per_pci_mac: dict[int, list[tuple[int, bytes]]] = defaultdict(list)
    per_pci_mib: dict[int, list[tuple[int, bytes]]] = defaultdict(list)

    for cell in spec["cells"]:
        pci = int(cell["pci"])
        anchor_sf = int(round(float(cell["anchor_s"]) * 1000))
        anchor_us = base_us + anchor_sf * 1000
        pcap = run / cell["dl_pcap"]
        log = run / cell["decode_log"]
        mib = parse_mib(log)
        downlink = unwrap_downlink(read_pcap(pcap), int(mib["tti0"]))
        segment_mac = []
        for file_sf, record in downlink:
            rewritten = isolate_context(record, pci, context_ids)
            item = (anchor_us + file_sf * 1000, rewritten)
            segment_mac.append(item)
            all_mac.append(item)
            per_pci_mac[pci].append(item)

        mib_payload = encode_mib(
            25, mib["phich_length"], mib["phich_resources"], mib["sfn"])
        mib_item = (anchor_us, mib_payload)
        all_mib.append(mib_item)
        per_pci_mib[pci].append(mib_item)

        segment_ul = []
        ul_jsonl = ul_overrides.get(cell["label"], cell.get("ul_jsonl"))
        if ul_jsonl:
            for line in (run / ul_jsonl).read_text().splitlines():
                item = json.loads(line)
                grant, decoded = item["grant"], item["decode"]
                if not decoded.get("crc") or decoded.get("all_zero"):
                    continue
                record = mac_lte_record(
                    bytes.fromhex(decoded["payload_hex"]),
                    int(grant["rnti"]), int(grant["tti"]), True)
                record = isolate_context(record, pci, context_ids)
                stamped = (anchor_us + int(grant["file_sf"]) * 1000, record)
                segment_ul.append(stamped)
                all_ul.append(stamped)
                all_mac.append(stamped)
                per_pci_mac[pci].append(stamped)

        per_segment.append({
            "label": cell["label"], "pci": pci,
            "anchor_seconds": float(cell["anchor_s"]),
            "tti0": mib["tti0"], "mib": mib,
            "downlink_mac": len(segment_mac),
            "crc_valid_uplink_mac": len(segment_ul),
        })

    mac_pcap = output_dir / "all_cells_full_dl_plus_crc_valid_ul.pcap"
    ul_pcap = output_dir / "all_cells_crc_valid_ul_only.pcap"
    mib_pcap = output_dir / "all_cells_mib.pcap"
    complete = output_dir / "all_cells_complete_dl_ul_with_mib.pcapng"
    write_pcap(mac_pcap, 147, all_mac)
    write_pcap(ul_pcap, 147, all_ul)
    write_pcap(mib_pcap, 148, all_mib)
    subprocess.run(["mergecap", "-w", str(complete),
                    str(mib_pcap), str(mac_pcap)], check=True)

    per_pci_outputs = {}
    for pci in sorted(set(per_pci_mac) | set(per_pci_mib)):
        directory = output_dir / "per_pci" / f"pci{pci}"
        mac_path = directory / "complete_dl_plus_crc_valid_ul.pcap"
        mib_path = directory / "mib.pcap"
        complete_path = directory / "complete_dl_ul_with_mib.pcapng"
        write_pcap(mac_path, 147, per_pci_mac[pci])
        write_pcap(mib_path, 148, per_pci_mib[pci])
        subprocess.run(["mergecap", "-w", str(complete_path),
                        str(mib_path), str(mac_path)], check=True)
        per_pci_outputs[str(pci)] = str(complete_path)

    summary = {
        "capture": str(run),
        "ul_jsonl_overrides": ul_overrides,
        "timestamp_method": (
            "capture UTC plus segment anchor plus LTE TTI unwrapped from "
            "the decoded MIB SFN offset"
        ),
        "pci_matching_method": (
            "unique MAC-LTE UEID per (PCI,RNTI); UL reuses its serving "
            "PCI/RNTI UEID; per-PCI PCAPNGs are also emitted"
        ),
        "segments": per_segment,
        "ue_contexts": {
            f"pci{pci}_rnti{rnti}": ueid
            for (pci, rnti), ueid in sorted(context_ids.items())
        },
        "packets": {
            "downlink_mac": sum(item["downlink_mac"] for item in per_segment),
            "crc_valid_uplink_mac": len(all_ul),
            "mib": len(all_mib),
            "complete_total": len(all_mac) + len(all_mib),
        },
        "outputs": {
            "combined_complete": str(complete),
            "combined_mac_dl_ul": str(mac_pcap),
            "uplink_only": str(ul_pcap),
            "mib_only": str(mib_pcap),
            "per_pci": per_pci_outputs,
        },
        "limitations": (
            "UL contains only independently CRC-valid nonzero transport "
            "blocks. Strong UL bursts without a valid transport CRC are excluded."
        ),
    }
    summary_path = output_dir / "full_trace_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
