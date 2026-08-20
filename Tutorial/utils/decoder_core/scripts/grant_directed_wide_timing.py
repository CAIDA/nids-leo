#!/usr/bin/env python3
"""Reacquire known LTE UL grants over a wide, grant-directed timing window.

Unlike the blind 10x8 DMRS table search, each timing/CFO candidate is ranked
using the exact DCI/RAR grant PCI, subframe sequence, cyclic shift, and RB
allocation. This prevents a wide NTN timing window from anchoring to an
unrelated neighboring PUSCH transmission.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

from burst_first_ul_decode_v2 import (
    decode_grant,
    grant_for_allocation,
    rrc_hypotheses,
    standards_grants,
)
from probe_ul_grants import (
    extract_rrc_configs_many,
    parse_grants,
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--grant-log", required=True, type=Path)
    parser.add_argument("--burst-audit", required=True, type=Path)
    parser.add_argument("--pci", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--rrc-pcap", action="append", default=[], type=Path)
    parser.add_argument("--probe", type=Path, default=(
        Path(__file__).resolve().parents[1] / "build" / "ul_grant_probe"))
    parser.add_argument("--radius-ms", type=float, default=1.5)
    parser.add_argument(
        "--grant-delta-sf", type=int, default=2,
        help="test grants within this many grid subframes of a detected burst",
    )
    parser.add_argument("--dmrs-min-snr-db", type=float, default=0.0)
    parser.add_argument("--dmrs-min-coherence", type=float, default=0.7)
    parser.add_argument(
        "--timing-candidates", type=int, default=4,
        help=(
            "number of exact-grant timing/CFO peaks to CRC-test per window; "
            "use several candidates for multi-subframe search radii"
        ),
    )
    parser.add_argument("--workers", type=int, default=4)
    return parser.parse_args()


def acquire_expected(args: argparse.Namespace, task: dict) -> dict:
    burst, allocation, grant = task["burst"], task["allocation"], task["grant"]
    command = [
        str(args.probe), "--input", str(args.input),
        "--target-sf", str(burst["burst_sf"]),
        "--radius-ms", str(args.radius_ms),
        "--pci", str(args.pci), "--tti", str(grant["tti"]),
        "--prb", str(allocation["prb0"]),
        "--prb-slot1", str(allocation["prb1"]),
        "--len-prb", str(allocation["len_prb"]),
        "--n-dmrs", str(grant["n_dmrs"]), "--top",
        str(args.timing_candidates),
    ]
    run = subprocess.run(command, text=True, capture_output=True)
    physicals = []
    for line in run.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item.get("rank"), int):
            physicals.append(item)
    physicals.sort(key=lambda item: int(item["rank"]))
    return {
        **task, "physicals": physicals,
        "acquire_return_code": run.returncode,
        "acquire_stderr": run.stderr.strip(),
    }


def main() -> int:
    args = arguments()
    for path in [args.input, args.grant_log, args.burst_audit, args.probe,
                 *args.rrc_pcap]:
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    if (args.radius_ms <= 0 or args.grant_delta_sf < 0 or
            args.timing_candidates <= 0):
        raise SystemExit(
            "radius and timing-candidate count must be positive; "
            "grant delta must be nonnegative"
        )

    bursts = [
        json.loads(line) for line in args.burst_audit.read_text().splitlines()
        if line.strip()
    ]
    grants = standards_grants(parse_grants(args.grant_log, strict=True), False)
    grants_by_sf: dict[int, list[dict]] = defaultdict(list)
    for grant in grants:
        grants_by_sf[int(grant["file_sf"])].append(grant)

    tasks_by_key = {}
    for burst in bursts:
        burst_sf = int(burst["burst_sf"])
        nearby = []
        for delta in range(-args.grant_delta_sf, args.grant_delta_sf + 1):
            nearby.extend(grants_by_sf.get(burst_sf + delta, []))
        for allocation in burst.get("candidate_allocations", []):
            for grant in nearby:
                if not grant_for_allocation(grant, allocation):
                    continue
                key = (
                    burst_sf, int(grant["file_sf"]), int(grant["tti"]),
                    int(grant["rnti"]), int(grant["prb_tilde0"]),
                    int(grant["prb_tilde1"]), int(grant["len_prb"]),
                    int(grant["n_dmrs"]), int(grant["mcs"]),
                    int(grant["tbs"]), int(grant["rv"]),
                )
                tasks_by_key.setdefault(key, {
                    "burst": {"burst_sf": burst_sf},
                    "allocation": allocation,
                    "grant": grant,
                    "grant_minus_burst_sf": int(grant["file_sf"]) - burst_sf,
                })
    tasks = list(tasks_by_key.values())

    acquired = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        futures = [pool.submit(acquire_expected, args, task) for task in tasks]
        for completed, future in enumerate(
                concurrent.futures.as_completed(futures), 1):
            acquired.append(future.result())
            if completed % 250 == 0:
                print(f"acquired {completed}/{len(tasks)} exact-grant windows")

    accepted = []
    for item in acquired:
        for physical in item["physicals"]:
            if (float(physical["snr_db"]) >= args.dmrs_min_snr_db and
                    float(physical.get("coherence", 0.0)) >=
                    args.dmrs_min_coherence):
                accepted.append({**item, "physical": physical})

    configs = extract_rrc_configs_many(args.rrc_pcap)
    hypothesis_args = SimpleNamespace(unknown_uci="both")
    probe_args = SimpleNamespace(
        input=args.input, probe=args.probe, radius_ms=args.radius_ms,
    )
    decode_tasks = []
    for item in accepted:
        acquisition = {"allocation": item["allocation"], "pci": args.pci}
        for uci in rrc_hypotheses(item["grant"], configs, hypothesis_args):
            decode_tasks.append((item, acquisition, uci))

    attempts = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(
                decode_grant, probe_args, item["burst"], acquisition,
                item["grant"], item["physical"], uci,
            ): item
            for item, acquisition, uci in decode_tasks
        }
        for future in concurrent.futures.as_completed(future_map):
            item = future_map[future]
            attempts.append({
                "burst_sf": int(item["burst"]["burst_sf"]),
                "pci": args.pci,
                "allocation": item["allocation"],
                "grant_minus_burst_sf": item["grant_minus_burst_sf"],
                "dmrs": item["physical"],
                **future.result(),
            })

    attempts.sort(key=lambda item: (
        int(item["grant"]["file_sf"]), int(item["grant"]["rnti"]),
        int(item["burst_sf"]), str(item["uci"]["cqi_type"]),
    ))
    valid = [item for item in attempts if item["crc_valid"]]
    grouped = defaultdict(list)
    for item in valid:
        key = (
            args.pci, int(item["grant"]["file_sf"]),
            int(item["grant"]["tti"]), int(item["grant"]["rnti"]),
            item["decode"]["payload_hex"],
        )
        grouped[key].append(item)
    unique_valid = [
        max(values, key=lambda item: (
            float(item["dmrs"]["snr_db"]),
            float(item["dmrs"].get("coherence", 0.0)),
            -abs(int(item["grant_minus_burst_sf"])),
        ))
        for values in grouped.values()
    ]
    unique_valid.sort(key=lambda item: (
        int(item["grant"]["file_sf"]), int(item["grant"]["rnti"])
    ))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    acquisition_path = args.output_dir / "grant_directed_acquisition.jsonl"
    attempts_path = args.output_dir / "decode_attempts.jsonl"
    valid_path = args.output_dir / "crc_valid_ul.jsonl"
    with acquisition_path.open("w") as output:
        for item in sorted(acquired, key=lambda value: (
                int(value["burst"]["burst_sf"]),
                int(value["grant"]["file_sf"]),
                int(value["grant"]["rnti"]))):
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    with attempts_path.open("w") as output:
        for item in attempts:
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    with valid_path.open("w") as output:
        for item in unique_valid:
            output.write(json.dumps(item, separators=(",", ":")) + "\n")

    summary = {
        "input": str(args.input), "pci": args.pci,
        "radius_ms": args.radius_ms,
        "timing_candidates_per_grant": args.timing_candidates,
        "grant_delta_sf": args.grant_delta_sf,
        "detected_bursts_reused": len(bursts),
        "grant_directed_timing_tasks": len(tasks),
        "dmrs_accepted": len(accepted),
        "decode_attempts": len(attempts),
        "crc_valid_packets": len(unique_valid),
        "crc_valid_grant_minus_burst_sf": dict(sorted(Counter(
            int(item["grant_minus_burst_sf"]) for item in unique_valid
        ).items())),
        "rrc_pcaps": [str(path) for path in args.rrc_pcap],
        "acquisition_output": str(acquisition_path),
        "decode_attempts_output": str(attempts_path),
        "crc_valid_output": str(valid_path),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
