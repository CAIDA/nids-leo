#!/usr/bin/env python3
"""Decode LTE UL grants with a DL-directed fast pass and wide fallback.

Each exact DCI/RAR grant is first searched at its DL-scheduled subframe over a
narrow timing window. Decoding stops for that grant after a valid transport-
block CRC. Only unresolved grants enter the burst-associated wide timing/DMRS
search, so the completeness fallback is retained without paying for it on
already-decoded packets.
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
    decode_grant_hypotheses,
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
        "--fast-radius-ms", type=float, default=0.75,
        help="DL-directed first-pass radius before the wide fallback",
    )
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


def acquire_expected_group(args: argparse.Namespace, tasks: list[dict],
                           radius_ms: float) -> list[dict]:
    """Acquire exact DMRS candidates once for grants sharing time/RBs."""
    first = tasks[0]
    burst, allocation = first["burst"], first["allocation"]
    sequence_keys = []
    for task in tasks:
        key = (int(task["grant"]["tti"]) % 10,
               int(task["grant"]["n_dmrs"]))
        if key not in sequence_keys:
            sequence_keys.append(key)
    command = [
        str(args.probe), "--input", str(args.input),
        "--target-sf", str(burst["burst_sf"]),
        "--radius-ms", str(radius_ms),
        "--pci", str(args.pci), "--tti", "0",
        "--prb", str(allocation["prb0"]),
        "--prb-slot1", str(allocation["prb1"]),
        "--len-prb", str(allocation["len_prb"]),
        "--n-dmrs", "0", "--top", str(args.timing_candidates),
        "--sequence-keys", ",".join(
            f"{sf_idx}:{n_dmrs}" for sf_idx, n_dmrs in sequence_keys
        ),
    ]
    run = subprocess.run(command, text=True, capture_output=True)
    physicals_by_sequence = defaultdict(list)
    for line in run.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("sequence_key_top"):
            key = (int(item["sf_idx"]), int(item["n_dmrs"]))
            physical = {
                name: value for name, value in item.items()
                if name not in {"sequence_key_top", "sequence_rank"}
            }
            physical["rank"] = len(physicals_by_sequence[key]) + 1
            physicals_by_sequence[key].append(physical)
    return [{
        **task,
        "physicals": physicals_by_sequence.get(
            (int(task["grant"]["tti"]) % 10,
             int(task["grant"]["n_dmrs"])),
            [],
        ),
        "acquire_return_code": run.returncode,
        "acquire_stderr": run.stderr.strip(),
    } for task in tasks]


def grant_key(grant: dict) -> tuple[int, ...]:
    return tuple(int(grant[name]) for name in (
        "file_sf", "tti", "rnti", "prb_tilde0", "prb_tilde1", "len_prb",
        "n_dmrs", "mcs", "tbs", "rv", "mod", "nof_ack", "cqi_request",
    ))


def acquire_tasks(args: argparse.Namespace, tasks: list[dict],
                  radius_ms: float, label: str) -> tuple[list[dict], int]:
    task_groups = defaultdict(list)
    for task in tasks:
        allocation = task["allocation"]
        key = (
            int(task["burst"]["burst_sf"]), int(allocation["prb0"]),
            int(allocation["prb1"]), int(allocation["len_prb"]),
        )
        task_groups[key].append(task)
    acquired = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        futures = [
            pool.submit(acquire_expected_group, args, group, radius_ms)
            for group in task_groups.values()
        ]
        for completed, future in enumerate(
                concurrent.futures.as_completed(futures), 1):
            acquired.extend(future.result())
            if completed % 100 == 0:
                print(
                    f"{label}: acquired {completed}/{len(task_groups)} "
                    "grouped exact-grant windows"
                )
    return acquired, len(task_groups)


def accepted_candidates(args: argparse.Namespace,
                        acquired: list[dict]) -> list[dict]:
    accepted = []
    for item in acquired:
        for physical in item["physicals"]:
            if (float(physical["snr_db"]) >= args.dmrs_min_snr_db and
                    float(physical.get("coherence", 0.0)) >=
                    args.dmrs_min_coherence):
                accepted.append({**item, "physical": physical})
    return accepted


def decode_until_crc(args: argparse.Namespace, candidates: list[dict],
                     configs: dict, radius_ms: float,
                     already_attempted: set[tuple] | None = None) -> list[dict]:
    """Try ranked candidates for one grant and stop after its first CRC hit."""
    hypothesis_args = SimpleNamespace(unknown_uci="both")
    probe_args = SimpleNamespace(
        input=args.input, probe=args.probe, radius_ms=radius_ms,
    )
    attempted = already_attempted or set()
    ordered = sorted(candidates, key=lambda item: (
        abs(int(item["grant_minus_burst_sf"])),
        int(item["physical"]["rank"]),
        -float(item["physical"]["snr_db"]),
    ))
    results = []
    for item in ordered:
        physical = item["physical"]
        physical_key = (
            int(physical["file_sample"]),
            round(float(physical["correction_hz"]), 3),
            int(physical["sf_idx"]), int(physical["n_dmrs"]),
        )
        if physical_key in attempted:
            continue
        attempted.add(physical_key)
        acquisition = {"allocation": item["allocation"], "pci": args.pci}
        ucis = rrc_hypotheses(item["grant"], configs, hypothesis_args)
        for uci in ucis:
            decoded = decode_grant_hypotheses(
                probe_args, item["burst"], acquisition, item["grant"],
                physical, [uci],
            )[0]
            attempt = {
                "burst_sf": int(item["burst"]["burst_sf"]),
                "pci": args.pci,
                "allocation": item["allocation"],
                "grant_minus_burst_sf": item["grant_minus_burst_sf"],
                "dmrs": physical,
                "recovery_source": item["recovery_source"],
                **decoded,
            }
            results.append(attempt)
            if attempt["crc_valid"]:
                return results
    return results


def decode_grant_groups(args: argparse.Namespace, accepted: list[dict],
                        configs: dict, radius_ms: float,
                        prior_attempts: list[dict] | None = None) -> list[dict]:
    grouped = defaultdict(list)
    for item in accepted:
        grouped[grant_key(item["grant"])].append(item)
    prior_by_grant = defaultdict(set)
    for item in prior_attempts or []:
        physical = item["dmrs"]
        prior_by_grant[grant_key(item["grant"])].add((
            int(physical["file_sample"]),
            round(float(physical["correction_hz"]), 3),
            int(physical["sf_idx"]), int(physical["n_dmrs"]),
        ))
    attempts = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(
                decode_until_crc, args, candidates, configs, radius_ms,
                prior_by_grant.get(key, set()),
            ): key
            for key, candidates in grouped.items()
        }
        for future in concurrent.futures.as_completed(future_map):
            attempts.extend(future.result())
    return attempts


def main() -> int:
    args = arguments()
    for path in [args.input, args.grant_log, args.burst_audit, args.probe,
                 *args.rrc_pcap]:
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    if (args.radius_ms <= 0 or args.fast_radius_ms <= 0 or
            args.fast_radius_ms > args.radius_ms or args.grant_delta_sf < 0 or
            args.timing_candidates <= 0):
        raise SystemExit(
            "radii and timing-candidate count must be positive; fast radius "
            "must not exceed fallback radius; grant delta must be nonnegative"
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

    # Phase 1: trust the DL grant's scheduled subframe, RB allocation, DMRS
    # sequence, MCS/TBS, and RRC-derived UCI first. No burst alias is needed.
    unique_grants = {}
    for task in tasks:
        unique_grants.setdefault(grant_key(task["grant"]), task["grant"])
    fast_tasks = []
    for grant in unique_grants.values():
        allocation = {
            "prb0": int(grant["prb_tilde0"]),
            "prb1": int(grant["prb_tilde1"]),
            "len_prb": int(grant["len_prb"]),
        }
        fast_tasks.append({
            "burst": {"burst_sf": int(grant["file_sf"])},
            "allocation": allocation,
            "grant": grant,
            "grant_minus_burst_sf": 0,
            "recovery_source": "dl_directed_fast",
        })

    fast_acquired, fast_windows = acquire_tasks(
        args, fast_tasks, args.fast_radius_ms, "fast DL pass"
    )
    fast_accepted = accepted_candidates(args, fast_acquired)
    configs = extract_rrc_configs_many(args.rrc_pcap)
    fast_attempts = decode_grant_groups(
        args, fast_accepted, configs, args.fast_radius_ms,
    )
    solved_fast = {
        grant_key(item["grant"]) for item in fast_attempts
        if item["crc_valid"]
    }

    # Phase 2: only grants without a fast-pass CRC enter the original ±wide
    # burst/DMRS association. This is the completeness-preserving fallback.
    fallback_tasks = []
    for task in tasks:
        if grant_key(task["grant"]) in solved_fast:
            continue
        fallback_tasks.append({
            **task, "recovery_source": "wide_burst_dmrs_fallback",
        })
    fallback_acquired, fallback_windows = acquire_tasks(
        args, fallback_tasks, args.radius_ms, "wide fallback"
    )
    fallback_accepted = accepted_candidates(args, fallback_acquired)
    fallback_attempts = decode_grant_groups(
        args, fallback_accepted, configs, args.radius_ms,
        prior_attempts=fast_attempts,
    )
    attempts = fast_attempts + fallback_attempts
    acquired = fast_acquired + fallback_acquired
    accepted = fast_accepted + fallback_accepted

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
        "fast_radius_ms": args.fast_radius_ms,
        "fallback_radius_ms": args.radius_ms,
        "timing_candidates_per_grant": args.timing_candidates,
        "grant_delta_sf": args.grant_delta_sf,
        "detected_bursts_reused": len(bursts),
        "unique_dl_grants": len(unique_grants),
        "grant_directed_timing_tasks": len(tasks),
        "fast_grouped_timing_windows": fast_windows,
        "fast_dmrs_accepted": len(fast_accepted),
        "fast_decode_attempts": len(fast_attempts),
        "fast_crc_valid_grants": len(solved_fast),
        "fallback_grants": len(unique_grants) - len(solved_fast),
        "fallback_timing_tasks": len(fallback_tasks),
        "fallback_grouped_timing_windows": fallback_windows,
        "fallback_dmrs_accepted": len(fallback_accepted),
        "fallback_decode_attempts": len(fallback_attempts),
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
