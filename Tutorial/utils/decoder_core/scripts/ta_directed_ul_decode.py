#!/usr/bin/env python3
"""Decode LTE PUSCH using RAR/MAC-CE timing advance, with wide fallback.

Each grant whose C-RNTI has a known TA state is searched in a narrow window
around the predicted UE-local boundary. Previously CRC-valid results from the
wide top-four search are retained as the fallback for missing TA state, missed
TA updates, and narrow-search failures.
"""

from __future__ import annotations

import argparse
import bisect
import concurrent.futures
import json
import statistics
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from types import SimpleNamespace

from burst_first_ul_decode_v2 import decode_grant, rrc_hypotheses, standards_grants
from probe_ul_grants import extract_rrc_configs_many, parse_grants


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--grant-log", required=True, type=Path)
    parser.add_argument("--ta-state", required=True, type=Path)
    parser.add_argument("--pci", required=True, type=int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--fallback-jsonl", required=True, type=Path)
    parser.add_argument(
        "--reuse-acquisition", type=Path,
        help="reuse a prior ta_acquisition.jsonl instead of rescanning IQ",
    )
    parser.add_argument("--rrc-pcap", action="append", default=[], type=Path)
    parser.add_argument("--probe", type=Path, default=(
        Path(__file__).resolve().parents[1] / "build" / "ul_grant_probe"))
    parser.add_argument("--narrow-radius-us", type=float, default=30.0)
    parser.add_argument("--timing-candidates", type=int, default=4)
    parser.add_argument("--dmrs-min-snr-db", type=float, default=0.0)
    parser.add_argument("--dmrs-min-coherence", type=float, default=0.7)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--target-rnti", action="append", default=[], type=int,
        help="limit the TA-directed pass to this RNTI (repeatable); the wide "
             "fallback is still retained in full",
    )
    return parser.parse_args()


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def state_at(states: dict[int, list[dict]], rnti: int, file_sf: int) -> dict | None:
    timeline = states.get(rnti)
    if not timeline:
        return None
    positions = [int(item["effective_file_sf"]) for item in timeline]
    index = bisect.bisect_right(positions, file_sf) - 1
    return timeline[index] if index >= 0 else None


def packet_key(item: dict) -> tuple:
    grant, decoded = item["grant"], item["decode"]
    return (
        int(grant["file_sf"]), int(grant["tti"]), int(grant["rnti"]),
        str(decoded["payload_hex"]),
    )


def grant_key(grant: dict) -> tuple:
    return tuple(int(grant[name]) for name in (
        "file_sf", "tti", "rnti", "prb_tilde0", "prb_tilde1", "len_prb",
        "n_dmrs", "mcs", "tbs", "rv", "mod", "nof_ack", "cqi_request",
    ))


def acquire(args: argparse.Namespace, task: dict) -> dict:
    grant = task["grant"]
    command = [
        str(args.probe), "--input", str(args.input),
        "--target-sf", str(grant["file_sf"]),
        "--center-lag-samples", str(task["predicted_lag_samples"]),
        "--radius-ms", str(args.narrow_radius_us / 1000.0),
        "--pci", str(args.pci), "--tti", str(grant["tti"]),
        "--prb", str(grant["prb_tilde0"]),
        "--prb-slot1", str(grant["prb_tilde1"]),
        "--len-prb", str(grant["len_prb"]),
        "--n-dmrs", str(grant["n_dmrs"]),
        "--top", str(args.timing_candidates),
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
    for path in [args.input, args.grant_log, args.ta_state,
                 args.fallback_jsonl, args.probe, *args.rrc_pcap,
                 *([args.reuse_acquisition] if args.reuse_acquisition else [])]:
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    if args.narrow_radius_us <= 0 or args.timing_candidates <= 0:
        raise SystemExit("narrow radius and timing candidates must be positive")

    ta_document = json.loads(args.ta_state.read_text())
    states = {
        int(rnti): sorted(values, key=lambda item: int(item["effective_file_sf"]))
        for rnti, values in ta_document.get("states", {}).items()
    }
    fallback = load_jsonl(args.fallback_jsonl)

    # Estimate only a small fixed DSP/channelization bias. TA evolution remains
    # driven by decoded RAR/MAC-CE state, not by this calibration.
    residuals: dict[int, list[int]] = defaultdict(list)
    for packet in fallback:
        grant = packet["grant"]
        state = state_at(states, int(grant["rnti"]), int(grant["file_sf"]))
        measured = packet.get("dmrs") or packet.get("physical")
        if state and measured and "lag_samples" in measured:
            residual = int(measured["lag_samples"]) - int(state["lag_samples_5p76"])
            if abs(residual) <= 288:  # at most 50 us; larger means missing TA state
                residuals[int(grant["rnti"])].append(residual)
    lag_bias = {
        rnti: int(round(statistics.median(values)))
        for rnti, values in residuals.items() if values
    }

    grants = standards_grants(parse_grants(args.grant_log, strict=True), False)
    target_rntis = set(args.target_rnti)
    if target_rntis:
        grants = [grant for grant in grants
                  if int(grant["rnti"]) in target_rntis]
    unique_grants = {}
    for grant in grants:
        unique_grants.setdefault(grant_key(grant), grant)
    tasks = []
    for grant in unique_grants.values():
        rnti, file_sf = int(grant["rnti"]), int(grant["file_sf"])
        state = state_at(states, rnti, file_sf)
        if not state:
            continue
        tasks.append({
            "grant": grant, "ta_state": state,
            "lag_bias_samples": lag_bias.get(rnti, 0),
            "predicted_lag_samples": (
                int(state["lag_samples_5p76"]) + lag_bias.get(rnti, 0)
            ),
        })

    if args.reuse_acquisition:
        acquired = load_jsonl(args.reuse_acquisition)
        print(f"reused {len(acquired)} TA grant acquisitions")
    else:
        acquired = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=max(1, args.workers)) as pool:
            futures = [pool.submit(acquire, args, task) for task in tasks]
            for completed, future in enumerate(concurrent.futures.as_completed(futures), 1):
                acquired.append(future.result())
                if completed % 250 == 0:
                    print(f"TA-acquired {completed}/{len(tasks)} grants")

    accepted = []
    for item in acquired:
        for physical in item["physicals"]:
            if (float(physical.get("snr_db", -999.0)) >= args.dmrs_min_snr_db and
                    float(physical.get("coherence", 0.0)) >= args.dmrs_min_coherence):
                accepted.append((item, physical))

    configs = extract_rrc_configs_many(args.rrc_pcap)
    hypothesis_args = SimpleNamespace(unknown_uci="both")
    probe_args = SimpleNamespace(
        input=args.input, probe=args.probe,
        radius_ms=args.narrow_radius_us / 1000.0,
    )
    decode_tasks = []
    for item, physical in accepted:
        grant = item["grant"]
        allocation = {
            "prb0": int(grant["prb_tilde0"]),
            "prb1": int(grant["prb_tilde1"]),
            "len_prb": int(grant["len_prb"]),
        }
        acquisition = {"allocation": allocation, "pci": args.pci}
        burst = {"burst_sf": int(grant["file_sf"])}
        for uci in rrc_hypotheses(grant, configs, hypothesis_args):
            decode_tasks.append((item, physical, burst, acquisition, uci))

    attempts = []
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(decode_grant, probe_args, burst, acquisition,
                        item["grant"], physical, uci):
            (item, physical)
            for item, physical, burst, acquisition, uci in decode_tasks
        }
        for future in concurrent.futures.as_completed(future_map):
            item, physical = future_map[future]
            attempts.append({
                "burst_sf": int(item["grant"]["file_sf"]),
                "pci": args.pci,
                "allocation": {
                    "prb0": int(item["grant"]["prb_tilde0"]),
                    "prb1": int(item["grant"]["prb_tilde1"]),
                    "len_prb": int(item["grant"]["len_prb"]),
                },
                "grant_minus_burst_sf": 0,
                "ta_state": item["ta_state"],
                "predicted_lag_samples": item["predicted_lag_samples"],
                "lag_bias_samples": item["lag_bias_samples"],
                "dmrs": physical,
                "recovery_source": "ta_directed_narrow",
                **future.result(),
            })

    new_valid_groups: dict[tuple, list[dict]] = defaultdict(list)
    for attempt in attempts:
        if attempt["crc_valid"]:
            new_valid_groups[packet_key(attempt)].append(attempt)
    new_valid = {
        key: max(values, key=lambda item: (
            float(item["dmrs"].get("snr_db", -999.0)),
            float(item["dmrs"].get("coherence", 0.0)),
            -abs(int(item["dmrs"]["lag_samples"]) -
                 int(item["predicted_lag_samples"])),
        ))
        for key, values in new_valid_groups.items()
    }
    fallback_by_key = {packet_key(item): item for item in fallback}
    combined = dict(fallback_by_key)
    combined.update(new_valid)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "ta_acquisition.jsonl").open("w") as output:
        for item in sorted(acquired, key=lambda value: (
                int(value["grant"]["file_sf"]), int(value["grant"]["rnti"]))):
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    with (args.output_dir / "ta_decode_attempts.jsonl").open("w") as output:
        for item in sorted(attempts, key=lambda value: (
                int(value["grant"]["file_sf"]), int(value["grant"]["rnti"]))):
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    with (args.output_dir / "ta_crc_valid_only.jsonl").open("w") as output:
        for item in sorted(new_valid.values(), key=lambda value: (
                int(value["grant"]["file_sf"]), int(value["grant"]["rnti"]))):
            output.write(json.dumps(item, separators=(",", ":")) + "\n")
    with (args.output_dir / "crc_valid_ul.jsonl").open("w") as output:
        for item in sorted(combined.values(), key=lambda value: (
                int(value["grant"]["file_sf"]), int(value["grant"]["rnti"]))):
            output.write(json.dumps(item, separators=(",", ":")) + "\n")

    added = set(new_valid) - set(fallback_by_key)
    summary = {
        "input": str(args.input), "pci": args.pci,
        "ta_state": str(args.ta_state),
        "narrow_radius_us": args.narrow_radius_us,
        "timing_candidates": args.timing_candidates,
        "target_rntis": sorted(target_rntis),
        "strict_unique_grants": len(unique_grants),
        "rntis_with_ta_state": sorted(states),
        "grants_with_ta_prediction": len(tasks),
        "ta_dmrs_candidates_accepted": len(accepted),
        "ta_decode_attempts": len(attempts),
        "ta_crc_valid_packets": len(new_valid),
        "fallback_top4_packets": len(fallback_by_key),
        "added_by_ta_directed": len(added),
        "removed_from_fallback": 0,
        "combined_crc_valid_packets": len(combined),
        "lag_bias_samples_by_rnti": {str(k): v for k, v in sorted(lag_bias.items())},
        "ta_valid_by_rnti": dict(sorted(Counter(
            int(item["grant"]["rnti"]) for item in new_valid.values()).items())),
    }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
