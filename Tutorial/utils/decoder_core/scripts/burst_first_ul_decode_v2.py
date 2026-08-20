#!/usr/bin/env python3
"""Strict burst-first LTE PUSCH association and decode.

The pipeline deliberately orders evidence as follows:

1. detect UL energy and an approximate occupied-RB boundary from IQ;
2. acquire an exact CP boundary/CFO and a complete 10x8 DMRS sequence table;
3. admit DCI0/RAR grants only when their exact allocation and DMRS sequence
   match that waveform;
4. apply decoded per-RNTI RRC/UCI state (or a small, explicit unknown-UE set);
5. decode and promote only nonzero transport blocks with a valid CRC.

Unlike the first version, this tool never silently fills fields missing from a
legacy grant log, never truncates the grant list before DMRS validation, uses
the DCI allocation for DMRS extraction, and pins transport decoding to the
already-acquired physical boundary and CFO.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_ul_grants import (  # noqa: E402
    MODULATION,
    apply_rrc_overrides,
    extract_rrc_configs_many,
    parse_grants,
)


FS = 5_760_000
SAMPLES_PER_SF = 5760
N_PRB = 25


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path,
                        help="sample-major paired DL/UL fc32 file")
    parser.add_argument("--grant-log", required=True, type=Path,
                        help="enhanced LTEsniffer log with complete [UL-TRY] fields")
    parser.add_argument("--pci", required=True, type=int,
                        help="serving PCI associated with the grant log")
    parser.add_argument("--pci-candidates", default="",
                        help="comma-separated additional PCIs to classify physically")
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--rrc-pcap", type=Path, action="append", default=[],
        help=(
            "decoded DL MAC pcap carrying dedicated UL/UCI configuration; "
            "repeat to merge complementary decoder outputs"
        ),
    )
    parser.add_argument("--rrc-override", action="append", default=[])
    parser.add_argument("--probe", type=Path, default=(
        Path(__file__).resolve().parents[1] / "build" / "ul_grant_probe"))
    parser.add_argument("--min-contrast-db", type=float, default=18.0)
    parser.add_argument("--min-peak-db", type=float, default=0.0)
    parser.add_argument("--boundary-drop-db", type=float, default=8.0)
    parser.add_argument("--max-width-prb", type=int, default=25)
    parser.add_argument("--time-window-sf", type=int, default=256,
                        help="maximum |grant file_sf - burst grid sf| before DMRS testing")
    parser.add_argument("--min-rb-iou", type=float, default=0.45)
    parser.add_argument("--max-allocations-per-burst", type=int, default=6)
    parser.add_argument("--dmrs-min-snr-db", type=float, default=5.0)
    parser.add_argument(
        "--dmrs-min-coherence", type=float, default=0.90,
        help=(
            "minimum adjacent-subcarrier coherence of the DMRS-derived "
            "channel estimate; rejects high-SNR cross-sequence aliases"
        ),
    )
    parser.add_argument("--dmrs-near-best-db", type=float, default=0.10)
    parser.add_argument(
        "--radius-ms", type=float, default=0.35,
        help=(
            "physical CP/DMRS boundary search radius for the blind sequence-"
            "table acquisition; use grant_directed_wide_timing.py for a "
            "wider NTN-safe search without neighboring-burst capture"
        ),
    )
    parser.add_argument(
        "--burst-audit-input", type=Path,
        help=(
            "reuse a prior burst_audit.jsonl inventory so a timing-radius "
            "rerun holds burst and candidate-allocation selection constant"
        ),
    )
    parser.add_argument("--unknown-uci", choices=("none", "both"), default="both")
    parser.add_argument("--enable64qam", action="store_true",
                        help="select the 64QAM-enabled LTE MCS table")
    parser.add_argument("--max-decodes-per-burst", type=int, default=24)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-bursts", type=int, default=0,
                        help="diagnostic limit; zero scans every detected burst")
    parser.add_argument("--inventory-only", action="store_true")
    return parser.parse_args()


def rb_spectrum(samples: np.ndarray) -> np.ndarray:
    window = np.hanning(512).astype(np.float32)
    power = np.zeros(512, dtype=np.float64)
    for index in range(9):
        start = 256 + index * 576
        block = samples[start:start + 512] * window
        power += np.abs(np.fft.fftshift(np.fft.fft(block))) ** 2
    power /= 9
    bins = np.fft.fftshift(np.fft.fftfreq(512, 1 / FS))
    result = np.empty(N_PRB, dtype=np.float64)
    for rb in range(N_PRB):
        low = -2.25e6 + rb * 180e3
        selected = (bins >= low) & (bins < low + 180e3)
        result[rb] = 10 * np.log10(power[selected].mean() + 1e-30)
    return result


def strongest_group(mask: np.ndarray, powers: np.ndarray) -> tuple[int, int] | None:
    groups: list[tuple[int, int]] = []
    start = None
    for index, active in enumerate(np.r_[mask, False]):
        if active and start is None:
            start = index
        elif not active and start is not None:
            groups.append((start, index - 1))
            start = None
    if not groups:
        return None
    return max(groups, key=lambda pair: float(powers[pair[0]:pair[1] + 1].mean()))


def detect_bursts(path: Path, args: argparse.Namespace) -> list[dict]:
    raw = np.memmap(path, dtype=np.float32, mode="r")
    if raw.size % 4:
        raise SystemExit("paired fc32 input must contain four floats per sample")
    paired = raw.reshape(-1, 4)
    nof_sf = len(paired) // SAMPLES_PER_SF
    bursts: list[dict] = []
    for sf in range(nof_sf):
        frame = paired[sf * SAMPLES_PER_SF:(sf + 1) * SAMPLES_PER_SF]
        ul = frame[:, 2].astype(np.float64) + 1j * frame[:, 3].astype(np.float64)
        powers = rb_spectrum(ul)
        peak = float(powers.max())
        floor = float(np.median(powers))
        group = strongest_group(powers >= peak - args.boundary_drop_db, powers)
        if group is None:
            continue
        first, last = group
        width = last - first + 1
        # Edge allocations are legal LTE PUSCH and are deliberately retained.
        if width > args.max_width_prb:
            continue
        if width == 1 and first == 12:
            continue
        if peak < args.min_peak_db or peak - floor < args.min_contrast_db:
            continue
        bursts.append({
            "burst_sf": sf,
            "grid_start_sample": sf * SAMPLES_PER_SF,
            "rb_start": first,
            "len_prb": width,
            "rb_end": last,
            "peak_db": round(peak, 3),
            "floor_db": round(floor, 3),
            "contrast_db": round(peak - floor, 3),
            "rb_power_db": [round(float(value), 3) for value in powers],
        })
        if args.max_bursts and len(bursts) >= args.max_bursts:
            break
    return bursts


def overlap_metrics(burst: dict, grant: dict) -> tuple[float, float]:
    a0, a1 = int(burst["rb_start"]), int(burst["rb_end"]) + 1
    b0 = int(grant["prb_tilde0"])
    b1 = b0 + int(grant["len_prb"])
    overlap = max(0, min(a1, b1) - max(a0, b0))
    union = max(a1, b1) - min(a0, b0)
    return overlap / max(1, union), overlap / max(1, a1 - a0)


def standards_grants(grants: list[dict], enable64qam: bool) -> list[dict]:
    """Keep the MCS-table branch permitted by SIB2, including RAR grants."""
    selected = []
    wanted = "[PUSCH-64" if enable64qam else "[PUSCH-16"
    for grant in grants:
        mode = str(grant.get("mode", ""))
        if not mode.startswith(wanted):
            continue
        if int(grant["mod"]) not in MODULATION:
            continue
        if not math.isfinite(float(grant["snr_db"])):
            # DCI fields remain usable even if the stock decoder measured an
            # empty/misaligned subframe, so do not otherwise gate on SNR.
            grant = dict(grant)
            grant["snr_db"] = -999.0
        selected.append(grant)
    return selected


def candidate_allocations(burst: dict, grants: list[dict], args: argparse.Namespace) -> list[dict]:
    grouped: dict[tuple[int, int, int], dict] = {}
    for grant in grants:
        delta = int(grant["file_sf"]) - int(burst["burst_sf"])
        if abs(delta) > args.time_window_sf:
            continue
        iou, coverage = overlap_metrics(burst, grant)
        if iou < args.min_rb_iou:
            continue
        key = (int(grant["prb_tilde0"]), int(grant["prb_tilde1"]),
               int(grant["len_prb"]))
        score = 8.0 * iou + 2.0 * coverage - 0.01 * abs(delta)
        item = grouped.setdefault(key, {
            "prb0": key[0], "prb1": key[1], "len_prb": key[2],
            "best_energy_iou": 0.0, "best_time_delta_sf": delta,
            "rank_score": -1e9, "grant_count": 0,
        })
        item["grant_count"] += 1
        if score > float(item["rank_score"]):
            item["rank_score"] = score
            item["best_energy_iou"] = round(iou, 4)
            item["best_time_delta_sf"] = delta
    values = sorted(grouped.values(), key=lambda item: -float(item["rank_score"]))
    return values[:args.max_allocations_per_burst]


def parse_pcis(args: argparse.Namespace) -> list[int]:
    values = {args.pci}
    for value in args.pci_candidates.split(","):
        if value.strip():
            values.add(int(value))
    if any(value < 0 or value > 503 for value in values):
        raise SystemExit("PCI values must be in 0..503")
    return sorted(values)


def acquire_table(args: argparse.Namespace, burst: dict, allocation: dict,
                  pci: int) -> dict:
    command = [
        str(args.probe), "--input", str(args.input),
        "--target-sf", str(burst["burst_sf"]),
        "--radius-ms", str(args.radius_ms),
        "--pci", str(pci), "--tti", "0",
        "--prb", str(allocation["prb0"]),
        "--prb-slot1", str(allocation["prb1"]),
        "--len-prb", str(allocation["len_prb"]),
        "--n-dmrs", "0", "--top", "1", "--sequence-table",
    ]
    run = subprocess.run(command, text=True, capture_output=True)
    best = None
    table = []
    for line in run.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("rank") == 1:
            best = item
        if item.get("sequence_table"):
            table.append(item)
    lookup = {
        f"{int(item['sf_idx'])}:{int(item['n_dmrs'])}": item for item in table
    }
    table_best = table[0] if table else None
    return {
        "pci": pci, "allocation": allocation, "best_global": best,
        "table_best": table_best, "sequence_scores": lookup,
        "return_code": run.returncode, "stderr": run.stderr.strip(),
    }


def grant_for_allocation(grant: dict, allocation: dict) -> bool:
    return (int(grant["prb_tilde0"]) == int(allocation["prb0"]) and
            int(grant["prb_tilde1"]) == int(allocation["prb1"]) and
            int(grant["len_prb"]) == int(allocation["len_prb"]))


def sequence_acceptance(acquisition: dict, grant: dict,
                        args: argparse.Namespace) -> tuple[bool, dict | None]:
    key = f"{int(grant['tti']) % 10}:{int(grant['n_dmrs'])}"
    expected = acquisition["sequence_scores"].get(key)
    best = acquisition.get("table_best")
    if not expected or not best:
        return False, expected
    snr = float(expected["snr_db"])
    coherence = float(expected.get("coherence", 0.0))
    margin = float(best["snr_db"]) - snr
    return (snr >= args.dmrs_min_snr_db and
            coherence >= args.dmrs_min_coherence and
            margin <= args.dmrs_near_best_db), expected


def rrc_hypotheses(grant: dict, configs: dict[int, dict],
                   args: argparse.Namespace) -> list[dict]:
    rrc = configs.get(int(grant["rnti"]))
    if rrc:
        period, offset = int(rrc["cqi_period"]), int(rrc["cqi_offset"])
        due = period > 0 and (int(grant["tti"]) - offset) % period == 0
        cqi_type = str(rrc["cqi_type"]) if due else "none"
        if int(grant["cqi_request"]):
            cqi_type = str(rrc["cqi_type"])
        return [{
            "source": str(rrc["source"]), "known_rnti": True,
            "cqi_due": due, "cqi_type": cqi_type, "ri_len": 0,
            "offset_ack": int(rrc["offset_ack"]),
            "offset_cqi": int(rrc["offset_cqi"]),
            "offset_ri": int(rrc["offset_ri"]),
        }]
    # Msg3 occurs before RRCConnectionSetup and carries no configured periodic
    # CQI unless requested by the RAR grant.
    if int(grant.get("rar", 0)):
        return [{
            "source": "RAR_pre_setup", "known_rnti": False,
            "cqi_due": False,
            "cqi_type": "wideband" if int(grant["cqi_request"]) else "none",
            "ri_len": 0, "offset_ack": 7, "offset_cqi": 7, "offset_ri": 1,
        }]
    values = ["none"]
    if args.unknown_uci == "both" or int(grant["cqi_request"]):
        values.append("wideband")
    if int(grant["cqi_request"]):
        values = ["wideband"]
    return [{
        "source": "unknown_rnti_bounded_hypothesis", "known_rnti": False,
        "cqi_due": value == "wideband", "cqi_type": value, "ri_len": 0,
        "offset_ack": 7, "offset_cqi": 7, "offset_ri": 1,
    } for value in values]


def decode_grant(args: argparse.Namespace, burst: dict, acquisition: dict,
                 grant: dict, expected: dict, uci: dict) -> dict:
    allocation = acquisition["allocation"]
    command = [
        str(args.probe), "--input", str(args.input),
        "--target-sf", str(burst["burst_sf"]),
        "--radius-ms", str(args.radius_ms),
        "--center-lag-samples", str(expected["lag_samples"]),
        "--fixed-lag-samples", str(expected["lag_samples"]),
        "--fixed-correction-hz", str(expected["correction_hz"]),
        "--pci", str(acquisition["pci"]), "--tti", str(grant["tti"]),
        "--prb", str(allocation["prb0"]),
        "--prb-slot1", str(allocation["prb1"]),
        "--len-prb", str(allocation["len_prb"]),
        "--n-dmrs", str(grant["n_dmrs"]), "--top", "1", "--decode",
        "--rnti", str(grant["rnti"]), "--mcs", str(grant["mcs"]),
        "--tbs", str(grant["tbs"]), "--rv", str(grant["rv"]),
        "--mod", MODULATION[int(grant["mod"])],
        "--nof-ack", str(grant["nof_ack"]),
        "--cqi-type", str(uci["cqi_type"]), "--ri-len", str(uci["ri_len"]),
        "--offset-ack", str(uci["offset_ack"]),
        "--offset-cqi", str(uci["offset_cqi"]),
        "--offset-ri", str(uci["offset_ri"]), "--decode-top", "1",
    ]
    run = subprocess.run(command, text=True, capture_output=True)
    decoded = None
    physical = None
    for line in run.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("rank") == 1:
            physical = item
        if item.get("decode_rank") == 1:
            decoded = item
    return {
        "grant": grant, "uci": uci, "physical": physical, "decode": decoded,
        "crc_valid": bool(decoded and decoded.get("crc") and
                          not decoded.get("all_zero")),
        "return_code": run.returncode, "stderr": run.stderr.strip(),
    }


def main() -> int:
    args = arguments()
    required_paths = [args.input, args.grant_log, args.probe]
    if args.burst_audit_input:
        required_paths.append(args.burst_audit_input)
    for path in required_paths:
        if not path.is_file():
            raise SystemExit(f"missing input: {path}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    pcis = parse_pcis(args)
    configs = extract_rrc_configs_many(args.rrc_pcap)
    apply_rrc_overrides(configs, args.rrc_override)
    try:
        parsed = parse_grants(args.grant_log, strict=True)
    except ValueError as error:
        raise SystemExit(str(error)) from error
    grants = standards_grants(parsed, args.enable64qam)
    if args.burst_audit_input:
        bursts = [
            json.loads(line)
            for line in args.burst_audit_input.read_text().splitlines()
            if line.strip()
        ]
        # Results from the previous physical acquisition are deliberately
        # discarded. Only the energy boundary and candidate allocation list
        # are reused, which isolates the effect of the new timing radius.
        for burst in bursts:
            burst.pop("physical_allocations", None)
    else:
        bursts = detect_bursts(args.input, args)
        for burst in bursts:
            burst["candidate_allocations"] = candidate_allocations(
                burst, grants, args
            )

    inventory = {
        "input": str(args.input), "grant_log": str(args.grant_log),
        "serving_pci": args.pci, "physical_pci_candidates": pcis,
        "dmrs_min_snr_db": args.dmrs_min_snr_db,
        "dmrs_min_coherence": args.dmrs_min_coherence,
        "dmrs_near_best_db": args.dmrs_near_best_db,
        "radius_ms": args.radius_ms,
        "burst_inventory_source": (
            str(args.burst_audit_input) if args.burst_audit_input else "fresh"
        ),
        "strict_grants": len(grants), "detected_bursts": len(bursts),
        "bursts_with_candidate_allocations": sum(
            bool(burst["candidate_allocations"]) for burst in bursts),
    }
    (args.output_dir / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    if args.inventory_only:
        print(json.dumps(inventory))
        return 0

    tasks = []
    for burst_index, burst in enumerate(bursts):
        for allocation_index, allocation in enumerate(burst["candidate_allocations"]):
            for pci in pcis:
                tasks.append((burst_index, allocation_index, pci))

    acquisitions: dict[tuple[int, int, int], dict] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        future_map = {
            pool.submit(acquire_table, args, bursts[burst_index],
                        bursts[burst_index]["candidate_allocations"][allocation_index], pci):
            (burst_index, allocation_index, pci)
            for burst_index, allocation_index, pci in tasks
        }
        for completed, future in enumerate(concurrent.futures.as_completed(future_map), 1):
            key = future_map[future]
            acquisitions[key] = future.result()
            if completed % 100 == 0:
                print(f"acquired {completed}/{len(tasks)} allocation/PCI tables", file=sys.stderr)

    all_associations = []
    valid = []
    lag_histogram: Counter[int] = Counter()
    for burst_index, burst in enumerate(bursts):
        burst["physical_allocations"] = []
        decode_budget = args.max_decodes_per_burst
        for allocation_index, allocation in enumerate(burst["candidate_allocations"]):
            for pci in pcis:
                acquisition = acquisitions[(burst_index, allocation_index, pci)]
                compact = {
                    "pci": pci, "allocation": allocation,
                    "best": acquisition["table_best"],
                    "return_code": acquisition["return_code"],
                }
                burst["physical_allocations"].append(compact)
                # This run has a grant catalog only for the serving PCI. Other
                # PCIs classify the waveform but cannot supply transport state.
                if pci != args.pci or not acquisition["table_best"]:
                    continue
                nearby = []
                for grant in grants:
                    delta = int(grant["file_sf"]) - int(burst["burst_sf"])
                    if abs(delta) > args.time_window_sf:
                        continue
                    if grant_for_allocation(grant, allocation):
                        nearby.append(grant)
                nearby.sort(key=lambda grant: abs(
                    int(grant["file_sf"]) - int(burst["burst_sf"])))
                for grant in nearby:
                    accepted, expected = sequence_acceptance(acquisition, grant, args)
                    if not accepted or expected is None:
                        continue
                    association = {
                        "burst_sf": burst["burst_sf"], "pci": pci,
                        "allocation": allocation, "grant": grant,
                        "grant_minus_burst_sf": int(grant["file_sf"]) -
                                                int(burst["burst_sf"]),
                        "dmrs_expected": expected,
                        "dmrs_best": acquisition["table_best"],
                        "decode_attempts": [],
                    }
                    lag_histogram[int(association["grant_minus_burst_sf"])] += 1
                    for uci in rrc_hypotheses(grant, configs, args):
                        if decode_budget <= 0:
                            break
                        attempt = decode_grant(args, burst, acquisition, grant, expected, uci)
                        association["decode_attempts"].append(attempt)
                        decode_budget -= 1
                        if attempt["crc_valid"]:
                            valid.append({
                                "burst_sf": burst["burst_sf"], "pci": pci,
                                "allocation": allocation, "dmrs": expected,
                                **attempt,
                            })
                    all_associations.append(association)

    audit_path = args.output_dir / "burst_audit.jsonl"
    with audit_path.open("w") as output:
        for burst in bursts:
            output.write(json.dumps(burst, separators=(",", ":")) + "\n")
    associations_path = args.output_dir / "dmrs_validated_associations.jsonl"
    with associations_path.open("w") as output:
        for association in all_associations:
            output.write(json.dumps(association, separators=(",", ":")) + "\n")

    # LTE DMRS and PUSCH scrambling repeat with the 10-subframe index. Field
    # traffic in this capture also has an 80-subframe cadence, so a physically
    # valid burst can decode against several time-shifted copies of an
    # otherwise identical grant. Select one constant paired-file mapping only
    # after decoding. Prefer the lag explaining the most distinct bursts and,
    # when periodic aliases tie, the smallest absolute displacement because
    # DL and UL were recorded synchronously into the same paired file.
    crc_lag_bursts: dict[int, set[int]] = defaultdict(set)
    for packet in valid:
        delta = int(packet["grant"]["file_sf"]) - int(packet["burst_sf"])
        crc_lag_bursts[delta].add(int(packet["burst_sf"]))
    selected_offset = None
    if crc_lag_bursts:
        selected_offset = min(
            crc_lag_bursts,
            key=lambda delta: (-len(crc_lag_bursts[delta]), abs(delta), delta),
        )
    # A logical transport block can decode from several periodic timing aliases.
    # Group first, then retain the representative at the selected physical
    # mapping.  Assigning directly into a dictionary here used to let a later
    # alias overwrite a correct zero-offset result.
    grouped_valid = defaultdict(list)
    for packet in valid:
        decoded = packet["decode"]
        key = (packet["pci"], int(packet["grant"]["tti"]),
               int(packet["grant"]["rnti"]), decoded["payload_hex"])
        grouped_valid[key].append(packet)

    unique_valid = {}
    promoted = {}
    for key, candidates in grouped_valid.items():
        preferred = max(candidates, key=lambda packet: (
            selected_offset is not None and
            int(packet["grant"]["file_sf"]) - int(packet["burst_sf"]) == selected_offset,
            float(packet["dmrs"].get("snr_db", -999.0)),
            float(packet["dmrs"].get("coherence", 0.0)),
        ))
        unique_valid[key] = preferred
        if (selected_offset is not None and
                int(preferred["grant"]["file_sf"]) -
                int(preferred["burst_sf"]) == selected_offset):
            promoted[key] = preferred

    all_valid_path = args.output_dir / "crc_valid_all_timing_hypotheses.jsonl"
    with all_valid_path.open("w") as output:
        for packet in unique_valid.values():
            output.write(json.dumps(packet, separators=(",", ":")) + "\n")
    valid_path = args.output_dir / "crc_valid_ul.jsonl"
    with valid_path.open("w") as output:
        for packet in promoted.values():
            output.write(json.dumps(packet, separators=(",", ":")) + "\n")

    summary = {
        **inventory,
        "allocation_pci_tables": len(tasks),
        "dmrs_validated_associations": len(all_associations),
        "crc_valid_attempts": len(valid),
        "unique_crc_valid_timing_hypotheses": len(unique_valid),
        "crc_valid_bursts_by_file_sf_offset": {
            str(delta): len(values) for delta, values in sorted(crc_lag_bursts.items())
        },
        "selected_file_sf_offset": selected_offset,
        "promoted_crc_valid_packets": len(promoted),
        "grant_minus_burst_sf_histogram": dict(sorted(lag_histogram.items())),
        "rrc_configured_rntis": sorted(configs),
        "rrc_pcaps": [str(path) for path in args.rrc_pcap],
        "burst_audit": str(audit_path),
        "associations": str(associations_path),
        "all_crc_valid_timing_hypotheses": str(all_valid_path),
        "crc_valid": str(valid_path),
    }
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
