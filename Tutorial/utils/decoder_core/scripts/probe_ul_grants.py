#!/usr/bin/env python3
"""Re-acquire and decode PUSCH bursts from LTEsniffer grant diagnostics."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


FIELD = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+)")
MODULATION = {1: "qpsk", 2: "16qam", 3: "64qam", 4: "256qam"}
INTEGER_FIELDS = (
    "file_sf", "tti", "rnti", "prb_tilde0", "len_prb", "mcs", "tbs",
)
STRICT_GRANT_FIELDS = (
    "file_sf", "tti", "rnti", "prb_tilde0", "prb_tilde1", "len_prb",
    "freq_hopping", "n_dmrs", "mcs", "tbs", "rv", "mod", "nof_ack",
    "cqi_request", "ndi", "rar", "snr_db",
)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path,
                        help="sample-major paired DL/UL fc32 file")
    parser.add_argument("--grant-log", required=True, type=Path,
                        help="patched LTEsniffer log containing [UL-TRY] lines")
    parser.add_argument("--pci", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--radius-ms", type=float, default=3.0)
    parser.add_argument(
        "--file-sf-correction", type=int, default=0,
        help="constant subframe correction added to grant-log file_sf",
    )
    parser.add_argument("--rnti", type=int)
    parser.add_argument("--min-original-snr-db", type=float, default=5.0)
    parser.add_argument("--max-grants", type=int, default=0,
                        help="zero means all matching grants")
    parser.add_argument("--standards-only", action="store_true",
                        help="discard alternate modulation/TBS diagnostic branches")
    parser.add_argument("--cqi-type", default="none",
                        choices=("none", "wideband", "subband-ue", "subband-hl"))
    parser.add_argument("--ri-len", type=int, default=0, choices=(0, 1))
    parser.add_argument("--pmi-present", action="store_true")
    parser.add_argument("--offset-ack", type=int, default=10)
    parser.add_argument("--offset-cqi", type=int, default=8)
    parser.add_argument("--offset-ri", type=int, default=11)
    parser.add_argument(
        "--rrc-pcap", type=Path, action="append", default=[],
        help=(
            "decoded DL MAC pcap used to learn per-RNTI UCI configuration; "
            "repeat to merge complementary DL-mode and UL-mode traces "
            "(later files take precedence on a conflicting RNTI)"
        ),
    )
    parser.add_argument(
        "--rrc-override", action="append", default=[], metavar="SPEC",
        help="add missing config as RNTI:ACK:CQI:RI:CQI_PMI_INDEX (repeatable)",
    )
    parser.add_argument(
        "--probe",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "build" / "ul_grant_probe",
    )
    return parser.parse_args()


def parse_grants(path: Path, *, strict: bool = False) -> list[dict[str, int | float | str]]:
    grants: list[dict[str, int | float | str]] = []
    seen: set[tuple[int, ...]] = set()
    missing_by_line: list[tuple[int, list[str]]] = []
    for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        if "[UL-TRY]" not in line:
            continue
        raw = dict(FIELD.findall(line))
        if strict:
            missing = [name for name in STRICT_GRANT_FIELDS if name not in raw]
            if missing:
                missing_by_line.append((line_number, missing))
                continue
        if not all(name in raw for name in INTEGER_FIELDS) or "snr_db" not in raw:
            continue
        try:
            grant: dict[str, int | float | str] = {
                name: int(raw[name]) for name in INTEGER_FIELDS
            }
            mcs = int(grant["mcs"])
            inferred_mod = 1 if mcs < 11 else (2 if mcs < 21 else 3)
            grant["n_dmrs"] = int(raw.get("n_dmrs", 0))
            grant["prb_tilde1"] = int(raw.get("prb_tilde1", grant["prb_tilde0"]))
            grant["freq_hopping"] = int(raw.get("freq_hopping", 0))
            grant["rv"] = int(raw.get("rv", 0))
            grant["mod"] = int(raw.get("mod", inferred_mod))
            grant["nof_ack"] = int(raw.get("nof_ack", 0))
            grant["cqi_request"] = int(raw.get("cqi_request", 0))
            grant["cqi_enabled"] = int(raw.get("cqi_enabled", 0))
            grant["ndi"] = int(raw.get("ndi", 0))
            grant["rar"] = int(raw.get("rar", 0))
            grant["hist"] = int(raw.get("hist", 0))
            grant["snr_db"] = float(raw["snr_db"])
            mode_match = re.search(r"mode=(\[[^\]]+\])", line)
            grant["mode"] = mode_match.group(1) if mode_match else "unknown"
        except ValueError:
            continue
        key = tuple(int(grant[name]) for name in (
            "file_sf", "tti", "rnti", "prb_tilde0", "prb_tilde1",
            "len_prb", "freq_hopping", "n_dmrs", "mcs", "tbs", "rv",
            "mod", "nof_ack", "cqi_request", "ndi", "rar",
        ))
        if key not in seen:
            seen.add(key)
            grants.append(grant)
    if strict and missing_by_line:
        examples = "; ".join(
            f"line {line_number}: {','.join(missing)}"
            for line_number, missing in missing_by_line[:3]
        )
        raise ValueError(
            f"grant log is missing required enhanced fields on "
            f"{len(missing_by_line)} [UL-TRY] rows ({examples})"
        )
    return grants


def cqi_period_offset(index: int) -> tuple[int, int] | None:
    """3GPP TS 36.213 table 7.2.2-1A, FDD periodic CQI/PMI."""
    ranges = (
        (0, 1, 2, 0), (2, 6, 5, 2), (7, 16, 10, 7),
        (17, 36, 20, 17), (37, 76, 40, 37),
        (77, 156, 80, 77), (157, 316, 160, 157),
        (318, 349, 32, 318), (350, 413, 64, 350),
        (414, 541, 128, 414),
    )
    for first, last, period, base in ranges:
        if first <= index <= last:
            return period, index - base
    return None


def extract_rrc_configs(path: Path) -> dict[int, dict[str, int | str | bool]]:
    fields = (
        "mac-lte.rnti", "lte-rrc.betaOffset_ACK_Index",
        "lte-rrc.betaOffset_CQI_Index", "lte-rrc.betaOffset_RI_Index",
        "lte-rrc.cqi_pmi_ConfigIndex", "lte-rrc.cqi_FormatIndicatorPeriodic",
        "lte-rrc.ri_ConfigIndex", "lte-rrc.simultaneousAckNackAndCQI",
    )
    command = [
        "tshark", "-r", str(path), "-Y", "lte-rrc.betaOffset_ACK_Index",
        "-T", "fields", "-E", "separator=|",
    ]
    for field in fields:
        command.extend(("-e", field))
    run = subprocess.run(command, text=True, capture_output=True, check=True)
    configs: dict[int, dict[str, int | str | bool]] = {}
    for line in run.stdout.splitlines():
        values = line.split("|")
        if len(values) != len(fields) or not all(values[index] for index in range(5)):
            continue
        try:
            rnti, ack, cqi, ri, cqi_index = map(int, values[:5])
            format_value = int(values[5]) if values[5] else 0
            ri_index = int(values[6]) if values[6] else None
        except ValueError:
            continue
        schedule = cqi_period_offset(cqi_index)
        configs[rnti] = {
            "rnti": rnti, "offset_ack": ack, "offset_cqi": cqi,
            "offset_ri": ri, "cqi_pmi_config_index": cqi_index,
            "cqi_type": "wideband" if format_value == 0 else "subband-ue",
            "ri_config_index": ri_index,
            "simultaneous_ack_cqi": values[7] == "1",
            "cqi_period": schedule[0] if schedule else 0,
            "cqi_offset": schedule[1] if schedule else 0,
            "source": "decoded_dl_rrc",
        }
    return configs


def extract_rrc_configs_many(
    paths: list[Path],
) -> dict[int, dict[str, int | str | bool]]:
    """Merge complementary RRC decodes, preferring later PCAPs on conflict."""
    configs: dict[int, dict[str, int | str | bool]] = {}
    for path in paths:
        decoded = extract_rrc_configs(path)
        for rnti, config in decoded.items():
            item = dict(config)
            item["source"] = f"decoded_dl_rrc:{path}"
            configs[rnti] = item
    return configs


def apply_rrc_overrides(
    configs: dict[int, dict[str, int | str | bool]], specs: list[str]
) -> None:
    for spec in specs:
        try:
            rnti, ack, cqi, ri, cqi_index = map(int, spec.split(":"))
        except ValueError as error:
            raise SystemExit(f"invalid --rrc-override {spec!r}") from error
        schedule = cqi_period_offset(cqi_index)
        if schedule is None:
            raise SystemExit(f"unsupported CQI/PMI config index in override: {spec}")
        configs[rnti] = {
            "rnti": rnti, "offset_ack": ack, "offset_cqi": cqi,
            "offset_ri": ri, "cqi_pmi_config_index": cqi_index,
            "cqi_type": "wideband", "ri_config_index": None,
            "simultaneous_ack_cqi": True, "cqi_period": schedule[0],
            "cqi_offset": schedule[1], "source": "explicit_override",
        }


def main() -> int:
    args = arguments()
    if not args.input.is_file() or not args.grant_log.is_file():
        raise SystemExit("input and grant log must be existing files")
    if not args.probe.is_file():
        raise SystemExit(f"probe binary not found: {args.probe}; run scripts/build.sh")
    if not 0 <= args.pci <= 503 or args.radius_ms <= 0:
        raise SystemExit("PCI must be 0..503 and radius must be positive")

    rrc_configs = extract_rrc_configs_many(args.rrc_pcap)
    apply_rrc_overrides(rrc_configs, args.rrc_override)

    grants = [
        grant for grant in parse_grants(args.grant_log)
        if float(grant["snr_db"]) >= args.min_original_snr_db
        and (args.rnti is None or int(grant["rnti"]) == args.rnti)
        and int(grant["mod"]) in MODULATION
        and (not args.standards_only or int(grant["mod"]) == (
            1 if int(grant["mcs"]) < 11 else (2 if int(grant["mcs"]) < 21 else 3)
        ))
    ]
    if args.max_grants:
        grants = grants[:args.max_grants]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    acquired = strong = crc_valid = 0
    with args.output.open("w") as output:
        for index, grant in enumerate(grants, 1):
            target_file_sf = int(grant["file_sf"]) + args.file_sf_correction
            if target_file_sf < 0:
                continue
            rrc = rrc_configs.get(int(grant["rnti"]))
            cqi_type = args.cqi_type
            ri_len = args.ri_len
            offset_ack = args.offset_ack
            offset_cqi = args.offset_cqi
            offset_ri = args.offset_ri
            cqi_due = False
            if rrc:
                period = int(rrc["cqi_period"])
                cqi_offset = int(rrc["cqi_offset"])
                cqi_due = period > 0 and (int(grant["tti"]) - cqi_offset) % period == 0
                cqi_type = str(rrc["cqi_type"]) if cqi_due else "none"
                # No decoded ri-ConfigIndex is present in these one-port cells.
                ri_len = 0
                offset_ack = int(rrc["offset_ack"])
                offset_cqi = int(rrc["offset_cqi"])
                offset_ri = int(rrc["offset_ri"])
            if int(grant.get("cqi_request", 0)):
                # The field traces currently report zero, but preserve DCI0's
                # aperiodic request if a future grant exposes it.
                cqi_type = str(rrc["cqi_type"]) if rrc else "wideband"
            command = [
                str(args.probe),
                "--input", str(args.input),
                "--target-sf", str(target_file_sf),
                "--radius-ms", str(args.radius_ms),
                "--pci", str(args.pci),
                "--tti", str(grant["tti"]),
                "--prb", str(grant["prb_tilde0"]),
                "--len-prb", str(grant["len_prb"]),
                "--n-dmrs", str(grant["n_dmrs"]),
                "--top", "1", "--decode",
                "--rnti", str(grant["rnti"]),
                "--mcs", str(grant["mcs"]),
                "--tbs", str(grant["tbs"]),
                "--rv", str(grant["rv"]),
                "--mod", MODULATION[int(grant["mod"])],
                "--nof-ack", str(grant["nof_ack"]),
                "--cqi-type", cqi_type,
                "--ri-len", str(ri_len),
                "--offset-ack", str(offset_ack),
                "--offset-cqi", str(offset_cqi),
                "--offset-ri", str(offset_ri),
                "--decode-top", "1",
            ]
            if args.pmi_present:
                command.append("--pmi-present")
            run = subprocess.run(command, text=True, capture_output=True)
            records = []
            for line in run.stdout.splitlines():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
            candidate = next((item for item in records if item.get("rank") == 1), None)
            decoded = next((item for item in records if item.get("decode_rank") == 1), None)
            acquired += candidate is not None
            strong += candidate is not None and float(candidate["snr_db"]) >= 5.0
            crc_valid += decoded is not None and bool(decoded["crc"])
            output.write(json.dumps({
                "grant_index": index,
                "grant": grant,
                "target_file_sf": target_file_sf,
                "file_sf_correction": args.file_sf_correction,
                "rrc_config": rrc,
                "rrc_applied": {
                    "known_rnti": rrc is not None, "cqi_due": cqi_due,
                    "cqi_type": cqi_type, "ri_len": ri_len,
                    "offset_ack": offset_ack, "offset_cqi": offset_cqi,
                    "offset_ri": offset_ri,
                },
                "candidate": candidate,
                "decode": decoded,
                "return_code": run.returncode,
                "stderr": run.stderr.strip(),
            }, separators=(",", ":")) + "\n")

    summary = {
        "input": str(args.input),
        "grant_log": str(args.grant_log),
        "pci": args.pci,
        "radius_ms": args.radius_ms,
        "file_sf_correction": args.file_sf_correction,
        "selected_grants": len(grants),
        "acquired": acquired,
        "dmrs_snr_at_least_5_db": strong,
        "crc_valid_nonzero": crc_valid,
        "rrc_configured_rntis": sorted(rrc_configs),
        "rrc_config_count": len(rrc_configs),
        "rrc_pcaps": [str(path) for path in args.rrc_pcap],
        "results": str(args.output),
    }
    args.output.with_suffix(".summary.json").write_text(
        json.dumps(summary, indent=2) + "\n"
    )
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
