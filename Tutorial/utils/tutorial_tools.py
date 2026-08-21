"""Inspection and visualization helpers used by the tutorial notebook.

The PHY decoder itself lives in ``utils/decoder_core``.  This module stays
small on purpose: it reads the decoder's JSONL/PCAP artifacts and draws the
intermediate decisions so students can see what each stage accomplished.
"""

from __future__ import annotations

from collections import Counter
from html import escape
import json
from pathlib import Path
import shutil
import subprocess
from typing import Iterable

import matplotlib.pyplot as plt
from matplotlib.patches import Patch, Rectangle
import numpy as np


FC32 = np.dtype("<c8")
LTE_RATE_HZ = 5_760_000
PRB_WIDTH_HZ = 180_000


def decoder_paths(repo_root: Path) -> dict[str, Path]:
    root = repo_root.resolve()
    return {
        "repo": root,
        "processed": root / "Tutorial" / "processed_data",
        "results": root / "Tutorial" / "decoder_results",
        "runtime": root / "Tutorial" / "decoder_results" / "runtime",
        "core": root / "Tutorial" / "utils" / "decoder_core",
    }


def load_manifest(results_dir: Path) -> dict:
    return json.loads((results_dir / "manifest.json").read_text())


def load_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    rows: list[dict] = []
    with path.open(errors="replace") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
                if limit is not None and len(rows) >= limit:
                    break
    return rows


def html_table(rows: Iterable[dict], columns: list[str] | None = None) -> str:
    items = list(rows)
    if not items:
        return "<p><em>No rows.</em></p>"
    columns = columns or list(items[0])
    head = "".join(f"<th>{escape(str(column))}</th>" for column in columns)
    body = []
    for row in items:
        cells = "".join(f"<td>{escape(str(row.get(column, '')))}</td>" for column in columns)
        body.append(f"<tr>{cells}</tr>")
    return (
        "<div style='overflow-x:auto'><table>"
        f"<thead><tr>{head}</tr></thead><tbody>{''.join(body)}</tbody></table></div>"
    )


def _waterfall(
    path: Path,
    sample_rate_hz: float,
    start_s: float,
    duration_s: float,
    *,
    fft_size: int = 2048,
    rows: int = 700,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    source = np.memmap(path, dtype=FC32, mode="r")
    first = max(0, int(round(start_s * sample_rate_hz)))
    last = min(source.size, int(round((start_s + duration_s) * sample_rate_hz)))
    if last - first < fft_size:
        raise ValueError("selected waterfall interval is outside the IQ file")
    starts = np.linspace(first, last - fft_size, rows, dtype=np.int64)
    window = np.hanning(fft_size).astype(np.float32)
    power = np.empty((rows, fft_size), dtype=np.float32)
    for row, offset in enumerate(starts):
        spectrum = np.fft.fftshift(
            np.fft.fft(np.asarray(source[offset:offset + fft_size]) * window)
        )
        power[row] = 10 * np.log10(np.abs(spectrum) ** 2 + 1e-20)
    power -= np.percentile(power, 99.8)
    times = starts / sample_rate_hz
    frequencies = np.fft.fftshift(np.fft.fftfreq(fft_size, 1 / sample_rate_hz))
    return times, frequencies, power


def plot_cell_waterfall(
    dl_path: Path,
    manifest: dict,
    *,
    sample_rate_hz: float = LTE_RATE_HZ,
    center_hz: float = 1_992_500_000,
):
    duration = np.memmap(dl_path, dtype=FC32, mode="r").size / sample_rate_hz
    times, offsets, power = _waterfall(
        dl_path, sample_rate_hz, 0.0, duration, fft_size=2048, rows=1100
    )
    frequency_mhz = (center_hz + offsets) / 1e6
    fig, axis = plt.subplots(figsize=(15, 10))
    image = axis.imshow(
        power,
        origin="upper",
        aspect="auto",
        extent=[frequency_mhz[0], frequency_mhz[-1], times[-1], times[0]],
        cmap="turbo",
        vmin=-52,
        vmax=0,
    )
    colors = plt.cm.tab10(np.linspace(0, 1, 10))
    seen = {}
    for index, cell in enumerate(manifest["cells"]):
        color = colors[index % len(colors)]
        start = float(cell["start_s"])
        end = float(cell["end_s"])
        rectangle = Rectangle(
            ((center_hz - 2.25e6) / 1e6, start),
            4.5,
            max(0.02, end - start),
            fill=False,
            edgecolor=color,
            linewidth=1.5,
        )
        axis.add_patch(rectangle)
        identity = (
            f"logical sat {cell['logical_satellite_id']}, sector {cell['sector_id']}"
            if cell.get("logical_satellite_id") is not None
            else "SIB1 identity unavailable"
        )
        label_y = min(end, start + 0.35 + 0.45 * (index % 3))
        axis.text(
            (center_hz - 2.18e6) / 1e6,
            label_y,
            f"PCI {cell['pci']} | {identity}\n{start:.1f}–{end:.1f} s",
            color="white",
            fontsize=7.2,
            va="top",
            bbox={"facecolor": color, "alpha": 0.72, "edgecolor": "white", "pad": 2},
        )
        seen[int(cell["pci"])] = color
    axis.set_title("Complete downlink: decoder-confirmed PCI coverage and SIB1 identities")
    axis.set_xlabel("Frequency (MHz)")
    axis.set_ylabel("Seconds after capture start")
    axis.legend(
        handles=[Patch(color=color, label=f"PCI {pci}") for pci, color in sorted(seen.items())],
        loc="upper right",
        ncol=2,
        fontsize=8,
    )
    fig.colorbar(image, ax=axis, label="Relative power (dB)", pad=0.01)
    fig.tight_layout()
    return fig


def summarize_downlink(results_dir: Path, manifest: dict) -> list[dict]:
    rows = []
    for cell in manifest["cells"]:
        pcap = results_dir / cell["dl_pcap"]
        rows.append(
            {
                "PCI": cell["pci"],
                "start (s)": cell["start_s"],
                "end (s)": cell["end_s"],
                "ECI": cell.get("eci_28bit", "not decoded"),
                "Tsat satellite ID": cell.get("logical_satellite_id", "unresolved"),
                "sector": cell.get("sector_id", "unresolved"),
                "DL frames": _pcap_frame_count(pcap),
            }
        )
    return rows


def _pcap_frame_count(path: Path) -> int:
    if shutil.which("tshark") is None or not path.is_file():
        return -1
    result = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.number"],
        text=True,
        capture_output=True,
        check=False,
    )
    return sum(bool(line.strip()) for line in result.stdout.splitlines())


def pcap_protocol_counts(path: Path) -> Counter:
    if shutil.which("tshark") is None:
        return Counter()
    result = subprocess.run(
        ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.protocols"],
        text=True,
        capture_output=True,
        check=False,
    )
    counts: Counter = Counter()
    for line in result.stdout.splitlines():
        for protocol in set(line.strip().split(":")):
            if protocol:
                counts[protocol] += 1
    return counts


def _grant_time(row: dict, cell: dict) -> float:
    return (
        float(cell["start_s"])
        + float(cell.get("aligned_start_offset_s", 0.0))
        + float(row["burst"]["burst_sf"]) / 1000.0
    )


def plot_ul_grants(
    ul_path: Path,
    acquisitions: list[dict],
    cell: dict,
    *,
    start_s: float,
    duration_s: float,
    observed_rows: list[dict] | None = None,
    sample_rate_hz: float = LTE_RATE_HZ,
    center_hz: float = 1_912_500_000,
):
    times, offsets, power = _waterfall(
        ul_path, sample_rate_hz, start_s, duration_s, fft_size=2048, rows=700
    )
    frequency_mhz = (center_hz + offsets) / 1e6
    fig, axes = plt.subplots(
        2, 1, figsize=(12, 8.5), sharex=True, sharey=True, layout="constrained"
    )
    images = []
    for axis in axes:
        images.append(axis.imshow(
            power,
            origin="upper",
            aspect="auto",
            extent=[frequency_mhz[0], frequency_mhz[-1], times[-1], times[0]],
            cmap="magma",
            vmin=-48,
            vmax=0,
        ))
    signal_axis, grant_axis = axes
    signal_axis.set_title("Observed uplink signal (no scheduling overlay)")
    observed_by_sf = {
        int(row["burst_sf"]): row for row in (observed_rows or [])
    }
    shown = 0
    for row in acquisitions:
        event_s = _grant_time(row, cell)
        if not start_s <= event_s <= start_s + duration_s:
            continue
        grant = row["grant"]
        low_hz = -2.25e6 + int(grant["prb_tilde0"]) * PRB_WIDTH_HZ
        width_hz = int(grant["len_prb"]) * PRB_WIDTH_HZ
        rectangle = Rectangle(
            ((center_hz + low_hz) / 1e6, event_s),
            width_hz / 1e6,
            0.001,
            facecolor=(0.0, 0.9, 1.0, 0.14),
            edgecolor="#00e5ff",
            linewidth=2.2,
        )
        grant_axis.add_patch(rectangle)
        observed = observed_by_sf.get(int(row["burst"]["burst_sf"]))
        if observed is not None:
            observed_s = (
                float(cell["start_s"])
                + float(cell.get("aligned_start_offset_s", 0.0))
                + int(observed["physical"]["file_sample"]) / sample_rate_hz
            )
            grant_axis.add_patch(Rectangle(
                ((center_hz + low_hz) / 1e6, observed_s),
                width_hz / 1e6,
                0.001,
                facecolor=(0.2, 1.0, 0.2, 0.10),
                edgecolor="#66ff66",
                linestyle="--",
                linewidth=2.2,
            ))
        if shown < 4:
            prb_start = int(grant["prb_tilde0"])
            prb_end = prb_start + int(grant["len_prb"]) - 1
            grant_axis.annotate(
                f"sf {int(row['burst']['burst_sf'])}: PRBs {prb_start}–{prb_end}",
                xy=((center_hz + low_hz + width_hz / 2) / 1e6, event_s + 0.0005),
                xytext=(12, 14),
                textcoords="offset points",
                color="white",
                fontsize=8,
                arrowprops={"arrowstyle": "->", "color": "#00e5ff"},
                bbox={"facecolor": "black", "alpha": 0.75, "edgecolor": "#00e5ff"},
            )
        shown += 1
    grant_axis.set_title(
        f"PCI {cell['pci']}: expected grant window versus CRC-valid observed window"
    )
    grant_axis.set_xlabel("Uplink frequency (MHz)")
    for axis in axes:
        axis.set_ylabel("Seconds after capture start")
    grant_axis.text(
        0.01,
        0.02,
        f"{shown} grant in view; cyan = expected, dashed green = observed after timing search",
        transform=grant_axis.transAxes,
        color="white",
        bbox={"facecolor": "black", "alpha": 0.65},
    )
    fig.colorbar(
        images[0], ax=axes, label="Relative power (dB)", pad=0.02, shrink=0.92
    )
    fig.suptitle("Recorded UL signal: scheduled position and observed decoded position")
    return fig


def plot_timing_candidates(acquisitions: list[dict], crc_rows: list[dict]):
    passed = {
        (int(row["burst_sf"]), int(row["physical"]["lag_samples"]))
        for row in crc_rows
    }
    figure, axis = plt.subplots(figsize=(12, 6))
    for acquisition in acquisitions:
        burst = int(acquisition["burst"]["burst_sf"])
        for physical in acquisition.get("physicals", []):
            key = (burst, int(physical["lag_samples"]))
            axis.scatter(
                float(physical["lag_us"]),
                float(physical["coherence"]),
                s=34 if key in passed else 13,
                c="#2ecc71" if key in passed else "#7f8c8d",
                alpha=0.85 if key in passed else 0.25,
            )
    axis.set_xlabel("Candidate timing relative to the grant (µs)")
    axis.set_ylabel("DMRS coherence (1.0 is an excellent match)")
    axis.set_title("Why the decoder retains four timing/CFO candidates per grant")
    axis.grid(alpha=0.2)
    axis.text(
        0.01,
        0.02,
        "green = a candidate that produced at least one CRC-valid transport block",
        transform=axis.transAxes,
    )
    figure.tight_layout()
    return figure


def summarize_uplink(results_dir: Path, manifest: dict) -> list[dict]:
    rows = []
    for cell in manifest["cells"]:
        label = cell.get("ul_result")
        if not label:
            rows.append({"PCI": cell["pci"], "segment": cell["label"], "unique DL grants": 0, "DMRS candidates": 0, "decode attempts": 0, "CRC passed": 0})
            continue
        summary = json.loads((results_dir / "uplink" / label / "summary.json").read_text())
        rows.append(
            {
                "PCI": cell["pci"],
                "segment": cell["label"],
                "unique DL grants": summary.get("unique_dl_grants", summary["grant_directed_timing_tasks"]),
                "DMRS candidates": summary["dmrs_accepted"],
                "decode attempts": summary["decode_attempts"],
                "CRC passed": summary["crc_valid_packets"],
            }
        )
    return rows


def plot_crc_outcomes(rows: list[dict]):
    labels = [row["segment"] for row in rows]
    attempts = np.array([row["decode attempts"] for row in rows])
    passed = np.array([row["CRC passed"] for row in rows])
    positions = np.arange(len(rows))
    figure, axis = plt.subplots(figsize=(14, 6))
    axis.bar(positions, attempts, color="#95a5a6", label="transport-block hypotheses tried")
    axis.bar(positions, passed, color="#2ecc71", label="CRC-valid UL packets")
    axis.set_xticks(positions, labels, rotation=35, ha="right")
    axis.set_yscale("symlog", linthresh=10)
    axis.set_ylabel("Count (symlog scale)")
    axis.set_title("UL decoding narrows many hypotheses to CRC-validated packets")
    axis.legend()
    axis.grid(axis="y", alpha=0.2)
    figure.tight_layout()
    return figure


def pcap_summary(path: Path) -> dict:
    protocols = pcap_protocol_counts(path)
    directions = Counter()
    if shutil.which("tshark") is not None:
        result = subprocess.run(
            ["tshark", "-r", str(path), "-T", "fields", "-e", "mac-lte.direction"],
            text=True,
            capture_output=True,
            check=False,
        )
        directions.update(line.strip() for line in result.stdout.splitlines() if line.strip())
    return {
        "file": path.name,
        "bytes": path.stat().st_size,
        "frames": _pcap_frame_count(path),
        "downlink MAC frames": directions.get("1", 0),
        "uplink MAC frames": directions.get("0", 0),
        "MAC-LTE frames": protocols.get("mac-lte", 0),
        "RRC frames": protocols.get("lte_rrc", 0),
        "NAS-EPS frames": protocols.get("nas-eps", 0),
        "RLC-LTE frames": protocols.get("rlc-lte", 0),
    }
