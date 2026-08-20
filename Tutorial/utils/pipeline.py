"""Persistent, restartable decoder pipeline used by the tutorial notebook.

Every public ``ensure_*`` method validates its expected output and prints
``SKIP`` when it is already stored. Missing stages call the checked-in decoder
scripts and external LTE/srsRAN binaries, write into ``decoder_results/``, and
leave their intermediate audit files available for the following notebook
visualizations.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any
from contextlib import contextmanager
import fcntl


class PipelineError(RuntimeError):
    pass


class TutorialPipeline:
    def __init__(self, repo_root: Path, config_path: Path | None = None):
        self.repo = repo_root.resolve()
        self.tutorial = self.repo / "Tutorial"
        self.core = self.tutorial / "utils" / "decoder_core"
        self.config_path = config_path or self.tutorial / "config" / "tsat_5s_demo_pipeline.json"
        self.config = json.loads(self.config_path.read_text())
        self.raw = self.tutorial / "raw_data"
        local_processed = self.tutorial / "processed_data"
        self.local_processed = local_processed
        override_path = local_processed / "source_override.json"
        override: dict[str, Any] = {}
        if override_path.is_file():
            override = json.loads(override_path.read_text())
        selected = os.environ.get("LTE_PROCESSED_DATA_DIR") or override.get("directory")
        self.processed = Path(selected).expanduser().resolve() if selected else local_processed
        self.downlink_iq = self.processed / override.get(
            "downlink_file", "downlink_5p76Msps.fc32"
        )
        self.uplink_iq = self.processed / override.get(
            "uplink_file", "uplink_5p76Msps.fc32"
        )
        self.results = self.tutorial / "decoder_results"
        self.runtime = self.results / "runtime"
        self.downlink = self.results / "downlink"
        self.uplink = self.results / "uplink"
        self.pcap = self.results / "pcap"
        self.rate = int(self.config["sample_rate_hz"])
        self.report: list[dict[str, Any]] = []

    def ensure_processed(self) -> tuple[Path, Path]:
        """Create or validate the continuous 5.76 MS/s IQ pair."""
        source_manifest = self.raw / "capture.json"
        if not source_manifest.is_file():
            raise PipelineError(f"missing raw capture metadata: {source_manifest}")
        raw_metadata = json.loads(source_manifest.read_text())
        capture = raw_metadata["capture"]
        input_rate = int(capture["sample_rate_hz"])
        input_samples = int(capture["sample_count_per_channel"])
        nominal_samples = input_samples * self.rate // input_rate
        processing_manifest = self.local_processed / "processing.json"

        saved: dict[str, Any] = {}
        if processing_manifest.is_file():
            try:
                saved = json.loads(processing_manifest.read_text())
            except json.JSONDecodeError:
                saved = {}
        dl_samples = self.downlink_iq.stat().st_size // 8 if self.downlink_iq.is_file() else -1
        ul_samples = self.uplink_iq.stat().st_size // 8 if self.uplink_iq.is_file() else -1
        complete = (
            saved.get("method") == "gnuradio.rational_resampler_ccc"
            and int(saved.get("input_sample_rate_hz", -1)) == input_rate
            and int(saved.get("output_sample_rate_hz", -1)) == self.rate
            and int(saved.get("source_samples_per_channel", -1)) == input_samples
            and dl_samples == ul_samples
            and abs(dl_samples - nominal_samples) <= 256
        )
        if complete:
            self._record("processed IQ", "SKIP", f"{dl_samples:,} samples per channel")
            return self.downlink_iq, self.uplink_iq

        if self.processed != self.local_processed:
            raise PipelineError(
                f"invalid processed-IQ override: {self.processed}; remove "
                f"{self.local_processed / 'source_override.json'} or repair the override"
            )
        if not (self.raw / "downlink.fc32").is_file() or not (self.raw / "uplink.fc32").is_file():
            raise PipelineError(f"missing raw IQ under {self.raw}")

        self.local_processed.mkdir(parents=True, exist_ok=True)
        dl_partial = self.downlink_iq.with_suffix(".fc32.partial")
        ul_partial = self.uplink_iq.with_suffix(".fc32.partial")
        manifest_partial = self.local_processed / "processing.partial.json"
        for partial in (dl_partial, ul_partial, manifest_partial):
            partial.unlink(missing_ok=True)
        self._run([
            "/usr/bin/python3", str(self.core / "scripts" / "channelize_pair.py"),
            "--manifest", str(source_manifest), "--dl-output", str(dl_partial),
            "--ul-output", str(ul_partial), "--output-rate", str(self.rate),
            "--result", str(manifest_partial),
        ])
        dl_samples = dl_partial.stat().st_size // 8
        ul_samples = ul_partial.stat().st_size // 8
        if dl_samples != ul_samples or abs(dl_samples - nominal_samples) > 256:
            raise PipelineError(
                f"invalid resampler output: DL={dl_samples:,}, UL={ul_samples:,}, "
                f"nominal={nominal_samples:,}"
            )
        dl_partial.replace(self.downlink_iq)
        ul_partial.replace(self.uplink_iq)
        processing = json.loads(manifest_partial.read_text())
        processing.update({
            "source_samples_per_channel": input_samples,
            "processed_samples_per_channel": dl_samples,
            "downlink_file": self.downlink_iq.name,
            "uplink_file": self.uplink_iq.name,
        })
        processing_manifest.write_text(json.dumps(processing, indent=2) + "\n")
        manifest_partial.unlink(missing_ok=True)
        self._record("processed IQ", "CREATE", f"{dl_samples:,} samples per channel")
        return self.downlink_iq, self.uplink_iq

    def _record(self, stage: str, status: str, detail: str) -> None:
        item = {"stage": stage, "status": status, "detail": detail}
        self.report.append(item)
        print(f"{status:7} {stage}: {detail}")

    @contextmanager
    def _stage_lock(self, name: str):
        """Prevent two notebook kernels from rewriting one stage concurrently."""
        self.results.mkdir(parents=True, exist_ok=True)
        path = self.results / f".{name}.lock"
        with path.open("a+") as handle:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                handle.seek(0)
                owner = handle.read().strip() or "another process"
                raise PipelineError(
                    f"{name} stage is already running ({owner}). Wait for that "
                    "notebook kernel to finish; do not start a second Run All."
                ) from exc
            handle.seek(0)
            handle.truncate()
            handle.write(f"pid={os.getpid()}")
            handle.flush()
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _nonempty(path: Path, minimum: int = 1) -> bool:
        return path.is_file() and path.stat().st_size >= minimum

    @staticmethod
    def _jsonl_valid(path: Path, *, allow_empty: bool = False) -> bool:
        if not path.is_file():
            return False
        lines = [line for line in path.read_text(errors="replace").splitlines() if line.strip()]
        if not lines:
            return allow_empty
        try:
            for line in lines:
                json.loads(line)
        except json.JSONDecodeError:
            return False
        return True

    def _tool(self, env_name: str, config_name: str) -> Path:
        candidates = []
        if os.environ.get(env_name):
            candidates.append(os.environ[env_name])
        if config_name in {"ltesniffer", "aligner", "ul_probe"}:
            local_name = {
                "ltesniffer": "LTESniffer",
                "aligner": "align_duplex_lte",
                "ul_probe": "ul_grant_probe",
            }[config_name]
            candidates.append(str(self.core / "build" / local_name))
        candidates.extend(self.config.get("legacy_tool_candidates", {}).get(config_name, []))
        for candidate in candidates:
            path = Path(candidate).expanduser()
            if path.is_file() and os.access(path, os.X_OK):
                return path.resolve()
        raise PipelineError(
            f"Missing {config_name}. Set {env_name}, or build the helper described in "
            f"{self.core / 'README.md'}"
        )

    def _run(
        self,
        command: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        log: Path | None = None,
        accepted: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess:
        if cwd:
            cwd.mkdir(parents=True, exist_ok=True)
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            env=env,
        )
        if log:
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(completed.stdout)
        if completed.returncode not in accepted:
            tail = "\n".join(completed.stdout.splitlines()[-30:])
            raise PipelineError(
                f"command failed ({completed.returncode}): {' '.join(command)}\n{tail}"
            )
        return completed

    def ensure_manifest(self) -> Path:
        path = self.results / "manifest.json"
        if self._nonempty(path):
            stored = json.loads(path.read_text())
            stored_labels = [cell.get("label") for cell in stored.get("cells", [])]
            configured_labels = [cell["label"] for cell in self.config["cells"]]
            if (
                stored.get("capture") == self.config.get("capture")
                and stored.get("minimum_crc_valid_ul")
                == self.config.get("minimum_crc_valid_ul")
                and stored_labels == configured_labels
            ):
                self._record("manifest", "SKIP", str(path))
                return path
        self.results.mkdir(parents=True, exist_ok=True)
        manifest = {
            **self.config,
            "duration_s": float(self.config["capture_duration_s"]),
            "downlink_center_hz": 1_992_500_000,
            "uplink_center_hz": 1_912_500_000,
            "identity_note": (
                "logical_satellite_id is the conventional 20-bit eNB portion of the "
                "28-bit SIB1 ECI; it is not a NORAD spacecraft ID."
            ),
        }
        for cell in manifest["cells"]:
            cell["dl_pcap"] = f"downlink/{cell['label']}.pcap"
        path.write_text(json.dumps(manifest, indent=2) + "\n")
        self._record("manifest", "CREATE", str(path))
        return path

    def _segment_paths(self, cell: dict) -> dict[str, Path]:
        label = cell["label"]
        directory = self.runtime / label
        return {
            "directory": directory,
            "paired": directory / "ltesniffer_duplex_aligned.fc32",
            "alignment_log": directory / "alignment.log",
            "ul_mode": directory / "ul_mode",
            "grant_log": directory / "ul_mode" / "decode.log",
            "rrc_pcap": directory / "ul_mode" / "ltesniffer_ul_mode.pcap",
            "dl_runtime": directory / "full_dl",
            "dl_pcap": self.downlink / f"{label}.pcap",
            "dl_log": self.downlink / f"{label}.log",
        }

    def ensure_downlink(self, cell: dict) -> dict[str, Path]:
        paths = self._segment_paths(cell)
        stage = f"DL {cell['label']}"
        if (
            self._nonempty(paths["dl_pcap"], 24)
            and self._nonempty(paths["dl_log"])
            and "Decoded MIB" in paths["dl_log"].read_text(errors="replace")
        ):
            self._record(stage, "SKIP", "stored PCAP and MIB-confirmed log")
            return paths

        aligner = self._tool("ALIGN_DUPLEX_LTE_BIN", "aligner")
        ltesniffer = self._tool("LTESNIFFER_BIN", "ltesniffer")
        paths["directory"].mkdir(parents=True, exist_ok=True)
        max_subframes = int(round(float(cell["duration_s"]) * 1000))
        offset = int(round(float(cell["start_s"]) * self.rate))
        paired_bytes = max_subframes * (self.rate // 1000) * 2 * 8

        if not paths["paired"].is_file() or paths["paired"].stat().st_size != paired_bytes:
            if paths["paired"].is_file():
                paths["paired"].unlink()
            self._run(
                [
                    str(aligner), "--dl", str(self.downlink_iq),
                    "--ul", str(self.uplink_iq),
                    "--output", str(paths["paired"]), "--pci", str(cell["pci"]),
                    "--prb", str(self.config["prb"]),
                    "--cfo-hz", str(cell["cfo_hz"]), "--offset-samples", str(offset),
                    "--max-subframes", str(max_subframes),
                ],
                log=paths["alignment_log"],
                accepted=(0, 3),
            )
            actual_bytes = paths["paired"].stat().st_size if paths["paired"].is_file() else 0
            if actual_bytes != paired_bytes:
                raise PipelineError(
                    f"alignment failed for {cell['label']}: retained "
                    f"{actual_bytes // (self.rate // 1000 * 2 * 8):,}/"
                    f"{max_subframes:,} subframes using CFO seed {cell['cfo_hz']} Hz"
                )

        # DL mode preserves broadcast plus dedicated DL traffic, including SIBs.
        self._run(
            [
                "python3", str(self.core / "scripts" / "decode_complete_downlink.py"),
                "--input", str(paths["paired"]), "--output-dir", str(paths["dl_runtime"]),
                "--pci", str(cell["pci"]), "--subframes", str(max_subframes),
                "--ports", str(self.config["ports"]), "--prb", str(self.config["prb"]),
                "--decoder", str(ltesniffer),
            ]
        )
        self.downlink.mkdir(parents=True, exist_ok=True)
        shutil.copy2(paths["dl_runtime"] / "ltesniffer_dl_mode.pcap", paths["dl_pcap"])
        shutil.copy2(paths["dl_runtime"] / "decode.log", paths["dl_log"])
        if not self._nonempty(paths["dl_pcap"], 24) or "Decoded MIB" not in paths["dl_log"].read_text(errors="replace"):
            raise PipelineError(f"DL validation failed for {cell['label']}")
        self._record(stage, "CREATE", str(paths["dl_pcap"]))
        return paths

    def ensure_uplink(self, cell: dict, paths: dict[str, Path]) -> Path | None:
        result_label = cell.get("ul_result")
        if not result_label:
            self._record(f"UL {cell['label']}", "SKIP", "no UL segment configured")
            return None
        output = self.uplink / result_label
        crc_path = output / "crc_valid_ul.jsonl"
        minimum_crc = int(cell.get("minimum_ul_crc", 0))
        allow_empty = minimum_crc == 0
        required = [
            output / "summary.json", output / "grant_directed_acquisition.jsonl",
            output / "decode_attempts.jsonl", crc_path,
        ]
        stored_crc = (
            sum(bool(line.strip()) for line in crc_path.read_text().splitlines())
            if crc_path.is_file() else -1
        )
        if (
            all(path.is_file() for path in required)
            and self._jsonl_valid(crc_path, allow_empty=allow_empty)
            and stored_crc >= minimum_crc
        ):
            self._record(f"UL {cell['label']}", "SKIP", "stored acquisition, attempts, and CRC output")
            return crc_path

        # This replay extracts DCI0/RAR scheduling rows from the already decoded
        # DL. It deliberately runs here, after every DL segment has completed.
        ltesniffer = self._tool("LTESNIFFER_BIN", "ltesniffer")
        max_subframes = int(round(float(cell["duration_s"]) * 1000))
        if not self._nonempty(paths["grant_log"]) or "[UL-TRY]" not in paths["grant_log"].read_text(errors="replace"):
            command = [
                str(ltesniffer), "-A", "2", "-W", "4", "-i", str(paths["paired"]),
                "-P", str(self.config["ports"]), "-c", str(cell["pci"]),
                "-p", str(self.config["prb"]), "-x", self.config["phich_resources"],
                "-X", self.config["phich_length"], "-K", self.config["cp"],
                "-m", "1", "-n", str(max_subframes), "-D", "dci.txt", "-E", "stats.txt",
            ]
            ul_environment = os.environ.copy()
            ul_environment["LTESNIFFER_UL_DIAGNOSTICS"] = "1"
            self._run(
                command, cwd=paths["ul_mode"], env=ul_environment,
                log=paths["grant_log"], accepted=(0, 1, -6, -11),
            )
        grant_rows = paths["grant_log"].read_text(errors="replace").count("[UL-TRY]")
        if grant_rows == 0:
            raise PipelineError(
                f"no parseable UL grants for {cell['label']}; check PCI, CFO seed, "
                "aligned duration, and the patched LTEsniffer binary"
            )

        probe = self._tool("UL_GRANT_PROBE_BIN", "ul_probe")
        preliminary = self.runtime / cell["label"] / "burst_first"
        burst_audit = preliminary / "burst_audit.jsonl"
        if not self._jsonl_valid(burst_audit):
            self._run(
                [
                    "python3", str(self.core / "scripts" / "burst_first_ul_decode_v2.py"),
                    "--input", str(paths["paired"]), "--grant-log", str(paths["grant_log"]),
                    "--pci", str(cell["pci"]), "--output-dir", str(preliminary),
                    "--rrc-pcap", str(paths["rrc_pcap"]), "--rrc-pcap", str(paths["dl_pcap"]),
                    "--probe", str(probe), "--radius-ms", "0.35", "--workers", "4",
                ]
            )
        self._run(
            [
                "python3", str(self.core / "scripts" / "grant_directed_wide_timing.py"),
                "--input", str(paths["paired"]), "--grant-log", str(paths["grant_log"]),
                "--burst-audit", str(burst_audit), "--pci", str(cell["pci"]),
                "--output-dir", str(output), "--rrc-pcap", str(paths["rrc_pcap"]),
                "--rrc-pcap", str(paths["dl_pcap"]), "--probe", str(probe),
                "--radius-ms", "5.0", "--timing-candidates", "4", "--workers", "4",
            ]
        )
        generated_crc = sum(bool(line.strip()) for line in crc_path.read_text().splitlines()) if crc_path.is_file() else -1
        if not self._jsonl_valid(crc_path, allow_empty=allow_empty) or generated_crc < minimum_crc:
            summary_path = output / "summary.json"
            summary = json.loads(summary_path.read_text()) if summary_path.is_file() else {}
            raise PipelineError(
                f"UL validation failed for {cell['label']}: generated {generated_crc} "
                f"CRC-valid packets, required at least {minimum_crc}; "
                f"timing tasks={summary.get('grant_directed_timing_tasks', 'unknown')}, "
                f"DMRS accepted={summary.get('dmrs_accepted', 'unknown')}, "
                f"decode attempts={summary.get('decode_attempts', 'unknown')}"
            )
        self._record(f"UL {cell['label']}", "CREATE", str(crc_path))
        return crc_path

    def _write_packaging_spec(self, segment_outputs: dict[str, dict[str, Path]]) -> tuple[Path, list[str]]:
        cells = []
        overrides = []
        for cell in self.config["cells"]:
            paths = segment_outputs[cell["label"]]
            cells.append({
                "label": cell["label"], "pci": cell["pci"], "anchor_s": cell["start_s"],
                "dl_pcap": str(paths["dl_pcap"]), "decode_log": str(paths["dl_log"]),
            })
            if cell.get("ul_result"):
                crc = self.uplink / cell["ul_result"] / "crc_valid_ul.jsonl"
                overrides.append(f"{cell['label']}={crc}")
        path = self.runtime / "packaging_spec.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"cells": cells}, indent=2) + "\n")
        return path, overrides

    def ensure_discovery_metadata(self, segment_outputs: dict[str, dict[str, Path]]) -> None:
        search_path = self.results / "cell_search_results.json"
        mib_path = self.results / "mib_results.json"
        if self._nonempty(search_path) and self._nonempty(mib_path):
            self._record("PCI/MIB metadata", "SKIP", "stored JSON summaries")
            return
        search_rows = []
        mib_rows = []
        for cell in self.config["cells"]:
            paths = segment_outputs[cell["label"]]
            text = paths["dl_log"].read_text(errors="replace")
            decoded = re.search(r"Decoded MIB\. SFN: (\d+), offset: (\d+)", text)
            if not decoded:
                raise PipelineError(f"cannot summarize MIB for {cell['label']}")
            sfn, sfn_offset = map(int, decoded.groups())
            search = {
                "found": True,
                "frame_type": "FDD",
                "pci": int(cell["pci"]),
                "time_s": float(cell["start_s"]),
                "offset_samples": int(round(float(cell["start_s"]) * 1_920_000)),
                "source": "configured segment followed by synchronization and MIB confirmation",
            }
            search_rows.append(search)
            mib_rows.append({
                "pci": int(cell["pci"]), "mib_found": True, "frame_type": "FDD",
                "nof_prb": int(self.config["prb"]), "nof_ports": int(self.config["ports"]),
                "phich_length": self.config["phich_length"],
                "phich_resources": self.config["phich_resources"],
                "sfn": sfn, "sfn_offset": sfn_offset, "search": search,
            })
        search_path.write_text(json.dumps(search_rows, indent=2) + "\n")
        mib_path.write_text(json.dumps(mib_rows, indent=2) + "\n")
        self._record("PCI/MIB metadata", "CREATE", "summaries derived from MIB-confirmed DL logs")

    def ensure_sib1_identities(self, segment_outputs: dict[str, dict[str, Path]]) -> None:
        if shutil.which("tshark") is None:
            raise PipelineError("tshark is required to extract SIB1 cellIdentity")
        manifest_path = self.results / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        by_label = {cell["label"]: cell for cell in manifest["cells"]}
        decoded_count = 0
        changed = False
        for configured in self.config["cells"]:
            stored = by_label[configured["label"]]
            pcap = segment_outputs[configured["label"]]["dl_pcap"]
            completed = subprocess.run(
                [
                    "tshark", "-r", str(pcap), "-Y", "lte-rrc.cellIdentity",
                    "-T", "fields", "-e", "lte-rrc.cellIdentity",
                    "-e", "lte-rrc.trackingAreaCode",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            first = next((line for line in completed.stdout.splitlines() if line.strip()), "")
            identity = {"eci_28bit": None, "logical_satellite_id": None, "sector_id": None, "tac_hex": None}
            if first:
                fields = first.split("\t")
                try:
                    eci = int(fields[0], 16) >> 4
                except (ValueError, IndexError):
                    eci = None
                if eci is not None:
                    identity = {
                        "eci_28bit": eci,
                        "logical_satellite_id": eci >> 8,
                        "sector_id": eci & 0xFF,
                        "tac_hex": fields[1] if len(fields) > 1 and fields[1] else None,
                    }
                    decoded_count += 1
            for key, value in identity.items():
                if stored.get(key) != value:
                    stored[key] = value
                    changed = True
        if changed:
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        self._record("SIB1 identities", "VERIFY", f"decoded from {decoded_count}/{len(self.config['cells'])} DL PCAP segments")

    def ensure_pcap(self, segment_outputs: dict[str, dict[str, Path]]) -> Path:
        final = self.pcap / "all_cells_complete_dl_ul_with_mib.pcapng"
        summary = self.pcap / "full_trace_summary.json"
        if self._nonempty(final, 1000) and self._nonempty(summary):
            decoded = json.loads(summary.read_text())
            packets = decoded.get("packets", {})
            minimum = int(self.config["minimum_crc_valid_ul"])
            current_ul = 0
            for cell in self.config["cells"]:
                if cell.get("ul_result"):
                    crc_path = self.uplink / cell["ul_result"] / "crc_valid_ul.jsonl"
                    if crc_path.is_file():
                        current_ul += sum(
                            bool(line.strip()) for line in crc_path.read_text().splitlines()
                        )
            stored_capture = Path(decoded.get("capture", "")).expanduser().resolve()
            if (
                int(packets.get("crc_valid_uplink_mac", -1)) == current_ul
                and current_ul >= minimum
                and stored_capture == self.raw.resolve()
            ):
                self._record("final PCAPNG", "SKIP", str(final))
                return final

        spec, overrides = self._write_packaging_spec(segment_outputs)
        command = [
            "python3", str(self.core / "scripts" / "package_segmented_full_duplex.py"),
            "--run", str(self.raw), "--spec", str(spec), "--output-dir", str(self.pcap),
        ]
        for override in overrides:
            command.extend(["--ul-jsonl", override])
        self._run(command)
        if not self._nonempty(final, 1000):
            raise PipelineError("final PCAPNG was not created")
        decoded = json.loads((self.pcap / "full_trace_summary.json").read_text())
        generated_ul = int(decoded.get("packets", {}).get("crc_valid_uplink_mac", -1))
        if generated_ul < int(self.config["minimum_crc_valid_ul"]):
            raise PipelineError(
                f"final PCAP contains {generated_ul} CRC-valid UL frames; "
                f"required at least {self.config['minimum_crc_valid_ul']}"
            )
        self._record("final PCAPNG", "CREATE", str(final))
        return final

    def _check_prerequisites(self) -> None:
        for required in (
            self.raw / "capture.json",
            self.downlink_iq,
            self.uplink_iq,
        ):
            if not required.is_file():
                raise PipelineError(f"missing prerequisite: {required}")

    def _write_report(self) -> None:
        self.results.mkdir(parents=True, exist_ok=True)
        report_path = self.results / "pipeline_report.json"
        report_path.write_text(json.dumps(self.report, indent=2) + "\n")

    def _ensure_downlinks_unlocked(self) -> tuple[dict[str, dict[str, Path]], list[dict[str, Any]]]:
        """Finish every configured DL segment before any expensive UL work."""
        self.ensure_processed()
        self._check_prerequisites()
        self.ensure_manifest()
        segment_outputs: dict[str, dict[str, Path]] = {}
        for cell in self.config["cells"]:
            paths = self.ensure_downlink(cell)
            segment_outputs[cell["label"]] = paths
        self.ensure_sib1_identities(segment_outputs)
        self.ensure_discovery_metadata(segment_outputs)
        self._write_report()
        return segment_outputs, self.report

    def ensure_downlinks(self) -> tuple[dict[str, dict[str, Path]], list[dict[str, Any]]]:
        with self._stage_lock("downlink"):
            return self._ensure_downlinks_unlocked()

    def _ensure_uplinks_unlocked(
        self, segment_outputs: dict[str, dict[str, Path]] | None = None
    ) -> tuple[Path, list[dict[str, Any]]]:
        """Decode UL from completed DL grants, then package the final trace."""
        if segment_outputs is None:
            segment_outputs, _ = self.ensure_downlinks()
        for cell in self.config["cells"]:
            self.ensure_uplink(cell, segment_outputs[cell["label"]])
        final = self.ensure_pcap(segment_outputs)
        self._write_report()
        return final, self.report

    def ensure_uplinks(
        self, segment_outputs: dict[str, dict[str, Path]] | None = None
    ) -> tuple[Path, list[dict[str, Any]]]:
        with self._stage_lock("uplink"):
            return self._ensure_uplinks_unlocked(segment_outputs)

    def ensure_all(self) -> tuple[Path, list[dict[str, Any]]]:
        segment_outputs, _ = self.ensure_downlinks()
        return self.ensure_uplinks(segment_outputs)
