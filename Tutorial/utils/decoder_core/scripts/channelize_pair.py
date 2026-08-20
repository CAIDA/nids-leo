#!/usr/bin/python3
"""Resample a synchronized DL/UL fc32 pair with identical DSP chains."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from gnuradio import blocks, filter, gr


class PairResampler(gr.top_block):
    def __init__(
        self,
        dl_input: Path,
        ul_input: Path,
        dl_output: Path,
        ul_output: Path,
        input_rate: int,
        output_rate: int,
    ) -> None:
        super().__init__("synchronized_duplex_resampler")
        common = math.gcd(input_rate, output_rate)
        interpolation = output_rate // common
        decimation = input_rate // common

        for source_path, sink_path in (
            (dl_input, dl_output),
            (ul_input, ul_output),
        ):
            source = blocks.file_source(gr.sizeof_gr_complex, str(source_path), False)
            resampler = filter.rational_resampler_ccc(
                interpolation=interpolation,
                decimation=decimation,
                taps=[],
                fractional_bw=0.45,
            )
            sink = blocks.file_sink(gr.sizeof_gr_complex, str(sink_path), False)
            self.connect(source, resampler, sink)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--dl-output", type=Path, required=True)
    parser.add_argument("--ul-output", type=Path, required=True)
    parser.add_argument("--output-rate", type=int, required=True)
    parser.add_argument("--result", type=Path)
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    capture = manifest["capture"]
    dl_input = Path(capture["dl_file"])
    ul_input = Path(capture["ul_file"])
    # Captures are sometimes renamed after collection (for example, to correct
    # a duration label).  Keep the manifest portable by resolving stale
    # absolute paths from the capture directory that contains the manifest.
    if not dl_input.is_file():
        direct = args.manifest.resolve().parent / dl_input.name
        nested = args.manifest.resolve().parent / "raw" / dl_input.name
        dl_input = direct if direct.is_file() else nested
    if not ul_input.is_file():
        direct = args.manifest.resolve().parent / ul_input.name
        nested = args.manifest.resolve().parent / "raw" / ul_input.name
        ul_input = direct if direct.is_file() else nested
    if not dl_input.is_file() or not ul_input.is_file():
        raise SystemExit(
            f"raw input missing: DL={dl_input} UL={ul_input}"
        )
    input_rate = int(capture["sample_rate_hz"])
    if dl_input.stat().st_size != ul_input.stat().st_size:
        raise SystemExit("raw DL and UL files are not the same size")

    args.dl_output.parent.mkdir(parents=True, exist_ok=True)
    flowgraph = PairResampler(
        dl_input,
        ul_input,
        args.dl_output,
        args.ul_output,
        input_rate,
        args.output_rate,
    )
    flowgraph.run()

    dl_bytes = args.dl_output.stat().st_size
    ul_bytes = args.ul_output.stat().st_size
    if dl_bytes == 0 or ul_bytes == 0 or dl_bytes % 8 or ul_bytes % 8:
        raise SystemExit(
            f"invalid paired output lengths: DL={dl_bytes}, UL={ul_bytes}"
        )
    trimmed_samples = 0
    if dl_bytes != ul_bytes:
        difference = abs(dl_bytes - ul_bytes)
        if difference > 64 * 8:
            raise SystemExit(
                f"invalid paired output lengths: DL={dl_bytes}, UL={ul_bytes}"
            )
        paired_bytes = min(dl_bytes, ul_bytes)
        for output in (args.dl_output, args.ul_output):
            with output.open("r+b") as handle:
                handle.truncate(paired_bytes)
        trimmed_samples = difference // 8
        dl_bytes = paired_bytes
        ul_bytes = paired_bytes

    result = {
        "method": "gnuradio.rational_resampler_ccc",
        "source_manifest": str(args.manifest.resolve()),
        "input_sample_rate_hz": input_rate,
        "output_sample_rate_hz": args.output_rate,
        "dl_output": str(args.dl_output.resolve()),
        "ul_output": str(args.ul_output.resolve()),
        "samples_per_channel": dl_bytes // 8,
        "bytes_per_file": dl_bytes,
        "end_of_stream_samples_trimmed": trimmed_samples,
        "alignment": (
            "identical rational ratio, taps, and group delay were applied "
            "to both channels in one flowgraph"
        ),
    }
    result_path = args.result or args.dl_output.parent / "pair_resample.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
