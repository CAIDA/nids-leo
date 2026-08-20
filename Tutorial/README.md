# Raw IQ to LTE PCAP tutorial

This directory contains an undergraduate-friendly, executable tutorial for
converting a synchronized five-second X300 downlink/uplink excerpt into a
trusted LTE packet trace. The excerpt is capture time 4.000–9.000 seconds from
the archived 150-second recording and focuses on PCI 427.

Start with:

1. `01_raw_iq_and_downsampling.ipynb` — the complete tutorial in one notebook:
   IQ validation, full-trace downsampling, DL cell/MIB/SIB decoding, multi-PCI
   and SIB1 identity visualization, grant-directed UL recovery, CRC filtering,
   and final PCAP/PCAPNG inspection.

The reusable outputs are written to `Tutorial/processed_data/`. The DL and UL
are continuously resampled together with GNU Radio; output size alone is not
accepted as proof of a valid processed pair. Plots appear only in the notebook
and are not stored as images.

The restartable orchestrator is `Tutorial/utils/pipeline.py`, and the decoder
implementation is under `Tutorial/utils/decoder_core/`. Each stage validates
and skips a complete stored output, or generates it when missing. Intermediate
artifacts and final PCAPs are written to
`Tutorial/decoder_results/` and ignored by Git.

A clean rebuild uses the measured CFO seed stored for each fixed-capture cell,
requires the exact configured number of aligned subframes, and enables the
patched LTEsniffer diagnostic grant catalog needed by the UL decoder. The
notebook then analyzes the generated PCI, SIB1, grant, timing/CFO, DMRS, CRC,
and PCAP artifacts in place.

The notebook completes the selected PCI 427 DL and its analysis first. The
grant-directed UL search starts later in Part 3. A clean rebuild is restartable:
validated stages print `SKIP` on the next run.

## Setup

On Ubuntu 22.04/24.04, start from a clean checkout with:

```bash
bash Tutorial/setup_ubuntu.sh
.venv/bin/jupyter lab Tutorial/01_raw_iq_and_downsampling.ipynb
```

The setup script installs the system compiler/DSP/Wireshark dependencies,
creates `.venv`, installs `requirements.txt`, clones a pinned upstream
LTESniffer revision, applies `Tutorial/vendor/ltesniffer-overlay/`, and builds
these repository-local executables:

```text
Tutorial/utils/decoder_core/build/LTESniffer
Tutorial/utils/decoder_core/build/align_duplex_lte
Tutorial/utils/decoder_core/build/ul_grant_probe
```

No preinstalled LTEsniffer or srsRAN tree is assumed. Internet access and sudo
permission for `apt-get` are required during initial setup. Run
`python Tutorial/check_setup.py` to verify the installation before decoding.

Typical time on an 8-core workstation is approximately 10–60 seconds for IQ
resampling, 1–3 minutes for the PCI 427 DL stage, and roughly 5–20 minutes for
grant-directed UL recovery. Storage speed, CPU count, and candidate count can
change these estimates.

The notebook expects the two 400 MB, 10 MS/s excerpt files in
`Tutorial/raw_data/`. The complete 150-second IQ is deliberately
not required by the tutorial.
