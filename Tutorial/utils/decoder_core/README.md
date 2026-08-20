# Decoder core used by the notebook

This directory keeps the real decoder implementation separate from the short
inspection and plotting helpers imported by the notebook.

- `process.py` performs cell search, PBCH/MIB confirmation, paired DL/UL
  subframe alignment, and LTEsniffer replay.
- `decode_complete_downlink.py` runs the patched LTEsniffer DL path.
- `probe_ul_grants.py`, `burst_first_ul_decode_v2.py`, and
  `grant_directed_wide_timing.py` implement DCI/RAR-directed PUSCH recovery.
- `ta_directed_ul_decode.py` and `extract_lte_ta_state.py` add RAR and timing
  advance guidance.
- `ul_grant_probe.cpp` performs UL timing/CFO/DMRS acquisition and transport
  block decoding using srsRAN 4G.
- the packaging scripts create MAC-LTE PCAP/PCAPNG output with timestamps,
  direction, PCI, and RNTI context.

The Python files are checked in here, but the patched LTEsniffer and srsRAN
libraries are external build dependencies. Set `LTESNIFFER_BIN` and
`UL_GRANT_PROBE_BIN` before enabling full decoder execution in the notebook.
Cached intermediate artifacts are used by default so every visualization can
be reproduced without spending hours rerunning the PHY decoder.

Build the two included srsRAN-based helpers with:

```bash
SRSRAN_ROOT=/path/to/srsRAN_4G ./build.sh
export UL_GRANT_PROBE_BIN="$PWD/build/ul_grant_probe"
```
