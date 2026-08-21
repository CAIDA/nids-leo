/*
 * Search a paired LTEsniffer fc32 file for the waveform belonging to one
 * known uplink grant.  This deliberately does not assume a common DL/UL lag:
 * it finds LTE normal-CP symbol boundaries, corrects their CP-derived CFO,
 * and scores the configured PUSCH DMRS across an arbitrary time window.
 */

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <complex.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "srsran/srsran.h"
}
#undef I

namespace {

struct Options {
  std::string input;
  uint64_t target_sf = 0;
  double radius_ms = 20.0;
  uint32_t pci = 0;
  uint32_t tti = 0;
  uint32_t prb = 0;
  uint32_t prb_slot1 = 0;
  bool prb_slot1_set = false;
  uint32_t len_prb = 0;
  uint32_t n_dmrs = 0;
  uint32_t top = 20;
  bool sweep_sequence = false;
  bool sequence_table = false;
  bool decode = false;
  uint32_t rnti = 0;
  uint32_t mcs = 0;
  uint32_t tbs = 0;
  uint32_t rv = 0;
  uint32_t nof_ack = 0;
  std::string cqi_type = "none";
  uint32_t ri_len = 0;
  bool pmi_present = false;
  uint32_t offset_ack = 10;
  uint32_t offset_cqi = 8;
  uint32_t offset_ri = 11;
  uint32_t decode_top = 20;
  std::string modulation = "qpsk";
  bool fixed_lag = false;
  int64_t fixed_lag_samples = 0;
  int64_t center_lag_samples = 0;
  bool fixed_correction = false;
  float fixed_correction_hz = 0.0f;
  std::string diag_output;
  std::string sweep_output;
  std::string sweep_rntis;
  std::string sequence_keys;
};

struct PairSample {
  cf_t dl;
  cf_t ul;
};

struct Candidate {
  int64_t lag_samples;
  uint64_t file_sample;
  float cp;
  float cp_cfo_hz;
  float correction_hz;
  int cfo_branch;
  uint32_t sf_idx;
  uint32_t n_dmrs;
  float coherence;
  float snr_db;
  float ta_us;
};

void usage(const char* program)
{
  std::fprintf(
      stderr,
      "Usage: %s --input paired.fc32 --target-sf N --radius-ms MS\n"
      "          --pci PCI --tti TTI --prb START --len-prb N --n-dmrs N\n"
      "          [--prb-slot1 START] [--top N] [--sweep-sequence]\n"
      "          [--sequence-table]\n"
      "          [--sequence-keys SF:NDMRS,...]\n"
      "          [--center-lag-samples N]\n"
      "          [--fixed-lag-samples N --fixed-correction-hz HZ]\n"
      "          [--decode --rnti RNTI --mcs MCS --tbs BITS --rv RV\n"
      "           --mod qpsk|16qam|64qam|256qam --nof-ack 0|1|2\n"
      "           --cqi-type none|wideband|subband-ue|subband-hl|both\n"
      "           --ri-len 0|1 --pmi-present\n"
      "           --offset-ack N --offset-cqi N --offset-ri N\n"
      "           --decode-top N --diag-output FILE.json\n"
      "           --sweep-output FILE.csv [--sweep-rntis RNTI,...]]\n",
      program);
}

bool parse_options(int argc, char** argv, Options& options)
{
  static const option long_options[] = {
      {"input", required_argument, nullptr, 'i'},
      {"target-sf", required_argument, nullptr, 't'},
      {"radius-ms", required_argument, nullptr, 'r'},
      {"pci", required_argument, nullptr, 'c'},
      {"tti", required_argument, nullptr, 'T'},
      {"prb", required_argument, nullptr, 'p'},
      {"prb-slot1", required_argument, nullptr, 1006},
      {"len-prb", required_argument, nullptr, 'l'},
      {"n-dmrs", required_argument, nullptr, 'n'},
      {"top", required_argument, nullptr, 'k'},
      {"sweep-sequence", no_argument, nullptr, 's'},
      {"sequence-table", no_argument, nullptr, 1007},
      {"decode", no_argument, nullptr, 'd'},
      {"rnti", required_argument, nullptr, 'R'},
      {"mcs", required_argument, nullptr, 'm'},
      {"tbs", required_argument, nullptr, 'b'},
      {"rv", required_argument, nullptr, 'v'},
      {"mod", required_argument, nullptr, 'M'},
      {"nof-ack", required_argument, nullptr, 'a'},
      {"cqi-type", required_argument, nullptr, 'q'},
      {"ri-len", required_argument, nullptr, 'I'},
      {"pmi-present", no_argument, nullptr, 'P'},
      {"offset-ack", required_argument, nullptr, 1000},
      {"offset-cqi", required_argument, nullptr, 1001},
      {"offset-ri", required_argument, nullptr, 1002},
      {"diag-output", required_argument, nullptr, 1003},
      {"sweep-output", required_argument, nullptr, 1004},
      {"sweep-rntis", required_argument, nullptr, 1005},
      {"decode-top", required_argument, nullptr, 'D'},
      {"fixed-lag-samples", required_argument, nullptr, 'L'},
      {"fixed-correction-hz", required_argument, nullptr, 'F'},
      {"center-lag-samples", required_argument, nullptr, 1008},
      {"sequence-keys", required_argument, nullptr, 1009},
      {"help", no_argument, nullptr, 'h'},
      {nullptr, 0, nullptr, 0},
  };

  int ch;
  while ((ch = getopt_long(
              argc, argv, "i:t:r:c:T:p:l:n:k:sdR:m:b:v:M:a:q:I:PD:L:F:h", long_options, nullptr)) != -1) {
    switch (ch) {
      case 'i': options.input = optarg; break;
      case 't': options.target_sf = std::strtoull(optarg, nullptr, 10); break;
      case 'r': options.radius_ms = std::strtod(optarg, nullptr); break;
      case 'c': options.pci = std::strtoul(optarg, nullptr, 10); break;
      case 'T': options.tti = std::strtoul(optarg, nullptr, 10); break;
      case 'p': options.prb = std::strtoul(optarg, nullptr, 10); break;
      case 1006:
        options.prb_slot1 = std::strtoul(optarg, nullptr, 10);
        options.prb_slot1_set = true;
        break;
      case 'l': options.len_prb = std::strtoul(optarg, nullptr, 10); break;
      case 'n': options.n_dmrs = std::strtoul(optarg, nullptr, 10); break;
      case 'k': options.top = std::strtoul(optarg, nullptr, 10); break;
      case 's': options.sweep_sequence = true; break;
      case 1007:
        options.sequence_table = true;
        options.sweep_sequence = true;
        break;
      case 'd': options.decode = true; break;
      case 'R': options.rnti = std::strtoul(optarg, nullptr, 10); break;
      case 'm': options.mcs = std::strtoul(optarg, nullptr, 10); break;
      case 'b': options.tbs = std::strtoul(optarg, nullptr, 10); break;
      case 'v': options.rv = std::strtoul(optarg, nullptr, 10); break;
      case 'M': options.modulation = optarg; break;
      case 'a': options.nof_ack = std::strtoul(optarg, nullptr, 10); break;
      case 'q': options.cqi_type = optarg; break;
      case 'I': options.ri_len = std::strtoul(optarg, nullptr, 10); break;
      case 'P': options.pmi_present = true; break;
      case 1000: options.offset_ack = std::strtoul(optarg, nullptr, 10); break;
      case 1001: options.offset_cqi = std::strtoul(optarg, nullptr, 10); break;
      case 1002: options.offset_ri = std::strtoul(optarg, nullptr, 10); break;
      case 1003: options.diag_output = optarg; break;
      case 1004: options.sweep_output = optarg; break;
      case 1005: options.sweep_rntis = optarg; break;
      case 'D': options.decode_top = std::strtoul(optarg, nullptr, 10); break;
      case 'L':
        options.fixed_lag = true;
        options.fixed_lag_samples = std::strtoll(optarg, nullptr, 10);
        break;
      case 'F':
        options.fixed_correction = true;
        options.fixed_correction_hz = std::strtof(optarg, nullptr);
        break;
      case 1008:
        options.center_lag_samples = std::strtoll(optarg, nullptr, 10);
        break;
      case 1009: options.sequence_keys = optarg; break;
      default: usage(argv[0]); return false;
    }
  }

  if (!options.prb_slot1_set) {
    options.prb_slot1 = options.prb;
  }
  const bool common_valid =
      !options.input.empty() && options.radius_ms > 0.0 &&
      options.pci <= 503 && options.prb < 25 &&
      options.prb_slot1 < 25 &&
      options.len_prb > 0 && options.prb + options.len_prb <= 25 &&
      options.prb_slot1 + options.len_prb <= 25 &&
      options.n_dmrs < SRSRAN_NOF_CSHIFT && options.top > 0;
  if (!common_valid || !options.decode) {
    return common_valid;
  }
  const bool modulation_valid =
      options.modulation == "qpsk" || options.modulation == "16qam" ||
      options.modulation == "64qam" || options.modulation == "256qam";
  const bool cqi_valid =
      options.cqi_type == "none" || options.cqi_type == "wideband" ||
      options.cqi_type == "subband-ue" || options.cqi_type == "subband-hl";
  const bool cqi_batch_valid = options.cqi_type == "both";
  return options.rnti > 0 && options.rnti <= 65535 && options.mcs <= 31 &&
         options.tbs > 0 && options.tbs % 8 == 0 && options.rv <= 3 &&
         options.nof_ack <= 2 && options.ri_len <= 1 &&
         options.offset_ack <= 15 && options.offset_cqi <= 15 &&
         options.offset_ri <= 15 && options.decode_top > 0 &&
         modulation_valid && (cqi_valid || cqi_batch_valid);
}

float cp_metric(const cf_t* samples, uint32_t count, float* phase)
{
  cf_t corr = 0.0f;
  float p0 = 0.0f;
  float p1 = 0.0f;
  constexpr uint32_t fft_size = 384;
  for (uint32_t i = 0; i < count; ++i) {
    const cf_t a = samples[i];
    const cf_t b = samples[fft_size + i];
    corr += conjf(a) * b;
    p0 += crealf(a * conjf(a));
    p1 += crealf(b * conjf(b));
  }
  if (phase != nullptr) {
    *phase = cargf(corr);
  }
  const float denominator = std::sqrt(p0 * p1);
  return denominator > 0.0f ? cabsf(corr) / denominator : 0.0f;
}

float dmrs_coherence(const cf_t* received, const cf_t* known, uint32_t nrefs_per_slot)
{
  float score = 0.0f;
  for (uint32_t slot = 0; slot < SRSRAN_NOF_SLOTS_PER_SF; ++slot) {
    const cf_t* rx = &received[slot * nrefs_per_slot];
    const cf_t* ref = &known[slot * nrefs_per_slot];
    cf_t adjacent = 0.0f;
    float p0 = 0.0f;
    float p1 = 0.0f;
    for (uint32_t k = 0; k + 1 < nrefs_per_slot; ++k) {
      const cf_t h0 = rx[k] * conjf(ref[k]);
      const cf_t h1 = rx[k + 1] * conjf(ref[k + 1]);
      adjacent += conjf(h0) * h1;
      p0 += crealf(h0 * conjf(h0));
      p1 += crealf(h1 * conjf(h1));
    }
    const float denominator = std::sqrt(p0 * p1);
    if (denominator > 0.0f) {
      score += cabsf(adjacent) / denominator;
    }
  }
  return score / SRSRAN_NOF_SLOTS_PER_SF;
}

srsran_mod_t parse_modulation(const std::string& modulation)
{
  if (modulation == "16qam") {
    return SRSRAN_MOD_16QAM;
  }
  if (modulation == "64qam") {
    return SRSRAN_MOD_64QAM;
  }
  if (modulation == "256qam") {
    return SRSRAN_MOD_256QAM;
  }
  return SRSRAN_MOD_QPSK;
}

std::string payload_hex(const uint8_t* payload, size_t size)
{
  static const char digits[] = "0123456789abcdef";
  std::string result(size * 2, '0');
  for (size_t i = 0; i < size; ++i) {
    result[2 * i] = digits[payload[i] >> 4U];
    result[2 * i + 1] = digits[payload[i] & 0x0fU];
  }
  return result;
}

bool write_diagnostic(const std::string& path,
                      const Options& options,
                      const Candidate& candidate,
                      const srsran_pusch_cfg_t& cfg,
                      const srsran_pusch_t& decoder,
                      const srsran_pusch_res_t& result,
                      const srsran_chest_ul_res_t& chest,
                      const srsran_softbuffer_rx_t& softbuffer,
                      int decode_rc,
                      bool valid_crc)
{
  std::ofstream out(path);
  if (!out) {
    std::fprintf(stderr, "Unable to open diagnostic output %s\n", path.c_str());
    return false;
  }
  out.precision(9);
  out << "{\n"
      << "\"input\":\"" << options.input << "\",\n"
      << "\"target_sf\":" << options.target_sf << ",\n"
      << "\"tti\":" << options.tti << ",\n"
      << "\"pci\":" << options.pci << ",\n"
      << "\"rnti\":" << options.rnti << ",\n"
      << "\"prb\":" << options.prb << ",\n"
      << "\"len_prb\":" << options.len_prb << ",\n"
      << "\"mcs\":" << options.mcs << ",\n"
      << "\"tbs\":" << options.tbs << ",\n"
      << "\"rv\":" << options.rv << ",\n"
      << "\"modulation\":\"" << options.modulation << "\",\n"
      << "\"nof_ack\":" << options.nof_ack << ",\n"
      << "\"lag_samples\":" << candidate.lag_samples << ",\n"
      << "\"correction_hz\":" << candidate.correction_hz << ",\n"
      << "\"sf_idx\":" << candidate.sf_idx << ",\n"
      << "\"n_dmrs\":" << candidate.n_dmrs << ",\n"
      << "\"dmrs_snr_db\":" << chest.snr_db << ",\n"
      << "\"ta_us\":" << chest.ta_us << ",\n"
      << "\"decode_rc\":" << decode_rc << ",\n"
      << "\"crc\":" << (valid_crc ? "true" : "false") << ",\n"
      << "\"turbo_crc\":" << (result.crc ? "true" : "false") << ",\n"
      << "\"evm_builtin\":" << result.evm << ",\n"
      << "\"avg_turbo_iterations\":" << result.avg_iterations_block << ",\n"
      << "\"nof_re\":" << cfg.grant.nof_re << ",\n"
      << "\"nof_bits\":" << cfg.grant.tb.nof_bits << ",\n"
      << "\"nof_data_symbols\":" << cfg.grant.nof_symb << ",\n";

  out << "\"despread_symbols\":[";
  for (uint32_t i = 0; i < cfg.grant.nof_re; ++i) {
    if (i) out << ',';
    out << '[' << crealf(decoder.d[i]) << ',' << cimagf(decoder.d[i]) << ']';
  }
  out << "],\n";

  const uint32_t nof_bits = cfg.grant.tb.nof_bits;
  const int16_t* descrambled = static_cast<const int16_t*>(decoder.q);
  const int16_t* deinterleaved = static_cast<const int16_t*>(decoder.g);
  out << "\"descrambled_llr\":[";
  for (uint32_t i = 0; i < nof_bits; ++i) {
    if (i) out << ',';
    out << descrambled[i];
  }
  out << "],\n\"deinterleaved_llr\":[";
  for (uint32_t i = 0; i < nof_bits; ++i) {
    if (i) out << ',';
    out << deinterleaved[i];
  }
  out << "],\n";

  srsran_cbsegm_t segmentation = {};
  const bool segmented = srsran_cbsegm(&segmentation, options.tbs) == SRSRAN_SUCCESS;
  out << "\"turbo_codeblocks\":[";
  if (segmented) {
    for (uint32_t cb = 0; cb < segmentation.C; ++cb) {
      if (cb) out << ',';
      const uint32_t k = cb < segmentation.C1 ? segmentation.K1 : segmentation.K2;
      const uint32_t k_pi = ((k + 4U + 31U) / 32U) * 32U;
      const uint32_t mother_len = std::min<uint32_t>(3U * k_pi, softbuffer.max_cb_size);
      out << "{\"k\":" << k << ",\"cb_crc\":"
          << (softbuffer.cb_crc[cb] ? "true" : "false") << ",\"llr\":[";
      for (uint32_t i = 0; i < mother_len; ++i) {
        if (i) out << ',';
        out << softbuffer.buffer_f[cb][i];
      }
      out << "]}";
    }
  }
  out << "]\n}\n";
  return true;
}

std::vector<uint16_t> parse_rnti_list(const Options& options)
{
  std::set<uint16_t> unique = {static_cast<uint16_t>(options.rnti)};
  std::stringstream input(options.sweep_rntis);
  std::string item;
  while (std::getline(input, item, ',')) {
    char* end = nullptr;
    const unsigned long value = std::strtoul(item.c_str(), &end, 10);
    if (end != item.c_str() && *end == '\0' && value > 0 && value <= 65535) {
      unique.insert(static_cast<uint16_t>(value));
    }
  }
  return {unique.begin(), unique.end()};
}

struct SweepSummary {
  uint64_t attempted = 0;
  uint64_t crc_hits = 0;
};

SweepSummary run_hypothesis_sweep(const Options& options,
                                  const std::vector<cf_t>& symbols,
                                  srsran_pusch_t& decoder,
                                  const srsran_pusch_cfg_t& base_cfg,
                                  srsran_softbuffer_rx_t& softbuffer)
{
  SweepSummary summary;
  std::ofstream out(options.sweep_output);
  if (!out) {
    std::fprintf(stderr, "Unable to open hypothesis sweep output %s\n", options.sweep_output.c_str());
    return summary;
  }
  out << "stage,rnti,scrambling_sf,modulation,tbs,rv,nof_ack,cqi_type,ri_len,pmi_present,"
         "offset_ack,offset_cqi,offset_ri,decode_rc,turbo_crc,all_zero,valid_crc,iterations,payload_hex\n";

  const srsran_mod_t modulation = parse_modulation(options.modulation);
  const uint32_t nof_re = base_cfg.grant.nof_re;
  const uint32_t nof_bits = nof_re * srsran_mod_bits_x_symbol(modulation);
  std::vector<int16_t> raw_llr(nof_bits);
  srsran_demod_soft_demodulate_s(modulation, symbols.data(), raw_llr.data(), nof_re);
  const std::vector<uint16_t> rntis = parse_rnti_list(options);
  std::set<uint32_t> standard_tbs;
  standard_tbs.insert(options.tbs);
  for (uint32_t index = 0; index < SRSRAN_RA_NOF_TBS_IDX; ++index) {
    const int value = srsran_ra_tbs_from_idx(index, options.len_prb);
    if (value > 0 && static_cast<uint32_t>(value + 24) <= nof_bits) {
      standard_tbs.insert(static_cast<uint32_t>(value));
    }
  }
  struct Offsets { uint32_t ack; uint32_t cqi; uint32_t ri; };
  const std::vector<Offsets> offsets = {
      {options.offset_ack, options.offset_cqi, options.offset_ri},
      {7, 7, 1},
  };
  std::set<std::string> seen;

  auto attempt = [&](const char* stage,
                     uint16_t rnti,
                     uint32_t sf_idx,
                     uint32_t tbs,
                     uint32_t rv,
                     uint32_t nof_ack,
                     const char* cqi_name,
                     uint32_t ri_len,
                     bool pmi_present,
                     const Offsets& beta) {
    std::ostringstream key;
    key << rnti << ':' << sf_idx << ':' << tbs << ':' << rv << ':' << nof_ack << ':'
        << cqi_name << ':' << ri_len << ':' << pmi_present << ':'
        << beta.ack << ':' << beta.cqi << ':' << beta.ri;
    if (!seen.insert(key.str()).second) return;

    srsran_pusch_cfg_t cfg = base_cfg;
    cfg.rnti = rnti;
    cfg.grant.tb.mod = modulation;
    cfg.grant.tb.tbs = static_cast<int>(tbs);
    cfg.grant.tb.rv = static_cast<int>(rv);
    cfg.grant.tb.nof_bits = nof_bits;
    cfg.softbuffers.rx = &softbuffer;
    cfg.uci_offset.I_offset_ack = beta.ack;
    cfg.uci_offset.I_offset_cqi = beta.cqi;
    cfg.uci_offset.I_offset_ri = beta.ri;
    cfg.uci_cfg.ack[0].nof_acks = nof_ack;
    cfg.uci_cfg.cqi.data_enable = std::strcmp(cqi_name, "none") != 0;
    cfg.uci_cfg.cqi.ri_len = ri_len;
    cfg.uci_cfg.cqi.pmi_present = pmi_present;
    cfg.uci_cfg.cqi.rank_is_not_one = false;
    if (std::strcmp(cqi_name, "wideband") == 0) {
      cfg.uci_cfg.cqi.type = SRSRAN_CQI_TYPE_WIDEBAND;
    } else if (std::strcmp(cqi_name, "subband-ue") == 0) {
      cfg.uci_cfg.cqi.type = SRSRAN_CQI_TYPE_SUBBAND_UE;
    } else {
      cfg.uci_cfg.cqi.type = SRSRAN_CQI_TYPE_SUBBAND_HL;
    }

    std::memcpy(decoder.q, raw_llr.data(), nof_bits * sizeof(int16_t));
    srsran_sequence_pusch_apply_s(static_cast<const int16_t*>(decoder.q),
                                  static_cast<int16_t*>(decoder.q),
                                  rnti,
                                  2 * sf_idx,
                                  options.pci,
                                  nof_bits);
    uint8_t* sequence = reinterpret_cast<uint8_t*>(decoder.z);
    srsran_sequence_pusch_gen_unpack(sequence, rnti, 2 * sf_idx, options.pci, nof_bits);
    srsran_softbuffer_rx_reset_tbs(&softbuffer, tbs);
    // The turbo decoder writes the decoded 24-bit TB CRC after the payload.
    std::vector<uint8_t> payload((tbs + 24 + 7) / 8, 0);
    srsran_uci_value_t uci = {};
    const int rc = srsran_ulsch_decode(&decoder.ul_sch,
                                       &cfg,
                                       static_cast<int16_t*>(decoder.q),
                                       static_cast<int16_t*>(decoder.g),
                                       sequence,
                                       payload.data(),
                                       &uci);
    const bool turbo_crc = rc == SRSRAN_SUCCESS;
    const size_t payload_bytes = tbs / 8;
    const bool all_zero = std::all_of(payload.begin(), payload.begin() + payload_bytes,
                                      [](uint8_t byte) { return byte == 0; });
    const bool valid_crc = turbo_crc && !all_zero;
    ++summary.attempted;
    summary.crc_hits += valid_crc;
    out << stage << ',' << rnti << ',' << sf_idx << ',' << options.modulation << ','
        << tbs << ',' << rv << ',' << nof_ack << ',' << cqi_name << ',' << ri_len << ','
        << (pmi_present ? 1 : 0) << ',' << beta.ack << ',' << beta.cqi << ',' << beta.ri << ','
        << rc << ',' << (turbo_crc ? 1 : 0) << ',' << (all_zero ? 1 : 0) << ','
        << (valid_crc ? 1 : 0) << ',' << decoder.ul_sch.avg_iterations << ',';
    if (turbo_crc) out << payload_hex(payload.data(), payload_bytes);
    out << '\n';
  };

  // A: exact DCI RNTI, but every LTE scrambling subframe, standards-table
  // TBS, RV, ACK count, and both the legacy and SIB2-derived beta offsets.
  for (uint32_t sf = 0; sf < 10; ++sf)
    for (uint32_t tbs : standard_tbs)
      for (uint32_t rv = 0; rv < 4; ++rv)
        for (uint32_t ack = 0; ack < 3; ++ack)
          for (const Offsets& beta : offsets)
            attempt("transport", options.rnti, sf, tbs, rv, ack, "none", 0, false, beta);

  // B: RNTIs observed in this cell, retaining the reported TBS while
  // sweeping the remaining transport parameters.
  for (uint16_t rnti : rntis)
    for (uint32_t sf = 0; sf < 10; ++sf)
      for (uint32_t rv = 0; rv < 4; ++rv)
        for (uint32_t ack = 0; ack < 3; ++ack)
          for (const Offsets& beta : offsets)
            attempt("rnti", rnti, sf, options.tbs, rv, ack, "none", 0, false, beta);

  // C: periodic/aperiodic CQI and RI multiplexing layouts. CQI request in
  // DCI was zero, so these are broader diagnostics rather than primary DCI
  // interpretations.
  // First exhaust every beta-offset index for the exact DCI transport
  // hypothesis.  This is intentionally kept separate from the broad sweep:
  // beta offsets are UE-dedicated RRC parameters, and multiplying them into
  // every RNTI/TBS/RV hypothesis would create millions of redundant trials.
  // The decoded field RRC messages configure wideband periodic CQI and one
  // antenna port, but RI=1 is retained as a defensive unknown-UE check.
  const uint32_t exact_sf = options.tti % 10;
  // Valid index domains from 3GPP TS 36.213 tables 8.6.3-1..3:
  // ACK 0..14, CQI 2..15, and RI 0..12.
  for (uint32_t ack_beta = 0; ack_beta <= 14; ++ack_beta) {
    const Offsets beta_no_cqi = {ack_beta, options.offset_cqi, options.offset_ri};
    attempt("beta_exact", options.rnti, exact_sf, options.tbs, options.rv,
            options.nof_ack, "none", 0, false, beta_no_cqi);
    for (uint32_t cqi_beta = 2; cqi_beta <= 15; ++cqi_beta) {
      const Offsets beta_cqi = {ack_beta, cqi_beta, options.offset_ri};
      attempt("beta_exact", options.rnti, exact_sf, options.tbs, options.rv,
              options.nof_ack, "wideband", 0, false, beta_cqi);
      for (uint32_t ri_beta = 0; ri_beta <= 12; ++ri_beta) {
        const Offsets beta_ri = {ack_beta, cqi_beta, ri_beta};
        attempt("beta_exact", options.rnti, exact_sf, options.tbs, options.rv,
                options.nof_ack, "wideband", 1, false, beta_ri);
      }
    }
  }

  const char* cqi_types[] = {"wideband", "subband-ue", "subband-hl"};
  for (uint32_t sf = 0; sf < 10; ++sf)
    for (uint32_t rv = 0; rv < 4; ++rv)
      for (uint32_t ack = 0; ack < 3; ++ack)
        for (const char* cqi : cqi_types)
          for (uint32_t ri = 0; ri < 2; ++ri)
            for (uint32_t pmi = 0; pmi < 2; ++pmi)
              for (const Offsets& beta : offsets)
                attempt("cqi_ri", options.rnti, sf, options.tbs, rv, ack, cqi, ri, pmi != 0, beta);

  return summary;
}

}  // namespace

int main(int argc, char** argv)
{
  Options options;
  if (!parse_options(argc, argv, options)) {
    usage(argv[0]);
    return 2;
  }

  constexpr uint32_t nof_prb = 25;
  constexpr uint32_t sf_len = 5760;
  constexpr float sample_rate = 5760000.0f;
  constexpr uint32_t cp_probe_len = 24;
  constexpr uint32_t fft_size = 384;

  const int64_t center_sample =
      static_cast<int64_t>(options.target_sf) * static_cast<int64_t>(sf_len);
  const int64_t search_center_sample = center_sample + options.center_lag_samples;
  const int64_t radius_samples =
      static_cast<int64_t>(std::llround(options.radius_ms * sample_rate / 1000.0));
  // A fixed-lag invocation is the second, CRC-decoding stage: the wide
  // acquisition pass has already chosen the exact boundary and CFO.  The old
  // path nevertheless reread and CP-scanned the full timing radius before
  // discarding every discovered peak.  Restrict fixed-lag reads to the chosen
  // subframe while leaving non-fixed acquisition byte-for-byte unchanged.
  const int64_t fixed_file_sample = center_sample + options.fixed_lag_samples;
  const int64_t first_candidate = options.fixed_lag
                                      ? fixed_file_sample
                                      : std::max<int64_t>(
                                            0, search_center_sample - radius_samples);
  const int64_t last_candidate = options.fixed_lag
                                     ? fixed_file_sample
                                     : search_center_sample + radius_samples;
  const int64_t read_start = std::max<int64_t>(0, first_candidate - 64);
  const uint64_t read_count =
      static_cast<uint64_t>(last_candidate - read_start) + sf_len + fft_size + 64;

  FILE* input = std::fopen(options.input.c_str(), "rb");
  if (input == nullptr) {
    std::fprintf(stderr, "cannot open %s: %s\n", options.input.c_str(), std::strerror(errno));
    return 1;
  }
  if (fseeko(input, static_cast<off_t>(read_start * sizeof(PairSample)), SEEK_SET) != 0) {
    std::fprintf(stderr, "cannot seek input: %s\n", std::strerror(errno));
    std::fclose(input);
    return 1;
  }

  std::vector<PairSample> pair(read_count);
  const size_t actual = std::fread(pair.data(), sizeof(PairSample), pair.size(), input);
  std::fclose(input);
  if (actual < sf_len + fft_size) {
    std::fprintf(stderr, "input window is too short\n");
    return 1;
  }
  pair.resize(actual);

  std::vector<cf_t> ul(pair.size());
  for (size_t i = 0; i < pair.size(); ++i) {
    ul[i] = pair[i].ul;
  }

  /*
   * Locate local CP-correlation maxima. A 100-sample exclusion radius leaves
   * at most one candidate per LTE OFDM symbol while preserving arbitrary
   * subframe phase and multi-millisecond propagation delay.
   */
  struct CpPeak {
    size_t offset;
    float metric;
    float phase;
  };
  std::vector<CpPeak> peaks;
  if (!options.fixed_lag) {
    const size_t scan_begin = static_cast<size_t>(first_candidate - read_start);
    const size_t scan_end = std::min<size_t>(
        static_cast<size_t>(last_candidate - read_start),
        ul.size() - sf_len - fft_size - cp_probe_len);
    for (size_t p = scan_begin + 1; p + 1 < scan_end; ++p) {
      float phase = 0.0f;
      const float metric = cp_metric(&ul[p], cp_probe_len, &phase);
      if (metric < 0.55f) {
        continue;
      }
      float left_phase = 0.0f;
      float right_phase = 0.0f;
      const float left = cp_metric(&ul[p - 1], cp_probe_len, &left_phase);
      const float right = cp_metric(&ul[p + 1], cp_probe_len, &right_phase);
      if (metric >= left && metric > right) {
        peaks.push_back({p, metric, phase});
      }
    }
  }
  std::sort(peaks.begin(), peaks.end(), [](const CpPeak& a, const CpPeak& b) {
    return a.metric > b.metric;
  });
  std::vector<CpPeak> selected;
  if (options.fixed_lag) {
    if (fixed_file_sample < read_start ||
        fixed_file_sample + static_cast<int64_t>(sf_len + fft_size + cp_probe_len) >
            read_start + static_cast<int64_t>(ul.size())) {
      std::fprintf(stderr, "fixed lag lies outside the input window\n");
      return 2;
    }
    const size_t offset = static_cast<size_t>(fixed_file_sample - read_start);
    float phase = 0.0f;
    const float metric = cp_metric(&ul[offset], cp_probe_len, &phase);
    selected.push_back({offset, metric, phase});
  } else {
    for (const CpPeak& peak : peaks) {
      bool too_close = false;
      for (const CpPeak& keep : selected) {
        const int64_t distance =
            std::llabs(static_cast<int64_t>(peak.offset) - static_cast<int64_t>(keep.offset));
        if (distance < 100) {
          too_close = true;
          break;
        }
      }
      if (!too_close) {
        selected.push_back(peak);
      }
    }
  }
  std::sort(selected.begin(), selected.end(), [](const CpPeak& a, const CpPeak& b) {
    return a.offset < b.offset;
  });

  std::vector<cf_t> time_buffer(sf_len);
  srsran_enb_ul_t enb_ul = {};
  if (srsran_enb_ul_init(&enb_ul, time_buffer.data(), nof_prb) != SRSRAN_SUCCESS) {
    std::fprintf(stderr, "srsran_enb_ul_init failed\n");
    return 1;
  }
  srsran_cell_t cell = {};
  cell.id = options.pci;
  cell.nof_prb = nof_prb;
  cell.nof_ports = 1;
  cell.cp = SRSRAN_CP_NORM;
  cell.frame_type = SRSRAN_FDD;
  cell.phich_length = SRSRAN_PHICH_NORM;
  cell.phich_resources = SRSRAN_PHICH_R_1_6;
  srsran_refsignal_dmrs_pusch_cfg_t dmrs = {};
  if (srsran_enb_ul_set_cell(&enb_ul, cell, &dmrs, nullptr) != SRSRAN_SUCCESS) {
    std::fprintf(stderr, "srsran_enb_ul_set_cell failed\n");
    srsran_enb_ul_free(&enb_ul);
    return 1;
  }

  srsran_pusch_cfg_t pusch = {};
  pusch.meas_ta_en = true;
  pusch.meas_evm_en = true;
  pusch.grant.L_prb = options.len_prb;
  pusch.grant.n_prb[0] = options.prb;
  pusch.grant.n_prb[1] = options.prb_slot1;
  pusch.grant.n_prb_tilde[0] = options.prb;
  pusch.grant.n_prb_tilde[1] = options.prb_slot1;
  pusch.grant.n_dmrs = options.n_dmrs;

  srsran_ul_sf_cfg_t ul_sf = {};
  ul_sf.tti = options.tti;
  const uint32_t nrefs_per_slot = options.len_prb * SRSRAN_NRE;
  std::vector<cf_t> received(2 * nrefs_per_slot);
  std::vector<Candidate> results;
  std::vector<std::pair<uint32_t, uint32_t>> requested_sequences;
  if (!options.sequence_keys.empty()) {
    std::istringstream stream(options.sequence_keys);
    std::string token;
    while (std::getline(stream, token, ',')) {
      const size_t colon = token.find(':');
      if (colon == std::string::npos) {
        std::fprintf(stderr, "invalid sequence key: %s\n", token.c_str());
        srsran_enb_ul_free(&enb_ul);
        return 2;
      }
      const uint32_t sf_idx = std::strtoul(token.substr(0, colon).c_str(), nullptr, 10);
      const uint32_t n_dmrs = std::strtoul(token.substr(colon + 1).c_str(), nullptr, 10);
      if (sf_idx >= 10 || n_dmrs >= SRSRAN_NOF_CSHIFT) {
        std::fprintf(stderr, "sequence key out of range: %s\n", token.c_str());
        srsran_enb_ul_free(&enb_ul);
        return 2;
      }
      const std::pair<uint32_t, uint32_t> key{sf_idx, n_dmrs};
      if (std::find(requested_sequences.begin(), requested_sequences.end(), key) ==
          requested_sequences.end()) {
        requested_sequences.push_back(key);
      }
    }
  }

  for (const CpPeak& peak : selected) {
    const float cp_cfo_hz = peak.phase * sample_rate /
                            (2.0f * static_cast<float>(M_PI) * fft_size);
    const int branch_begin = options.fixed_correction ? 0 : -2;
    const int branch_end = options.fixed_correction ? 0 : 2;
    for (int branch = branch_begin; branch <= branch_end; ++branch) {
      /*
       * LTE SC-FDMA deliberately applies a +0.5-subcarrier (7.5 kHz)
       * shift at the UE, and srsRAN's eNB FFT removes it internally.
       * CP phase therefore must be brought to +7.5 kHz, not to zero.
       */
      const float correction_hz = options.fixed_correction
                                      ? options.fixed_correction_hz
                                      : 7500.0f - cp_cfo_hz +
                                            15000.0f * static_cast<float>(branch);
      const float phase_step =
          2.0f * static_cast<float>(M_PI) * correction_hz / sample_rate;
      for (uint32_t n = 0; n < sf_len; ++n) {
        const float phase = phase_step * static_cast<float>(n);
        cf_t rotator = 0.0f;
        __real__ rotator = std::cos(phase);
        __imag__ rotator = std::sin(phase);
        time_buffer[n] = ul[peak.offset + n] * rotator;
      }
      enb_ul.in_buffer = time_buffer.data();
      srsran_enb_ul_fft(&enb_ul);
      srsran_refsignal_dmrs_pusch_get(
          &enb_ul.chest.dmrs_signal, &pusch, enb_ul.sf_symbols, received.data());

      std::vector<std::pair<uint32_t, uint32_t>> sequences = requested_sequences;
      if (sequences.empty()) {
        const uint32_t sf_begin = options.sweep_sequence ? 0 : options.tti % 10;
        const uint32_t sf_end = options.sweep_sequence ? 10 : sf_begin + 1;
        const uint32_t dmrs_begin = options.sweep_sequence ? 0 : options.n_dmrs;
        const uint32_t dmrs_end =
            options.sweep_sequence ? SRSRAN_NOF_CSHIFT : dmrs_begin + 1;
        for (uint32_t sf_idx = sf_begin; sf_idx < sf_end; ++sf_idx) {
          for (uint32_t n_dmrs = dmrs_begin; n_dmrs < dmrs_end; ++n_dmrs) {
            sequences.push_back({sf_idx, n_dmrs});
          }
        }
      }
      for (const auto& sequence : sequences) {
          const uint32_t sf_idx = sequence.first;
          const uint32_t n_dmrs = sequence.second;
          const cf_t* known = enb_ul.chest.dmrs_pregen.r[n_dmrs][sf_idx][options.len_prb];
          const float coherence =
              dmrs_coherence(received.data(), known, nrefs_per_slot);

          pusch.grant.n_dmrs = n_dmrs;
          ul_sf.tti = (options.tti / 10) * 10 + sf_idx;
          srsran_chest_ul_res_t chest_result = {};
          chest_result.ce = enb_ul.chest_res.ce;
          srsran_chest_ul_estimate_pusch(
              &enb_ul.chest, &ul_sf, &pusch, enb_ul.sf_symbols, &chest_result);

          const uint64_t file_sample =
              static_cast<uint64_t>(read_start + static_cast<int64_t>(peak.offset));
          results.push_back({
              static_cast<int64_t>(file_sample) - center_sample,
              file_sample,
              peak.metric,
              cp_cfo_hz,
              correction_hz,
              branch,
              sf_idx,
              n_dmrs,
              coherence,
              chest_result.snr_db,
              chest_result.ta_us,
          });
      }
    }
  }

  // srsRAN's pilot SNR uses both the expected DMRS and its residual error,
  // so it is the primary discriminator between sequence hypotheses.
  std::sort(results.begin(), results.end(), [](const Candidate& a, const Candidate& b) {
    if (a.snr_db != b.snr_db) {
      return a.snr_db > b.snr_db;
    }
    return a.coherence > b.coherence;
  });

  std::printf(
      "{\"input\":\"%s\",\"target_sf\":%llu,\"target_sample\":%lld,"
      "\"search_center_sample\":%lld,\"center_lag_samples\":%lld,"
      "\"radius_ms\":%.3f,\"pci\":%u,\"tti\":%u,\"prb\":%u,"
      "\"prb_slot1\":%u,\"len_prb\":%u,\"n_dmrs\":%u,"
      "\"cp_peaks\":%zu,\"hypotheses\":%zu}\n",
      options.input.c_str(),
      static_cast<unsigned long long>(options.target_sf),
      static_cast<long long>(center_sample),
      static_cast<long long>(search_center_sample),
      static_cast<long long>(options.center_lag_samples),
      options.radius_ms,
      options.pci,
      options.tti,
      options.prb,
      options.prb_slot1,
      options.len_prb,
      options.n_dmrs,
      selected.size(),
      results.size());
  const size_t count = std::min<size_t>(options.top, results.size());
  for (size_t i = 0; i < count; ++i) {
    const Candidate& result = results[i];
    std::printf(
        "{\"rank\":%zu,\"lag_samples\":%lld,\"lag_us\":%.3f,"
        "\"file_sample\":%llu,\"cp\":%.6f,\"cp_cfo_hz\":%.3f,"
        "\"correction_hz\":%.3f,"
        "\"cfo_branch\":%d,\"sf_idx\":%u,\"n_dmrs\":%u,"
        "\"coherence\":%.6f,\"snr_db\":%.3f,\"ta_us\":%.3f}\n",
        i + 1,
        static_cast<long long>(result.lag_samples),
        static_cast<double>(result.lag_samples) * 1e6 / sample_rate,
        static_cast<unsigned long long>(result.file_sample),
        result.cp,
        result.cp_cfo_hz,
        result.correction_hz,
        result.cfo_branch,
        result.sf_idx,
        result.n_dmrs,
        result.coherence,
        result.snr_db,
        result.ta_us);
  }

  // A grouped acquisition asks for several exact DCI/RAR DMRS sequences that
  // share one burst boundary and RB allocation. Emit an independent top-N for
  // each sequence so grouping changes only computation reuse, never ranking.
  for (const auto& sequence : requested_sequences) {
    size_t sequence_rank = 0;
    for (const Candidate& result : results) {
      if (result.sf_idx != sequence.first || result.n_dmrs != sequence.second) {
        continue;
      }
      ++sequence_rank;
      if (sequence_rank > options.top) {
        break;
      }
      std::printf(
          "{\"sequence_key_top\":true,\"sequence_rank\":%zu,"
          "\"lag_samples\":%lld,\"lag_us\":%.3f,"
          "\"file_sample\":%llu,\"cp\":%.6f,\"cp_cfo_hz\":%.3f,"
          "\"correction_hz\":%.3f,\"cfo_branch\":%d,"
          "\"sf_idx\":%u,\"n_dmrs\":%u,\"coherence\":%.6f,"
          "\"snr_db\":%.3f,\"ta_us\":%.3f}\n",
          sequence_rank,
          static_cast<long long>(result.lag_samples),
          static_cast<double>(result.lag_samples) * 1e6 / sample_rate,
          static_cast<unsigned long long>(result.file_sample),
          result.cp,
          result.cp_cfo_hz,
          result.correction_hz,
          result.cfo_branch,
          result.sf_idx,
          result.n_dmrs,
          result.coherence,
          result.snr_db,
          result.ta_us);
    }
  }

  /*
   * A global top-N sweep can mix several CP peaks and CFO aliases.  For grant
   * association the caller needs all 10x8 LTE DMRS sequence scores evaluated
   * at one and the same physical boundary/CFO solution.  Anchor the table to
   * the globally best result and emit the complete 80-entry cluster.
   */
  if (options.sequence_table && !results.empty()) {
    const Candidate anchor = results.front();
    std::vector<Candidate> table;
    for (const Candidate& candidate : results) {
      if (candidate.file_sample == anchor.file_sample &&
          candidate.cfo_branch == anchor.cfo_branch) {
        table.push_back(candidate);
      }
    }
    std::sort(table.begin(), table.end(), [](const Candidate& a, const Candidate& b) {
      if (a.snr_db != b.snr_db) {
        return a.snr_db > b.snr_db;
      }
      if (a.sf_idx != b.sf_idx) {
        return a.sf_idx < b.sf_idx;
      }
      return a.n_dmrs < b.n_dmrs;
    });
    for (size_t i = 0; i < table.size(); ++i) {
      const Candidate& result = table[i];
      std::printf(
          "{\"sequence_table\":true,\"sequence_rank\":%zu,"
          "\"lag_samples\":%lld,\"lag_us\":%.3f,"
          "\"file_sample\":%llu,\"cp\":%.6f,\"cp_cfo_hz\":%.3f,"
          "\"correction_hz\":%.3f,\"cfo_branch\":%d,"
          "\"sf_idx\":%u,\"n_dmrs\":%u,\"coherence\":%.6f,"
          "\"snr_db\":%.3f,\"ta_us\":%.3f}\n",
          i + 1,
          static_cast<long long>(result.lag_samples),
          static_cast<double>(result.lag_samples) * 1e6 / sample_rate,
          static_cast<unsigned long long>(result.file_sample),
          result.cp,
          result.cp_cfo_hz,
          result.correction_hz,
          result.cfo_branch,
          result.sf_idx,
          result.n_dmrs,
          result.coherence,
          result.snr_db,
          result.ta_us);
    }
  }

  if (options.decode) {
    const std::vector<std::string> decode_cqi_types =
        options.cqi_type == "both"
            ? std::vector<std::string>{"none", "wideband"}
            : std::vector<std::string>{options.cqi_type};
    size_t cqi_hypothesis_index = 0;
    for (const std::string& decode_cqi_type : decode_cqi_types) {
    if (cqi_hypothesis_index++ > 0) {
      // srsRAN keeps decoder work state inside enb_ul.pusch. Each hypothesis
      // must begin with the same clean state as an independent invocation.
      srsran_enb_ul_free(&enb_ul);
      enb_ul = {};
      if (srsran_enb_ul_init(&enb_ul, time_buffer.data(), nof_prb) !=
              SRSRAN_SUCCESS ||
          srsran_enb_ul_set_cell(&enb_ul, cell, &dmrs, nullptr) !=
              SRSRAN_SUCCESS) {
        std::fprintf(stderr, "srsRAN hypothesis-state reset failed\n");
        return 1;
      }
    }
    pusch.rnti = static_cast<uint16_t>(options.rnti);
    pusch.max_nof_iterations = 12;
    pusch.enable_64qam =
        options.modulation == "64qam" || options.modulation == "256qam";
    pusch.uci_offset.I_offset_ack = options.offset_ack;
    pusch.uci_offset.I_offset_cqi = options.offset_cqi;
    pusch.uci_offset.I_offset_ri = options.offset_ri;
    pusch.uci_cfg.ack[0].nof_acks = options.nof_ack;
    pusch.uci_cfg.cqi.data_enable = decode_cqi_type != "none";
    pusch.uci_cfg.cqi.pmi_present = options.pmi_present;
    pusch.uci_cfg.cqi.rank_is_not_one = false;
    pusch.uci_cfg.cqi.four_antenna_ports = false;
    pusch.uci_cfg.cqi.ri_len = options.ri_len;
    pusch.uci_cfg.cqi.N = srsran_cqi_hl_get_no_subbands(cell.nof_prb);
    if (decode_cqi_type == "wideband") {
      pusch.uci_cfg.cqi.type = SRSRAN_CQI_TYPE_WIDEBAND;
    } else if (decode_cqi_type == "subband-ue") {
      pusch.uci_cfg.cqi.type = SRSRAN_CQI_TYPE_SUBBAND_UE;
    } else {
      pusch.uci_cfg.cqi.type = SRSRAN_CQI_TYPE_SUBBAND_HL;
    }
    pusch.grant.tb.mod = parse_modulation(options.modulation);
    pusch.grant.tb.tbs = static_cast<int>(options.tbs);
    pusch.grant.tb.rv = static_cast<int>(options.rv);
    pusch.grant.tb.mcs_idx = options.mcs;
    pusch.grant.tb.cw_idx = 0;
    pusch.grant.tb.enabled = true;
    pusch.grant.last_tb = pusch.grant.tb;
    srsran_ra_ul_compute_nof_re(&pusch.grant, cell.cp, 0);

    srsran_softbuffer_rx_t softbuffer = {};
    if (srsran_softbuffer_rx_init(&softbuffer, SRSRAN_MAX_PRB) != SRSRAN_SUCCESS) {
      std::fprintf(stderr, "srsran_softbuffer_rx_init failed\n");
      srsran_enb_ul_free(&enb_ul);
      return 1;
    }
    pusch.softbuffers.rx = &softbuffer;
    // srsRAN's turbo decoder writes the decoded 24-bit TB CRC after the MAC
    // payload, so retain three bytes of private headroom.
    const size_t payload_bytes = options.tbs / 8;
    std::vector<uint8_t> payload(payload_bytes + 3);
    const size_t decode_count =
        std::min<size_t>(options.decode_top, results.size());

    for (size_t i = 0; i < decode_count; ++i) {
      const Candidate& result = results[i];
      const uint64_t local_offset = result.file_sample -
                                    static_cast<uint64_t>(read_start);
      if (local_offset + sf_len > ul.size()) {
        continue;
      }
      const float phase_step =
          2.0f * static_cast<float>(M_PI) * result.correction_hz / sample_rate;
      for (uint32_t n = 0; n < sf_len; ++n) {
        const float phase = phase_step * static_cast<float>(n);
        cf_t rotator = 0.0f;
        __real__ rotator = std::cos(phase);
        __imag__ rotator = std::sin(phase);
        time_buffer[n] = ul[local_offset + n] * rotator;
      }

      enb_ul.in_buffer = time_buffer.data();
      srsran_enb_ul_fft(&enb_ul);
      ul_sf.tti = (options.tti / 10) * 10 + result.sf_idx;
      pusch.grant.n_dmrs = result.n_dmrs;
      srsran_softbuffer_rx_reset_tbs(&softbuffer, options.tbs);
      srsran_chest_ul_res_t chest_result = {};
      chest_result.ce = enb_ul.chest_res.ce;
      const int chest_rc = srsran_chest_ul_estimate_pusch(
          &enb_ul.chest, &ul_sf, &pusch, enb_ul.sf_symbols, &chest_result);

      std::fill(payload.begin(), payload.end(), 0);
      srsran_pusch_res_t pusch_result = {};
      pusch_result.data = payload.data();
      int decode_rc = SRSRAN_ERROR;
      if (chest_rc == SRSRAN_SUCCESS) {
        decode_rc = srsran_pusch_decode(
            &enb_ul.pusch,
            &ul_sf,
            &pusch,
            &chest_result,
            enb_ul.sf_symbols,
            &pusch_result);
      }
      const bool all_zero =
          std::all_of(payload.begin(), payload.begin() + payload_bytes, [](uint8_t byte) {
            return byte == 0;
          });
      const bool valid_crc =
          decode_rc == SRSRAN_SUCCESS && pusch_result.crc && !all_zero;
      // Preserve the turbo decoder's tentative bytes even when CRC fails.
      // They are useful for a CRC-failed diagnostic PCAP, but must never be
      // treated as a validated MAC PDU unless valid_crc is true.
      const std::string hex = payload_hex(payload.data(), payload_bytes);
      std::string symbol_power_json = "[";
      for (uint32_t symbol = 0; symbol < SRSRAN_CP_NSYMB(cell.cp) * 2; ++symbol) {
        float power = 0.0f;
        uint32_t count_re = 0;
        for (uint32_t rb = 0; rb < options.len_prb; ++rb) {
          for (uint32_t re = 0; re < SRSRAN_NRE; ++re) {
            const uint32_t index =
                symbol * nof_prb * SRSRAN_NRE +
                (options.prb + rb) * SRSRAN_NRE + re;
            power += crealf(enb_ul.sf_symbols[index] *
                            conjf(enb_ul.sf_symbols[index]));
            ++count_re;
          }
        }
        power = count_re > 0 ? power / count_re : 0.0f;
        const float power_db =
            power > 0.0f ? 10.0f * std::log10(power) : -INFINITY;
        char value[64];
        std::snprintf(
            value, sizeof(value), "%s%.3f", symbol == 0 ? "" : ",", power_db);
        symbol_power_json += value;
      }
      symbol_power_json += "]";
      std::printf(
          "{\"decode_rank\":%zu,\"lag_samples\":%lld,"
          "\"correction_hz\":%.3f,\"sf_idx\":%u,\"n_dmrs\":%u,"
          "\"rnti\":%u,\"mcs\":%u,\"tbs\":%u,\"rv\":%u,"
          "\"mod\":\"%s\",\"nof_ack\":%u,\"snr_db\":%.3f,"
          "\"ta_us\":%.3f,\"decode_rc\":%d,\"crc\":%s,\"turbo_crc\":%s,"
          "\"all_zero\":%s,\"symbol_power_db\":%s,"
          "\"payload_hex\":\"%s\"}\n",
          i + 1,
          static_cast<long long>(result.lag_samples),
          result.correction_hz,
          result.sf_idx,
          result.n_dmrs,
          options.rnti,
          options.mcs,
          options.tbs,
          options.rv,
          options.modulation.c_str(),
          options.nof_ack,
          chest_result.snr_db,
          chest_result.ta_us,
          decode_rc,
          valid_crc ? "true" : "false",
          pusch_result.crc ? "true" : "false",
          all_zero ? "true" : "false",
          symbol_power_json.c_str(),
          hex.c_str());
      if (i == 0 && !options.diag_output.empty()) {
        write_diagnostic(options.diag_output,
                         options,
                         result,
                         pusch,
                         enb_ul.pusch,
                         pusch_result,
                         chest_result,
                         softbuffer,
                         decode_rc,
                         valid_crc);
      }
      if (i == 0 && !options.sweep_output.empty() && chest_rc == SRSRAN_SUCCESS &&
          decode_rc == SRSRAN_SUCCESS) {
        std::vector<cf_t> equalized_symbols(
            enb_ul.pusch.d, enb_ul.pusch.d + pusch.grant.nof_re);
        const SweepSummary sweep = run_hypothesis_sweep(options,
                                                        equalized_symbols,
                                                        enb_ul.pusch,
                                                        pusch,
                                                        softbuffer);
        std::printf(
            "{\"hypothesis_sweep\":\"%s\",\"attempted\":%llu,\"crc_hits\":%llu}\n",
            options.sweep_output.c_str(),
            static_cast<unsigned long long>(sweep.attempted),
            static_cast<unsigned long long>(sweep.crc_hits));
      }
    }
    srsran_softbuffer_rx_free(&softbuffer);
    }
  }

  srsran_enb_ul_free(&enb_ul);
  return 0;
}
