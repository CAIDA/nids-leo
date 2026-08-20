/*
 * Synchronize a separately recorded DL/UL pair on the DL LTE cell and emit
 * LTEsniffer's two-channel, sample-major fc32 file layout.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "srsran/srsran.h"

typedef struct {
  FILE* dl;
  FILE* ul;
  uint64_t samples_read;
  bool eof;
} pair_source_t;

static int pair_recv(void* opaque,
                     cf_t* data[SRSRAN_MAX_CHANNELS],
                     uint32_t nsamples,
                     srsran_timestamp_t* timestamp)
{
  pair_source_t* source = (pair_source_t*)opaque;
  (void)timestamp;
  const size_t dl_count = fread(data[0], sizeof(cf_t), nsamples, source->dl);
  const size_t ul_count = fread(data[1], sizeof(cf_t), nsamples, source->ul);
  if (dl_count != ul_count) {
    fprintf(stderr,
            "paired input length mismatch at sample %" PRIu64 ": DL=%zu UL=%zu\n",
            source->samples_read,
            dl_count,
            ul_count);
    source->eof = true;
    return SRSRAN_ERROR;
  }
  source->samples_read += dl_count;
  if (dl_count != nsamples) {
    if (ferror(source->dl) || ferror(source->ul)) {
      fprintf(stderr, "paired input read failed: %s\n", strerror(errno));
    }
    source->eof = true;
    return SRSRAN_ERROR;
  }
  return (int)dl_count;
}

static void usage(const char* program)
{
  fprintf(stderr,
          "Usage: %s --dl DL.fc32 --ul UL.fc32 --output paired.bin\n"
          "          --pci PCI --prb PRB [--cfo-hz HZ] [--offset-samples N]\n"
          "          [--max-subframes N] [--ul-shift-samples N]\n"
          "          [--ul-cfo-hz HZ]\n",
          program);
}

/*
 * ue_sync must see both channels so that its read/discard operations remain
 * sample-identical.  However, it applies the DL PSS CFO correction to every
 * channel.  That is invalid for a separately tuned UL receiver and especially
 * damaging for an NTN link where DL and UE Doppler are unrelated.
 *
 * Recover the untouched UL samples directly from the source file after each
 * synchronized DL subframe.  A signed shift and an independent UL-only CFO
 * correction make wide satellite timing/CFO sweeps possible without moving
 * the DL frame boundary.
 */
static int read_raw_ul_window(pair_source_t* source,
                              int64_t start_sample,
                              cf_t* output,
                              uint32_t nsamples)
{
  if (start_sample < 0) {
    return SRSRAN_ERROR;
  }
  const off_t restore = ftello(source->ul);
  const off_t target = (off_t)((uint64_t)start_sample * sizeof(cf_t));
  if (restore < 0 || fseeko(source->ul, target, SEEK_SET) != 0) {
    return SRSRAN_ERROR;
  }
  const size_t count = fread(output, sizeof(cf_t), nsamples, source->ul);
  const int read_error = ferror(source->ul);
  clearerr(source->ul);
  if (fseeko(source->ul, restore, SEEK_SET) != 0) {
    return SRSRAN_ERROR;
  }
  return count == nsamples && !read_error ? SRSRAN_SUCCESS : SRSRAN_ERROR;
}

int main(int argc, char** argv)
{
  const char* dl_path = NULL;
  const char* ul_path = NULL;
  const char* output_path = NULL;
  int pci = -1;
  uint32_t nof_prb = 0;
  float initial_cfo_hz = 0.0f;
  uint64_t input_offset_samples = 0;
  uint32_t max_output_sf = 0;
  int64_t ul_shift_samples = 0;
  float ul_cfo_hz = 0.0f;

  static const struct option options[] = {
      {"dl", required_argument, NULL, 'd'},
      {"ul", required_argument, NULL, 'u'},
      {"output", required_argument, NULL, 'o'},
      {"pci", required_argument, NULL, 'p'},
      {"prb", required_argument, NULL, 'b'},
      {"cfo-hz", required_argument, NULL, 'c'},
      {"offset-samples", required_argument, NULL, 's'},
      {"max-subframes", required_argument, NULL, 'n'},
      {"ul-shift-samples", required_argument, NULL, 'S'},
      {"ul-cfo-hz", required_argument, NULL, 'F'},
      {"help", no_argument, NULL, 'h'},
      {NULL, 0, NULL, 0},
  };

  int option;
  while ((option = getopt_long(argc, argv, "d:u:o:p:b:c:s:n:S:F:h", options, NULL)) != -1) {
    switch (option) {
      case 'd': dl_path = optarg; break;
      case 'u': ul_path = optarg; break;
      case 'o': output_path = optarg; break;
      case 'p': pci = atoi(optarg); break;
      case 'b': nof_prb = (uint32_t)strtoul(optarg, NULL, 10); break;
      case 'c': initial_cfo_hz = strtof(optarg, NULL); break;
      case 's': input_offset_samples = strtoull(optarg, NULL, 10); break;
      case 'n': max_output_sf = (uint32_t)strtoul(optarg, NULL, 10); break;
      case 'S': ul_shift_samples = strtoll(optarg, NULL, 10); break;
      case 'F': ul_cfo_hz = strtof(optarg, NULL); break;
      default: usage(argv[0]); return 2;
    }
  }
  if (dl_path == NULL || ul_path == NULL || output_path == NULL ||
      pci < 0 || pci > 503 || !srsran_nofprb_isvalid(nof_prb)) {
    usage(argv[0]);
    return 2;
  }

  FILE* dl = fopen(dl_path, "rb");
  FILE* ul = fopen(ul_path, "rb");
  FILE* output = fopen(output_path, "wb");
  if (dl == NULL || ul == NULL || output == NULL) {
    fprintf(stderr, "cannot open input/output: %s\n", strerror(errno));
    if (dl) fclose(dl);
    if (ul) fclose(ul);
    if (output) fclose(output);
    return 1;
  }

  const off_t byte_offset = (off_t)(input_offset_samples * sizeof(cf_t));
  if (fseeko(dl, byte_offset, SEEK_SET) != 0 ||
      fseeko(ul, byte_offset, SEEK_SET) != 0) {
    fprintf(stderr,
            "cannot seek paired inputs to sample %" PRIu64 ": %s\n",
            input_offset_samples,
            strerror(errno));
    fclose(output); fclose(ul); fclose(dl);
    return 1;
  }

  pair_source_t source = {
      .dl = dl,
      .ul = ul,
      .samples_read = input_offset_samples,
      .eof = false,
  };
  srsran_ue_sync_t sync;
  memset(&sync, 0, sizeof(sync));
  if (srsran_ue_sync_init_multi(&sync, nof_prb, false, pair_recv, 2, &source)
      != SRSRAN_SUCCESS) {
    fprintf(stderr, "srsran_ue_sync_init_multi failed\n");
    fclose(output); fclose(ul); fclose(dl);
    return 1;
  }

  srsran_cell_t cell;
  memset(&cell, 0, sizeof(cell));
  cell.id = (uint32_t)pci;
  cell.nof_prb = nof_prb;
  cell.nof_ports = 1;
  cell.cp = SRSRAN_CP_NORM;
  cell.frame_type = SRSRAN_FDD;
  cell.phich_length = SRSRAN_PHICH_NORM;
  cell.phich_resources = SRSRAN_PHICH_R_1_6;
  if (srsran_ue_sync_set_cell(&sync, cell) != SRSRAN_SUCCESS) {
    fprintf(stderr, "srsran_ue_sync_set_cell failed\n");
    srsran_ue_sync_free(&sync);
    fclose(output); fclose(ul); fclose(dl);
    return 1;
  }
  if (initial_cfo_hz != 0.0f) {
    sync.cfo_current_value = initial_cfo_hz / 15000.0f;
    sync.cfo_is_copied = true;
    sync.cfo_correct_enable_find = true;
    srsran_sync_set_cfo_cp_enable(&sync.sfind, false, 0);
  }

  const uint32_t sf_len = SRSRAN_SF_LEN_PRB(nof_prb);
  const uint32_t buffer_len = 3 * sf_len;
  cf_t* buffer[SRSRAN_MAX_CHANNELS] = {NULL};
  buffer[0] = srsran_vec_cf_malloc(buffer_len);
  buffer[1] = srsran_vec_cf_malloc(buffer_len);
  cf_t* raw_ul_buffer = srsran_vec_cf_malloc(sf_len);
  if (buffer[0] == NULL || buffer[1] == NULL || raw_ul_buffer == NULL) {
    fprintf(stderr, "sample-buffer allocation failed\n");
    free(buffer[0]); free(buffer[1]); free(raw_ul_buffer);
    srsran_ue_sync_free(&sync);
    fclose(output); fclose(ul); fclose(dl);
    return 1;
  }

  bool started = false;
  uint32_t written_subframes = 0;
  uint32_t find_misses = 0;
  uint32_t sync_losses = 0;
  int first_sf_idx = -1;
  int last_sf_idx = -1;
  int64_t first_output_input_sample = -1;
  uint64_t ul_phase_sample = 0;

  while (!source.eof && (max_output_sf == 0 || written_subframes < max_output_sf)) {
    const int ret = srsran_ue_sync_zerocopy(&sync, buffer, buffer_len);
    if (ret < 0) break;
    if (ret == 0) {
      if (started) {
        ++sync_losses;
        fprintf(stderr, "stopping at first post-lock synchronization loss\n");
        break;
      }
      ++find_misses;
      continue;
    }

    const int sf_idx = (int)srsran_ue_sync_get_sfidx(&sync);
    if (!started) {
      if (sf_idx != 0) continue;
      started = true;
      first_sf_idx = sf_idx;
      fprintf(stderr,
              "locked PCI %d at paired input sample %" PRIu64
              "; output starts at LTE subframe 0; CFO %.3f Hz\n",
              pci,
              source.samples_read,
              srsran_ue_sync_get_cfo(&sync));
    }
    if (last_sf_idx >= 0 && sf_idx != ((last_sf_idx + 1) % 10)) {
      fprintf(stderr,
              "non-contiguous subframe index: previous=%d current=%d\n",
              last_sf_idx,
              sf_idx);
      ++sync_losses;
      break;
    }

    const int64_t dl_start_sample = (int64_t)source.samples_read - (int64_t)sf_len;
    const int64_t ul_start_sample = dl_start_sample + ul_shift_samples;
    if (read_raw_ul_window(&source, ul_start_sample, raw_ul_buffer, sf_len)
        != SRSRAN_SUCCESS) {
      fprintf(stderr,
              "cannot read shifted raw UL window at sample %" PRId64 "\n",
              ul_start_sample);
      source.eof = true;
      break;
    }
    if (first_output_input_sample < 0) {
      first_output_input_sample = dl_start_sample;
    }

    if (ul_cfo_hz != 0.0f) {
      const double phase_step =
          2.0 * M_PI * (double)ul_cfo_hz /
          (double)srsran_sampling_freq_hz(nof_prb);
      for (uint32_t i = 0; i < sf_len; ++i) {
        const double phase = phase_step * (double)(ul_phase_sample + i);
        raw_ul_buffer[i] *= cexpf(I * (float)phase);
      }
    }

    for (uint32_t i = 0; i < sf_len; ++i) {
      if (fwrite(&buffer[0][i], sizeof(cf_t), 1, output) != 1 ||
          fwrite(&raw_ul_buffer[i], sizeof(cf_t), 1, output) != 1) {
        fprintf(stderr, "paired output write failed: %s\n", strerror(errno));
        ++sync_losses;
        source.eof = true;
        break;
      }
    }
    if (source.eof) break;
    last_sf_idx = sf_idx;
    ++written_subframes;
    ul_phase_sample += sf_len;
  }

  fflush(output);
  const off_t output_bytes = ftello(output);
  printf("{\"pci\":%d,\"prb\":%u,\"channels\":2,\"sample_rate_hz\":%d,"
         "\"initial_cfo_hz\":%.3f,\"final_cfo_hz\":%.3f,"
         "\"input_samples_consumed_per_channel\":%" PRIu64 ","
         "\"first_output_input_sample\":%" PRId64 ","
         "\"ul_shift_samples\":%" PRId64 ",\"ul_cfo_hz\":%.3f,"
         "\"started\":%s,\"first_sf_idx\":%d,\"last_sf_idx\":%d,"
         "\"written_subframes\":%u,\"output_bytes\":%" PRIu64 ","
         "\"find_misses\":%u,\"sync_losses\":%u,\"eof\":%s,"
         "\"layout\":\"DL0,UL0,DL1,UL1 little-endian fc32\"}\n",
         pci,
         nof_prb,
         srsran_sampling_freq_hz(nof_prb),
         initial_cfo_hz,
         srsran_ue_sync_get_cfo(&sync),
         source.samples_read,
         first_output_input_sample,
         ul_shift_samples,
         ul_cfo_hz,
         started ? "true" : "false",
         first_sf_idx,
         last_sf_idx,
         written_subframes,
         (uint64_t)output_bytes,
         find_misses,
         sync_losses,
         source.eof ? "true" : "false");

  free(buffer[0]);
  free(buffer[1]);
  free(raw_ul_buffer);
  srsran_ue_sync_free(&sync);
  fclose(output);
  fclose(ul);
  fclose(dl);
  return started && written_subframes > 0 ? 0 : 3;
}
