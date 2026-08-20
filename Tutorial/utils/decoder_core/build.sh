#!/usr/bin/env bash
set -Eeuo pipefail

decoder_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${SRSRAN_ROOT:?Set SRSRAN_ROOT to an srsRAN 4G source tree}"
srsran_build="${SRSRAN_BUILD:-${SRSRAN_ROOT}/build}"
output_dir="${decoder_root}/build"
mkdir -p "${output_dir}"

common_includes=(
  -I"${srsran_build}/lib/include"
  -I"${SRSRAN_ROOT}/lib/include"
  -I"${SRSRAN_ROOT}"
)
common_libraries=(
  -Wl,-rpath,"${srsran_build}/lib/src/phy/rf"
  "${srsran_build}/lib/src/phy/libsrsran_phy.a"
  "${srsran_build}/lib/src/common/libsrsran_common.a"
  "${srsran_build}/lib/src/phy/rf/libsrsran_rf.so.23.04.0"
  "${srsran_build}/lib/src/support/libsupport.a"
  "${srsran_build}/lib/src/srslog/libsrslog.a"
  /usr/lib/x86_64-linux-gnu/libmbedcrypto.so
  /usr/lib/x86_64-linux-gnu/libsctp.so
  -ldl
  "${srsran_build}/lib/src/phy/rf/libsrsran_rf_utils.a"
  "${srsran_build}/lib/src/phy/libsrsran_phy.a"
  -lpthread -lm /usr/lib/x86_64-linux-gnu/libfftw3f.so
)

cc -std=c99 -D_GNU_SOURCE -O3 "${common_includes[@]}" \
  -c "${decoder_root}/src/align_duplex_lte.c" \
  -o "${output_dir}/align_duplex_lte.o"
c++ "${output_dir}/align_duplex_lte.o" \
  -o "${output_dir}/align_duplex_lte" "${common_libraries[@]}"

c++ -std=gnu++17 -O3 -Wall -Wextra -Wpedantic \
  "${common_includes[@]}" "${decoder_root}/src/ul_grant_probe.cpp" \
  -o "${output_dir}/ul_grant_probe" "${common_libraries[@]}"

echo "Built ${output_dir}/align_duplex_lte"
echo "Built ${output_dir}/ul_grant_probe"
