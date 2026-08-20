#!/usr/bin/env bash
set -Eeuo pipefail

tutorial_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${tutorial_root}/.." && pwd)"
vendor_build="${tutorial_root}/vendor/build"
ltesniffer_source="${vendor_build}/LTESniffer"
ltesniffer_build="${ltesniffer_source}/build"
decoder_build="${tutorial_root}/utils/decoder_core/build"
ltesniffer_commit="a694803082017ac2b349e6b113940e8b9ba2fe5b"

if [[ "${EUID}" -eq 0 ]]; then
  sudo_command=()
else
  sudo_command=(sudo)
fi

"${sudo_command[@]}" apt-get update
"${sudo_command[@]}" apt-get install -y \
  build-essential cmake git pkg-config python3 python3-dev python3-venv \
  gnuradio tshark wireshark-common \
  libfftw3-dev libmbedtls-dev libboost-program-options-dev \
  libboost-system-dev libboost-thread-dev libconfig++-dev libsctp-dev \
  libglib2.0-dev libudev-dev libcurl4-gnutls-dev

python3 -m venv --system-site-packages "${repo_root}/.venv"
"${repo_root}/.venv/bin/python" -m pip install --upgrade pip
"${repo_root}/.venv/bin/python" -m pip install -r "${tutorial_root}/requirements.txt"

mkdir -p "${vendor_build}"
if [[ ! -d "${ltesniffer_source}/.git" ]]; then
  git clone https://github.com/SysSec-KAIST/LTESniffer.git "${ltesniffer_source}"
fi
git -C "${ltesniffer_source}" checkout --detach "${ltesniffer_commit}"
cp -a "${tutorial_root}/vendor/ltesniffer-overlay/." "${ltesniffer_source}/"

cmake -S "${ltesniffer_source}" -B "${ltesniffer_build}" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_GUI=OFF -DENABLE_UHD=OFF -DENABLE_BLADERF=OFF \
  -DENABLE_SOAPYSDR=OFF -DFORCE_SUBPROJECT_CMNALIB=ON \
  -DFORCE_SUBPROJECT_SRSRAN=ON
cmake --build "${ltesniffer_build}" --parallel "$(nproc)"

SRSRAN_ROOT="${ltesniffer_build}/srsRAN-src" \
SRSRAN_BUILD="${ltesniffer_build}/srsRAN-build" \
  bash "${tutorial_root}/utils/decoder_core/build.sh"

mkdir -p "${decoder_build}"
cp -a "${ltesniffer_build}/src/LTESniffer" "${decoder_build}/LTESniffer"
"${repo_root}/.venv/bin/python" "${tutorial_root}/check_setup.py"

echo
echo "Setup complete. Start Jupyter with:"
echo "  ${repo_root}/.venv/bin/jupyter lab ${tutorial_root}/01_raw_iq_and_downsampling.ipynb"
