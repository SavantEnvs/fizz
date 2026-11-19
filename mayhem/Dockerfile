# syntax=docker/dockerfile:1.7
#
# Commit image for savantenvs/fizz (Meta's TLS 1.3 library, C++20, CMake under fizz/).
#
# fizz needs folly built from source at the revision upstream pins in
# build/deps/github_hashes/facebook/folly-rev.txt (Debian's libfolly-dev is years too old), and fmt
# at the version getdeps uses (12.1.0; trixie ships 10.x). These, libaegis and liboqs are built once
# here, uninstrumented,
# into /opt/toolchains/deps/<name>-<version>/ (SPEC §6.2 item 19); the rest comes from apt.
#
# Build (from the repo root):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t fizz .
FROM ghcr.io/savantenvs/base:20261023

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS
ARG COVERAGE_FLAGS=
ARG MAYHEM_JOBS=

USER root
RUN [ -n "$SOURCE_DATE_EPOCH" ] && repro-sources-list.sh || true ; \
    apt-get update && apt-get install -yq --no-install-recommends \
      libboost-context-dev libboost-filesystem-dev libboost-program-options-dev \
      libboost-regex-dev libboost-system-dev libboost-thread-dev \
      libdouble-conversion-dev libevent-dev libgflags-dev libgoogle-glog-dev \
      libfast-float-dev libsodium-dev libzstd-dev zlib1g-dev libssl-dev liblz4-dev \
      libsnappy-dev liblzma-dev libbz2-dev libunwind-dev libdwarf-dev libiberty-dev \
      libbrotli-dev libgtest-dev libgmock-dev \
 && rm -rf /var/lib/apt/lists/*

# fmt 12.1.0 (sha256 as in build/fbcode_builder/manifests/fmt).
ARG FMT_VER=12.1.0
ARG FMT_SHA256=ea7de4299689e12b6dddd392f9896f08fb0777ac7168897a244a6d6085043fea
RUN d=/opt/toolchains/deps/fmt-${FMT_VER} && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/fmtlib/fmt/archive/refs/tags/${FMT_VER}.tar.gz \
 && echo "${FMT_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cmake -S "$d/src" -B /tmp/dep-build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_FLAGS="-g -gdwarf-3" -DCMAKE_C_FLAGS="-g -gdwarf-3" \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF \
      -DFMT_TEST=OFF -DFMT_DOC=OFF -DCMAKE_INSTALL_PREFIX="$d" -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/dep-build -j"$(nproc)" && cmake --install /tmp/dep-build \
 && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX "$d"

# folly at the revision fizz pins (build/deps/github_hashes/facebook/folly-rev.txt), static.
ARG FOLLY_REV=f416c5d1cac01f8f3a59bce209a9ebb877da7307
ARG FOLLY_SHA256=ecab31615e7f03b524e51da4ce9c916bb51c67383a16e418fbf291eda3b4cd24
RUN d=/opt/toolchains/deps/folly-${FOLLY_REV} && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/facebook/folly/archive/${FOLLY_REV}.tar.gz \
 && echo "${FOLLY_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cmake -S "$d/src" -B /tmp/dep-build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_CXX_FLAGS="-g -gdwarf-3" -DCMAKE_C_FLAGS="-g -gdwarf-3" \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF -DBOOST_LINK_STATIC=ON \
      -DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF \
      -DCMAKE_PREFIX_PATH=/opt/toolchains/deps/fmt-${FMT_VER} \
      -DCMAKE_INSTALL_PREFIX="$d" -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/dep-build -j"$(nproc)" && cmake --install /tmp/dep-build \
 && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX "$d"

# libaegis (AEGIS AEADs; fizz enables its AEGIS cipher suites when find_package(aegis) succeeds).
ARG AEGIS_VER=0.10.7
ARG AEGIS_SHA256=0c64e1addcfb6297d2dcfaba083c76cd041ff9bf63306498ab2a57b6011e8cb9
RUN d=/opt/toolchains/deps/aegis-${AEGIS_VER} && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/jedisct1/libaegis/archive/refs/tags/${AEGIS_VER}.tar.gz \
 && echo "${AEGIS_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cmake -S "$d/src" -B /tmp/dep-build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-g -gdwarf-3" -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX="$d" -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/dep-build -j"$(nproc)" && cmake --install /tmp/dep-build \
 && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX "$d"

# liboqs (ML-KEM / Kyber; fizz sets FIZZ_HAVE_OQS and offers X25519MLKEM768 when
# find_package(liboqs) succeeds). Version, sha256 and OQS_MINIMAL_BUILD as in
# build/fbcode_builder/manifests/liboqs.
ARG OQS_VER=0.12.0
ARG OQS_SHA256=df999915204eb1eba311d89e83d1edd3a514d5a07374745d6a9e5b2dd0d59c08
RUN d=/opt/toolchains/deps/liboqs-${OQS_VER} && mkdir -p "$d/src" /tmp/dep-build \
 && curl -fsSL -o /tmp/dep.tgz https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${OQS_VER}.tar.gz \
 && echo "${OQS_SHA256}  /tmp/dep.tgz" | sha256sum -c - \
 && tar -xzf /tmp/dep.tgz --strip-components=1 -C "$d/src" \
 && cmake -S "$d/src" -B /tmp/dep-build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      -DCMAKE_C_FLAGS="-g -gdwarf-3" -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF \
      "-DOQS_MINIMAL_BUILD=KEM_kyber_512;KEM_kyber_768;KEM_kyber_1024;KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024" \
      -DOQS_BUILD_ONLY_LIB=ON -DCMAKE_INSTALL_PREFIX="$d" -DCMAKE_INSTALL_LIBDIR=lib \
 && cmake --build /tmp/dep-build -j"$(nproc)" && cmake --install /tmp/dep-build \
 && rm -rf /tmp/dep-build /tmp/dep.tgz && chmod -R a+rX "$d"

# build.sh hands this to CMake as CMAKE_PREFIX_PATH.
ENV FIZZ_DEPS_PREFIX="/opt/toolchains/deps/folly-${FOLLY_REV};/opt/toolchains/deps/fmt-${FMT_VER};/opt/toolchains/deps/aegis-${AEGIS_VER};/opt/toolchains/deps/liboqs-${OQS_VER}"

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN if [ -x /opt/mayhem/ccache/prefill ]; then /opt/mayhem/ccache/prefill bash mayhem/build.sh; \
    else bash mayhem/build.sh; fi

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
