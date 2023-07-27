FROM debian:buster

RUN apt update && \
  # Install common dependencies
  apt install -y \
    cmake \
    curl \
    g++ \
    gcc \
    git \
    make \
    wget \
    # LLVM script
    gnupg \
    lsb-release \
    software-properties-common \
    # Electron
    libasound2 \
    libgbm1 \
    libgdk-pixbuf2.0-0 \
    libgtk-3-0 \
    libnss3 \
    libxcomposite1 \
    libxcursor1 \
    libxi6 \
    libxss1 \
    libxtst6 \
    xvfb && \
    # Install node v14
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt install nodejs -y && \
    # Clear apt cache
    rm -rf /var/lib/{apt,dpkg,cache,log}/

# Install LLVM:12
RUN curl -sSf https://apt.llvm.org/llvm.sh | bash -s -- 12 && \
  ln -s $(which clang-12) /usr/bin/clang

# Install wasm-opt from binaryen
RUN git clone --depth 1 --branch version_114 https://github.com/WebAssembly/binaryen.git /binaryen && \
  cd /binaryen && \
  git submodule update --init && \
  cmake . && \
  make -j$(nproc) && \
  make install && \
  rm -rf /binaryen

# Add non-root user
RUN useradd -ms /bin/bash builduser
USER builduser

# Install Rust (using ./rust-toolchain version)
WORKDIR /home/builduser/
COPY rust-toolchain .
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y \
    --default-toolchain $(cat rust-toolchain) \
    --profile minimal \
    --component clippy,rustfmt,rust-src \
    --target wasm32-unknown-unknown \
    && rm rust-toolchain

CMD Xvfb :99 -screen 0 1024x768x24 > /dev/null 2>&1 & export DISPLAY=':99.0' && bash
