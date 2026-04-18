FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install compilers and sanitizer tooling
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    clang \
    clang-tools \
    llvm \
    libasan6 \
    libubsan1 \
    make \
    cmake \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Working directory for PoC trials
WORKDIR /sandbox

# Copy the PoC source in at runtime (not baked in)
# The runner will bind-mount or COPY the PoC before running

# Set sanitizer flags for compilation
ENV ASAN_OPTIONS=halt_on_error=1:print_stacktrace=1
ENV UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1

# Timeout wrapper — kill after 30 seconds
RUN apt-get update && apt-get install -y timeout && rm -rf /var/lib/apt/lists/* || true

CMD ["/bin/bash"]
