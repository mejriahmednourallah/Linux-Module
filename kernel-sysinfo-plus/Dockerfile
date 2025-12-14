FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /build/sysinfo_plus

# Install toolchain and headers for the running kernel inside the container.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential \
       linux-headers-$(uname -r) \
       ca-certificates \
       git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY . .

# Build the kernel module (no loading in container).
RUN make

CMD ["/bin/bash"]
