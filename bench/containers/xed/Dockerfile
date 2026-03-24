# Stage 1: Build XED
FROM python:3.11-slim AS xed-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential && \
    rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/intelxed/xed.git -b v2026.03.18 /build/xed && \
    git clone https://github.com/intelxed/mbuild.git -b v2026.03.18 /build/mbuild && \
    cd /build/xed && \
    ./mfile.py install && \
    mv kits/* /root/xedkit

# Stage 2: Compile CFFI bindings + install bench package
FROM python:3.11-slim AS cffi-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libffi-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=xed-builder /root/xedkit /root/xedkit

WORKDIR /build/bench
COPY pyproject.toml xed_build.py ./
COPY bench/ bench/

RUN pip install --no-cache-dir cffi>=1.16 && \
    python xed_build.py

RUN pip install --no-cache-dir .

# Stage 3: Runtime
FROM python:3.11-slim

COPY --from=xed-builder /root/xedkit/lib /root/xedkit/lib
COPY --from=cffi-builder /build/bench/_xed_cffi*.so /usr/local/lib/python3.11/site-packages/
COPY --from=cffi-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=cffi-builder /usr/local/bin/vmsifter-bench /usr/local/bin/vmsifter-bench

ENV LD_LIBRARY_PATH=/root/xedkit/lib

ENTRYPOINT ["python", "-m", "bench.container_entrypoint"]
