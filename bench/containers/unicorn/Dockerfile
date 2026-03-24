# Unicorn emulator backend
FROM python:3.11-slim

WORKDIR /build/bench
COPY pyproject.toml ./
COPY bench/ bench/

RUN pip install --no-cache-dir . unicorn>=2.0

ENTRYPOINT ["python", "-m", "bench.container_entrypoint"]
