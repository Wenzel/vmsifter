# Capstone decoder backend — no native build step needed
FROM python:3.11-slim

WORKDIR /build/bench
COPY pyproject.toml ./
COPY bench/ bench/

RUN pip install --no-cache-dir . capstone>=5.0

ENTRYPOINT ["python", "-m", "bench.container_entrypoint"]
