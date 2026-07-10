# ThreatTracer — CVE intelligence, triage & local-AI briefing CLI
FROM python:3.12-slim

LABEL org.opencontainers.image.title="ThreatTracer" \
      org.opencontainers.image.description="CVE intelligence, risk triage & local-AI briefing CLI" \
      org.opencontainers.image.source="https://github.com/anmolksachan/ThreatTracer"

# Non-root user
RUN useradd --create-home --uid 1000 tracer
WORKDIR /app

# Install dependencies first (better layer caching)
COPY pyproject.toml README.md ./
COPY threattracer ./threattracer
RUN pip install --no-cache-dir . \
    && mkdir -p /home/tracer/.threattracer \
    && chown -R tracer:tracer /home/tracer

USER tracer
ENV THREATTRACER_LLM_PROVIDER=auto

# The container talks to a host LLM via host.docker.internal (Docker Desktop) or
# --add-host / --network host on Linux. Override at run time, e.g.:
#   docker run --rm -e THREATTRACER_LLM_OLLAMA_URL=http://host.docker.internal:11434 \
#              threattracer scan -c apache -v 2.4.51 --summarize
ENTRYPOINT ["threattracer"]
CMD ["--help"]
