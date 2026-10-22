FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY railway_trace ./railway_trace
RUN pip install --no-cache-dir . && useradd -m tracer && mkdir -p /app/out && chown tracer /app/out
USER tracer
# The key is passed at runtime (--env-file .env or -e GOLDRUSH_API_KEY); it is never baked into the image.
ENTRYPOINT ["railway-trace"]
CMD ["--help"]
