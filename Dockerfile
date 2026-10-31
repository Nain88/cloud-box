FROM node:22-bookworm-slim AS web
RUN corepack enable && corepack prepare pnpm@10.20.0 --activate
WORKDIR /build/web
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends suricata libyara9 ca-certificates fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY cbb/ ./cbb/
COPY pyproject.toml ./
COPY rules/ ./rules/
COPY --from=web /build/web/dist ./web/dist
RUN useradd --uid 10001 --create-home cbb && mkdir /data && chown cbb:cbb /data
USER 10001:10001
ENV CBB_DATA=/data PYTHONUNBUFFERED=1
EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8765/health/ready',timeout=3)"
CMD ["python","-m","cbb.cli","serve","--host","0.0.0.0"]
