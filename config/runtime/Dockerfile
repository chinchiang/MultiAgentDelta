# 在無憑證的建置階段安裝工具；執行時禁止網路。 / Install without credentials; runtime has no network.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node
FROM python:3.11-slim-bookworm@sha256:0a310eeecf4e1f5a0743f9a6520c90c88d089c903ca5fd283f501e3a805f5f89
COPY --from=node /usr/local/ /usr/local/
ARG PROMPTFOO_VERSION=0.123.1
ARG GARAK_VERSION=0.17.0
COPY config/garak/constraints.txt /opt/constraints.txt
WORKDIR /tmp
# 可選 CA 只在建置步驟掛載；不保留在映像內。 / Optional build-only CA is never retained in the image.
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/proxy_ca PIP_CERT=/run/secrets/proxy_ca; fi; \
    npm install --global "promptfoo@${PROMPTFOO_VERSION}" && npm cache clean --force && \
    pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu 'torch==2.13.0+cpu' && \
    pip install --no-cache-dir -c /opt/constraints.txt "garak==${GARAK_VERSION}"
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=2 \
    CMD python -c "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3); assert r.status == 200"
