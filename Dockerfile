FROM debian:latest AS base
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Default environment variables for initial configuration
# Provide a small YAML initial config via `INITIAL_CONFIG`.

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        wireguard-tools \
        iproute2 \
        openresolv \
        iptables \
        nftables \
        procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install runtime requirements
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir --break-system-packages -r /app/requirements.txt

RUN mkdir -p /data

EXPOSE 5000
EXPOSE 51820/udp

CMD ["python3", "main.py"]

FROM base AS dev

# Dev stage needs build tools (make, java, node, npm)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        make \
        default-jre-headless \
        nodejs \
        npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements-build.txt /app/

# Install build-time requirements required to run codegen and server generation
RUN pip3 install --no-cache-dir --break-system-packages -r /app/requirements-build.txt

# Copy project files and run generation
COPY . /app/
RUN rm -rf openapi_generated static/js/openapi-client.js
RUN make openapi-client
RUN make openapi-server
RUN make openapi-python-client

FROM base AS full

# Copy runtime application source
COPY *.py /app/
# Silence the deprecated warnings from the outdated generator
COPY pyproject.toml /app/
COPY templates /app/templates
COPY static /app/static

# Copy generated artifacts from dev stage (if present)
COPY --from=dev /app/openapi_generated /tmp/openapi_generated
COPY --from=dev /app/static/js/openapi-client.js /app/static/js/openapi-client.js
# Install python-fastapi and python-client from generated
RUN pip3 install --no-cache-dir --break-system-packages /tmp/openapi_generated/python-fastapi
RUN pip3 install --no-cache-dir --break-system-packages /tmp/openapi_generated/python-client
