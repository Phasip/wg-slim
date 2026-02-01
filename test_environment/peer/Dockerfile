FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends iputils-ping tcpdump openresolv iptables wireguard-tools procps iproute2 python3 python3-requests \
  && rm -rf /var/lib/apt/lists/*

COPY peer_entrypoint.py /peer_entrypoint.py
CMD ["python3","-u", "/peer_entrypoint.py"]
