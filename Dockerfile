# Long-lived Linux lab image for mytcp.
# Go toolchain + network debugging tools; the container stays up via sleep
# so you can `docker compose exec` in for demos (see scripts/lab.sh).
FROM golang:1.25-bookworm

# Network utilities used from inside the lab:
#   iproute2 / net-tools  — create/configure tap0 (ip, ifconfig)
#   iputils-ping          — ICMP smoke tests against the stack (.2)
#   netcat-openbsd        — TCP echo smoke tests
#   curl                  — HTTP/HTTPS smoke tests
#   tcpdump               — live capture / pipe to Wireshark on the host
#   iptables              — NAT so mytcp -dial/-get can reach the internet
#   strace                — show that mytcp's client path opens no sockets
#   procps, vim-tiny, less — process inspection and light editing in-shell
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 \
      iputils-ping \
      netcat-openbsd \
      curl \
      tcpdump \
      iptables \
      strace \
      net-tools \
      procps \
      vim-tiny \
      less \
 && rm -rf /var/lib/apt/lists/*

# Repo is bind-mounted here by docker-compose (source on the host).
WORKDIR /work

# Stay up until `docker compose stop` / `make lab-down`.
CMD ["sleep", "infinity"]
