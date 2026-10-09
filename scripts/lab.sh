#!/usr/bin/env bash
# Thin wrapper around docker compose for the long-lived mytcp lab.
#
# Typical flow:
#   ./scripts/lab.sh up      # build image + start container
#   ./scripts/lab.sh shell   # interactive bash in mytcp-lab
#   ./scripts/lab.sh smoke   # run all app smoke tests inside the lab
#   ./scripts/lab.sh down    # stop and remove
set -euo pipefail
cd "$(dirname "$0")/.."

cmd="${1:-}"
shift || true

case "$cmd" in
  up)
    # Build (tools preinstalled) and start detached; CMD is sleep infinity.
    docker compose up -d --build
    echo "lab running. Next:  ./scripts/lab.sh shell"
    ;;
  shell)
    # Drop into bash with the repo mounted at /work.
    docker compose exec lab bash
    ;;
  down)
    docker compose down
    ;;
  smoke)
    # Build mytcp and exercise every -app once (see smoke-linux.sh).
    docker compose exec lab bash scripts/smoke-linux.sh
    ;;
  nat)
    # Route 10.0.0.0/24 out to the internet (see lab-nat.sh).
    docker compose exec lab bash scripts/lab-nat.sh
    ;;
  smoke-internet)
    # mytcp as a client through the container's NAT to a real site.
    docker compose exec lab bash scripts/smoke-internet.sh
    ;;
  logs)
    docker compose logs -f lab
    ;;
  status)
    docker compose ps
    ;;
  *)
    cat <<'EOF'
Usage: ./scripts/lab.sh <command>

  up      Build image (tools preinstalled) and start long-lived container
  shell   Interactive bash inside mytcp-lab
  smoke   Run ping + TCP echo smoke test inside the lab
  nat     NAT 10.0.0.0/24 out of the container (for mytcp -dial / -get)
  smoke-internet  mytcp -get through NAT to a real site
  status  Show compose status
  logs    Follow container logs
  down    Stop and remove the lab container

Inside the shell:
  scripts/setup-tap.sh          # tap0 + 10.0.0.1/24
  go build -o /tmp/mytcp ./cmd/mytcp
  /tmp/mytcp -i tap0 -dump=false
  # other shell: ./scripts/lab.sh shell   then  ping / nc
EOF
    exit 1
    ;;
esac
