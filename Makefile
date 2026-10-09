# mytcp — userspace TAP stack (Ethernet → IP → TCP)
#
#   make help     list targets
#   make test     unit tests (macOS or Linux)
#   make build    build ./cmd/mytcp → bin/mytcp
#   make lab-up   start long-lived Docker lab
#   make shell    bash inside mytcp-lab
#   make smoke    ping + TCP echo inside the lab
#   make smoke-internet  mytcp as a client, out through NAT
#   make lab-down stop lab container

BIN     := bin
MYTCP   := $(BIN)/mytcp
LAB     := ./scripts/lab.sh
UI_PORT ?= 8765
TALK_PORT ?= 8766

.PHONY: help test build clean \
	lab-up lab-down shell smoke smoke-internet lab-nat status logs \
	lab-build lab-run lab-run-https lab-run-https-diy lab-run-echo ui talk talk-index

help:
	@echo "mytcp targets:"
	@echo "  make test       go test ./...  (no TAP needed)"
	@echo "  make build      build ./cmd/mytcp → $(MYTCP)"
	@echo "  make clean      remove $(BIN)/"
	@echo "  make ui         serve web/ on UI_PORT (default $(UI_PORT))"
	@echo "                  e.g. make ui UI_PORT=9000"
	@echo "  make talk       serve Reveal deck (default port $(TALK_PORT))"
	@echo "                  open http://127.0.0.1:$(TALK_PORT)/"
	@echo "  make talk-index refresh docs/talk/src-index.json for GitHub Pages"
	@echo ""
	@echo "lab (Docker / Linux TAP):"
	@echo "  make lab-up     build image + start mytcp-lab"
	@echo "  make shell      interactive bash in the lab"
	@echo "  make smoke      ping + curl + echo smoke test, server and client"
	@echo "  make lab-nat    NAT 10.0.0.0/24 out of the lab (client mode)"
	@echo "  make smoke-internet  mytcp -get through NAT to a real site"
	@echo "  make status     docker compose ps"
	@echo "  make logs       follow lab container logs"
	@echo "  make lab-down   stop and remove lab"
	@echo ""
	@echo "inside the lab:"
	@echo "  make lab-build  go build → /tmp/mytcp"
	@echo "  make lab-run    HTTP + capture to captures/latest"
	@echo "  make lab-run-https  HTTPS (curl -k) + capture"
	@echo "  make lab-run-echo  TCP echo on :7"
	@echo ""
	@echo "typical flow:"
	@echo "  make lab-up && make shell"
	@echo "  # then: make lab-build && make lab-run"
	@echo "  # other terminal: make shell → curl http://10.0.0.2/"
	@echo "  # on Mac: make ui → open captures/latest.jsonl"

test:
	go test ./...

$(BIN):
	mkdir -p $(BIN)

build: $(MYTCP)

$(MYTCP): go.mod $(shell find cmd internal -type f -name '*.go' 2>/dev/null) | $(BIN)
	go build -o $(MYTCP) ./cmd/mytcp

clean:
	rm -rf $(BIN)

lab-up:
	$(LAB) up

lab-down:
	$(LAB) down

shell:
	$(LAB) shell

smoke:
	$(LAB) smoke

lab-nat:
	$(LAB) nat

smoke-internet:
	$(LAB) smoke-internet

status:
	$(LAB) status

logs:
	$(LAB) logs

# Run these from a Mac via: make lab-build / make lab-run
# Or inside the lab shell directly (PWD is /work).
lab-build:
	docker compose exec lab go build -o /tmp/mytcp ./cmd/mytcp

lab-run:
	docker compose exec lab /tmp/mytcp -i tap0 -app http -dump=false -pcap captures/latest

lab-run-https:
	docker compose exec lab /tmp/mytcp -i tap0 -app https -dump=false -pcap captures/latest

lab-run-https-diy:
	docker compose exec lab /tmp/mytcp -i tap0 -app https-diy -dump=false -pcap captures/latest

lab-run-echo:
	docker compose exec lab /tmp/mytcp -i tap0 -app echo -tcp 7 -dump=false -pcap captures/latest

ui:
	@echo "Open http://127.0.0.1:$(UI_PORT)/  then load captures/latest.jsonl"
	cd web && python3 -m http.server $(UI_PORT)

talk:
	@echo "Open http://127.0.0.1:$(TALK_PORT)/"
	@echo "Keys: arrows · F fullscreen · S speaker notes · Esc overview"
	python3 docs/talk/serve.py $(TALK_PORT)

# File list the Pages-hosted deck uses to open source in the in-deck viewer.
talk-index:
	python3 -c "import json,pathlib; r=pathlib.Path('.'); f=[]; \
[f.extend(p.as_posix() for p in sorted((r/d).rglob('*')) if p.is_file() and p.suffix in {'.go','.sh'}) for d in ('cmd','internal','scripts')]; \
(r/'docs/talk/src-index.json').write_text(json.dumps({'files':f,'remote':'https://raw.githubusercontent.com/doodlesbykumbi/mytcp/main/','blob':'https://github.com/doodlesbykumbi/mytcp/blob/main/'}, indent=2)+'\n'); print(len(f),'files')"
