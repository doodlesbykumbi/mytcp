# Demo playbook

Everything runs inside the Linux lab container. The kernel owns `10.0.0.1`
on `tap0`; mytcp answers as `10.0.0.2`. Anything you send to `10.0.0.2`
hits our stack.

## Before the talk

```bash
cd mytcp
make lab-up       # start the lab container (stays up)
make lab-build    # build /tmp/mytcp inside it
make smoke        # every app once; expect "... smoke ok" lines
make talk         # slides on http://127.0.0.1:8766/ (S = speaker notes)
```

## Run it (two lab shells)

**Shell A: the stack**

```bash
make lab-run      # -app http, capture to captures/latest.{pcap,jsonl}
```

**Shell B: ordinary tools**

```bash
make shell
ping -c 3 10.0.0.2          # ARP + ICMP
curl -v http://10.0.0.2/    # ARP + IPv4 + TCP + HTTP
```

Shell A logs each step (`SYN_RECEIVED`, `ESTABLISHED`, `GET /`), which shows
our stack answered, not the kernel. Drop `-dump=false` to see every frame
decoded.

## Other apps

Ctrl-C shell A, then from a lab shell:

| Run | Test |
|---|---|
| `/tmp/mytcp -i tap0 -app http-go -dump=false` | `curl http://10.0.0.2/` |
| `/tmp/mytcp -i tap0 -app https -dump=false` | `curl -k https://10.0.0.2/` |
| `/tmp/mytcp -i tap0 -app https-go -dump=false` | `curl -k https://10.0.0.2/` |
| `/tmp/mytcp -i tap0 -app https-diy -dump=false` | `curl -k --tlsv1.2 --tls-max 1.2 https://10.0.0.2/` |
| `/tmp/mytcp -i tap0 -app echo -dump=false` | `nc 10.0.0.2 7` |

Add `-pcap captures/<name>` to any of them to record.

## The other direction: mytcp as a client

`-dial` and `-get` connect out instead of listening; mytcp exits when done.

```bash
# kernel side as the server:
nc -l 9000                                                # shell B
/tmp/mytcp -i tap0 -dial 10.0.0.1:9000 -dump=false        # shell A; type both ways

# Go's http.Client over our TCP, out through NAT:
make lab-nat                                              # once per lab start
/tmp/mytcp -i tap0 -get http://example.com/ -dump=false
/tmp/mytcp -i tap0 -get https://example.com/ -dump=false  # crypto/tls on our TCP
```

The log shows `arp: who-has 10.0.0.1`, then `dns: ask 1.1.1.1 for …`,
then `SYN_SENT` and `ESTABLISHED (dialed)`. The ARP request and the DNS
question are ours this time. No kernel sockets at all:

```bash
strace -f -e trace=%network /tmp/mytcp -i tap0 -get https://www.google.com/ -dump=false
```

Only netlink lines appear (the `ip` commands that set up tap0). Wireshark
filter for the whole story: `arp || dns || tcp`.

## See the packets

The traffic lives inside Docker's Linux VM, so Wireshark on the Mac cannot
see it on any interface. Use one of:

- **File:** open `captures/latest.pcap` in Wireshark (bind-mounted to the
  Mac; Cmd-R to reload while it runs).
- **Live:**
  ```bash
  docker compose exec -T lab tcpdump -i tap0 -U -w - \
    | /Applications/Wireshark.app/Contents/MacOS/Wireshark -k -i -
  ```
  Filters: `arp || icmp`, `tcp.port == 80`, `tls`.
- **Browser inspector:** `make ui`, open http://127.0.0.1:8765, load
  `captures/latest.jsonl`.

TLS records show up, but Wireshark cannot decrypt them: the keys never leave
mytcp.

## If something breaks

- **No reply at all:** is shell A still running? Rerun `make lab-build` after
  code changes.
- **Port busy (`make ui` / `make talk`):** `make ui UI_PORT=9000`,
  `make talk TALK_PORT=9001`.
- **Lab in a bad state:** `make lab-down && make lab-up && make lab-build`.

## After

```bash
make lab-down
```
