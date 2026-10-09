// Command mytcp runs the userspace network stack on a Linux TAP device.
//
// The kernel sees the TAP as a normal network card with its own address
// (-host). Every frame the kernel sends to it lands in this process as raw
// bytes, and mytcp answers as if it were a separate machine at -ip / -mac:
// ARP, ping, and one TCP application chosen with -app. Opening a TAP needs
// Linux and CAP_NET_ADMIN (root, or a privileged container).
//
// Typical invocations:
//
//	mytcp                               # HTTP on 10.0.0.2:80 (our http1 on net.Listener)
//	mytcp -app http-go                  # same Listener, Go's net/http.Server
//	mytcp -app echo                     # TCP echo on port 7
//	mytcp -app https                    # HTTPS on :443 via crypto/tls
//	mytcp -app https-go                 # same, but tls.NewListener + net/http.Server
//	mytcp -app https-diy                # HTTPS on :443 via our own mintls (TLS 1.2)
//	mytcp -dump-only                    # decode and capture frames, never reply
//	mytcp -i tap1 -ip 10.0.1.2 -host 10.0.1.1/24 -tcp 8080
//	mytcp -dump=false -pcap captures/run1
//	mytcp -dial 10.0.0.1:9000           # client: like nc, stdin/stdout over our TCP
//	mytcp -get http://10.0.0.1:8080/    # client: Go's http.Client over our Dial
//
// As a server, try it from another shell on the same machine:
// curl http://10.0.0.2/ or ping 10.0.0.2. With -dial or -get, mytcp
// connects out instead and exits when the exchange is over; addresses off
// the -host subnet go via -gw, and host names are looked up by our own
// DNS client (-dns), so the client path opens no kernel sockets at all.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/capture"
	"github.com/doodlesbykumbi/mytcp/internal/dump"
	"github.com/doodlesbykumbi/mytcp/internal/http1"
	"github.com/doodlesbykumbi/mytcp/internal/https1"
	"github.com/doodlesbykumbi/mytcp/internal/stack"
	"github.com/doodlesbykumbi/mytcp/internal/tap"
)

// main parses flags, picks the TCP application, opens the TAP, wires the
// stack together, and then runs until Ctrl-C, a read error, or the end of
// a -dial / -get exchange.
func main() {
	// Registered first so it runs last, after the other deferred Closes.
	exitCode := 0
	defer func() {
		if exitCode != 0 {
			os.Exit(exitCode)
		}
	}()

	// The first four flags are identity: which TAP to use, the address we
	// pretend to be, the address the kernel gets on its side of the
	// virtual cable, and our MAC. The two IPs share a subnet so the kernel
	// sends straight to us over the TAP. The default MAC starts with 02,
	// the "locally administered" bit, so it cannot clash with a real
	// vendor MAC. The rest choose the app and port, how much to print,
	// and where to record frames.
	var (
		ifName   = flag.String("i", "tap0", "TAP interface name (created if missing)")
		ipStr    = flag.String("ip", "10.0.0.2", "IPv4 address we claim (userspace)")
		hostCIDR = flag.String("host", "10.0.0.1/24", "kernel-side address on the TAP (empty = skip)")
		macStr   = flag.String("mac", "02:00:00:00:00:02", "MAC address we claim")
		tcpPort  = flag.Uint("tcp", 0, "TCP listen port (0 = default: 80 http, 443 https, 7 echo)")
		appName  = flag.String("app", "http", "TCP app: http | http-go | https | https-go | https-diy | echo")
		doDump   = flag.Bool("dump", true, "layered onion decode of RX/TX frames")
		dumpOnly = flag.Bool("dump-only", false, "Stage 0: decode frames only, no replies")
		pcapPath = flag.String("pcap", "captures/latest", "capture stem (.jsonl + .pcap); empty disables")
		gwStr    = flag.String("gw", "", "gateway for addresses off the -host subnet (default: the -host address)")
		dialAddr = flag.String("dial", "", "client: connect to host:port and copy stdin/stdout, like nc")
		getURL   = flag.String("get", "", "client: fetch URL with net/http.Client over our TCP")
		dnsStr   = flag.String("dns", "1.1.1.1", "DNS server our own resolver asks for -dial/-get names (reached via -gw; the lab's 127.0.0.11 is loopback and unreachable)")
	)
	flag.Parse()
	client := *dialAddr != "" || *getURL != ""

	mac, err := net.ParseMAC(*macStr)
	if err != nil {
		log.Fatalf("mac: %v", err)
	}
	// The stack speaks IPv4 only, so reject IPv6 addresses up front.
	ip := net.ParseIP(*ipStr)
	if ip == nil || ip.To4() == nil {
		log.Fatalf("ip: need IPv4 address, got %q", *ipStr)
	}

	// Pick what runs on top of TCP. Every app is the same shape: a
	// function that takes a net.Listener and serves connections from it,
	// exactly as it would on a kernel socket. Each has a default port.
	var (
		serve   func(net.Listener) error
		port    = uint16(*tcpPort)
		defPort uint16
		appDesc string
	)
	switch *appName {
	case "echo":
		serve, defPort, appDesc = serveEcho, 7, "TCP echo"
	case "http":
		serve, defPort, appDesc = http1.New(log.Default()).Serve, 80, "HTTP/1 (our server on net.Listener)"
	case "http-go":
		// Go's own HTTP server, given our Listener instead of net.Listen's.
		srv := &http.Server{Handler: http1.New(log.Default()).Handler()}
		srv.SetKeepAlivesEnabled(false)
		serve, defPort, appDesc = srv.Serve, 80, "HTTP/1 (net/http.Server on net.Listener)"
	case "https":
		hs, err := https1.New(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https: %v", err)
		}
		serve, defPort, appDesc = hs.Serve, 443, "HTTPS (crypto/tls + HTTP/1)"
	case "https-go":
		// All stdlib above our TCP: tls.NewListener wraps our Listener, and
		// http.Server serves the TLS conns it returns.
		hs, err := https1.New(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https-go: %v", err)
		}
		srv := &http.Server{Handler: http1.New(log.Default()).Handler()}
		srv.SetKeepAlivesEnabled(false)
		serve = func(ln net.Listener) error { return srv.Serve(tls.NewListener(ln, hs.TLSConfig())) }
		defPort, appDesc = 443, "HTTPS (tls.NewListener + net/http.Server)"
	case "https-diy":
		hs, err := https1.NewDIY(ip.To4(), log.Default())
		if err != nil {
			log.Fatalf("https-diy: %v", err)
		}
		serve, defPort, appDesc = hs.Serve, 443, "HTTPS (mintls TLS 1.2 DIY + HTTP/1)"
	default:
		log.Fatalf("unknown -app %q (want http|http-go|https|https-go|https-diy|echo)", *appName)
	}
	if port == 0 {
		port = defPort
	}

	var dnsIP net.IP
	if *dnsStr != "" {
		if dnsIP = net.ParseIP(*dnsStr).To4(); dnsIP == nil {
			log.Fatalf("dns: need an IPv4 address, got %q", *dnsStr)
		}
	}

	// Routing, such as it is: the -host subnet is on the link, and
	// everything else goes to one gateway, by default the kernel side.
	var subnet *net.IPNet
	gw := net.ParseIP(*gwStr)
	if *hostCIDR != "" {
		hostIP, n, err := net.ParseCIDR(*hostCIDR)
		if err != nil {
			log.Fatalf("host: %v", err)
		}
		subnet = n
		if gw == nil {
			gw = hostIP
		}
	}

	// Open the TAP. From here on, every Read is one Ethernet frame the
	// kernel sent toward our side of the virtual cable.
	dev, err := tap.Open(*ifName)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	// Bring the interface up and give the kernel side its address, so the
	// kernel knows that -ip is reachable through this TAP.
	if err := tap.ConfigureHostSide(dev.Name(), *hostCIDR); err != nil {
		log.Fatalf("configure %s: %v", dev.Name(), err)
	}

	// Optional capture: every RX and TX frame is written to <stem>.jsonl
	// (for the browser viewer in web/) and <stem>.pcap (for Wireshark).
	var rec *capture.Recorder
	if *pcapPath != "" {
		rec, err = capture.Open(*pcapPath)
		if err != nil {
			log.Fatalf("capture: %v", err)
		}
		defer rec.Close()
		abs, _ := filepath.Abs(rec.Path())
		log.Printf("capturing → %s.jsonl + .pcap  (open web/index.html to inspect)", abs)
	}

	// Startup banner, including a ready-to-paste command to try the
	// chosen app from another shell.
	log.Printf("TAP %s open — we are %s / %s (host %s)", dev.Name(), mac, ip.To4(), *hostCIDR)
	switch {
	case *dumpOnly:
		log.Printf("dump-only mode: no protocol replies")
	case client:
		log.Printf("client mode: ARP, ICMP echo, outgoing TCP via gateway %s, DNS via %s (our UDP)", gw, dnsIP)
	default:
		log.Printf("protocols: ARP, ICMP echo, %s :%d", appDesc, port)
	}
	switch {
	case client:
	case *appName == "http" || *appName == "http-go":
		log.Printf("from another shell: curl http://%s/   or   printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc %s %d",
			ip.To4(), ip.To4(), port)
	case *appName == "https" || *appName == "https-go" || *appName == "https-diy":
		// -k because the certificate is self-signed. The TLS 1.2 cap is
		// required for mintls, which speaks nothing newer.
		log.Printf("from another shell: curl -k --tlsv1.2 --tls-max 1.2 https://%s/", ip.To4())
	default:
		log.Printf("from another shell: ping %s   or   nc %s %d", ip.To4(), ip.To4(), port)
	}

	// In client mode stdout carries the received bytes, so dumps move to
	// stderr next to the log.
	dumpOut := io.Writer(os.Stdout)
	if client {
		dumpOut = os.Stderr
	}
	st := stack.New(dev, stack.Config{
		MAC:     mac,
		IP:      ip.To4(),
		Subnet:  subnet,
		Gateway: gw,
		DNS:     dnsIP,
		Dump:    *doDump,
		DumpOut: dumpOut,
		Capture: rec,
		Logger:  log.Default(),
	})

	clientDone := make(chan error, 1)
	switch {
	case *dialAddr != "":
		go func() { clientDone <- runDial(st, *dialAddr) }()
	case *getURL != "":
		go func() { clientDone <- runGet(st, *getURL) }()
	default:
		// The same call a kernel program makes with net.Listen, but on our TCP.
		ln := st.TCP().Listen(port)
		go func() {
			if err := serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("%s: %v", *appName, err)
			}
		}()
	}

	// Ctrl-C (SIGINT) or SIGTERM ends the program cleanly so the deferred
	// Close calls run and the capture files are complete.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Timer goroutine: TCP must resend segments that were never ACKed,
	// and that needs a clock. Every 100 ms the stack checks for segments
	// whose retransmit timeout has passed.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	go func() {
		for range tick.C {
			if !*dumpOnly {
				st.Tick()
			}
		}
	}()

	// Reader goroutine: the receive loop. It is the only caller of
	// HandleFrame, so incoming frames are processed one at a time, in
	// order. 2048 bytes holds any standard Ethernet frame (up to 1514
	// bytes without the checksum, which the TAP does not deliver).
	buf := make([]byte, 2048)
	errCh := make(chan error, 1)
	go func() {
		for {
			n, err := dev.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			// Copy the frame out of the shared read buffer, so nothing
			// downstream holds a slice the next Read will overwrite.
			frame := append([]byte(nil), buf[:n]...)
			// Dump-only mode: watch and record, but never hand frames to
			// the stack. With no ARP replies, the host cannot even find
			// us, so all you see are its questions.
			if *dumpOnly {
				if *doDump {
					dump.Frame(os.Stdout, "<<< RX", frame)
				}
				if rec != nil {
					_ = rec.Write(capture.RX, frame)
				}
				continue
			}
			// A bad frame is logged and skipped; it must not stop the loop.
			if err := st.HandleFrame(frame); err != nil {
				log.Printf("handle: %v", err)
			}
		}
	}()

	// The main goroutine just waits for a signal or a fatal read error.
	// log.Fatalf exits immediately, without running deferred calls.
	select {
	case <-stop:
		log.Printf("shutting down")
	case err := <-errCh:
		log.Fatalf("read: %v", err)
	case err := <-clientDone:
		if err != nil {
			log.Printf("client: %v", err)
			exitCode = 1
		}
	}
}

// runDial is nc on our TCP: stdin goes to the peer, and whatever the peer
// sends goes to stdout until it closes. There is no half-close, so when
// stdin ends we keep reading until the peer hangs up.
func runDial(st *stack.Stack, addr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := st.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	log.Printf("connected %s → %s", c.LocalAddr(), c.RemoteAddr())
	go func() { _, _ = io.Copy(c, os.Stdin) }()
	_, err = io.Copy(os.Stdout, c)
	return err
}

// runGet fetches url with Go's own HTTP client. The only change from a
// normal http.Get is the Transport's DialContext: every connection it
// opens, plain or TLS, rides on our TCP instead of the kernel's.
func runGet(st *stack.Stack, url string) error {
	hc := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:       st.DialContext,
			DisableKeepAlives: true,
		},
	}
	resp, err := hc.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
	for k, vs := range resp.Header {
		for _, v := range vs {
			fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
		}
	}
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

// serveEcho writes every byte it reads straight back, one goroutine per
// connection, until the client closes. Try it with nc.
func serveEcho(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}
