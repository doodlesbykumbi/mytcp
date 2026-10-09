package stack

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/doodlesbykumbi/mytcp/internal/dns"
)

// DialContext connects to addr ("host:port") over our TCP. It has the
// same signature as net.Dialer.DialContext, so it drops straight into
// http.Transport.DialContext.
//
// Host names are looked up by LookupIPv4, over our own UDP, so dialing
// makes no socket calls into the kernel at all. Ports must be numeric,
// which is what http.Transport always passes.
func (s *Stack) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" {
		return nil, fmt.Errorf("dial %s %s: only tcp is supported", network, addr)
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("dial %s: port %q is not a number", addr, portStr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if ip, err = s.LookupIPv4(ctx, host); err != nil {
			return nil, err
		}
	}
	c, err := s.tcp.Dial(ctx, ip, uint16(port))
	if err != nil {
		return nil, err
	}
	return c, nil
}

// dnsTries is how many times LookupIPv4 asks before giving up; each
// try waits up to dnsRetry for the answer.
const (
	dnsTries = 3
	dnsRetry = time.Second
)

// LookupIPv4 asks the Config.DNS server for host's A records and returns
// the first one. It is a stub resolver, like the one in libc: the server
// does the recursive work, and we send one UDP question and read one
// UDP answer. Nothing is cached.
func (s *Stack) LookupIPv4(ctx context.Context, host string) (net.IP, error) {
	if s.cfg.DNS == nil {
		return nil, fmt.Errorf("lookup %s: no DNS server configured", host)
	}
	// A random ID makes a forged answer harder to slip in: it must
	// match the ID, our port, and come from the server's address.
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	q, err := dns.Query(id, host)
	if err != nil {
		return nil, err
	}
	u, err := s.BindUDP(0)
	if err != nil {
		return nil, err
	}
	defer u.Close()

	for try := 0; try < dnsTries; try++ {
		s.log.Printf("dns: ask %s for %s (id=%d, from :%d)", s.cfg.DNS, host, id, u.Port())
		if err := u.WriteTo(ctx, q, s.cfg.DNS, 53); err != nil {
			return nil, fmt.Errorf("lookup %s: %w", host, err)
		}
		ips, err := s.awaitAnswer(ctx, u, id)
		switch {
		case err == nil:
			s.log.Printf("dns: %s is %s", host, ips[0])
			return ips[0], nil
		case errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil:
			continue // this try timed out; ask again
		default:
			return nil, fmt.Errorf("lookup %s: %w", host, err)
		}
	}
	return nil, fmt.Errorf("lookup %s: no answer from %s", host, s.cfg.DNS)
}

// awaitAnswer reads datagrams until one from the DNS server answers id,
// or dnsRetry passes. Anything else arriving on the port is ignored.
func (s *Stack) awaitAnswer(ctx context.Context, u *UDPPort, id uint16) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, dnsRetry)
	defer cancel()
	for {
		b, ip, port, err := u.ReadFrom(ctx)
		if err != nil {
			return nil, err
		}
		if !ip.Equal(s.cfg.DNS) || port != 53 {
			continue
		}
		ips, err := dns.ParseResponse(b, id)
		if err != nil && len(b) >= 2 && binary.BigEndian.Uint16(b) != id {
			continue // a late answer to an earlier question
		}
		return ips, err
	}
}
