package stack_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestUDPExchange(t *testing.T) {
	client, server := cabled(t)
	srv, err := server.BindUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() {
		b, ip, port, err := srv.ReadFrom(ctx)
		if err != nil {
			return
		}
		_ = srv.WriteTo(ctx, append([]byte("re:"), b...), ip, port)
	}()

	c, err := client.BindUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.WriteTo(ctx, []byte("hi"), gwIP, 5353); err != nil {
		t.Fatal(err)
	}
	b, ip, port, err := c.ReadFrom(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "re:hi" || !ip.Equal(gwIP) || port != 5353 {
		t.Fatalf("got %q from %s:%d", b, ip, port)
	}
}

func TestUDPBind(t *testing.T) {
	st, _ := routedStack(t)
	a, _ := st.BindUDP(0)
	b, _ := st.BindUDP(0)
	if a.Port() == b.Port() || a.Port() < 49152 {
		t.Fatalf("ephemeral ports %d and %d", a.Port(), b.Port())
	}
	if _, err := st.BindUDP(a.Port()); err == nil {
		t.Fatal("bound the same port twice")
	}
	a.Close()
	if _, _, _, err := a.ReadFrom(context.Background()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close: %v", err)
	}
	if _, err := st.BindUDP(a.Port()); err != nil {
		t.Fatalf("port not freed by Close: %v", err)
	}
}
