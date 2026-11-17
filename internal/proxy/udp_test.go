package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/anixops/speedtest/internal/proxy/proxytest"
)

func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], from)
		}
	}()
	return pc
}

func TestListenUDPRoundTrip(t *testing.T) {
	srv := proxytest.Start(t, false)
	echo := udpEcho(t)
	port := echo.LocalAddr().(*net.UDPAddr).Port

	c, err := ListenUDP(context.Background(), srv.URL, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, dst := range []net.Addr{
		echo.LocalAddr(),                    // IP destination
		Addr{Host: "localhost", Port: port}, // hostname: resolved by the proxy
	} {
		msg := []byte("ping " + dst.String())
		if _, err := c.WriteTo(msg, dst); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%v: %v", dst, err)
		}
		if !bytes.Equal(buf[:n], msg) {
			t.Fatalf("got %q want %q", buf[:n], msg)
		}
		if u, ok := from.(*net.UDPAddr); !ok || u.Port != port {
			t.Fatalf("reply source %v, want port %d", from, port)
		}
	}
	want := "localhost:" + strconv.Itoa(port)
	if d := srv.Dests(); len(d) != 2 || d[1] != want {
		t.Fatalf("proxy saw %v, want hostname kept as %s", d, want)
	}
}

func TestListenUDPUnsupported(t *testing.T) {
	srv := proxytest.Start(t, true)
	_, err := ListenUDP(context.Background(), srv.URL, 2*time.Second)
	if !errors.Is(err, ErrUDPUnsupported) {
		t.Fatalf("err = %v, want ErrUDPUnsupported", err)
	}
}

func TestListenUDPRejectsHTTPProxy(t *testing.T) {
	if _, err := ListenUDP(context.Background(), "http://127.0.0.1:1", time.Second); err == nil {
		t.Fatal("expected error for http proxy")
	}
}

func TestParseUDPHeader(t *testing.T) {
	b := appendSocksAddr([]byte{0, 0, 0}, nil, "example.com", 443)
	b = append(b, "data"...)
	host, port, payload, err := parseUDPHeader(b)
	if err != nil || host != "example.com" || port != 443 || string(payload) != "data" {
		t.Fatalf("got %q %d %q %v", host, port, payload, err)
	}
	if _, _, _, err := parseUDPHeader([]byte{0, 0, 1, 1, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("fragmented datagram accepted")
	}
	if _, _, _, err := parseUDPHeader([]byte{0, 0, 0, 1, 1}); err == nil {
		t.Fatal("short header accepted")
	}
}
