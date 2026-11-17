// Package proxytest is a minimal SOCKS5 server for tests: no auth, CONNECT and
// UDP ASSOCIATE (or ASSOCIATE refused with code 7 when NoUDP is set).
package proxytest

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
)

type Server struct {
	// URL is socks5://127.0.0.1:<port>.
	URL   string
	ln    net.Listener
	noUDP bool

	mu sync.Mutex
	// UDPDests records every destination a relayed datagram was sent to, as
	// written by the client ("host:port", hostname kept as is).
	UDPDests []string
}

// Start runs a server until the test ends.
func Start(t *testing.T, noUDP bool) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{URL: "socks5://" + ln.Addr().String(), ln: ln, noUDP: noUDP}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

// Dests returns a copy of UDPDests.
func (s *Server) Dests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.UDPDests...)
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, c, int64(hdr[1])); err != nil {
		return
	}
	_, _ = c.Write([]byte{5, 0})
	req := make([]byte, 3)
	if _, err := io.ReadFull(c, req); err != nil {
		return
	}
	host, port, err := readAddr(c)
	if err != nil {
		return
	}
	switch req[1] {
	case 1: // CONNECT
		up, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		defer up.Close()
		_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		go func() { _, _ = io.Copy(up, c) }()
		_, _ = io.Copy(c, up)
	case 3: // UDP ASSOCIATE
		if s.noUDP {
			_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
			return
		}
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return
		}
		defer func() { _ = relay.Close() }()
		// Reply with 0.0.0.0 so the client has to substitute the proxy host.
		rep := []byte{5, 0, 0, 1, 0, 0, 0, 0}
		rep = binary.BigEndian.AppendUint16(rep, uint16(relay.LocalAddr().(*net.UDPAddr).Port))
		_, _ = c.Write(rep)
		go s.relay(relay)
		_, _ = io.Copy(io.Discard, c) // association ends with the TCP connection
	default:
		_, _ = c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
	}
}

func (s *Server) relay(relay *net.UDPConn) {
	var client *net.UDPAddr
	buf := make([]byte, 65535)
	for {
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if client == nil || (from.IP.Equal(client.IP) && from.Port == client.Port) {
			client = from
			host, port, payload, ok := parseUDP(buf[:n])
			if !ok {
				continue
			}
			s.mu.Lock()
			s.UDPDests = append(s.UDPDests, net.JoinHostPort(host, strconv.Itoa(port)))
			s.mu.Unlock()
			dst, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				continue
			}
			_, _ = relay.WriteToUDP(payload, dst)
			continue
		}
		// From the remote: wrap and send back to the client.
		out := []byte{0, 0, 0, 1}
		out = append(out, from.IP.To4()...)
		out = binary.BigEndian.AppendUint16(out, uint16(from.Port))
		out = append(out, buf[:n]...)
		_, _ = relay.WriteToUDP(out, client)
	}
}

func readAddr(r io.Reader) (string, int, error) {
	a := make([]byte, 1)
	if _, err := io.ReadFull(r, a); err != nil {
		return "", 0, err
	}
	var host string
	switch a[0] {
	case 1, 4:
		n := 4
		if a[0] == 4 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(p)), nil
}

func parseUDP(b []byte) (string, int, []byte, bool) {
	if len(b) < 4 || b[2] != 0 {
		return "", 0, nil, false
	}
	off := 4
	var host string
	switch b[3] {
	case 1:
		if len(b) < off+6 {
			return "", 0, nil, false
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case 4:
		if len(b) < off+18 {
			return "", 0, nil, false
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	case 3:
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return "", 0, nil, false
		}
		host = string(b[off : off+l])
		off += l
	default:
		return "", 0, nil, false
	}
	return host, int(binary.BigEndian.Uint16(b[off:])), b[off+2:], true
}
