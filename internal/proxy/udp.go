package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUDPUnsupported means the SOCKS5 server answered UDP ASSOCIATE with
// "command not supported" (reply code 7): the kernel has no UDP relay, so any
// UDP-based probe (HTTP/3, QUIC) cannot run through it.
var ErrUDPUnsupported = errors.New("socks5 server does not support UDP ASSOCIATE")

// Addr is a SOCKS5 destination that may be a hostname. Passing it to WriteTo
// lets the proxy resolve the name (remote DNS), like socks5h for TCP.
type Addr struct {
	Host string
	Port int
}

func (a Addr) Network() string { return "udp" }
func (a Addr) String() string  { return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) }

// ParseAddr splits "host:port" into an Addr.
func ParseAddr(hostport string) (Addr, error) {
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return Addr{}, err
	}
	return Addr{Host: host, Port: port}, nil
}

// UDPConn is a net.PacketConn relayed through a SOCKS5 UDP ASSOCIATE (RFC 1928
// §7). The TCP control connection stays open for the lifetime of the
// association; closing the UDPConn closes both. Datagrams read from the relay
// are reported with the source address the relay put in their header (a QUIC
// client does not check it, so a hostname destination answering from its IP is
// fine).
type UDPConn struct {
	ctrl      net.Conn
	udp       *net.UDPConn
	relay     *net.UDPAddr
	closeOnce sync.Once
}

// ListenUDP opens a UDP association through a socks5:// or socks5h:// proxy.
func ListenUDP(ctx context.Context, proxyURL string, timeout time.Duration) (*UDPConn, error) {
	parsed, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "socks5", "socks5h":
	default:
		return nil, fmt.Errorf("UDP needs a socks5 proxy, got %q", parsed.Scheme)
	}

	dialer := &net.Dialer{Timeout: timeout}
	proxyAddr := hostPortForProxy(parsed)
	ctrl, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect socks5 proxy %q: %w", proxyAddr, err)
	}
	if timeout > 0 {
		_ = ctrl.SetDeadline(time.Now().Add(timeout))
	}
	if err := socks5Handshake(ctrl, parsed); err != nil {
		ctrl.Close()
		return nil, err
	}

	// Local UDP socket first, so the ASSOCIATE request can name the client
	// address. Many servers ignore it; 0.0.0.0:0 would also be legal.
	var laddr *net.UDPAddr
	if proxyIsLoopback(ctrl) {
		laddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		ctrl.Close()
		return nil, fmt.Errorf("open local UDP socket: %w", err)
	}

	req := []byte{0x05, 0x03, 0x00}
	req = appendSocksAddr(req, local.LocalAddr().(*net.UDPAddr).IP, "", local.LocalAddr().(*net.UDPAddr).Port)
	if _, err := ctrl.Write(req); err != nil {
		ctrl.Close()
		local.Close()
		return nil, fmt.Errorf("socks5 udp associate: %w", err)
	}
	head := make([]byte, 3)
	if _, err := io.ReadFull(ctrl, head); err != nil {
		ctrl.Close()
		local.Close()
		return nil, fmt.Errorf("socks5 udp associate reply: %w", err)
	}
	if head[0] != 0x05 {
		ctrl.Close()
		local.Close()
		return nil, fmt.Errorf("unexpected socks version %d", head[0])
	}
	if head[1] != 0x00 {
		ctrl.Close()
		local.Close()
		if head[1] == 0x07 {
			return nil, ErrUDPUnsupported
		}
		return nil, fmt.Errorf("socks5 udp associate failed: code %d", head[1])
	}
	bindHost, bindPort, err := readSocksAddr(ctrl)
	if err != nil {
		ctrl.Close()
		local.Close()
		return nil, fmt.Errorf("read socks5 relay address: %w", err)
	}
	_ = ctrl.SetDeadline(time.Time{})

	relayIP := net.ParseIP(bindHost)
	if relayIP == nil || relayIP.IsUnspecified() {
		// "0.0.0.0" (or a name) means "the address you reached me on".
		relayIP = ctrl.RemoteAddr().(*net.TCPAddr).IP
	}
	c := &UDPConn{ctrl: ctrl, udp: local, relay: &net.UDPAddr{IP: relayIP, Port: bindPort}}
	// The association lives as long as the control connection; when the server
	// drops it, unblock any reader instead of hanging until the deadline.
	go func() {
		_, _ = io.Copy(io.Discard, ctrl)
		_ = local.Close()
	}()
	return c, nil
}

func proxyIsLoopback(ctrl net.Conn) bool {
	if a, ok := ctrl.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.IsLoopback()
	}
	return false
}

// socks5Handshake runs the greeting and optional user/pass auth.
func socks5Handshake(conn net.Conn, proxyURL *url.URL) error {
	methods := []byte{0x05, 0x01, 0x00}
	if proxyURL.User != nil {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(methods); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return fmt.Errorf("socks5 auth select: %w", err)
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("unexpected socks version %d", sel[0])
	}
	switch sel[1] {
	case 0x00:
		return nil
	case 0x02:
		return socks5UserPassAuth(conn, proxyURL)
	default:
		return fmt.Errorf("socks5 unsupported auth method %d", sel[1])
	}
}

// appendSocksAddr appends ATYP + address + port. host wins over ip when set
// and is not an IP literal.
func appendSocksAddr(b []byte, ip net.IP, host string, port int) []byte {
	if host != "" {
		if parsed := net.ParseIP(host); parsed != nil {
			ip = parsed
		} else {
			b = append(b, 0x03, byte(len(host)))
			b = append(b, host...)
			return binary.BigEndian.AppendUint16(b, uint16(port))
		}
	}
	if v4 := ip.To4(); v4 != nil {
		b = append(b, 0x01)
		b = append(b, v4...)
	} else if v6 := ip.To16(); v6 != nil {
		b = append(b, 0x04)
		b = append(b, v6...)
	} else {
		b = append(b, 0x01, 0, 0, 0, 0)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port))
}

// readSocksAddr reads ATYP + address + port from a stream.
func readSocksAddr(r io.Reader) (string, int, error) {
	atyp := make([]byte, 1)
	if _, err := io.ReadFull(r, atyp); err != nil {
		return "", 0, err
	}
	var host string
	switch atyp[0] {
	case 0x01, 0x04:
		n := 4
		if atyp[0] == 0x04 {
			n = 16
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = net.IP(ip).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		return "", 0, fmt.Errorf("unknown socks5 address type %d", atyp[0])
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(r, p); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(p)), nil
}

// parseUDPHeader splits a relayed datagram into source address and payload.
func parseUDPHeader(b []byte) (string, int, []byte, error) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 {
		return "", 0, nil, errors.New("short or malformed socks5 udp header")
	}
	if b[2] != 0 {
		return "", 0, nil, errors.New("fragmented socks5 udp datagram")
	}
	off := 4
	var host string
	switch b[3] {
	case 0x01:
		if len(b) < off+4+2 {
			return "", 0, nil, errors.New("short socks5 udp header")
		}
		host = net.IP(b[off : off+4]).String()
		off += 4
	case 0x04:
		if len(b) < off+16+2 {
			return "", 0, nil, errors.New("short socks5 udp header")
		}
		host = net.IP(b[off : off+16]).String()
		off += 16
	case 0x03:
		if len(b) < off+1 {
			return "", 0, nil, errors.New("short socks5 udp header")
		}
		l := int(b[off])
		off++
		if len(b) < off+l+2 {
			return "", 0, nil, errors.New("short socks5 udp header")
		}
		host = string(b[off : off+l])
		off += l
	default:
		return "", 0, nil, fmt.Errorf("unknown socks5 address type %d", b[3])
	}
	port := int(binary.BigEndian.Uint16(b[off : off+2]))
	return host, port, b[off+2:], nil
}

// ReadFrom reads one relayed datagram. Datagrams that do not come from the
// relay, or that are malformed, are dropped.
func (c *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+262)
	for {
		n, from, err := c.udp.ReadFromUDP(buf)
		if err != nil {
			return 0, nil, err
		}
		if !from.IP.Equal(c.relay.IP) || from.Port != c.relay.Port {
			continue
		}
		host, port, payload, err := parseUDPHeader(buf[:n])
		if err != nil {
			continue
		}
		return copy(p, payload), sourceAddr(host, port), nil
	}
}

func sourceAddr(host string, port int) net.Addr {
	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}
	}
	return Addr{Host: host, Port: port}
}

// WriteTo sends p to addr through the relay. addr may be a *net.UDPAddr or an
// Addr carrying a hostname.
func (c *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var host string
	var ip net.IP
	var port int
	switch a := addr.(type) {
	case *net.UDPAddr:
		ip, port = a.IP, a.Port
	case Addr:
		host, port = a.Host, a.Port
	default:
		parsed, err := ParseAddr(addr.String())
		if err != nil {
			return 0, err
		}
		host, port = parsed.Host, parsed.Port
	}
	b := make([]byte, 0, len(p)+262)
	b = append(b, 0, 0, 0)
	b = appendSocksAddr(b, ip, host, port)
	b = append(b, p...)
	if _, err := c.udp.WriteToUDP(b, c.relay); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the association.
func (c *UDPConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.udp.Close()
		_ = c.ctrl.Close()
	})
	return err
}

func (c *UDPConn) LocalAddr() net.Addr                { return c.udp.LocalAddr() }
func (c *UDPConn) SetDeadline(t time.Time) error      { return c.udp.SetDeadline(t) }
func (c *UDPConn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *UDPConn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// SetReadBuffer / SetWriteBuffer let quic-go grow the socket buffers.
func (c *UDPConn) SetReadBuffer(n int) error  { return c.udp.SetReadBuffer(n) }
func (c *UDPConn) SetWriteBuffer(n int) error { return c.udp.SetWriteBuffer(n) }
