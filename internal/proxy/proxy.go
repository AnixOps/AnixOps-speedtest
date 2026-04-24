package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func NewHTTPClient(proxyURL string, timeout time.Duration) (*http.Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(proxyURL))
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
	}

	switch scheme {
	case "socks5", "socks5h":
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if network != "tcp" {
				return nil, fmt.Errorf("unsupported network for socks5 proxy: %q", network)
			}
			return dialSOCKS5(ctx, dialer, parsed, addr)
		}
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
	case "":
		transport.DialContext = dialer.DialContext
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", scheme)
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

func DialTCP(ctx context.Context, proxyURL string, target string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	trimmed := strings.TrimSpace(proxyURL)
	if trimmed == "" {
		return dialer.DialContext(ctx, "tcp", target)
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	switch strings.ToLower(parsed.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5(ctx, dialer, parsed, target)
	case "http", "https":
		return dialHTTPConnect(ctx, dialer, parsed, target)
	default:
		return nil, fmt.Errorf("unsupported proxy scheme %q", parsed.Scheme)
	}
}

func dialSOCKS5(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	proxyAddr := hostPortForProxy(proxyURL)
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("connect socks5 proxy %q: %w", proxyAddr, err)
	}

	methods := []byte{0x05, 0x01, 0x00}
	if proxyURL.User != nil {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(methods); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}

	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth select: %w", err)
	}
	if sel[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("unexpected socks version %d", sel[0])
	}

	switch sel[1] {
	case 0x00: // no auth
	case 0x02: // user/pass
		if err := socks5UserPassAuth(conn, proxyURL); err != nil {
			conn.Close()
			return nil, err
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5 unsupported auth method %d", sel[1])
	}

	host, port, err := splitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}

	connectReq := []byte{0x05, 0x01, 0x00}
	ip := net.ParseIP(host)
	switch {
	case ip != nil && ip.To4() != nil:
		connectReq = append(connectReq, 0x01)
		connectReq = append(connectReq, ip.To4()...)
	case ip != nil && ip.To16() != nil:
		connectReq = append(connectReq, 0x04)
		connectReq = append(connectReq, ip.To16()...)
	default:
		if len(host) > 255 {
			conn.Close()
			return nil, fmt.Errorf("hostname too long")
		}
		connectReq = append(connectReq, 0x03, byte(len(host)))
		connectReq = append(connectReq, []byte(host)...)
	}
	connectReq = append(connectReq, byte(port>>8), byte(port))

	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect reply: %w", err)
	}
	if reply[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("unexpected socks version %d", reply[0])
	}
	if reply[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: code %d", reply[1])
	}

	// discard bound address
	switch reply[3] {
	case 0x01:
		io.CopyN(io.Discard, conn, 4+2)
	case 0x04:
		io.CopyN(io.Discard, conn, 16+2)
	case 0x03:
		lenByte := make([]byte, 1)
		io.ReadFull(conn, lenByte)
		io.CopyN(io.Discard, conn, int64(lenByte[0])+2)
	default:
		io.CopyN(io.Discard, conn, 2)
	}

	return conn, nil
}

func socks5UserPassAuth(conn net.Conn, proxyURL *url.URL) error {
	username := ""
	password := ""
	if proxyURL.User != nil {
		username = proxyURL.User.Username()
		password, _ = proxyURL.User.Password()
	}
	req := []byte{0x01, byte(len(username))}
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 auth write: %w", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fmt.Errorf("socks5 auth read: %w", err)
	}
	if resp[0] != 0x01 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth rejected")
	}
	return nil
}

func dialHTTPConnect(ctx context.Context, dialer *net.Dialer, proxyURL *url.URL, target string) (net.Conn, error) {
	addr := hostPortForProxy(proxyURL)
	var conn net.Conn
	var err error
	if proxyURL.Scheme == "https" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName: proxyURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("connect proxy %q: %w", addr, err)
	}

	connectReq := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(proxyURL.User.Username() + ":" + password))
		connectReq.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT read: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

func hostPortForProxy(proxyURL *url.URL) string {
	if _, _, err := net.SplitHostPort(proxyURL.Host); err == nil {
		return proxyURL.Host
	}
	defaultPort := "80"
	if proxyURL.Scheme == "https" {
		defaultPort = "443"
	}
	return net.JoinHostPort(proxyURL.Hostname(), defaultPort)
}

func splitHostPort(raw string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(raw)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return "", 0, err
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	return host, port, nil
}
