package sub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Node struct {
	Protocol            string
	Server              string
	Port                string
	Name                string
	UUID                string
	Password            string
	Method              string
	Network             string
	Host                string
	Path                string
	TLS                 string
	SNI                 string
	RealityPublicKey    string
	RealityShortID      string
	ClientFingerprint   string
	Flow                string
}

func FetchAndParse(ctx context.Context, subscriptionURL string, userAgent string) ([]Node, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subscriptionURL, nil)
	if err != nil {
		return nil, err
	}
	ua := strings.TrimSpace(userAgent)
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	req.Header.Set("Accept", "*/*")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription fetch: status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(body))

	// 1. Try Clash YAML first (subscription may return Clash config directly)
	if nodes := parseClashYAML(content); len(nodes) > 0 {
		return nodes, nil
	}

	// 2. Try share link format (vmess://, vless://, etc.)
	nodes := parseSubscription(content)
	if len(nodes) > 0 {
		return nodes, nil
	}

	// 3. Try base64 decode then share links
	if decoded, derr := decodeBase64String(content); derr == nil {
		// Try Clash YAML from decoded content
		if nodes := parseClashYAML(strings.TrimSpace(string(decoded))); len(nodes) > 0 {
			return nodes, nil
		}
		nodes = parseSubscription(strings.TrimSpace(string(decoded)))
		if len(nodes) > 0 {
			return nodes, nil
		}
	}

	return nil, errors.New("subscription: no nodes parsed")
}

func parseSubscription(content string) []Node {
	if content == "" {
		return nil
	}
	content = strings.ReplaceAll(content, "\r\n", "\n")
	lines := strings.Split(content, "\n")
	var nodes []Node
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		node, err := parseLine(line)
		if err != nil {
			continue
		}
		nodes = append(nodes, node)
	}
	return nodes
}

func parseClashYAML(content string) []Node {
	var raw struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return nil
	}
	if len(raw.Proxies) == 0 {
		return nil
	}

	var nodes []Node
	for _, p := range raw.Proxies {
		node := parseClashProxy(p)
		if node.Name != "" && node.Server != "" && node.Port != "" {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func parseClashProxy(p map[string]any) Node {
	getStr := func(key string) string {
		v, ok := p[key]
		if !ok {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}
	getInt := func(key string) string {
		v, ok := p[key]
		if !ok {
			return ""
		}
		switch val := v.(type) {
		case int:
			return strconv.Itoa(val)
		case float64:
			return strconv.Itoa(int(val))
		default:
			return fmt.Sprintf("%v", v)
		}
	}
	getBool := func(key string) bool {
		v, ok := p[key]
		if !ok {
			return false
		}
		b, _ := v.(bool)
		return b
	}

	proto := strings.ToLower(getStr("type"))
	node := Node{
		Protocol: proto,
		Server:   getStr("server"),
		Port:     getInt("port"),
		Name:     getStr("name"),
		UUID:     getStr("uuid"),
		Password: getStr("password"),
		Method:   getStr("cipher"),
		Network:  getStr("network"),
		SNI:      getStr("servername"),
		TLS:      "",
	}

	if getBool("tls") {
		node.TLS = "true"
	}

	// WS options
	if ws, ok := p["ws-opts"].(map[string]any); ok {
		if path, ok := ws["path"].(string); ok {
			node.Path = path
		}
		if headers, ok := ws["headers"].(map[string]any); ok {
			if host, ok := headers["Host"].(string); ok {
				node.Host = host
			}
		}
	}

	// Reality options
	if reality, ok := p["reality-opts"].(map[string]any); ok {
		if pk, ok := reality["public-key"].(string); ok {
			node.RealityPublicKey = pk
		}
		if sid, ok := reality["short-id"].(string); ok {
			node.RealityShortID = sid
		}
	}

	// Client fingerprint
	if fp := getStr("client-fingerprint"); fp != "" {
		node.ClientFingerprint = fp
	}

	// Flow for vless/trojan
	if flow := getStr("flow"); flow != "" {
		node.Flow = flow
	}

	if node.Network == "" {
		node.Network = "tcp"
	}

	return node
}

func parseLine(raw string) (Node, error) {
	line := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(strings.ToLower(line), "vmess://"):
		return parseVmess(line)
	case strings.HasPrefix(strings.ToLower(line), "vless://"):
		return parseVless(line)
	case strings.HasPrefix(strings.ToLower(line), "trojan://"):
		return parseTrojan(line)
	case strings.HasPrefix(strings.ToLower(line), "ss://"):
		return parseShadowsocks(line)
	default:
		return Node{}, errors.New("unsupported scheme")
	}
}

func parseVmess(line string) (Node, error) {
	payload := strings.TrimSpace(line[len("vmess://"):])
	if payload == "" {
		return Node{}, errors.New("empty vmess payload")
	}
	decoded, err := decodeBase64String(payload)
	if err != nil {
		return Node{}, err
	}

	type vmessPayload struct {
		PS       string `json:"ps"`
		Add      string `json:"add"`
		Port     string `json:"port"`
		ID       string `json:"id"`
		Security string `json:"security"`
		Scy      string `json:"scy"`
		Net      string `json:"net"`
		Type     string `json:"type"`
		Host     string `json:"host"`
		Path     string `json:"path"`
		TLS      string `json:"tls"`
		SNI      string `json:"sni"`
	}

	var p vmessPayload
	if err := json.Unmarshal(decoded, &p); err != nil {
		return Node{}, err
	}

	method := p.Security
	if method == "" {
		method = p.Scy
	}

	return Node{
		Protocol: "vmess",
		Server:   p.Add,
		Port:     p.Port,
		Name:     p.PS,
		UUID:     p.ID,
		Method:   method,
		Network:  p.Net,
		Host:     p.Host,
		Path:     p.Path,
		TLS:      p.TLS,
		SNI:      p.SNI,
	}, nil
}

func parseVless(line string) (Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return Node{}, err
	}
	if u.User == nil {
		return Node{}, errors.New("vless: missing user info")
	}
	node := Node{
		Protocol: "vless",
		Server:   u.Hostname(),
		Port:     u.Port(),
		UUID:     u.User.Username(),
		Name:     decodeFragment(u.Fragment),
	}
	q := u.Query()
	if node.Network = q.Get("type"); node.Network == "" {
		node.Network = q.Get("network")
	}
	node.Path = q.Get("path")
	node.Host = q.Get("host")
	node.TLS = firstNonEmpty(q.Get("security"), q.Get("tls"))
	node.SNI = q.Get("sni")
	return node, nil
}

func parseTrojan(line string) (Node, error) {
	u, err := url.Parse(line)
	if err != nil {
		return Node{}, err
	}
	if u.User == nil {
		return Node{}, errors.New("trojan: missing user info")
	}
	node := Node{
		Protocol: "trojan",
		Server:   u.Hostname(),
		Port:     u.Port(),
		Password: u.User.Username(),
		Name:     decodeFragment(u.Fragment),
	}
	q := u.Query()
	node.Network = q.Get("type")
	node.Path = q.Get("path")
	node.Host = firstNonEmpty(q.Get("host"), q.Get("peer"))
	node.TLS = firstNonEmpty(q.Get("security"), q.Get("tls"))
	node.SNI = q.Get("sni")
	return node, nil
}

func parseShadowsocks(line string) (Node, error) {
	raw := strings.TrimSpace(line[len("ss://"):])
	if raw == "" {
		return Node{}, errors.New("empty ss payload")
	}

	name := ""
	if idx := strings.Index(raw, "#"); idx >= 0 {
		if decoded, err := url.PathUnescape(raw[idx+1:]); err == nil {
			name = decoded
		}
		raw = raw[:idx]
	}
	if qidx := strings.Index(raw, "?"); qidx >= 0 {
		raw = raw[:qidx]
	}

	var method, password, server, port string

	if atIdx := strings.Index(raw, "@"); atIdx >= 0 {
		left := raw[:atIdx]
		right := raw[atIdx+1:]
		if strings.Contains(left, ":") {
			parts := strings.SplitN(left, ":", 2)
			method = parts[0]
			password = parts[1]
		} else {
			decoded, err := decodeBase64String(left)
			if err != nil {
				return Node{}, err
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 {
				return Node{}, errors.New("invalid ss credentials")
			}
			method = parts[0]
			password = parts[1]
		}
		var err error
		server, port, err = net.SplitHostPort(right)
		if err != nil {
			return Node{}, err
		}
	} else {
		decoded, err := decodeBase64String(raw)
		if err != nil {
			return Node{}, err
		}
		parts := strings.SplitN(string(decoded), "@", 2)
		if len(parts) != 2 {
			return Node{}, errors.New("invalid ss format")
		}
		cred := strings.SplitN(parts[0], ":", 2)
		if len(cred) != 2 {
			return Node{}, errors.New("invalid ss credentials")
		}
		method = cred[0]
		password = cred[1]
		var err2 error
		server, port, err2 = net.SplitHostPort(parts[1])
		if err2 != nil {
			return Node{}, err2
		}
	}

	return Node{
		Protocol: "ss",
		Server:   server,
		Port:     port,
		Name:     name,
		Password: password,
		Method:   method,
	}, nil
}

func decodeFragment(value string) string {
	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func decodeBase64String(raw string) ([]byte, error) {
	cleaned := removeWhitespace(raw)
	if cleaned == "" {
		return nil, errors.New("empty base64 string")
	}
	if mod := len(cleaned) % 4; mod != 0 {
		cleaned += strings.Repeat("=", 4-mod)
	}
	encoders := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encoders {
		if data, err := enc.DecodeString(cleaned); err == nil {
			return data, nil
		} else {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("base64 decode failed: %w", lastErr)
}

func removeWhitespace(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		switch r {
		case '\n', '\r', '\t', ' ':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
