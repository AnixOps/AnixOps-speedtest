package clash

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Proxy struct {
	Name       string            `yaml:"name"`
	Type       string            `yaml:"type"`
	Server     string            `yaml:"server"`
	Port       int               `yaml:"port"`
	Password   string            `yaml:"password,omitempty"`
	UUID       string            `yaml:"uuid,omitempty"`
	AlterID    int               `yaml:"alterId,omitempty"`
	Cipher     string            `yaml:"cipher,omitempty"`
	Flow       string            `yaml:"flow,omitempty"`
	Network    string            `yaml:"network,omitempty"`
	TLS        bool              `yaml:"tls,omitempty"`
	SNI        string            `yaml:"sni,omitempty"`
	SkipCertVerify bool          `yaml:"skip-cert-verify,omitempty"`
	WSOpts     *WSOptions        `yaml:"ws-opts,omitempty"`
	H2Opts     *H2Options        `yaml:"h2-opts,omitempty"`
	GRPCOpts   *GRPCOptions      `yaml:"grpc-opts,omitempty"`
	RealityOpts *RealityOptions  `yaml:"reality-opts,omitempty"`
	Plugin     string            `yaml:"plugin,omitempty"`
	PluginOpts map[string]any    `yaml:"plugin-opts,omitempty"`
	UDP        bool              `yaml:"udp,omitempty"`
	ClientFingerprint string    `yaml:"client-fingerprint,omitempty"`
	Extra      map[string]any    `yaml:",inline"`
}

type WSOptions struct {
	Path    string            `yaml:"path,omitempty"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type H2Options struct {
	Host []string `yaml:"host,omitempty"`
	Path string   `yaml:"path,omitempty"`
}

type GRPCOptions struct {
	ServiceName string `yaml:"grpc-service-name,omitempty"`
}

type RealityOptions struct {
	PublicKey string `yaml:"public-key,omitempty"`
	ShortID   string `yaml:"short-id,omitempty"`
}

type Config struct {
	Proxies []Proxy `yaml:"proxies"`
}

func ParseFile(path string) ([]Proxy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read clash config: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) ([]Proxy, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse clash config: %w", err)
	}
	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("no proxies found in clash config")
	}

	var valid []Proxy
	for _, p := range cfg.Proxies {
		if p.Name == "" || p.Server == "" || p.Port <= 0 {
			continue
		}
		p.Type = normalizeType(p.Type)
		valid = append(valid, p)
	}
	return valid, nil
}

func normalizeType(t string) string {
	switch t {
	case "ss":
		return "shadowsocks"
	case "ssr":
		return "shadowsocksr"
	default:
		return t
	}
}
