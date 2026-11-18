package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/anixops/speedtest/internal/proxy/proxytest"
)

// startH3 serves 204 over HTTP/3 on 127.0.0.1 with a self-signed cert for
// "localhost", and trusts it for MeasureH3.
func startH3(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	h3RootCAs = pool
	t.Cleanup(func() { h3RootCAs = nil })

	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 3 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Close(); pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestMeasureH3ThroughSocksUDP(t *testing.T) {
	port := startH3(t)
	socks := proxytest.Start(t, false)
	target := "https://localhost:" + strconv.Itoa(port) + "/generate_204"

	res, ev := MeasureH3(context.Background(), socks.URL, target, 3*time.Second, 3)
	if !res.OK() || res.Error != "" {
		t.Fatalf("h3 failed: %+v ev=%+v", res, ev)
	}
	if res.Status != http.StatusNoContent || res.Samples != 3 || res.LossPct != 0 {
		t.Fatalf("unexpected result %+v", res)
	}
	if res.HandshakeMs <= 0 || res.HandshakeMs > res.Ms {
		t.Fatalf("handshake %.1f should be >0 and <= total %.1f", res.HandshakeMs, res.Ms)
	}
	if len(ev) != 1 || ev[0].Test != "latency_h3" {
		t.Fatalf("evidence %+v", ev)
	}
	// The hostname reaches the proxy unresolved (remote DNS).
	if d := socks.Dests(); len(d) == 0 || d[0] != "localhost:"+strconv.Itoa(port) {
		t.Fatalf("proxy saw %v", d)
	}
}

func TestMeasureH3Unsupported(t *testing.T) {
	socks := proxytest.Start(t, true)
	res, _ := MeasureH3(context.Background(), socks.URL, DefaultH3Target, time.Second, 3)
	if !res.Unsupported || res.OK() || res.Samples != 0 {
		t.Fatalf("want unsupported with no samples, got %+v", res)
	}
}

func TestMeasureH3NoAnswerIsLoss(t *testing.T) {
	// UDP relay works but nothing listens at the target: every sample times out.
	socks := proxytest.Start(t, false)
	dead, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()
	target := "https://localhost:" + strconv.Itoa(port) + "/"
	res, _ := MeasureH3(context.Background(), socks.URL, target, 500*time.Millisecond, 2)
	if res.OK() || res.LossPct != 100 || res.Samples != 2 || res.Error == "" {
		t.Fatalf("want 100%% loss, got %+v", res)
	}
}
