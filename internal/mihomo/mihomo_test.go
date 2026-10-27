package mihomo

import (
	"testing"

	"github.com/anixops/speedtest/internal/kernel"
)

func TestSelectAssetPrefersCompatibleGz(t *testing.T) {
	assets := []kernel.Asset{
		{Name: "mihomo-linux-amd64-v1.19.0.gz"},
		{Name: "mihomo-linux-amd64-compatible-v1.19.0.gz"},
		{Name: "mihomo-linux-arm64-v1.19.0.gz"},
		{Name: "mihomo-windows-amd64-compatible-v1.19.0.zip"},
	}
	a, ok := selectAsset(assets, "linux", "amd64")
	if !ok || a.Name != "mihomo-linux-amd64-compatible-v1.19.0.gz" {
		t.Fatalf("got %v %v", a, ok)
	}
	if a, ok := selectAsset(assets, "windows", "amd64"); !ok || a.Name != "mihomo-windows-amd64-compatible-v1.19.0.zip" {
		t.Fatalf("windows: %v %v", a, ok)
	}
	if _, ok := selectAsset(assets, "plan9", "amd64"); ok {
		t.Fatal("unsupported platform must not match")
	}
}
