package chart

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anixops/speedtest/internal/ats"
	"github.com/anixops/speedtest/internal/checker"
	"github.com/anixops/speedtest/internal/probe"
)

// Render generates an HTML file with Chart.js charts visualizing speedtest results.
func Render(w io.Writer, results []probe.NodeResult, cert *ats.ATSCertificate) {
	// Legacy: RenderDenseTable is the new default format
	RenderDenseTable(w, results, cert)
}

// RenderDenseTable generates a dense table report styled like mespeed/mfca.
func RenderDenseTable(w io.Writer, results []probe.NodeResult, cert *ats.ATSCertificate) {
	if len(results) == 0 {
		fmt.Fprintln(w, "No results to report")
		return
	}

	now := time.Now().Format("2006-01-02 15:04:05")

	// Collect all unique streaming service names for columns
	serviceSet := map[string]struct{}{}
	for _, r := range results {
		for _, u := range r.Unlocks {
			serviceSet[u.Service] = struct{}{}
		}
	}
	services := make([]string, 0, len(serviceSet))
	for s := range serviceSet {
		services = append(services, s)
	}
	sort.Strings(services)

	// Compute summary stats
	var totalTested, totalOK, totalSpeedOK int
	var sumHTTP, sumTCP, sumSpeed float64
	for _, r := range results {
		totalTested++
		if r.Error == "" {
			totalOK++
		}
		if r.Speed != nil && r.Speed.Mbps > 0 {
			totalSpeedOK++
			sumSpeed += r.Speed.Mbps
		}
		if r.Latency != nil {
			if r.Latency.HTTPMs > 0 {
				sumHTTP += r.Latency.HTTPMs
			}
			if r.Latency.TCPMs > 0 {
				sumTCP += r.Latency.TCPMs
			}
		}
	}
	var avgHTTP, avgTCP, avgSpeed float64
	if totalOK > 0 {
		avgHTTP = sumHTTP / float64(totalOK)
		avgTCP = sumTCP / float64(totalOK)
	}
	if totalSpeedOK > 0 {
		avgSpeed = sumSpeed / float64(totalSpeedOK)
	}

	// Find max speed for color scaling
	maxSpeed := 0.0
	for _, r := range results {
		if r.Speed != nil && r.Speed.Mbps > maxSpeed {
			maxSpeed = r.Speed.Mbps
		}
	}

	fmt.Fprint(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AnixOps Speedtest</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 12px;
    background: #1a1a2e;
    color: #e0e0e0;
    padding: 8px;
  }
  h1 {
    font-size: 16px;
    color: #38bdf8;
    margin-bottom: 4px;
  }
  .summary-bar {
    background: #16213e;
    border: 1px solid #0f3460;
    border-radius: 4px;
    padding: 6px 12px;
    margin-bottom: 6px;
    display: flex;
    gap: 16px;
    font-size: 11px;
    color: #94a3b8;
  }
  .summary-bar span { color: #38bdf8; font-weight: 700; }
  .table-wrap {
    overflow-x: auto;
    border: 1px solid #0f3460;
    border-radius: 4px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    white-space: nowrap;
    font-size: 11px;
  }
  th, td {
    border: 1px solid #1a1a3e;
    padding: 3px 5px;
    text-align: center;
    min-width: 52px;
  }
  th {
    background: #0f3460;
    color: #e0e0e0;
    font-weight: 600;
    position: sticky;
    top: 0;
    z-index: 2;
  }
  th:first-child, td:first-child {
    position: sticky;
    left: 0;
    z-index: 1;
    background: #16213e;
    min-width: 36px;
  }
  th:nth-child(2), td:nth-child(2) {
    position: sticky;
    left: 36px;
    z-index: 1;
    background: #16213e;
    min-width: 100px;
    text-align: left;
  }
  th:nth-child(3), td:nth-child(3) {
    position: sticky;
    left: 136px;
    z-index: 1;
    background: #16213e;
    min-width: 50px;
  }
  tr:hover td { background: #1e2a4a; }
  .name-cell { text-align: left !important; max-width: 160px; overflow: hidden; text-overflow: ellipsis; }
  .yes { background: #1b5e20; color: #a5d6a7; }
  .no { background: #4a0000; color: #ef9a9a; }
  .partial { background: #e65100; color: #ffcc80; }
  .error-cell { background: #2a2a3e; color: #78909c; }
  .footer {
    font-size: 10px;
    color: #546e7a;
    margin-top: 6px;
    padding: 4px 8px;
  }
</style>
</head>
<body>
<h1>AnixOps Speedtest — 节点质量报告</h1>
<div class="summary-bar">
  节点总数: <span>`+strconv.Itoa(totalTested)+`</span> &nbsp;
  成功测试: <span>`+strconv.Itoa(totalOK)+`</span> &nbsp;
  平均HTTP延迟: <span>`+formatMs(avgHTTP)+`</span> &nbsp;
  平均TCP延迟: <span>`+formatMs(avgTCP)+`</span> &nbsp;
  平均速度: <span>`+formatSpeed(avgSpeed)+`</span>
</div>
<div class="table-wrap">
<table>
<thead><tr>
<th>#</th><th>节点名称</th><th>类型</th>
<th>HTTP延迟</th><th>TCP延迟</th><th>平均速度</th><th>最高速度</th>`)

	for _, svc := range services {
		fmt.Fprintf(w, "<th>%s</th>", escHTML(svc))
	}

	fmt.Fprint(w, `<th>IP风险</th><th>DNS地区</th><th>SSH 22</th>
</tr></thead>
<tbody>
`)

	for _, r := range results {
		fmt.Fprintf(w, `<tr>`)
		fmt.Fprintf(w, `<td>%d</td>`, r.Index+1)
		fmt.Fprintf(w, `<td class="name-cell">%s</td>`, escHTML(r.Name))
		fmt.Fprintf(w, `<td>%s</td>`, escHTML(r.Type))

		// HTTP latency
		httpMs := "-"
		if r.Latency != nil && r.Latency.HTTPMs > 0 {
			httpMs = fmt.Sprintf("%.0fms", r.Latency.HTTPMs)
		}
		fmt.Fprintf(w, `<td>%s</td>`, httpMs)

		// TCP latency
		tcpMs := "-"
		if r.Latency != nil && r.Latency.TCPMs > 0 {
			tcpMs = fmt.Sprintf("%.0fms", r.Latency.TCPMs)
		}
		fmt.Fprintf(w, `<td>%s</td>`, tcpMs)

		// Speed
		speedStr := "-"
		speedCellClass := ""
		if r.Error != "" {
			speedCellClass = "error-cell"
		} else if r.Speed != nil && r.Speed.Mbps > 0 {
			speedStr = formatSpeed(r.Speed.Mbps)
			speedCellClass = speedColorClass(r.Speed.Mbps, maxSpeed)
		}
		fmt.Fprintf(w, `<td class="%s">%s</td>`, speedCellClass, speedStr)

		// Max speed (same as avg for single-run)
		maxSpeedStr := speedStr
		if r.Speed != nil && r.Speed.Mbps > 0 {
			maxSpeedStr = formatSpeed(r.Speed.Mbps)
		}
		fmt.Fprintf(w, `<td class="%s">%s</td>`, speedCellClass, maxSpeedStr)

		// Streaming unlocks
		unlockMap := map[string]*checker.UnlockStatus{}
		for i := range r.Unlocks {
			u := &r.Unlocks[i]
			unlockMap[u.Service] = u
		}
		for _, svc := range services {
			u := unlockMap[svc]
			if u != nil {
				fmt.Fprintf(w, `<td class="%s">%s</td>`, unlockClass(u.Status), unlockLabel(u))
			} else {
				fmt.Fprintf(w, `<td class="error-cell">-</td>`)
			}
		}

		// IP Risk
		ipRisk := "-"
		if r.IPRisk != nil && r.IPRisk.RiskLevel != "" && r.IPRisk.RiskLevel != "error" {
			ipRisk = fmt.Sprintf("%d(%s)", int(r.IPRisk.RiskScore), r.IPRisk.RiskLevel)
		}
		fmt.Fprintf(w, `<td>%s</td>`, ipRisk)

		// DNS region
		dns := "-"
		if r.DNS != nil && r.DNS.Country != "" {
			dns = r.DNS.Country
		}
		fmt.Fprintf(w, `<td>%s</td>`, dns)

		// SSH
		ssh := "-"
		if r.SSH != nil {
			if r.SSH.Port22Open {
				ssh = "开放"
			} else {
				ssh = "关闭"
			}
		}
		fmt.Fprintf(w, `<td>%s</td>`, ssh)

		fmt.Fprintln(w, `</tr>`)
	}

	fmt.Fprintf(w, `</tbody></table></div>
<div class="footer">
  AnixOps Speedtest | 测试时间: %s | 共 %d 个节点
</div>
`, now, totalTested)

	if cert != nil {
		renderATSCertificate(w, cert, results)
	}

	fmt.Fprintf(w, `</body>
</html>
`)
}

func renderATSCertificate(w io.Writer, cert *ats.ATSCertificate, results []probe.NodeResult) {
	qrURL := ats.VerificationURL(cert.Hash)
	qrDataURI, _ := ats.QRCodePNGDataURI(qrURL, 100)

	// Embed canonical JSON for client-side verification (no HTML escaping, matching hash computation)
	resultsJSON := canonicalJSON(results)

	otsStatusClass := "ots-disabled"
	otsStatusText := "已禁用"
	switch cert.OTSStatus {
	case "confirmed":
		otsStatusClass = "ots-confirmed"
		otsStatusText = "已锚定"
	case "pending":
		otsStatusClass = "ots-pending"
		otsStatusText = "锚定中"
	}

	fmt.Fprintf(w, `<style>
  .ats-section {
    margin-top: 16px;
    border: 1px solid #0f3460;
    border-radius: 6px;
    background: #16213e;
    padding: 12px;
  }
  .ats-title {
    font-size: 14px;
    color: #38bdf8;
    margin-bottom: 8px;
    font-weight: 600;
  }
  .ats-grid {
    display: grid;
    grid-template-columns: 1fr 140px;
    gap: 12px;
    font-size: 11px;
  }
  .ats-fields .field {
    display: flex;
    gap: 8px;
    padding: 3px 0;
    color: #94a3b8;
  }
  .ats-fields .field-label { min-width: 100px; color: #64748b; }
  .ats-fields .field-value { color: #e0e0e0; font-family: "JetBrains Mono", "Fira Code", monospace; word-break: break-all; }
  .hash-display { font-size: 9px; color: #64748b; }
  .ats-qr { text-align: center; }
  .ats-qr img { border-radius: 4px; border: 2px solid #0f3460; max-width: 120px; }
  .ats-qr-label { font-size: 9px; color: #546e7a; margin-top: 4px; }
  .ots-confirmed { color: #4ade80; }
  .ots-pending { color: #fbbf24; }
  .ots-disabled { color: #64748b; }
  #verify-result {
    margin-top: 12px;
    padding: 8px 12px;
    border-radius: 4px;
    font-weight: 600;
    text-align: center;
    font-size: 12px;
    display: none;
  }
	.sig-display { font-size: 8px; color: #64748b; word-break: break-all; }
  .verify-ok { background: #1b5e20; color: #a5d6a7; }
  .verify-fail { background: #4a0000; color: #ef9a9a; }
</style>
<div class="ats-section">
  <div class="ats-title">防伪证书 | Certificate of Authenticity</div>
  <div class="ats-grid">
    <div class="ats-fields">
      <div class="field"><span class="field-label">防伪编号:</span><span class="field-value">%s</span></div>
      <div class="field"><span class="field-label">测试时间:</span><span class="field-value">%s UTC</span></div>
      <div class="field"><span class="field-label">工具版本:</span><span class="field-value">%s</span></div>
      <div class="field"><span class="field-label">区块链状态:</span><span class="field-value %s">%s</span></div>
      <div class="field"><span class="field-label">SHA-256:</span><span class="field-value hash-display">%s</span></div>
%s%s%s%s    </div>
    <div class="ats-qr">
      <img src="%s" alt="QR Code" width="100" height="100">
      <div class="ats-qr-label">扫码验证</div>
    </div>
  </div>
  <div id="verify-result"></div>
</div>
<div id="ats-data" style="display:none">%s</div>
<script>
(function(){
  var el = document.getElementById("ats-data");
  var embeddedHash = "%s";
  var embeddedSig = "%s";
  var embeddedPub = "%s";
  if(!el || !embeddedHash || !embeddedSig || !embeddedPub){ return; }
  var data = el.textContent.trim();
  if(!window.crypto || !window.crypto.subtle){
    showResult("浏览器不支持 Web Crypto API，请改用 speedtest verify 命令验证", false); return;
  }
  var enc = new TextEncoder();
  var dataBuf = enc.encode(data);
  // Step 1: check SHA-256 hash
  crypto.subtle.digest("SHA-256", dataBuf).then(function(hashBuf){
    var bytes = new Uint8Array(hashBuf);
    var hex = Array.from(bytes).map(function(b){ return b.toString(16).padStart(2,"0"); }).join("");
    if(hex !== embeddedHash){
      showResult("SHA-256 不匹配 — 数据已被篡改", false);
      return;
    }
    // Step 2: verify Ed25519 signature (Go signs the SHA-256 hash, not raw JSON)
    var sigBytes = hexToBytes(embeddedSig);
    var pubBytes = hexToBytes(embeddedPub);
    crypto.subtle.importKey("raw", pubBytes, {name:"Ed25519"}, false, ["verify"]).then(function(key){
      return crypto.subtle.verify({name:"Ed25519"}, key, sigBytes, hashBuf);
    }).then(function(ok){
      if(ok){ showResult("签名验证通过 | Ed25519 signature valid — 报告来源和完整性已确认", true); }
      else { showResult("签名无效 — 报告可能已被篡改", false); }
    }).catch(function(e){ showResult("Ed25519 验证失败: " + e.message, false); });
  }).catch(function(e){ showResult("验证失败: " + e.message, false); });
  function hexToBytes(hex){
    var arr = new Uint8Array(hex.length / 2);
    for(var i = 0; i < hex.length; i += 2){
      arr[i/2] = parseInt(hex.substr(i, 2), 16);
    }
    return arr;
  }
  function showResult(msg, ok){
    var r = document.getElementById("verify-result");
    if(!r) return;
    r.textContent = msg;
    r.className = ok ? "verify-ok" : "verify-fail";
    r.style.display = "block";
  }
})();
</script>
`,
		cert.AntiTamperID,
		cert.Timestamp.Format("2006-01-02 15:04:05"),
		cert.ToolVersion,
		otsStatusClass, otsStatusText,
		cert.Hash,
		signatureField(cert),
		publicKeyField(cert),
		mlDSASignatureField(cert),
		mlDSAPublicKeyField(cert),
		qrDataURI,
		escHTML(string(resultsJSON)),
		cert.Hash,
		cert.Signature,
		cert.PublicKey,
	)
}

func signatureField(cert *ats.ATSCertificate) string {
	if cert.Signature == "" {
		return ""
	}
	return fmt.Sprintf(`      <div class="field"><span class="field-label">数字签名:</span><span class="field-value sig-display">%s</span></div>
`, cert.Signature)
}

func publicKeyField(cert *ats.ATSCertificate) string {
	if cert.PublicKey == "" {
		return ""
	}
	return fmt.Sprintf(`      <div class="field"><span class="field-label">Ed25519公钥:</span><span class="field-value hash-display">%s</span></div>
`, cert.PublicKey)
}

func mlDSASignatureField(cert *ats.ATSCertificate) string {
	if cert.MLDSASignature == "" {
		return ""
	}
	return fmt.Sprintf(`      <div class="field"><span class="field-label">PQC签名:</span><span class="field-value sig-display">%s</span></div>
`, cert.MLDSASignature)
}

func mlDSAPublicKeyField(cert *ats.ATSCertificate) string {
	if cert.MLDSAPublicKey == "" {
		return ""
	}
	return fmt.Sprintf(`      <div class="field"><span class="field-label">ML-DSA-87公钥:</span><span class="field-value hash-display">%s</span></div>
`, cert.MLDSAPublicKey)
}

func unlockClass(status string) string {
	switch status {
	case "yes":
		return "yes"
	case "partial":
		return "partial"
	case "no":
		return "no"
	default:
		return "error-cell"
	}
}

func unlockLabel(u *checker.UnlockStatus) string {
	if u == nil {
		return "-"
	}
	switch u.Status {
	case "yes":
		if u.Region != "" {
			return fmt.Sprintf("解锁(%s)", u.Region)
		}
		return "解锁"
	case "partial":
		return "部分"
	case "no":
		return "未解锁"
	default:
		return "错误"
	}
}

func speedColorClass(mbps, max float64) string {
	if max <= 0 {
		return ""
	}
	ratio := mbps / max
	switch {
	case ratio >= 0.75:
		return "yes" // high speed = green (good)
	case ratio >= 0.4:
		return "partial" // medium = orange
	default:
		return "no" // low = red
	}
}

func formatMs(ms float64) string {
	if ms <= 0 {
		return "-"
	}
	if ms < 1 {
		return fmt.Sprintf("%.1fms", ms)
	}
	return fmt.Sprintf("%.0fms", ms)
}

func formatSpeed(mbps float64) string {
	if mbps <= 0 {
		return "-"
	}
	if mbps >= 1000 {
		return fmt.Sprintf("%.1fG", mbps/1000)
	}
	return fmt.Sprintf("%.1fM", mbps)
}

func escHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	return s
}

// canonicalJSON produces compact JSON without HTML escaping, matching ComputeCanonicalHash.
func canonicalJSON(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimSuffix(buf.String(), "\n")
}
