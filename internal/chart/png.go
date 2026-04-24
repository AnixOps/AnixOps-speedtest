package chart

import (
	_ "embed"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"sort"

	"github.com/anixops/speedtest/internal/ats"
	"github.com/anixops/speedtest/internal/checker"
	"github.com/anixops/speedtest/internal/probe"
	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/math/fixed"
)

//go:embed fonts/NotoSansSC-Regular.ttf
var fontData []byte

// col defines a column in the dense table.
type col struct {
	header string
	width  int
	data   func(probe.NodeResult) string
	fg     func(probe.NodeResult) color.Color
	bg     func(probe.NodeResult) color.Color
}

var (
	titleFace  font.Face
	bodyFace   font.Face
	titleSize  = 16.0
	bodySize   = 13.0
)

func init() {
	tt, err := opentype.Parse(fontData)
	if err != nil {
		panic("failed to parse font: " + err.Error())
	}
	titleFace, err = opentype.NewFace(tt, &opentype.FaceOptions{Size: titleSize, DPI: 96})
	if err != nil {
		panic("failed to create title face: " + err.Error())
	}
	bodyFace, err = opentype.NewFace(tt, &opentype.FaceOptions{Size: bodySize, DPI: 96})
	if err != nil {
		panic("failed to create body face: " + err.Error())
	}
}

// GeneratePNG creates a PNG image report with a dense colored table.
func GeneratePNG(path string, results []probe.NodeResult, cert *ats.ATSCertificate) error {
	if len(results) == 0 {
		return nil
	}

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

	var totalTested, totalOK int
	var sumHTTP, sumTCP, sumSpeed float64
	var speedCount int
	for _, r := range results {
		totalTested++
		if r.Error == "" {
			totalOK++
		}
		if r.Latency != nil {
			if r.Latency.HTTPMs > 0 {
				sumHTTP += r.Latency.HTTPMs
			}
			if r.Latency.TCPMs > 0 {
				sumTCP += r.Latency.TCPMs
			}
		}
		if r.Speed != nil && r.Speed.Mbps > 0 {
			speedCount++
			sumSpeed += r.Speed.Mbps
		}
	}
	var avgHTTP, avgTCP, avgSpeed float64
	if totalOK > 0 {
		avgHTTP = sumHTTP / float64(totalOK)
		avgTCP = sumTCP / float64(totalOK)
	}
	if speedCount > 0 {
		avgSpeed = sumSpeed / float64(speedCount)
	}

	maxSpeed := 0.0
	for _, r := range results {
		if r.Speed != nil && r.Speed.Mbps > maxSpeed {
			maxSpeed = r.Speed.Mbps
		}
	}

	// Colors
	bgDark := color.RGBA{22, 33, 62, 255}
	fgNormal := color.RGBA{224, 224, 224, 255}
	fgMuted := color.RGBA{120, 144, 156, 255}
	bgError := color.RGBA{42, 42, 62, 255}
	bgHeader := color.RGBA{15, 52, 96, 255}
	fgHeader := color.RGBA{224, 224, 224, 255}
	borderColor := color.RGBA{40, 40, 70, 255}

	cst := func(c color.Color) func(probe.NodeResult) color.Color {
		return func(probe.NodeResult) color.Color { return c }
	}

	fixedCols := []col{
		{"#", 30,
			func(r probe.NodeResult) string { return fmt.Sprintf("%d", r.Index+1) },
			cst(fgNormal), cst(bgDark)},
		{"Node Name", 200,
			func(r probe.NodeResult) string { return trunc(r.Name, 190) },
			cst(fgNormal), cst(bgDark)},
		{"Type", 55,
			func(r probe.NodeResult) string { return r.Type },
			cst(fgNormal), cst(bgDark)},
		{"HTTP", 60,
			func(r probe.NodeResult) string {
				if r.Latency != nil && r.Latency.HTTPMs > 0 {
					return fmt.Sprintf("%.0fms", r.Latency.HTTPMs)
				}
				return "-"
			}, cst(fgNormal), cst(bgDark)},
		{"TCP", 55,
			func(r probe.NodeResult) string {
				if r.Latency != nil && r.Latency.TCPMs > 0 {
					return fmt.Sprintf("%.1fms", r.Latency.TCPMs)
				}
				return "-"
			}, cst(fgNormal), cst(bgDark)},
		{"Speed", 70,
			func(r probe.NodeResult) string {
				if r.Error == "" && r.Speed != nil && r.Speed.Mbps > 0 {
					return fmt.Sprintf("%.1fM", r.Speed.Mbps)
				}
				return "-"
			},
			func(r probe.NodeResult) color.Color {
				if r.Error == "" && r.Speed != nil && r.Speed.Mbps > 0 {
					return speedFG(r.Speed.Mbps, maxSpeed)
				}
				return fgMuted
			},
			func(r probe.NodeResult) color.Color {
				if r.Error == "" && r.Speed != nil && r.Speed.Mbps > 0 {
					return speedBG(r.Speed.Mbps, maxSpeed)
				}
				return bgError
			},
		},
	}

	streamCols := make([]col, len(services))
	for i, svc := range services {
		svc := svc
		w := len(svc) * 10
		if w < 70 {
			w = 70
		}
		streamCols[i] = col{
			header: svc,
			width:  w,
			data: func(r probe.NodeResult) string {
				for _, u := range r.Unlocks {
					if u.Service == svc {
						return unlockLabelStr(u)
					}
				}
				return "-"
			},
			fg: func(r probe.NodeResult) color.Color {
				for _, u := range r.Unlocks {
					if u.Service == svc {
						return unlockFG(u.Status)
					}
				}
				return fgMuted
			},
			bg: func(r probe.NodeResult) color.Color {
				for _, u := range r.Unlocks {
					if u.Service == svc {
						return unlockBG(u.Status)
					}
				}
				return bgError
			},
		}
	}

	trailCols := []col{
		{"IP Risk", 75,
			func(r probe.NodeResult) string {
				if r.IPRisk != nil && r.IPRisk.RiskLevel != "" && r.IPRisk.RiskLevel != "error" {
					return fmt.Sprintf("%d(%s)", int(r.IPRisk.RiskScore), r.IPRisk.RiskLevel)
				}
				return "-"
			}, cst(fgNormal), cst(bgDark)},
		{"DNS", 40,
			func(r probe.NodeResult) string {
				if r.DNS != nil && r.DNS.Country != "" {
					return r.DNS.Country
				}
				return "-"
			}, cst(fgNormal), cst(bgDark)},
		{"SSH", 40,
			func(r probe.NodeResult) string {
				if r.SSH != nil {
					if r.SSH.Port22Open {
						return "Open"
					}
					return "Closed"
				}
				return "-"
			}, cst(fgNormal), cst(bgDark)},
	}

	allCols := append(append([]col{}, fixedCols...), streamCols...)
	allCols = append(allCols, trailCols...)

	// Layout
	bodyMetrics := bodyFace.Metrics()
	bodyH := bodyMetrics.Height.Ceil()
	bodyAscent := bodyMetrics.Ascent.Ceil()
	titleMetrics := titleFace.Metrics()
	titleH := titleMetrics.Height.Ceil()

	cellPad := 6
	rowH := bodyH + cellPad*2
	colGap := 1
	marginX := 20
	marginTop := 20
	marginBottom := 30
	gap := 12

	// Table width
	tableW := 0
	for _, c := range allCols {
		tableW += c.width + colGap
	}
	tableW += colGap

	// Measure title and summary for minimum width
	titleText := "AnixOps Speedtest - Node Quality Report"
	titleW := font.MeasureString(titleFace, titleText).Ceil()
	summaryText := fmt.Sprintf("Nodes: %d | Passed: %d | Avg HTTP: %.0fms | Avg TCP: %.1fms | Avg Speed: %.1f Mbps",
		totalTested, totalOK, avgHTTP, avgTCP, avgSpeed)
	summaryW := font.MeasureString(bodyFace, summaryText).Ceil()

	contentW := tableW
	if titleW > contentW {
		contentW = titleW
	}
	if summaryW > contentW {
		contentW = summaryW
	}

	imgW := contentW + marginX*2
	imgH := marginTop + titleH + gap + bodyH + gap + rowH + rowH*len(results) + marginBottom

	img := image.NewRGBA(image.Rect(0, 0, imgW, imgH))

	// Background
	for y := 0; y < imgH; y++ {
		for x := 0; x < imgW; x++ {
			img.Set(x, y, color.RGBA{22, 22, 42, 255})
		}
	}

	d := &painter{img: img}

	// Title
	d.text(titleFace, marginX, marginTop, titleText, color.RGBA{56, 189, 248, 255})

	// Summary
	summaryY := marginTop + titleH + gap
	d.text(bodyFace, marginX, summaryY, summaryText, color.RGBA{148, 163, 184, 255})

	// Table header
	hdrY := summaryY + bodyH + gap
	for ci, c := range allCols {
		x := marginX + colOff(allCols, ci)
		fillRect(img, x, hdrY, c.width, rowH, bgHeader)
		d.textCenter(bodyFace, x, hdrY, c.width, rowH, c.header, fgHeader, bodyAscent)
	}

	// Table rows
	for ri, r := range results {
		rowY := hdrY + rowH + ri*rowH
		for ci, c := range allCols {
			x := marginX + colOff(allCols, ci)
			fillRect(img, x, rowY, c.width, rowH, c.bg(r))
			d.textCenter(bodyFace, x, rowY, c.width, rowH, c.data(r), c.fg(r), bodyAscent)
			drawVLine(img, x, rowY, rowH, borderColor)
		}
		lastX := marginX + colOff(allCols, len(allCols)-1) + allCols[len(allCols)-1].width
		drawVLine(img, lastX, rowY, rowH, borderColor)
	}

	// Horizontal separator between header and rows
	hdrBottom := hdrY + rowH
	for x := marginX; x < marginX+tableW; x++ {
		img.Set(x, hdrBottom, borderColor)
	}

	// Footer
	footerY := hdrY + rowH + rowH*len(results) + 12
	d.text(bodyFace, marginX, footerY, fmt.Sprintf("AnixOps Speedtest | %d nodes tested", totalTested), color.RGBA{84, 110, 122, 255})

	// QR code for anti-tamper certificate
	if cert != nil {
		imgH += 90 + 10
		// Create a new larger image and copy existing content
		newImg := image.NewRGBA(image.Rect(0, 0, imgW, imgH))
		draw.Draw(newImg, img.Bounds(), img, image.Point{}, draw.Src)
		img = newImg
		d = &painter{img: img}

		// Draw separator line
		sepY := footerY + bodyH + 6
		for x := marginX; x < marginX+tableW; x++ {
			if sepY < imgH {
				img.Set(x, sepY, borderColor)
			}
		}

		// Draw QR code at bottom-right
		qrURL := ats.VerificationURL(cert.Hash)
		qrImg, err := ats.GenerateQRCodePNGImage(qrURL, 70)
		if err == nil {
			qrBounds := qrImg.Bounds()
			qrX := imgW - qrBounds.Dx() - marginX
			qrY := sepY + 6
			draw.Draw(img, image.Rect(qrX, qrY, qrX+qrBounds.Dx(), qrY+qrBounds.Dy()), qrImg, qrBounds.Min, draw.Over)
		}

		// Draw ATS info text
		atsY := sepY + 6 + 70 + 6
		d.text(bodyFace, marginX, atsY, fmt.Sprintf("ATS: %s | %s", cert.AntiTamperID, cert.Timestamp.Format("2006-01-02 15:04:05")), color.RGBA{100, 116, 139, 255})
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

type painter struct {
	img *image.RGBA
}

func (d *painter) text(face font.Face, x, y int, s string, c color.Color) {
	pt := fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}
	drawer := &font.Drawer{
		Dst:  d.img,
		Src:  &image.Uniform{C: c},
		Face: face,
		Dot:  pt,
	}
	drawer.DrawString(s)
}

func (d *painter) textCenter(face font.Face, x, y, w, h int, s string, c color.Color, ascent int) {
	tw := font.MeasureString(face, s).Ceil()
	cx := x + int(math.Max(0, float64((w-tw)/2)))
	baselineY := y + (h-ascent)/2 + ascent
	pt := fixed.Point26_6{X: fixed.I(cx), Y: fixed.I(baselineY)}
	drawer := &font.Drawer{
		Dst:  d.img,
		Src:  &image.Uniform{C: c},
		Face: face,
		Dot:  pt,
	}
	drawer.DrawString(s)
}

func fillRect(img *image.RGBA, x, y, w, h int, c color.Color) {
	for yy := y; yy < y+h && yy < img.Bounds().Dy(); yy++ {
		for xx := x; xx < x+w && xx < img.Bounds().Dx(); xx++ {
			img.Set(xx, yy, c)
		}
	}
}

func drawVLine(img *image.RGBA, x, y, h int, c color.Color) {
	for yy := y; yy < y+h && yy < img.Bounds().Dy(); yy++ {
		if x >= 0 && x < img.Bounds().Dx() {
			img.Set(x, yy, c)
		}
	}
}

func colOff(cols []col, idx int) int {
	x := 0
	for i := 0; i < idx; i++ {
		x += cols[i].width + 1
	}
	return x
}

func trunc(s string, maxPx int) string {
	w := font.MeasureString(bodyFace, s).Ceil()
	if w <= maxPx {
		return s
	}
	runes := []rune(s)
	for len(runes) > 3 {
		runes = runes[:len(runes)-1]
		if font.MeasureString(bodyFace, string(runes)+"..").Ceil() <= maxPx {
			return string(runes) + ".."
		}
	}
	return "..."
}

func speedBG(mbps, max float64) color.Color {
	if max <= 0 {
		return color.RGBA{42, 42, 62, 255}
	}
	ratio := mbps / max
	if ratio >= 0.75 {
		return color.RGBA{27, 94, 32, 255}
	}
	if ratio >= 0.4 {
		return color.RGBA{230, 81, 0, 255}
	}
	return color.RGBA{74, 0, 0, 255}
}

func speedFG(mbps, max float64) color.Color {
	if max <= 0 {
		return color.RGBA{120, 144, 156, 255}
	}
	ratio := mbps / max
	if ratio >= 0.75 {
		return color.RGBA{165, 214, 167, 255}
	}
	if ratio >= 0.4 {
		return color.RGBA{255, 204, 128, 255}
	}
	return color.RGBA{239, 154, 154, 255}
}

func unlockBG(status string) color.Color {
	switch status {
	case "yes":
		return color.RGBA{27, 94, 32, 255}
	case "partial":
		return color.RGBA{230, 81, 0, 255}
	case "no":
		return color.RGBA{74, 0, 0, 255}
	default:
		return color.RGBA{42, 42, 62, 255}
	}
}

func unlockFG(status string) color.Color {
	switch status {
	case "yes":
		return color.RGBA{165, 214, 167, 255}
	case "partial":
		return color.RGBA{255, 204, 128, 255}
	case "no":
		return color.RGBA{239, 154, 154, 255}
	default:
		return color.RGBA{120, 144, 156, 255}
	}
}

func unlockLabelStr(u checker.UnlockStatus) string {
	if u.Service == "" {
		return "-"
	}
	switch u.Status {
	case "yes":
		if u.Region != "" {
			return fmt.Sprintf("Yes(%s)", u.Region)
		}
		return "Yes"
	case "partial":
		return "Partial"
	case "no":
		return "No"
	default:
		return "-"
	}
}
