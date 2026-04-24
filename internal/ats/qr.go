package ats

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/draw"

	qrcode "github.com/skip2/go-qrcode"
)

func VerificationURL(hash string) string {
	return fmt.Sprintf("https://verify.opentimestamps.org/%s", hash)
}

func GenerateQRCodePNGImage(data string, size int) (image.Image, error) {
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	pngBytes, err := qr.PNG(size)
	if err != nil {
		return nil, err
	}
	img, _, err := image.Decode(bytes.NewReader(pngBytes))
	return img, err
}

func GenerateQRCodePNGBytes(data string, size int) ([]byte, error) {
	qr, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	return qr.PNG(size)
}

func QRCodePNGDataURI(data string, size int) (string, error) {
	pngBytes, err := GenerateQRCodePNGBytes(data, size)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(pngBytes)
	return fmt.Sprintf("data:image/png;base64,%s", encoded), nil
}

func DrawQRCodeOnto(dst draw.Image, qrData string, size int, x0, y0 int) error {
	img, err := GenerateQRCodePNGImage(qrData, size)
	if err != nil {
		return err
	}
	bounds := img.Bounds()
	draw.Draw(dst, image.Rect(x0, y0, x0+bounds.Dx(), y0+bounds.Dy()), img, bounds.Min, draw.Over)
	return nil
}
