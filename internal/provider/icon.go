package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	"os"

	_ "image/gif"  // registers GIF with image.DecodeConfig
	_ "image/jpeg" // registers JPEG with image.DecodeConfig
	_ "image/png"  // registers PNG with image.DecodeConfig
)

// Slack refuses an app icon outside these bounds with invalid_icon_size.
const (
	iconMinSide = 512
	iconMaxSide = 2000
)

type icon struct {
	//declscope:shared
	path string
	//declscope:shared
	image []byte
	//declscope:shared
	sha256 string
}

// readIcon reads the image at path and checks it is one Slack takes as an
// app icon, so that a bad file fails the plan rather than the apply.
//
//declscope:shared
func readIcon(path string) (icon, error) {
	image, err := os.ReadFile(path)
	if err != nil {
		return icon{}, err
	}

	if err := checkIconImage(image); err != nil {
		return icon{}, fmt.Errorf("%s: %w", path, err)
	}

	sum := sha256.Sum256(image)

	return icon{path: path, image: image, sha256: hex.EncodeToString(sum[:])}, nil
}

func checkIconImage(data []byte) error {
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("not a PNG, JPEG or GIF image: %w", err)
	}

	if config.Width < iconMinSide || config.Width > iconMaxSide || config.Height < iconMinSide || config.Height > iconMaxSide {
		return fmt.Errorf("the %s is %dx%d pixels; Slack takes %d to %d pixels per side",
			format, config.Width, config.Height, iconMinSide, iconMaxSide)
	}

	return nil
}
