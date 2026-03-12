package cipher

import (
	"bytes"
	"encoding/hex"
	"strings"
)

// padZero pads data with zero bytes to a multiple of blockSize.
func padZero(data []byte, blockSize int) []byte {
	if len(data)%blockSize == 0 {
		return data
	}
	padded := make([]byte, (len(data)/blockSize+1)*blockSize)
	copy(padded, data)
	return padded
}

// stripTrailingZeros removes trailing zero bytes.
func stripTrailingZeros(data []byte) []byte {
	return bytes.TrimRight(data, "\x00")
}

// hexEncode returns uppercase hex string for bytes.
func hexEncode(data []byte) string {
	return strings.ToUpper(hex.EncodeToString(data))
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
