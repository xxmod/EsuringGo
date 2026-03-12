package utils

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// GetTime returns the current time formatted for China timezone (+8).
func GetTime() string {
	loc := time.FixedZone("CST", 8*3600)
	return time.Now().In(loc).Format("2006-01-02 15:04:05")
}

// ExtractBetweenTags extracts text between startTag and endTag.
func ExtractBetweenTags(text, startTag, endTag string) string {
	startIdx := strings.Index(text, startTag)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(startTag)
	endIdx := strings.Index(text[startIdx:], endTag)
	if endIdx == -1 {
		return ""
	}
	return text[startIdx : startIdx+endIdx]
}

// RandomMACAddress generates a random MAC address string.
func RandomMACAddress() string {
	mac := make([]byte, 6)
	rand.Read(mac)
	mac[0] &= 0xFE // unicast
	parts := make([]string, 6)
	for i, b := range mac {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

// RandomString generates a random alphanumeric string of the given length.
func RandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
