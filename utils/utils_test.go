package utils

import (
	"regexp"
	"strings"
	"testing"
)

func TestGetTime(t *testing.T) {
	ts := GetTime()
	// Format: "2006-01-02 15:04:05"
	matched, _ := regexp.MatchString(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`, ts)
	if !matched {
		t.Errorf("GetTime() = %q, want format YYYY-MM-DD HH:MM:SS", ts)
	}
}

func TestExtractBetweenTags(t *testing.T) {
	tests := []struct {
		text, startTag, endTag, expected string
	}{
		{"<name>hello</name>", "<name>", "</name>", "hello"},
		{"<a>first</a><b>second</b>", "<b>", "</b>", "second"},
		{"no tags here", "<x>", "</x>", ""},
		{"<tag>content</tag> extra", "<tag>", "</tag>", "content"},
	}
	for _, tc := range tests {
		result := ExtractBetweenTags(tc.text, tc.startTag, tc.endTag)
		if result != tc.expected {
			t.Errorf("ExtractBetweenTags(%q, %q, %q) = %q, want %q", tc.text, tc.startTag, tc.endTag, result, tc.expected)
		}
	}
}

func TestRandomMACAddress(t *testing.T) {
	mac := RandomMACAddress()
	// Should be like XX:XX:XX:XX:XX:XX
	parts := strings.Split(mac, ":")
	if len(parts) != 6 {
		t.Errorf("RandomMACAddress() = %q, expected 6 parts separated by ':'", mac)
	}
	for _, p := range parts {
		if len(p) != 2 {
			t.Errorf("RandomMACAddress() part %q should be 2 hex chars", p)
		}
	}
}

func TestRandomString(t *testing.T) {
	s := RandomString(16)
	if len(s) != 16 {
		t.Errorf("RandomString(16) length = %d, want 16", len(s))
	}
	// Should only contain alphanumeric chars
	matched, _ := regexp.MatchString(`^[0-9a-zA-Z]+$`, s)
	if !matched {
		t.Errorf("RandomString(16) = %q, expected lowercase hex chars", s)
	}
	// Different calls should produce different results (with high probability)
	s2 := RandomString(16)
	if s == s2 {
		t.Logf("Warning: two RandomString calls produced same result: %s", s)
	}
}
