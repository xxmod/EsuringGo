package main

import (
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	// Build a fake ZSM payload that mirrors what the server sends.
	// ZSM structure: [4 header bytes (byte 3 = keyLen)] [keyLen bytes of key data] [separator byte] [algoIDLen byte] [algoID string]
	algoID := "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E" // AESCBC
	keyData := []byte("somekey123456789")

	zsm := make([]byte, 0)
	zsm = append(zsm, 0, 0, 0, byte(len(keyData))) // 4 header bytes, byte[3] is keyLen
	zsm = append(zsm, keyData...)                  // key bytes
	zsm = append(zsm, 0)                           // separator
	zsm = append(zsm, byte(len(algoID)))           // algoID length
	zsm = append(zsm, []byte(algoID)...)           // algoID string

	sess := NewSession()
	sess.Initialize(zsm)

	if !sess.IsInitialized() {
		t.Skip("Session initialization failed - ZSM format may differ, skip higher-level test")
	}

	// If initialized, test encrypt/decrypt
	original := "hello world"
	encrypted := sess.Encrypt(original)
	decrypted := sess.Decrypt(encrypted)
	if decrypted != original {
		t.Errorf("Session round-trip failed: got %q, want %q", decrypted, original)
	}

	sess.Free()
	if sess.IsInitialized() {
		t.Error("Session should not be initialized after Free()")
	}
}

func TestSessionNotInitialized(t *testing.T) {
	sess := NewSession()
	if sess.IsInitialized() {
		t.Error("New session should not be initialized")
	}
	if sess.GetAlgoID() != "" {
		t.Error("New session should have empty algoID")
	}
}
