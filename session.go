package main

import (
	"esurfing/cipher"
	"fmt"
	"log"
	"sync"
)

// Session manages the encryption cipher for the current connection.
type Session struct {
	mu          sync.RWMutex
	initialized bool
	cipher      cipher.Cipher
	algoID      string
}

func NewSession() *Session {
	return &Session{}
}

// Initialize parses the ZSM response bytes and initializes the cipher.
// ZSM format: [4 header bytes, byte[3]=keyLen] [keyLen key bytes] [separator] [algoIDLen] [algoID string]
func (s *Session) Initialize(zsm []byte) {
	log.Println("Initializing Session...")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = s.load(zsm)
}

func (s *Session) load(zsm []byte) bool {
	if len(zsm) < 4 {
		return false
	}
	pos := 4
	keyLen := int(zsm[3])
	if pos+keyLen > len(zsm) {
		return false
	}
	pos += keyLen
	if pos >= len(zsm) {
		return false
	}
	pos++ // skip separator byte
	algoIDLen := int(zsm[pos])
	pos++ // skip length byte
	if pos+algoIDLen > len(zsm) {
		return false
	}
	algoID := string(zsm[pos : pos+algoIDLen])

	c, err := cipher.NewCipher(algoID)
	if err != nil {
		log.Printf("Error: %v", err)
		return false
	}
	s.cipher = c
	s.algoID = algoID
	return true
}

func (s *Session) IsInitialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.initialized
}

func (s *Session) Encrypt(text string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cipher == nil {
		return "", fmt.Errorf("cipher not initialized")
	}
	return s.cipher.Encrypt(text), nil
}

func (s *Session) Decrypt(hexStr string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cipher == nil {
		return "", fmt.Errorf("cipher not initialized")
	}
	return s.cipher.Decrypt(hexStr), nil
}

func (s *Session) GetAlgoID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.algoID
}

func (s *Session) Free() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = false
	s.cipher = nil
}
