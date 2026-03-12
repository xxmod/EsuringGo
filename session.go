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
// ZSM format: [4 header bytes, byte[3]=keyLen] [keyLen key bytes] [separator '$'] [36-char UUID] [']'] [binary data...]
func (s *Session) Initialize(zsm []byte) {
	log.Println("Initializing Session...")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initialized = s.load(zsm)
}

func (s *Session) load(zsm []byte) bool {
	if len(zsm) < 4 {
		log.Printf("[Session] ZSM too short: %d bytes", len(zsm))
		return false
	}

	hexLen := min(len(zsm), 200)
	log.Printf("[Session] ZSM length: %d, first %d bytes hex: %X", len(zsm), hexLen, zsm[:hexLen])

	pos := 4
	keyLen := int(zsm[3])
	log.Printf("[Session] keyLen=%d (0x%02X)", keyLen, zsm[3])
	if pos+keyLen >= len(zsm) {
		log.Printf("[Session] keyLen exceeds ZSM length")
		return false
	}
	pos += keyLen
	pos++ // skip separator byte (e.g. '$')

	// UUID is directly after separator — always 36 characters, no length byte
	const uuidLen = 36
	if pos+uuidLen > len(zsm) {
		log.Printf("[Session] not enough bytes for UUID at pos=%d", pos)
		return false
	}
	algoID := string(zsm[pos : pos+uuidLen])
	log.Printf("[Session] Parsed algoID: %q", algoID)

	c, err := cipher.NewCipher(algoID)
	if err != nil {
		log.Printf("[Session] Error: %v", err)
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
