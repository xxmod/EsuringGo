package main

import (
	"esurfing/cipher"
	"log"
)

// Session manages the encryption cipher for the current connection.
type Session struct {
	initialized bool
	cipher      cipher.Cipher
	algoID      string
}

func NewSession() *Session {
	return &Session{}
}

// Initialize parses the ZSM response bytes and initializes the cipher.
func (s *Session) Initialize(zsm []byte) {
	log.Println("Initializing Session...")
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
	pos++
	algoIDLen := int(zsm[pos])
	pos++
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
	return s.initialized
}

func (s *Session) Encrypt(text string) string {
	if s.cipher == nil {
		panic("cipher not initialized")
	}
	return s.cipher.Encrypt(text)
}

func (s *Session) Decrypt(hexStr string) string {
	if s.cipher == nil {
		panic("cipher not initialized")
	}
	return s.cipher.Decrypt(hexStr)
}

func (s *Session) GetAlgoID() string {
	return s.algoID
}

func (s *Session) Free() {
	s.initialized = false
	s.cipher = nil
}
