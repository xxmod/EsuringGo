package cipher

import (
	"encoding/binary"
)

const (
	xteaNumRounds = 32
	xteaDelta     = 0x9E3779B9 // -1640531527 as uint32
)

// modXTEAEncryptBlock encrypts a single 8-byte block with modified XTEA.
func modXTEAEncryptBlock(v0In, v1In uint32, key [4]uint32) (uint32, uint32) {
	v0, v1 := v0In, v1In
	var sum uint32
	for i := 0; i < xteaNumRounds; i++ {
		sum += xteaDelta
		v0 += (v1 ^ sum) + key[sum&3] + (v1<<4 ^ v1>>5)
		v1 += key[sum>>11&3] + (v0 ^ sum) + (v0<<4 ^ v0>>5)
	}
	return v0, v1
}

// modXTEADecryptBlock decrypts a single 8-byte block with modified XTEA.
func modXTEADecryptBlock(v0In, v1In uint32, key [4]uint32) (uint32, uint32) {
	v0, v1 := v0In, v1In
	// Compute sum with intentional uint32 overflow (same as Java)
	var sum uint32
	for i := 0; i < xteaNumRounds; i++ {
		sum += xteaDelta
	}
	for i := 0; i < xteaNumRounds; i++ {
		v1 -= key[sum>>11&3] + (v0 ^ sum) + (v0<<4 ^ v0>>5)
		v0 -= (v1 ^ sum) + key[sum&3] + (v1<<4 ^ v1>>5)
		sum -= xteaDelta
	}
	return v0, v1
}

// getUint32BE reads a big-endian uint32 from a byte slice at offset.
func getUint32BE(data []byte, offset int) uint32 {
	return binary.BigEndian.Uint32(data[offset:])
}

// setUint32BE writes a big-endian uint32 into a byte slice at offset.
func setUint32BE(data []byte, offset int, value uint32) {
	binary.BigEndian.PutUint32(data[offset:], value)
}

// padToMultipleOf8 pads data with zeros to a multiple of 8 bytes.
func padToMultipleOf8(data []byte) []byte {
	padding := (8 - len(data)%8) % 8
	if padding == 0 {
		return data
	}
	result := make([]byte, len(data)+padding)
	copy(result, data)
	return result
}

// ModXTEA implements ModXTEA triple-key encryption (ECB mode).
type ModXTEA struct {
	key1, key2, key3 [4]uint32
}

func NewModXTEA(key1, key2, key3 [4]uint32) *ModXTEA {
	return &ModXTEA{key1: key1, key2: key2, key3: key3}
}

func (m *ModXTEA) Encrypt(text string) string {
	blocks := padToMultipleOf8([]byte(text))
	for i := 0; i+7 < len(blocks); i += 8 {
		v0 := getUint32BE(blocks, i)
		v1 := getUint32BE(blocks, i+4)
		v0, v1 = modXTEAEncryptBlock(v0, v1, m.key1)
		v0, v1 = modXTEAEncryptBlock(v0, v1, m.key2)
		v0, v1 = modXTEAEncryptBlock(v0, v1, m.key3)
		setUint32BE(blocks, i, v0)
		setUint32BE(blocks, i+4, v1)
	}
	return hexEncode(blocks)
}

func (m *ModXTEA) Decrypt(hexStr string) string {
	blocks, err := hexDecode(hexStr)
	if err != nil || len(blocks) == 0 {
		return ""
	}
	for i := 0; i+7 < len(blocks); i += 8 {
		v0 := getUint32BE(blocks, i)
		v1 := getUint32BE(blocks, i+4)
		v0, v1 = modXTEADecryptBlock(v0, v1, m.key3)
		v0, v1 = modXTEADecryptBlock(v0, v1, m.key2)
		v0, v1 = modXTEADecryptBlock(v0, v1, m.key1)
		setUint32BE(blocks, i, v0)
		setUint32BE(blocks, i+4, v1)
	}
	return string(stripTrailingZeros(blocks))
}
