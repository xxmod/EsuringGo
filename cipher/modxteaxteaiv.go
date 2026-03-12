package cipher

// ModXTEAXTEAIV implements ModXTEA with CBC-like IV chaining.
type ModXTEAXTEAIV struct {
	key1, key2, key3 [4]uint32
	iv               [2]uint32
}

func NewModXTEAXTEAIV(key1, key2, key3 [4]uint32, iv [2]uint32) *ModXTEAXTEAIV {
	return &ModXTEAXTEAIV{key1: key1, key2: key2, key3: key3, iv: iv}
}

func (m *ModXTEAXTEAIV) Encrypt(text string) string {
	blocks := padToMultipleOf8([]byte(text))
	prev := m.iv
	for i := 0; i+7 < len(blocks); i += 8 {
		v0 := getUint32BE(blocks, i)
		v1 := getUint32BE(blocks, i+4)
		// XOR with previous ciphertext (CBC mode)
		v0 ^= prev[0]
		v1 ^= prev[1]
		v0, v1 = modXTEAEncryptBlock(v0, v1, m.key3)
		v0, v1 = modXTEAEncryptBlock(v0, v1, m.key2)
		v0, v1 = modXTEAEncryptBlock(v0, v1, m.key1)
		setUint32BE(blocks, i, v0)
		setUint32BE(blocks, i+4, v1)
		prev = [2]uint32{getUint32BE(blocks, i), getUint32BE(blocks, i+4)}
	}
	return hexEncode(blocks)
}

func (m *ModXTEAXTEAIV) Decrypt(hexStr string) string {
	blocks, _ := hexDecode(hexStr)
	prev := m.iv
	for i := 0; i+7 < len(blocks); i += 8 {
		v0 := getUint32BE(blocks, i)
		v1 := getUint32BE(blocks, i+4)
		nextPrev := [2]uint32{v0, v1}
		v0, v1 = modXTEADecryptBlock(v0, v1, m.key1)
		v0, v1 = modXTEADecryptBlock(v0, v1, m.key2)
		v0, v1 = modXTEADecryptBlock(v0, v1, m.key3)
		// XOR with previous ciphertext
		v0 ^= prev[0]
		v1 ^= prev[1]
		setUint32BE(blocks, i, v0)
		setUint32BE(blocks, i+4, v1)
		prev = nextPrev
	}
	return string(stripTrailingZeros(blocks))
}
