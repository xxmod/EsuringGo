package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

// AESECB implements double AES-ECB encryption.
type AESECB struct {
	key1, key2 []byte
}

func NewAESECB(key1, key2 []byte) *AESECB {
	return &AESECB{key1: key1, key2: key2}
}

func ecbEncrypt(block cipher.Block, data []byte) []byte {
	bs := block.BlockSize()
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Encrypt(out[i:i+bs], data[i:i+bs])
	}
	return out
}

func ecbDecrypt(block cipher.Block, data []byte) []byte {
	bs := block.BlockSize()
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(out[i:i+bs], data[i:i+bs])
	}
	return out
}

func (a *AESECB) aesEncrypt(data, key []byte) []byte {
	padded := padZero(data, aes.BlockSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return ecbEncrypt(block, padded)
}

func (a *AESECB) aesDecrypt(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return ecbDecrypt(block, data)
}

func (a *AESECB) Encrypt(text string) string {
	r1 := a.aesEncrypt([]byte(text), a.key1)
	r2 := a.aesEncrypt(r1, a.key2)
	return hexEncode(r2)
}

func (a *AESECB) Decrypt(hexStr string) string {
	data, _ := hexDecode(hexStr)
	r1 := a.aesDecrypt(data, a.key2)
	r2 := a.aesDecrypt(r1, a.key1)
	return string(stripTrailingZeros(r2))
}
