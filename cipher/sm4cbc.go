package cipher

import (
	"crypto/cipher"

	"github.com/emmansun/gmsm/sm4"
)

// SM4CBC implements SM4-CBC encryption with PKCS5 padding.
type SM4CBC struct {
	key, iv []byte
}

func NewSM4CBC(key, iv []byte) *SM4CBC {
	return &SM4CBC{key: key, iv: iv}
}

func pkcs5Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

func pkcs5Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return data
	}
	return data[:len(data)-padding]
}

func (s *SM4CBC) Encrypt(text string) string {
	// Java code pads to 16 first, then PKCS5 adds another block
	data := padZero([]byte(text), sm4.BlockSize)
	padded := pkcs5Pad(data, sm4.BlockSize)
	block, err := sm4.NewCipher(s.key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, s.iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)
	return hexEncode(encrypted)
}

func (s *SM4CBC) Decrypt(hexStr string) string {
	data, _ := hexDecode(hexStr)
	block, err := sm4.NewCipher(s.key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, s.iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)
	unpadded := pkcs5Unpad(decrypted)
	return string(stripTrailingZeros(unpadded))
}
