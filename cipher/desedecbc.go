package cipher

import (
	"crypto/cipher"
	"crypto/des"
)

// DESedeCBC implements double 3DES-CBC encryption.
type DESedeCBC struct {
	key1, key2, iv []byte
}

func NewDESedeCBC(key1, key2, iv []byte) *DESedeCBC {
	return &DESedeCBC{key1: key1, key2: key2, iv: iv}
}

func (d *DESedeCBC) tripleDesEncrypt(data, key []byte) []byte {
	padded := padZero(data, 16)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCEncrypter(block, d.iv)
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)
	return encrypted
}

func (d *DESedeCBC) tripleDesDecrypt(data, key []byte) []byte {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, d.iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)
	return decrypted
}

func (d *DESedeCBC) Encrypt(text string) string {
	r1 := d.tripleDesEncrypt([]byte(text), d.key1)
	r2 := d.tripleDesEncrypt(r1, d.key2)
	return hexEncode(r2)
}

func (d *DESedeCBC) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) == 0 {
		return ""
	}
	r1 := d.tripleDesDecrypt(data, d.key2)
	r2 := d.tripleDesDecrypt(r1, d.key1)
	return string(stripTrailingZeros(r2))
}
