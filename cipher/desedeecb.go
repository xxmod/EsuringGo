package cipher

import (
	"crypto/des"
)

// DESedeECB implements double 3DES-ECB encryption.
type DESedeECB struct {
	key1, key2 []byte
}

func NewDESedeECB(key1, key2 []byte) *DESedeECB {
	return &DESedeECB{key1: key1, key2: key2}
}

func (d *DESedeECB) tripleDesEncrypt(data, key []byte) []byte {
	padded := padZero(data, 16)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	return ecbEncrypt(block, padded)
}

func (d *DESedeECB) tripleDesDecrypt(data, key []byte) []byte {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	return ecbDecrypt(block, data)
}

func (d *DESedeECB) Encrypt(text string) string {
	r1 := d.tripleDesEncrypt([]byte(text), d.key1)
	r2 := d.tripleDesEncrypt(r1, d.key2)
	return hexEncode(r2)
}

func (d *DESedeECB) Decrypt(hexStr string) string {
	data, err := hexDecode(hexStr)
	if err != nil || len(data) == 0 {
		return ""
	}
	r1 := d.tripleDesDecrypt(data, d.key2)
	r2 := d.tripleDesDecrypt(r1, d.key1)
	return string(stripTrailingZeros(r2))
}
