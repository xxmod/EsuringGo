package cipher

import (
	"github.com/emmansun/gmsm/zuc"
)

// ZUCCipher implements ZUC-128 stream cipher encryption.
type ZUCCipher struct {
	key, iv []byte
}

func NewZUC(key, iv []byte) *ZUCCipher {
	return &ZUCCipher{key: key, iv: iv}
}

func (z *ZUCCipher) processZUC(input []byte) []byte {
	c, err := zuc.NewCipher(z.key, z.iv)
	if err != nil {
		panic(err)
	}
	output := make([]byte, len(input))
	c.XORKeyStream(output, input)
	return output
}

func (z *ZUCCipher) Encrypt(text string) string {
	data := []byte(text)
	// pad to multiple of 4
	if len(data)%4 != 0 {
		padded := make([]byte, (len(data)/4+1)*4)
		copy(padded, data)
		data = padded
	}
	return hexEncode(z.processZUC(data))
}

func (z *ZUCCipher) Decrypt(hexStr string) string {
	data, _ := hexDecode(hexStr)
	result := z.processZUC(data)
	return string(stripTrailingZeros(result))
}
