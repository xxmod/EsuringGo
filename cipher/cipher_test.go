package cipher

import (
	"testing"
)

// TestAllCiphersRoundTrip verifies encrypt/decrypt round-trip for all cipher implementations.
func TestAESCBCRoundTrip(t *testing.T) {
	c := NewAESCBC(KeyCAFBCBAD_Key1, KeyCAFBCBAD_Key2, KeyCAFBCBAD_IV)
	testRoundTrip(t, "AESCBC", c)
}

func TestAESECBRoundTrip(t *testing.T) {
	c := NewAESECB(KeyA474B1C2_Key1, KeyA474B1C2_Key2)
	testRoundTrip(t, "AESECB", c)
}

func TestDESedeCBCRoundTrip(t *testing.T) {
	c := NewDESedeCBC(Key5BFBA864_Key1, Key5BFBA864_Key2, Key5BFBA864_IV)
	testRoundTrip(t, "DESedeCBC", c)
}

func TestDESedeECBRoundTrip(t *testing.T) {
	c := NewDESedeECB(Key6E0B65FF_Key1, Key6E0B65FF_Key2)
	testRoundTrip(t, "DESedeECB", c)
}

func TestSM4CBCRoundTrip(t *testing.T) {
	c := NewSM4CBC(KeyF3974434_Key, KeyF3974434_IV)
	testRoundTrip(t, "SM4CBC", c)
}

func TestSM4ECBRoundTrip(t *testing.T) {
	c := NewSM4ECB(KeyED382482_Key)
	testRoundTrip(t, "SM4ECB", c)
}

func TestZUCRoundTrip(t *testing.T) {
	c := NewZUC(KeyB809531F_Key, KeyB809531F_IV)
	testRoundTrip(t, "ZUC", c)
}

func TestModXTEARoundTrip(t *testing.T) {
	c := NewModXTEA(KeyB3047D4E_Key1, KeyB3047D4E_Key2, KeyB3047D4E_Key3)
	testRoundTrip(t, "ModXTEA", c)
}

func TestModXTEAXTEAIVRoundTrip(t *testing.T) {
	c := NewModXTEAXTEAIV(KeyC32C68F9_Key1, KeyC32C68F9_Key2, KeyC32C68F9_Key3, KeyC32C68F9_IV)
	testRoundTrip(t, "ModXTEAXTEAIV", c)
}

func testRoundTrip(t *testing.T, name string, c Cipher) {
	testCases := []string{
		"hello",
		"test message with more data",
		`<?xml version="1.0" encoding="utf-8"?><request><user-agent>CCTP/android64_vpn/2093</user-agent></request>`,
		"short",
		"a",
		"exactly16bytess!",
		"中文内容测试",
	}

	for _, original := range testCases {
		encrypted := c.Encrypt(original)
		if encrypted == "" {
			t.Errorf("[%s] Encrypt(%q) returned empty string", name, original)
			continue
		}
		if encrypted == original {
			t.Errorf("[%s] Encrypt(%q) returned plaintext", name, original)
			continue
		}
		decrypted := c.Decrypt(encrypted)
		if decrypted != original {
			t.Errorf("[%s] Round-trip failed for %q:\n  encrypted: %s\n  decrypted: %q", name, original, encrypted, decrypted)
		}
	}
}

// TestCipherFactory tests the factory function.
func TestCipherFactory(t *testing.T) {
	algoIDs := []string{
		"CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E",
		"A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4",
		"5BFBA864-BBA9-42DB-8EAD-49B5F412BD81",
		"6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5",
		"B809531F-0007-4B5B-923B-4BD560398113",
		"F3974434-C0DD-4C20-9E87-DDB6814A1C48",
		"ED382482-F72C-4C41-A76D-28EEA0F1F2AF",
		"B3047D4E-67DF-4864-A6A5-DF9B9E525C79",
		"C32C68F9-CA81-4260-A329-BBAFD1A9CCD1",
	}

	for _, id := range algoIDs {
		c, err := NewCipher(id)
		if err != nil {
			t.Errorf("NewCipher(%s) failed: %v", id, err)
			continue
		}
		original := "test data for " + id
		encrypted := c.Encrypt(original)
		decrypted := c.Decrypt(encrypted)
		if decrypted != original {
			t.Errorf("Factory round-trip failed for %s: got %q, want %q", id, decrypted, original)
		}
	}

	// Unknown algorithm should fail
	_, err := NewCipher("unknown-id")
	if err == nil {
		t.Error("NewCipher(unknown) should return error")
	}
}

// TestHexEncodeDecode tests hex encoding helpers.
func TestHexEncodeDecode(t *testing.T) {
	data := []byte{0x01, 0xAB, 0xFF, 0x00}
	encoded := hexEncode(data)
	if encoded != "01ABFF00" {
		t.Errorf("hexEncode = %s, want 01ABFF00", encoded)
	}
	decoded, err := hexDecode(encoded)
	if err != nil {
		t.Errorf("hexDecode error: %v", err)
	}
	for i, b := range decoded {
		if b != data[i] {
			t.Errorf("hexDecode[%d] = %d, want %d", i, b, data[i])
		}
	}
}

// TestStripTrailingZeros tests zero-padding removal.
func TestStripTrailingZeros(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
	}{
		{[]byte{1, 2, 3, 0, 0, 0}, []byte{1, 2, 3}},
		{[]byte{1, 2, 3}, []byte{1, 2, 3}},
		{[]byte{0, 0}, []byte{}},
		{[]byte{}, []byte{}},
	}
	for _, tc := range tests {
		result := stripTrailingZeros(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("stripTrailingZeros(%v) = %v, want %v", tc.input, result, tc.expected)
		}
	}
}
