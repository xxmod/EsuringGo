package cipher

import "fmt"

// Cipher defines the encryption/decryption interface.
type Cipher interface {
	Encrypt(text string) string
	Decrypt(hex string) string
}

// NewCipher creates a cipher instance for the given algorithm ID.
func NewCipher(algoID string) (Cipher, error) {
	switch algoID {
	case "CAFBCBAD-B6E7-4CAB-8A67-14D39F00CE1E":
		return NewAESCBC(
			KeyCAFBCBAD_Key1, KeyCAFBCBAD_Key2, KeyCAFBCBAD_IV,
		), nil
	case "A474B1C2-3DE0-4EA2-8C5F-7093409CE6C4":
		return NewAESECB(
			KeyA474B1C2_Key1, KeyA474B1C2_Key2,
		), nil
	case "5BFBA864-BBA9-42DB-8EAD-49B5F412BD81":
		return NewDESedeCBC(
			Key5BFBA864_Key1, Key5BFBA864_Key2, Key5BFBA864_IV,
		), nil
	case "6E0B65FF-0B5B-459C-8FCE-EC7F2BEA9FF5":
		return NewDESedeECB(
			Key6E0B65FF_Key1, Key6E0B65FF_Key2,
		), nil
	case "B809531F-0007-4B5B-923B-4BD560398113":
		return NewZUC(
			KeyB809531F_Key, KeyB809531F_IV,
		), nil
	case "F3974434-C0DD-4C20-9E87-DDB6814A1C48":
		return NewSM4CBC(
			KeyF3974434_Key, KeyF3974434_IV,
		), nil
	case "ED382482-F72C-4C41-A76D-28EEA0F1F2AF":
		return NewSM4ECB(
			KeyED382482_Key,
		), nil
	case "B3047D4E-67DF-4864-A6A5-DF9B9E525C79":
		return NewModXTEA(
			KeyB3047D4E_Key1, KeyB3047D4E_Key2, KeyB3047D4E_Key3,
		), nil
	case "C32C68F9-CA81-4260-A329-BBAFD1A9CCD1":
		return NewModXTEAXTEAIV(
			KeyC32C68F9_Key1, KeyC32C68F9_Key2, KeyC32C68F9_Key3, KeyC32C68F9_IV,
		), nil
	default:
		return nil, fmt.Errorf("unknown algorithm: %s", algoID)
	}
}
