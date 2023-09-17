package encryptme

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

// EncryptFile encrypts a file with AES-GCM algorithm
// contentFile is the file to be encrypted
// secretKey is the key to encrypt the file
// exportBin is the file to be exported
func EncryptFile(contentFile, secretKey, exportBin string) error {
	// Reading plaintext file
	plainText, err := os.ReadFile(contentFile)
	if err != nil {
		return fmt.Errorf("read file err: %v", err.Error())
	}

	// Reading key
	key, err := os.ReadFile(secretKey)
	if err != nil {
		return fmt.Errorf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher GCM err: %v", err.Error())
	}

	// Generating random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("nonce  err: %v", err.Error())
	}

	// Decrypt file
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Writing ciphertext file
	err = os.WriteFile(exportBin, cipherText, 0777)
	if err != nil {
		return fmt.Errorf("write file err: %v", err.Error())
	}
	return nil
}

// DecryptFile decrypts a file with AES-GCM algorithm
// importBin is the file to be decrypted
// secretKey is the key to decrypt the file
// content is the file to be exported
func DecryptFile(importBin, secretKey, content string) error {
	// Reading ciphertext file
	cipherText, err := os.ReadFile(importBin)
	if err != nil {
		return fmt.Errorf(err.Error())
	}

	// Reading key
	key, err := os.ReadFile(secretKey)
	if err != nil {
		return fmt.Errorf("read file err: %v", err.Error())
	}

	// Creating block of algorithm
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher err: %v", err.Error())
	}

	// Creating GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("cipher GCM err: %v", err.Error())
	}

	// Deattached nonce and decrypt
	nonce := cipherText[:gcm.NonceSize()]
	cipherText = cipherText[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return fmt.Errorf("decrypt file err: %v", err.Error())
	}

	// Writing decryption content
	err = os.WriteFile(content, plainText, 0777)
	if err != nil {
		return fmt.Errorf("write file err: %v", err.Error())
	}

	return nil
}
