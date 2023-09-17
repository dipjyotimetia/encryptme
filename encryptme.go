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
	// Read plaintext file
	plainText, err := os.ReadFile(contentFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Read encryption key
	key, err := os.ReadFile(secretKey)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the file
	cipherText := gcm.Seal(nonce, nonce, plainText, nil)

	// Write ciphertext to the export file
	if err := os.WriteFile(exportBin, cipherText, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	return nil
}

// DecryptFile decrypts a file with AES-GCM algorithm
// importBin is the file to be decrypted
// secretKey is the key to decrypt the file
// content is the file to be exported
func DecryptFile(importBin, secretKey, content string) error {
	// Read ciphertext file
	cipherText, err := os.ReadFile(importBin)
	if err != nil {
		return fmt.Errorf("failed to read ciphertext file: %w", err)
	}

	// Read decryption key
	key, err := os.ReadFile(secretKey)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	// Separate nonce and decrypt
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return fmt.Errorf("ciphertext is too short")
	}

	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	// Write decryption content to the specified file
	if err := os.WriteFile(content, plainText, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	return nil
}
