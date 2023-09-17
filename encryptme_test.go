package encryptme

import (
	"crypto/rand"
	"os"
	"testing"
)

func TestEncryptDecryptFile(t *testing.T) {
	// Create temporary files for testing
	plainTextFile := "plaintext_test.txt"
	encryptedFile := "encrypted_test.bin"
	decryptedFile := "decrypted_test.txt"
	secretKeyFile := "secret_test.key"

	// Clean up temporary files after testing
	defer func() {
		os.Remove(plainTextFile)
		os.Remove(encryptedFile)
		os.Remove(decryptedFile)
		os.Remove(secretKeyFile)
	}()

	// Generate a random secret key (for testing purposes)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Error generating random key: %v", err)
	}

	// Create a plaintext test file
	err = os.WriteFile(plainTextFile, []byte("Hello, world!"), 0644)
	if err != nil {
		t.Fatalf("Error creating plaintext test file: %v", err)
	}

	// Create a secret key file
	err = os.WriteFile(secretKeyFile, key, 0644)
	if err != nil {
		t.Fatalf("Error creating secret key file: %v", err)
	}

	// Test encryption
	EncryptFile(plainTextFile, secretKeyFile, encryptedFile)

	// Check if the encrypted file exists
	if _, err := os.Stat(encryptedFile); os.IsNotExist(err) {
		t.Fatalf("Encryption failed: encrypted file does not exist")
	}

	// Test decryption
	DecryptFile(encryptedFile, secretKeyFile, decryptedFile)

	// Read the decrypted content
	decryptedContent, err := os.ReadFile(decryptedFile)
	if err != nil {
		t.Fatalf("Error reading decrypted content: %v", err)
	}

	// Verify that the decrypted content matches the original plaintext
	expectedContent := "Hello, world!"
	if string(decryptedContent) != expectedContent {
		t.Fatalf("Decrypted content does not match expected: got %s, expected %s", decryptedContent, expectedContent)
	}
}

func TestInvalidEncryption(t *testing.T) {
	// Test encryption with invalid plaintext file
	err := EncryptFile("nonexistent_file.txt", "secret_test.key", "encrypted_test.bin")
	if err == nil {
		t.Fatalf("Expected error for invalid plaintext file, but got nil")
	}

	// Test encryption with invalid secret key file
	err = EncryptFile("plaintext_test.txt", "nonexistent_key.key", "encrypted_test.bin")
	if err == nil {
		t.Fatalf("Expected error for invalid secret key file, but got nil")
	}
}

func TestInvalidDecryption(t *testing.T) {
	// Test decryption with invalid encrypted file
	err := DecryptFile("nonexistent_file.bin", "secret_test.key", "decrypted_test.txt")
	if err == nil {
		t.Fatalf("Expected error for invalid encrypted file, but got nil")
	}

	// Test decryption with invalid secret key file
	err = DecryptFile("encrypted_test.bin", "nonexistent_key.key", "decrypted_test.txt")
	if err == nil {
		t.Fatalf("Expected error for invalid secret key file, but got nil")
	}

	// Test decryption with tampered encrypted file
	err = os.WriteFile("tampered_test.bin", []byte("tampered_data"), 0644)
	if err != nil {
		t.Fatalf("Error creating tampered encrypted file: %v", err)
	}
	err = DecryptFile("tampered_test.bin", "secret_test.key", "tampered_decrypted.txt")
	if err == nil {
		t.Fatalf("Expected error for tampered encrypted file, but got nil")
	}
}
