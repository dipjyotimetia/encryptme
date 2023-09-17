package encryptme

import (
	"crypto/rand"
	"os"
	"testing"
)

func TestEncryptDecryptFile(t *testing.T) {
	// Test data
	plainTextFile := "plaintext_test.txt"
	encryptedFile := "testdata/encrypted_test.bin"
	decryptedFile := "testdata/decrypted_test.txt"
	secretKeyFile := "testdata/secret_test.key"

	// Generate a random secret key (for testing purposes)
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Error generating random key: %v", err)
	}
	// Write the secret key to a file
	err = os.WriteFile(secretKeyFile, key, 0644)
	if err != nil {
		t.Fatalf("Error writing secret key to file: %v", err)
	}

	// Create a plaintext test file
	err = os.WriteFile(plainTextFile, []byte("Hello, world!"), 0644)
	if err != nil {
		t.Fatalf("Error creating plaintext test file: %v", err)
	}
	defer os.Remove(plainTextFile)

	// Test encryption
	EncryptFile(plainTextFile, secretKeyFile, encryptedFile)

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
