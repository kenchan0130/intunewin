package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeys(t *testing.T) {
	encKey, macKey, iv, err := GenerateKeys()
	require.NoError(t, err)

	assert.Len(t, encKey, 32, "Encryption key should be 32 bytes")
	assert.Len(t, macKey, 32, "MAC key should be 32 bytes")
	assert.Len(t, iv, 16, "IV should be 16 bytes")
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate keys
	encKey, macKey, iv, err := GenerateKeys()
	require.NoError(t, err)

	// Test data
	plaintext := []byte("Hello, World! This is a test message.")
	input := bytes.NewReader(plaintext)

	// Encrypt
	encrypted := new(bytes.Buffer)
	mac, err := Encrypt(input, encrypted, encKey, macKey, iv)
	require.NoError(t, err)
	assert.NotNil(t, mac)
	assert.Greater(t, encrypted.Len(), len(plaintext), "Encrypted data should be larger than plaintext")

	// Decrypt
	decrypted := new(bytes.Buffer)
	err = Decrypt(bytes.NewReader(encrypted.Bytes()), decrypted, encKey, macKey)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, plaintext, decrypted.Bytes(), "Decrypted data should match original plaintext")
}

func TestDecryptWithWrongKey(t *testing.T) {
	// Generate keys
	encKey, macKey, iv, err := GenerateKeys()
	require.NoError(t, err)

	// Test data
	plaintext := []byte("Hello, World!")
	input := bytes.NewReader(plaintext)

	// Encrypt
	encrypted := new(bytes.Buffer)
	_, err = Encrypt(input, encrypted, encKey, macKey, iv)
	require.NoError(t, err)

	// Try to decrypt with wrong key
	wrongKey := make([]byte, 32)
	decrypted := new(bytes.Buffer)
	err = Decrypt(bytes.NewReader(encrypted.Bytes()), decrypted, wrongKey, macKey)
	assert.Error(t, err, "Decryption should fail with wrong encryption key")
}

func TestDecryptWithWrongMacKey(t *testing.T) {
	// Generate keys
	encKey, macKey, iv, err := GenerateKeys()
	require.NoError(t, err)

	// Test data
	plaintext := []byte("Hello, World!")
	input := bytes.NewReader(plaintext)

	// Encrypt
	encrypted := new(bytes.Buffer)
	_, err = Encrypt(input, encrypted, encKey, macKey, iv)
	require.NoError(t, err)

	// Try to decrypt with wrong MAC key
	wrongMacKey := make([]byte, 32)
	decrypted := new(bytes.Buffer)
	err = Decrypt(bytes.NewReader(encrypted.Bytes()), decrypted, encKey, wrongMacKey)
	assert.Error(t, err, "Decryption should fail with wrong MAC key")
	assert.Contains(t, err.Error(), "HMAC verification failed")
}

func TestComputeFileDigest(t *testing.T) {
	data := []byte("Hello, World!")
	input := bytes.NewReader(data)

	digest, err := ComputeFileDigest(input)
	require.NoError(t, err)
	assert.Len(t, digest, 32, "SHA256 digest should be 32 bytes")

	// Compute again to verify consistency
	input.Seek(0, 0)
	digest2, err := ComputeFileDigest(input)
	require.NoError(t, err)
	assert.Equal(t, digest, digest2, "Digest should be consistent")
}

func TestPKCS7Padding(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		blockSize int
	}{
		{"Empty", []byte{}, 16},
		{"One byte", []byte{0x01}, 16},
		{"Block size minus one", make([]byte, 15), 16},
		{"Exact block size", make([]byte, 16), 16},
		{"More than one block", make([]byte, 17), 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			padded := pkcs7Pad(tt.data, tt.blockSize)
			assert.Equal(t, 0, len(padded)%tt.blockSize, "Padded data should be multiple of block size")

			// Get padding value
			paddingValue := int(padded[len(padded)-1])
			assert.Greater(t, paddingValue, 0, "Padding value should be positive")
			assert.LessOrEqual(t, paddingValue, tt.blockSize, "Padding value should not exceed block size")

			// Verify all padding bytes are the same
			for i := len(padded) - paddingValue; i < len(padded); i++ {
				assert.Equal(t, byte(paddingValue), padded[i], "All padding bytes should be equal")
			}

			// Test unpadding
			unpadded, err := pkcs7Unpad(padded, tt.blockSize)
			require.NoError(t, err)
			assert.Equal(t, tt.data, unpadded, "Unpadded data should match original")
		})
	}
}
