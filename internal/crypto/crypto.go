package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

// EncryptionInfo contains encryption metadata
type EncryptionInfo struct {
	EncryptionKey        []byte
	MacKey               []byte
	InitializationVector []byte
	Mac                  []byte
	FileDigest           []byte
	ProfileIdentifier    string
	FileDigestAlgorithm  string
}

// GenerateKeys generates encryption key, MAC key, and IV
func GenerateKeys() (encryptionKey, macKey, iv []byte, err error) {
	// Generate 256-bit AES key for encryption
	encryptionKey = make([]byte, 32)
	if _, err = rand.Read(encryptionKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	// Generate 256-bit key for HMAC
	macKey = make([]byte, 32)
	if _, err = rand.Read(macKey); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate MAC key: %w", err)
	}

	// Generate IV for AES
	iv = make([]byte, aes.BlockSize)
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	return encryptionKey, macKey, iv, nil
}

// Encrypt encrypts data using AES-256-CBC and writes to output with HMAC
// Format: [HMAC(32 bytes)][IV(16 bytes)][Encrypted Data]
func Encrypt(input io.Reader, output io.Writer, encryptionKey, macKey, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Read all input data
	plaintext, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	// Apply PKCS7 padding
	plaintext = pkcs7Pad(plaintext, aes.BlockSize)

	// Encrypt data
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Compute HMAC over IV + encrypted data
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(ciphertext)
	mac := h.Sum(nil)

	// Write to output: [HMAC][IV][Encrypted Data]
	if _, err := output.Write(mac); err != nil {
		return nil, fmt.Errorf("failed to write HMAC: %w", err)
	}
	if _, err := output.Write(iv); err != nil {
		return nil, fmt.Errorf("failed to write IV: %w", err)
	}
	if _, err := output.Write(ciphertext); err != nil {
		return nil, fmt.Errorf("failed to write encrypted data: %w", err)
	}

	return mac, nil
}

// pkcs7Pad adds PKCS7 padding to data
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}
	return append(data, padText...)
}

// Decrypt decrypts data using AES-256-CBC
// Format: [HMAC(32 bytes)][IV(16 bytes)][Encrypted Data]
func Decrypt(input io.Reader, output io.Writer, encryptionKey, macKey []byte) error {
	// Read HMAC
	storedMac := make([]byte, 32)
	if _, err := io.ReadFull(input, storedMac); err != nil {
		return fmt.Errorf("failed to read HMAC: %w", err)
	}

	// Read IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(input, iv); err != nil {
		return fmt.Errorf("failed to read IV: %w", err)
	}

	// Read all encrypted data for HMAC verification
	encryptedData, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("failed to read encrypted data: %w", err)
	}

	// Verify HMAC
	h := hmac.New(sha256.New, macKey)
	h.Write(iv)
	h.Write(encryptedData)
	computedMac := h.Sum(nil)

	if !hmac.Equal(storedMac, computedMac) {
		return fmt.Errorf("HMAC verification failed")
	}

	// Decrypt data
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	if len(encryptedData)%aes.BlockSize != 0 {
		return fmt.Errorf("encrypted data length is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(encryptedData))
	mode.CryptBlocks(plaintext, encryptedData)

	// Remove PKCS7 padding
	plaintext, err = pkcs7Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return fmt.Errorf("failed to remove padding: %w", err)
	}

	if _, err := output.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}

	return nil
}

// pkcs7Unpad removes PKCS7 padding from data
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data is empty")
	}

	padding := int(data[len(data)-1])
	if padding > blockSize || padding == 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	// Verify padding
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}

// ComputeFileDigest computes SHA256 hash of data
func ComputeFileDigest(data io.Reader) ([]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, data); err != nil {
		return nil, fmt.Errorf("failed to compute file digest: %w", err)
	}
	return h.Sum(nil), nil
}
