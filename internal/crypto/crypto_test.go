package crypto

import (
	"bytes"
	"crypto/aes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func encrypt(t *testing.T, keys Keys, plaintext []byte) (encrypted, mac []byte) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "enc")
	require.NoError(t, err)
	defer f.Close()

	enc, err := NewEncryptor(f, keys)
	require.NoError(t, err)
	// Write in odd-sized pieces to exercise buffering.
	for p := plaintext; len(p) > 0; {
		n := min(len(p), 7777)
		_, err := enc.Write(p[:n])
		require.NoError(t, err)
		p = p[n:]
	}
	require.NoError(t, enc.Close())

	encrypted, err = os.ReadFile(f.Name())
	require.NoError(t, err)
	return encrypted, enc.Mac()
}

func newKeys(t *testing.T) Keys {
	t.Helper()
	keys, err := GenerateKeys()
	require.NoError(t, err)
	return keys
}

func TestGenerateKeys(t *testing.T) {
	k1 := newKeys(t)
	k2 := newKeys(t)
	require.NoError(t, k1.Validate())
	assert.NotEqual(t, k1.EncryptionKey, k2.EncryptionKey)
	assert.NotEqual(t, k1.EncryptionKey, k1.MacKey)
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 15, 16, 17, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 5}
	for _, size := range sizes {
		keys := newKeys(t)
		plaintext := bytes.Repeat([]byte{0xA5, 0x5A, 0x01}, size/3+1)[:size]

		encrypted, mac := encrypt(t, keys, plaintext)
		assert.Len(t, encrypted, int(EncryptedSize(int64(size))), "size %d", size)
		assert.Equal(t, mac, encrypted[:MacSize], "size %d", size)
		assert.Equal(t, keys.InitializationVector, encrypted[MacSize:HeaderSize], "size %d", size)

		stored, err := VerifyMac(bytes.NewReader(encrypted), keys.MacKey)
		require.NoError(t, err, "size %d", size)
		assert.Equal(t, mac, stored)

		var out bytes.Buffer
		require.NoError(t, Decrypt(&out, bytes.NewReader(encrypted), keys.EncryptionKey), "size %d", size)
		assert.True(t, bytes.Equal(plaintext, out.Bytes()), "size %d", size)
	}
}

func TestVerifyMacDetectsTampering(t *testing.T) {
	keys := newKeys(t)
	encrypted, _ := encrypt(t, keys, []byte("Hello, World!"))

	for _, idx := range []int{0, MacSize, len(encrypted) - 1} {
		tampered := bytes.Clone(encrypted)
		tampered[idx] ^= 0x01
		_, err := VerifyMac(bytes.NewReader(tampered), keys.MacKey)
		assert.ErrorIs(t, err, ErrMacMismatch, "byte %d", idx)
	}

	_, err := VerifyMac(bytes.NewReader(encrypted), newKeys(t).MacKey)
	assert.ErrorIs(t, err, ErrMacMismatch)
}

func TestVerifyMacTruncated(t *testing.T) {
	keys := newKeys(t)
	encrypted, _ := encrypt(t, keys, []byte("data"))

	_, err := VerifyMac(bytes.NewReader(encrypted[:10]), keys.MacKey)
	require.Error(t, err)
	_, err = VerifyMac(bytes.NewReader(encrypted[:HeaderSize]), keys.MacKey)
	assert.ErrorContains(t, err, "truncated")
}

func TestDecryptErrors(t *testing.T) {
	// Fixed values keep the wrong-key case deterministic: with random keys the garbage
	// final block would look like valid padding about once in 256 runs.
	keys := Keys{
		EncryptionKey:        bytes.Repeat([]byte{0x11}, KeySize),
		MacKey:               bytes.Repeat([]byte{0x22}, KeySize),
		InitializationVector: bytes.Repeat([]byte{0x33}, IVSize),
	}
	wrongKey := bytes.Repeat([]byte{0x44}, KeySize)
	encrypted, _ := encrypt(t, keys, []byte("Hello, World!"))

	var out bytes.Buffer
	assert.ErrorContains(t, Decrypt(&out, bytes.NewReader(encrypted[:HeaderSize]), keys.EncryptionKey), "empty")
	assert.ErrorContains(t, Decrypt(&out, bytes.NewReader(encrypted[:len(encrypted)-1]), keys.EncryptionKey), "multiple of the block size")
	assert.ErrorContains(t, Decrypt(&out, bytes.NewReader(encrypted[:5]), keys.EncryptionKey), "header")
	assert.ErrorContains(t, Decrypt(&out, bytes.NewReader(encrypted), wrongKey), "padding")
	assert.ErrorContains(t, Decrypt(&out, bytes.NewReader(encrypted), keys.EncryptionKey[:16]), "must be 32 bytes")
}

func TestKeysValidate(t *testing.T) {
	keys := newKeys(t)
	bad := keys
	bad.EncryptionKey = keys.EncryptionKey[:16]
	assert.ErrorContains(t, bad.Validate(), "encryption key")
	bad = keys
	bad.MacKey = nil
	assert.ErrorContains(t, bad.Validate(), "MAC key")
	bad = keys
	bad.InitializationVector = keys.InitializationVector[:8]
	assert.ErrorContains(t, bad.Validate(), "initialization vector")

	f, err := os.CreateTemp(t.TempDir(), "enc")
	require.NoError(t, err)
	defer f.Close()
	_, err = NewEncryptor(f, bad)
	assert.Error(t, err)
}

func TestPKCS7Unpad(t *testing.T) {
	valid := append(bytes.Repeat([]byte("a"), 12), 4, 4, 4, 4)
	out, err := pkcs7Unpad(valid)
	require.NoError(t, err)
	assert.Equal(t, bytes.Repeat([]byte("a"), 12), out)

	full := bytes.Repeat([]byte{aes.BlockSize}, aes.BlockSize)
	out, err = pkcs7Unpad(full)
	require.NoError(t, err)
	assert.Empty(t, out)

	for name, block := range map[string][]byte{
		"zero":         append(bytes.Repeat([]byte("a"), 15), 0),
		"too large":    append(bytes.Repeat([]byte("a"), 15), 17),
		"inconsistent": append(bytes.Repeat([]byte("a"), 13), 1, 3, 3),
		"short":        {1},
	} {
		_, err := pkcs7Unpad(block)
		assert.Error(t, err, name)
	}
}

type failingFile struct {
	*os.File
	failAfter int
}

func (f *failingFile) Write(p []byte) (int, error) {
	if f.failAfter <= 0 {
		return 0, os.ErrClosed
	}
	f.failAfter--
	return f.File.Write(p) //nolint:wrapcheck // test helper
}

func TestEncryptorWriteReportsBytesWrittenOnError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "enc")
	require.NoError(t, err)
	defer f.Close()
	// Header writes (placeholder + IV) succeed; the first chunk flush fails.
	enc, err := NewEncryptor(&failingFile{File: f, failAfter: 2}, newKeys(t))
	require.NoError(t, err)

	n, err := enc.Write(make([]byte, chunkSize+100))
	require.ErrorIs(t, err, os.ErrClosed)
	assert.Equal(t, chunkSize, n, "bytes consumed before the failing flush")
	_, err = enc.Write([]byte{1})
	require.ErrorIs(t, err, os.ErrClosed, "the encryptor stays failed")
}
