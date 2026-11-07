// Package crypto implements the encryption scheme used by .intunewin packages.
//
// The encrypted content has the following layout:
//
//	[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-256-CBC ciphertext, PKCS#7 padded]
//
// The HMAC is computed with the MAC key over IV || ciphertext.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	// KeySize is the size in bytes of both the AES encryption key and the HMAC key.
	KeySize = 32
	// IVSize is the size in bytes of the AES-CBC initialization vector.
	IVSize = aes.BlockSize
	// MacSize is the size in bytes of the HMAC-SHA256 tag.
	MacSize = sha256.Size
	// HeaderSize is the number of bytes preceding the ciphertext (HMAC + IV).
	HeaderSize = MacSize + IVSize

	// chunkSize is the amount of data processed at once. It must be a multiple of aes.BlockSize.
	chunkSize = 64 * 1024
)

// ErrMacMismatch is returned when the HMAC of encrypted content does not verify.
var ErrMacMismatch = errors.New("HMAC verification failed")

// Keys holds the secrets needed to encrypt or decrypt content.
type Keys struct {
	EncryptionKey        []byte
	MacKey               []byte
	InitializationVector []byte
}

// Validate checks that every key has the expected length.
func (k Keys) Validate() error {
	if len(k.EncryptionKey) != KeySize {
		return fmt.Errorf("encryption key must be %d bytes, got %d", KeySize, len(k.EncryptionKey))
	}
	if len(k.MacKey) != KeySize {
		return fmt.Errorf("MAC key must be %d bytes, got %d", KeySize, len(k.MacKey))
	}
	if len(k.InitializationVector) != IVSize {
		return fmt.Errorf("initialization vector must be %d bytes, got %d", IVSize, len(k.InitializationVector))
	}
	return nil
}

// GenerateKeys returns a fresh random encryption key, MAC key and IV.
func GenerateKeys() (Keys, error) {
	k := Keys{
		EncryptionKey:        make([]byte, KeySize),
		MacKey:               make([]byte, KeySize),
		InitializationVector: make([]byte, IVSize),
	}
	for _, b := range [][]byte{k.EncryptionKey, k.MacKey, k.InitializationVector} {
		if _, err := rand.Read(b); err != nil {
			return Keys{}, fmt.Errorf("failed to generate random key material: %w", err)
		}
	}
	return k, nil
}

// EncryptedSize returns the size of the encrypted stream for a plaintext of n bytes.
func EncryptedSize(n int64) int64 {
	return HeaderSize + (n/aes.BlockSize+1)*aes.BlockSize
}

// Encryptor is an io.WriteCloser that encrypts everything written to it into dst.
//
// Because the HMAC precedes the ciphertext, dst must be seekable: a placeholder is
// written first and replaced with the real HMAC by Close.
type Encryptor struct {
	dst   io.WriteSeeker
	start int64
	mode  cipher.BlockMode
	mac   hash.Hash
	buf   []byte
	nbuf  int
	sum   []byte
	err   error
}

// NewEncryptor writes the encrypted-stream header to dst at its current offset and
// returns an Encryptor that writes the ciphertext after it.
func NewEncryptor(dst io.WriteSeeker, keys Keys) (*Encryptor, error) {
	if err := keys.Validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keys.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	start, err := dst.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to get output offset: %w", err)
	}
	if _, err := dst.Write(make([]byte, MacSize)); err != nil {
		return nil, fmt.Errorf("failed to write HMAC placeholder: %w", err)
	}
	if _, err := dst.Write(keys.InitializationVector); err != nil {
		return nil, fmt.Errorf("failed to write IV: %w", err)
	}
	mac := hmac.New(sha256.New, keys.MacKey)
	mac.Write(keys.InitializationVector)
	return &Encryptor{
		dst:   dst,
		start: start,
		mode:  cipher.NewCBCEncrypter(block, keys.InitializationVector),
		mac:   mac,
		buf:   make([]byte, chunkSize),
	}, nil
}

// Write encrypts p. Data is buffered until a full chunk is available.
func (e *Encryptor) Write(p []byte) (int, error) {
	if e.err != nil {
		return 0, e.err
	}
	if e.sum != nil {
		return 0, errors.New("write to closed encryptor")
	}
	n := len(p)
	for len(p) > 0 {
		m := copy(e.buf[e.nbuf:], p)
		e.nbuf += m
		p = p[m:]
		if e.nbuf == len(e.buf) {
			if err := e.flush(e.nbuf); err != nil {
				return n - len(p), err
			}
		}
	}
	return n, nil
}

func (e *Encryptor) flush(n int) error {
	chunk := e.buf[:n]
	e.mode.CryptBlocks(chunk, chunk)
	e.mac.Write(chunk)
	if _, err := e.dst.Write(chunk); err != nil {
		e.err = fmt.Errorf("failed to write encrypted data: %w", err)
		return e.err
	}
	e.nbuf = 0
	return nil
}

// Close pads and encrypts the remaining data and writes the HMAC into the header.
// The destination is left positioned at the end of the encrypted stream.
func (e *Encryptor) Close() error {
	if e.err != nil {
		return e.err
	}
	if e.sum != nil {
		return nil
	}
	// nbuf < len(buf) and len(buf) is a multiple of the block size, so the padding always fits.
	padding := aes.BlockSize - e.nbuf%aes.BlockSize
	for i := range padding {
		e.buf[e.nbuf+i] = byte(padding) // padding is in [1, aes.BlockSize]
	}
	if err := e.flush(e.nbuf + padding); err != nil {
		return err
	}
	e.sum = e.mac.Sum(nil)

	if _, err := e.dst.Seek(e.start, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek to HMAC position: %w", err)
	}
	if _, err := e.dst.Write(e.sum); err != nil {
		return fmt.Errorf("failed to write HMAC: %w", err)
	}
	if _, err := e.dst.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("failed to seek to end of output: %w", err)
	}
	return nil
}

// Mac returns the HMAC of the encrypted stream. It is only available after Close.
func (e *Encryptor) Mac() []byte {
	return bytes.Clone(e.sum)
}

// VerifyMac reads an entire encrypted stream from src, verifies its HMAC with macKey
// and returns the HMAC stored in the stream.
func VerifyMac(src io.Reader, macKey []byte) ([]byte, error) {
	if len(macKey) != KeySize {
		return nil, fmt.Errorf("MAC key must be %d bytes, got %d", KeySize, len(macKey))
	}
	stored := make([]byte, MacSize)
	if _, err := io.ReadFull(src, stored); err != nil {
		return nil, fmt.Errorf("failed to read HMAC: %w", err)
	}
	mac := hmac.New(sha256.New, macKey)
	n, err := io.Copy(mac, src)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted data: %w", err)
	}
	if n < IVSize+aes.BlockSize {
		return nil, errors.New("encrypted data is truncated")
	}
	if !hmac.Equal(stored, mac.Sum(nil)) {
		return nil, ErrMacMismatch
	}
	return stored, nil
}

// Decrypt streams the plaintext of the encrypted stream src into dst.
//
// Decrypt does NOT authenticate the data; call VerifyMac on the same stream first.
func Decrypt(dst io.Writer, src io.Reader, encryptionKey []byte) error {
	if len(encryptionKey) != KeySize {
		return fmt.Errorf("encryption key must be %d bytes, got %d", KeySize, len(encryptionKey))
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, header[MacSize:])

	// The last block holds the padding, so it is withheld until the end of the stream.
	buf := make([]byte, chunkSize)
	var tail [aes.BlockSize]byte
	haveTail := false
	for {
		n, rerr := io.ReadFull(src, buf)
		if n > 0 {
			if n%aes.BlockSize != 0 {
				return errors.New("encrypted data length is not a multiple of the block size")
			}
			chunk := buf[:n]
			mode.CryptBlocks(chunk, chunk)
			if haveTail {
				if _, err := dst.Write(tail[:]); err != nil {
					return fmt.Errorf("failed to write decrypted data: %w", err)
				}
			}
			if _, err := dst.Write(chunk[:n-aes.BlockSize]); err != nil {
				return fmt.Errorf("failed to write decrypted data: %w", err)
			}
			copy(tail[:], chunk[n-aes.BlockSize:])
			haveTail = true
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
			break
		}
		if rerr != nil {
			return fmt.Errorf("failed to read encrypted data: %w", rerr)
		}
	}
	if !haveTail {
		return errors.New("encrypted data is empty")
	}

	last, err := pkcs7Unpad(tail[:])
	if err != nil {
		return fmt.Errorf("failed to remove padding: %w", err)
	}
	if _, err := dst.Write(last); err != nil {
		return fmt.Errorf("failed to write decrypted data: %w", err)
	}
	return nil
}

// pkcs7Unpad removes PKCS#7 padding from the final block.
func pkcs7Unpad(block []byte) ([]byte, error) {
	if len(block) != aes.BlockSize {
		return nil, errors.New("invalid block length")
	}
	padding := int(block[len(block)-1])
	if padding == 0 || padding > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}
	for _, b := range block[len(block)-padding:] {
		if int(b) != padding {
			return nil, errors.New("invalid padding")
		}
	}
	return block[:len(block)-padding], nil
}
