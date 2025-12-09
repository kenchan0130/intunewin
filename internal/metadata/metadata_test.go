package metadata

import (
	"testing"

	"github.com/kenchan0130/intunewin/internal/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	encInfo := &crypto.EncryptionInfo{
		EncryptionKey:        make([]byte, 32),
		MacKey:               make([]byte, 32),
		InitializationVector: make([]byte, 16),
		Mac:                  make([]byte, 32),
		FileDigest:           make([]byte, 32),
		ProfileIdentifier:    "ProfileVersion1",
		FileDigestAlgorithm:  "SHA256",
	}

	meta := New("test.zip", 1000, encInfo)

	assert.Equal(t, "test.intunewin", meta.FileName)
	assert.Equal(t, int64(1000), meta.UnencryptedFileSize)
	assert.Equal(t, encInfo, meta.EncryptionInfo)
}

func TestToXML(t *testing.T) {
	encInfo := &crypto.EncryptionInfo{
		EncryptionKey:        []byte{1, 2, 3},
		MacKey:               []byte{4, 5, 6},
		InitializationVector: []byte{7, 8, 9},
		Mac:                  []byte{10, 11, 12},
		FileDigest:           []byte{13, 14, 15},
		ProfileIdentifier:    "ProfileVersion1",
		FileDigestAlgorithm:  "SHA256",
	}

	meta := New("test.zip", 1000, encInfo)

	xmlData, err := meta.ToXML()
	require.NoError(t, err)
	assert.NotEmpty(t, xmlData)
	assert.Contains(t, string(xmlData), "test.zip")
}

func TestFromXML(t *testing.T) {
	// Use longer byte slices to ensure they're valid
	encInfo := &crypto.EncryptionInfo{
		EncryptionKey:        make([]byte, 32),
		MacKey:               make([]byte, 32),
		InitializationVector: make([]byte, 16),
		Mac:                  make([]byte, 32),
		FileDigest:           make([]byte, 32),
		ProfileIdentifier:    "ProfileVersion1",
		FileDigestAlgorithm:  "SHA256",
	}
	// Fill with test data
	for i := range encInfo.EncryptionKey {
		encInfo.EncryptionKey[i] = byte(i)
	}
	for i := range encInfo.MacKey {
		encInfo.MacKey[i] = byte(i + 32)
	}
	for i := range encInfo.InitializationVector {
		encInfo.InitializationVector[i] = byte(i + 64)
	}

	meta := New("test.zip", 1000, encInfo)

	xmlData, err := meta.ToXML()
	require.NoError(t, err)

	meta2, err := FromXML(xmlData)
	require.NoError(t, err)

	// FileName is always "IntunePackage.intunewin" in the XML format
	assert.Equal(t, "IntunePackage.intunewin", meta2.FileName)
	assert.Equal(t, meta.Name, meta2.Name)
	assert.Equal(t, meta.UnencryptedFileSize, meta2.UnencryptedFileSize)
	assert.Equal(t, meta.EncryptionInfo.EncryptionKey, meta2.EncryptionInfo.EncryptionKey)
	assert.Equal(t, meta.EncryptionInfo.MacKey, meta2.EncryptionInfo.MacKey)
	assert.Equal(t, meta.EncryptionInfo.InitializationVector, meta2.EncryptionInfo.InitializationVector)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name      string
		meta      *Metadata
		wantError bool
		errMsg    string
	}{
		{
			name: "Valid metadata",
			meta: &Metadata{
				FileName:            "test.zip",
				UnencryptedFileSize: 1000,
				EncryptionInfo: &crypto.EncryptionInfo{
					EncryptionKey:        make([]byte, 32),
					MacKey:               make([]byte, 32),
					InitializationVector: make([]byte, 16),
				},
			},
			wantError: false,
		},
		{
			name: "Empty file name is allowed",
			meta: &Metadata{
				FileName:            "",
				UnencryptedFileSize: 1000,
				EncryptionInfo: &crypto.EncryptionInfo{
					EncryptionKey:        make([]byte, 32),
					MacKey:               make([]byte, 32),
					InitializationVector: make([]byte, 16),
				},
			},
			wantError: false,
		},
		{
			name: "Invalid unencrypted size",
			meta: &Metadata{
				FileName:            "test.zip",
				UnencryptedFileSize: 0,
				EncryptionInfo: &crypto.EncryptionInfo{
					EncryptionKey:        make([]byte, 32),
					MacKey:               make([]byte, 32),
					InitializationVector: make([]byte, 16),
				},
			},
			wantError: true,
			errMsg:    "unencryptedFileSize must be positive",
		},
		{
			name: "Missing encryption info",
			meta: &Metadata{
				FileName:            "test.zip",
				UnencryptedFileSize: 1000,
				EncryptionInfo:      nil,
			},
			wantError: true,
			errMsg:    "encryptionInfo is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.meta.Validate()
			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
