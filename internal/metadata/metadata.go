package metadata

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kenchan0130/intunewin/internal/crypto"
)

// Metadata represents the Detection.xml structure
type Metadata struct {
	ToolVersion         string
	Name                string
	Description         string
	UnencryptedFileSize int64
	FileName            string
	SetupFile           string
	EncryptionInfo      *crypto.EncryptionInfo
}

// New creates a new Metadata instance
func New(fileName string, unencryptedSize int64, encInfo *crypto.EncryptionInfo) *Metadata {
	// Remove extension from fileName to create the .intunewin name
	baseName := strings.TrimSuffix(fileName, filepath.Ext(fileName))

	return &Metadata{
		ToolVersion:         "1.4.0.0",
		Name:                fileName,
		Description:         "",
		UnencryptedFileSize: unencryptedSize,
		FileName:            baseName + ".intunewin",
		SetupFile:           "",
		EncryptionInfo:      encInfo,
	}
}

// ToXML converts metadata to XML
func (m *Metadata) ToXML() ([]byte, error) {
	appInfo := NewApplicationInfo(m.Name, m.SetupFile, m.UnencryptedFileSize, m.EncryptionInfo)
	return appInfo.ToXML()
}

// FromXML parses metadata from XML
func FromXML(data []byte) (*Metadata, error) {
	appInfo, err := FromXMLBytes(data)
	if err != nil {
		return nil, err
	}

	encInfo, err := appInfo.EncryptionInfo.ToEncryptionInfo()
	if err != nil {
		return nil, err
	}

	return &Metadata{
		ToolVersion:         appInfo.ToolVersion,
		Name:                appInfo.Name,
		Description:         appInfo.Description,
		UnencryptedFileSize: appInfo.UnencryptedContentSize,
		FileName:            appInfo.FileName,
		SetupFile:           appInfo.SetupFile,
		EncryptionInfo:      encInfo,
	}, nil
}

// Validate checks if metadata is valid
func (m *Metadata) Validate() error {
	if m.UnencryptedFileSize <= 0 {
		return fmt.Errorf("unencryptedFileSize must be positive")
	}
	if m.EncryptionInfo == nil {
		return fmt.Errorf("encryptionInfo is required")
	}
	if len(m.EncryptionInfo.EncryptionKey) == 0 {
		return fmt.Errorf("encryptionKey is required")
	}
	if len(m.EncryptionInfo.MacKey) == 0 {
		return fmt.Errorf("macKey is required")
	}
	if len(m.EncryptionInfo.InitializationVector) == 0 {
		return fmt.Errorf("initializationVector is required")
	}
	return nil
}
