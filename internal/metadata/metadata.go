// Package metadata reads and writes the Detection.xml file of an .intunewin package.
package metadata

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/kenchan0130/intunewin/internal/crypto"
)

const (
	// ToolVersion is the IntuneWinAppUtil version this implementation identifies as.
	ToolVersion = "1.8.7.0"
	// ContentFileName is the name of the encrypted content file inside the package.
	ContentFileName = "IntunePackage.intunewin"
	// ProfileIdentifier is the encryption profile used by IntuneWinAppUtil.
	ProfileIdentifier = "ProfileVersion1"
	// FileDigestAlgorithm is the digest algorithm used for FileDigest.
	FileDigestAlgorithm = "SHA256"

	// DetectionPath is the location of Detection.xml inside the outer package zip.
	DetectionPath = "IntuneWinPackage/Metadata/Detection.xml"
	// ContentPath is the location of the encrypted content inside the outer package zip.
	ContentPath = "IntuneWinPackage/Contents/" + ContentFileName

	// MaxSize is the largest Detection.xml accepted when parsing.
	MaxSize = 1 << 20
	// MaxContentSize is the largest UnencryptedContentSize accepted when parsing, chosen so
	// that the encrypted size cannot overflow int64.
	MaxContentSize = math.MaxInt64 - crypto.HeaderSize - 2*crypto.IVSize

	digestSize = 32
)

// Info is the content of Detection.xml.
type Info struct {
	ToolVersion            string
	Name                   string
	Description            string
	UnencryptedContentSize int64
	FileName               string
	SetupFile              string
	EncryptionInfo         EncryptionInfo
}

// EncryptionInfo holds the encryption parameters of the package content.
// These values are also what the Microsoft Graph API expects as fileEncryptionInfo
// when uploading the content of a Win32 app.
type EncryptionInfo struct {
	EncryptionKey        []byte
	MacKey               []byte
	InitializationVector []byte
	Mac                  []byte
	ProfileIdentifier    string
	FileDigest           []byte
	FileDigestAlgorithm  string
}

// xmlApplicationInfo is the on-disk XML representation of Info.
type xmlApplicationInfo struct {
	XMLName                xml.Name           `xml:"ApplicationInfo"`
	XMLXSD                 string             `xml:"xmlns:xsd,attr"`
	XMLXSI                 string             `xml:"xmlns:xsi,attr"`
	ToolVersion            string             `xml:"ToolVersion,attr"`
	Name                   string             `xml:"Name"`
	Description            string             `xml:"Description,omitempty"`
	UnencryptedContentSize int64              `xml:"UnencryptedContentSize"`
	FileName               string             `xml:"FileName"`
	SetupFile              string             `xml:"SetupFile"`
	EncryptionInfo         *xmlEncryptionInfo `xml:"EncryptionInfo"`
}

type xmlEncryptionInfo struct {
	EncryptionKey        string `xml:"EncryptionKey"`
	MacKey               string `xml:"MacKey"`
	InitializationVector string `xml:"InitializationVector"`
	Mac                  string `xml:"Mac"`
	ProfileIdentifier    string `xml:"ProfileIdentifier"`
	FileDigest           string `xml:"FileDigest"`
	FileDigestAlgorithm  string `xml:"FileDigestAlgorithm"`
}

// Marshal encodes info as Detection.xml.
//
// No XML declaration is emitted, matching the reference implementation
// (simeoncloud/IntuneAppBuilder).
func Marshal(info *Info) ([]byte, error) {
	enc := base64.StdEncoding.EncodeToString
	ei := info.EncryptionInfo
	doc := xmlApplicationInfo{
		XMLXSD:                 "http://www.w3.org/2001/XMLSchema",
		XMLXSI:                 "http://www.w3.org/2001/XMLSchema-instance",
		ToolVersion:            info.ToolVersion,
		Name:                   info.Name,
		Description:            info.Description,
		UnencryptedContentSize: info.UnencryptedContentSize,
		FileName:               info.FileName,
		SetupFile:              info.SetupFile,
		EncryptionInfo: &xmlEncryptionInfo{
			EncryptionKey:        enc(ei.EncryptionKey),
			MacKey:               enc(ei.MacKey),
			InitializationVector: enc(ei.InitializationVector),
			Mac:                  enc(ei.Mac),
			ProfileIdentifier:    ei.ProfileIdentifier,
			FileDigest:           enc(ei.FileDigest),
			FileDigestAlgorithm:  ei.FileDigestAlgorithm,
		},
	}
	out, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Detection.xml: %w", err)
	}
	// IntuneWinAppUtil writes CRLF line endings. Newlines in values are escaped by the
	// encoder, so every newline here is part of the indentation.
	return bytes.ReplaceAll(out, []byte("\n"), []byte("\r\n")), nil
}

// Parse decodes and validates Detection.xml.
func Parse(data []byte) (*Info, error) {
	var doc xmlApplicationInfo
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("failed to parse Detection.xml: %w", err)
	}
	if doc.EncryptionInfo == nil {
		return nil, errors.New("detection.xml has no EncryptionInfo element")
	}
	if doc.UnencryptedContentSize <= 0 || doc.UnencryptedContentSize > MaxContentSize {
		return nil, fmt.Errorf("detection.xml has invalid UnencryptedContentSize %d", doc.UnencryptedContentSize)
	}
	x := doc.EncryptionInfo
	if !strings.EqualFold(x.FileDigestAlgorithm, FileDigestAlgorithm) {
		return nil, fmt.Errorf("unsupported FileDigestAlgorithm %q", x.FileDigestAlgorithm)
	}

	info := &Info{
		ToolVersion:            doc.ToolVersion,
		Name:                   doc.Name,
		Description:            doc.Description,
		UnencryptedContentSize: doc.UnencryptedContentSize,
		FileName:               doc.FileName,
		SetupFile:              doc.SetupFile,
		EncryptionInfo: EncryptionInfo{
			ProfileIdentifier:   x.ProfileIdentifier,
			FileDigestAlgorithm: x.FileDigestAlgorithm,
		},
	}
	ei := &info.EncryptionInfo
	fields := []struct {
		name  string
		value string
		size  int
		dst   *[]byte
	}{
		{"EncryptionKey", x.EncryptionKey, crypto.KeySize, &ei.EncryptionKey},
		{"MacKey", x.MacKey, crypto.KeySize, &ei.MacKey},
		{"InitializationVector", x.InitializationVector, crypto.IVSize, &ei.InitializationVector},
		{"Mac", x.Mac, crypto.MacSize, &ei.Mac},
		{"FileDigest", x.FileDigest, digestSize, &ei.FileDigest},
	}
	for _, f := range fields {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(f.value))
		if err != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", f.name, err)
		}
		if len(b) != f.size {
			return nil, fmt.Errorf("%s must be %d bytes, got %d", f.name, f.size, len(b))
		}
		*f.dst = b
	}
	return info, nil
}
