package metadata

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"

	"github.com/kenchan0130/intunewin/internal/crypto"
)

// ApplicationInfo represents the XML structure for Detection.xml
type ApplicationInfo struct {
	XMLName                xml.Name           `xml:"ApplicationInfo"`
	XMLXSD                 string             `xml:"xmlns:xsd,attr"`
	XMLXSI                 string             `xml:"xmlns:xsi,attr"`
	ToolVersion            string             `xml:"ToolVersion,attr"`
	Name                   string             `xml:"Name"`
	Description            string             `xml:"Description,omitempty"`
	UnencryptedContentSize int64              `xml:"UnencryptedContentSize"`
	FileName               string             `xml:"FileName"`
	SetupFile              string             `xml:"SetupFile"`
	EncryptionInfo         *XMLEncryptionInfo `xml:"EncryptionInfo"`
}

// XMLEncryptionInfo represents the encryption information in XML format
type XMLEncryptionInfo struct {
	EncryptionKey        string `xml:"EncryptionKey"`
	MacKey               string `xml:"MacKey"`
	InitializationVector string `xml:"InitializationVector"`
	Mac                  string `xml:"Mac"`
	ProfileIdentifier    string `xml:"ProfileIdentifier"`
	FileDigest           string `xml:"FileDigest"`
	FileDigestAlgorithm  string `xml:"FileDigestAlgorithm"`
}

// NewApplicationInfo creates ApplicationInfo from encryption info
func NewApplicationInfo(name, setupFile string, unencryptedSize int64, encInfo *crypto.EncryptionInfo) *ApplicationInfo {
	return &ApplicationInfo{
		XMLXSD:                 "http://www.w3.org/2001/XMLSchema",
		XMLXSI:                 "http://www.w3.org/2001/XMLSchema-instance",
		ToolVersion:            "1.4.0.0",
		Name:                   name,
		UnencryptedContentSize: unencryptedSize,
		FileName:               "IntunePackage.intunewin",
		SetupFile:              setupFile,
		EncryptionInfo: &XMLEncryptionInfo{
			EncryptionKey:        base64.StdEncoding.EncodeToString(encInfo.EncryptionKey),
			MacKey:               base64.StdEncoding.EncodeToString(encInfo.MacKey),
			InitializationVector: base64.StdEncoding.EncodeToString(encInfo.InitializationVector),
			Mac:                  base64.StdEncoding.EncodeToString(encInfo.Mac),
			ProfileIdentifier:    encInfo.ProfileIdentifier,
			FileDigest:           base64.StdEncoding.EncodeToString(encInfo.FileDigest),
			FileDigestAlgorithm:  encInfo.FileDigestAlgorithm,
		},
	}
}

// ToXML converts ApplicationInfo to XML bytes
func (a *ApplicationInfo) ToXML() ([]byte, error) {
	output, err := xml.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ApplicationInfo to XML: %w", err)
	}
	// Don't add XML declaration to match the original tool's format
	return output, nil
}

// FromXMLBytes parses ApplicationInfo from XML bytes
func FromXMLBytes(data []byte) (*ApplicationInfo, error) {
	var appInfo ApplicationInfo
	if err := xml.Unmarshal(data, &appInfo); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ApplicationInfo from XML: %w", err)
	}
	return &appInfo, nil
}

// ToEncryptionInfo converts XMLEncryptionInfo to crypto.EncryptionInfo
func (x *XMLEncryptionInfo) ToEncryptionInfo() (*crypto.EncryptionInfo, error) {
	encKey, err := base64.StdEncoding.DecodeString(x.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %w", err)
	}

	macKey, err := base64.StdEncoding.DecodeString(x.MacKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC key: %w", err)
	}

	iv, err := base64.StdEncoding.DecodeString(x.InitializationVector)
	if err != nil {
		return nil, fmt.Errorf("failed to decode IV: %w", err)
	}

	mac, err := base64.StdEncoding.DecodeString(x.Mac)
	if err != nil {
		return nil, fmt.Errorf("failed to decode MAC: %w", err)
	}

	fileDigest, err := base64.StdEncoding.DecodeString(x.FileDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file digest: %w", err)
	}

	return &crypto.EncryptionInfo{
		EncryptionKey:        encKey,
		MacKey:               macKey,
		InitializationVector: iv,
		Mac:                  mac,
		ProfileIdentifier:    x.ProfileIdentifier,
		FileDigest:           fileDigest,
		FileDigestAlgorithm:  x.FileDigestAlgorithm,
	}, nil
}
