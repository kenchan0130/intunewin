package metadata

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleInfo() *Info {
	return &Info{
		ToolVersion:            ToolVersion,
		Name:                   "setup.exe",
		UnencryptedContentSize: 1234,
		FileName:               ContentFileName,
		SetupFile:              "setup.exe",
		EncryptionInfo: EncryptionInfo{
			EncryptionKey:        bytes.Repeat([]byte{1}, 32),
			MacKey:               bytes.Repeat([]byte{2}, 32),
			InitializationVector: bytes.Repeat([]byte{3}, 16),
			Mac:                  bytes.Repeat([]byte{4}, 32),
			ProfileIdentifier:    ProfileIdentifier,
			FileDigest:           bytes.Repeat([]byte{5}, 32),
			FileDigestAlgorithm:  FileDigestAlgorithm,
		},
	}
}

func TestMarshalStructure(t *testing.T) {
	data, err := Marshal(sampleInfo())
	require.NoError(t, err)
	s := string(data)

	assert.True(t, strings.HasPrefix(s, `<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.4.0.0">`), s)
	assert.NotContains(t, s, "<?xml")
	assert.NotContains(t, s, "<Description>", "empty Description must be omitted")

	// Element order matters for some consumers; keep it identical to IntuneWinAppUtil.
	order := []string{
		"<Name>setup.exe</Name>",
		"<UnencryptedContentSize>1234</UnencryptedContentSize>",
		"<FileName>IntunePackage.intunewin</FileName>",
		"<SetupFile>setup.exe</SetupFile>",
		"<EncryptionInfo>",
		"<EncryptionKey>" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "</EncryptionKey>",
		"<MacKey>",
		"<InitializationVector>",
		"<Mac>",
		"<ProfileIdentifier>ProfileVersion1</ProfileIdentifier>",
		"<FileDigest>",
		"<FileDigestAlgorithm>SHA256</FileDigestAlgorithm>",
	}
	pos := 0
	for _, el := range order {
		i := strings.Index(s[pos:], el)
		require.GreaterOrEqual(t, i, 0, "%s missing or out of order", el)
		pos += i + len(el)
	}
}

func TestRoundTrip(t *testing.T) {
	in := sampleInfo()
	in.Description = "desc"
	data, err := Marshal(in)
	require.NoError(t, err)

	out, err := Parse(data)
	require.NoError(t, err)
	assert.Equal(t, in, out)
}

func TestParseErrors(t *testing.T) {
	valid, err := Marshal(sampleInfo())
	require.NoError(t, err)
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	encKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))

	tests := map[string]struct {
		xml  string
		want string
	}{
		"not xml":                {"not xml", "failed to parse"},
		"missing EncryptionInfo": {"<ApplicationInfo><UnencryptedContentSize>1</UnencryptedContentSize></ApplicationInfo>", "no EncryptionInfo"},
		"zero size":              {strings.Replace(string(valid), ">1234<", ">0<", 1), "UnencryptedContentSize"},
		"overflowing size":       {strings.Replace(string(valid), ">1234<", ">9223372036854775807<", 1), "UnencryptedContentSize"},
		"bad base64":             {strings.Replace(string(valid), encKey, "!!!", 1), "failed to decode EncryptionKey"},
		"short key":              {strings.Replace(string(valid), encKey, b64(16), 1), "EncryptionKey must be 32 bytes"},
		"wrong algorithm":        {strings.Replace(string(valid), ">SHA256<", ">MD5<", 1), "unsupported FileDigestAlgorithm"},
	}
	for name, tt := range tests {
		_, err := Parse([]byte(tt.xml))
		assert.ErrorContains(t, err, tt.want, name)
	}
}
