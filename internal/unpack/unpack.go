// Package unpack reads .intunewin packages.
package unpack

import (
	"archive/zip"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/kenchan0130/intunewin/internal/crypto"
	"github.com/kenchan0130/intunewin/internal/metadata"
)

// Package is an opened .intunewin package.
type Package struct {
	info    *metadata.Info
	content *zip.File
}

// Open parses the outer zip and Detection.xml of the package in r.
func Open(r io.ReaderAt, size int64) (*Package, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("failed to open intunewin package: %w", err)
	}

	var detection, content *zip.File
	for _, f := range zr.File {
		var slot **zip.File
		switch f.Name {
		case metadata.DetectionPath:
			slot = &detection
		case metadata.ContentPath:
			slot = &content
		default:
			continue
		}
		if *slot != nil {
			return nil, fmt.Errorf("intunewin package contains %s more than once", f.Name)
		}
		*slot = f
	}
	if detection == nil {
		return nil, fmt.Errorf("%s not found in intunewin package", metadata.DetectionPath)
	}
	if content == nil {
		return nil, fmt.Errorf("%s not found in intunewin package", metadata.ContentPath)
	}

	data, err := readSmall(detection, metadata.MaxSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read Detection.xml: %w", err)
	}
	info, err := metadata.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("invalid Detection.xml: %w", err)
	}

	want := crypto.EncryptedSize(info.UnencryptedContentSize)
	if content.UncompressedSize64 != uint64(want) { //nolint:gosec // want is positive: metadata.Parse bounds UnencryptedContentSize
		return nil, fmt.Errorf("encrypted content is %d bytes but Detection.xml implies %d", content.UncompressedSize64, want)
	}
	return &Package{info: info, content: content}, nil
}

func readSmall(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

// Info returns the parsed Detection.xml.
func (p *Package) Info() *metadata.Info {
	return p.info
}

// Decrypt verifies the package and writes the decrypted content (a zip archive) to dst.
//
// The HMAC is verified before any plaintext is written. The file digest and size are
// verified while streaming; if they do not match, an error is returned after the data
// has been written, and the output must be discarded.
func (p *Package) Decrypt(dst io.Writer) error {
	ei := p.info.EncryptionInfo

	rc, err := p.content.Open()
	if err != nil {
		return fmt.Errorf("failed to open encrypted content: %w", err)
	}
	mac, err := crypto.VerifyMac(rc, ei.MacKey)
	_ = rc.Close()
	if err != nil {
		return fmt.Errorf("failed to verify encrypted content: %w", err)
	}
	if !hmac.Equal(mac, ei.Mac) {
		return errors.New("HMAC of the encrypted content does not match Detection.xml")
	}

	rc, err = p.content.Open()
	if err != nil {
		return fmt.Errorf("failed to open encrypted content: %w", err)
	}
	defer rc.Close()
	digest := sha256.New()
	var n countWriter
	if err := crypto.Decrypt(io.MultiWriter(dst, digest, &n), rc, ei.EncryptionKey); err != nil {
		return fmt.Errorf("failed to decrypt content: %w", err)
	}
	if n.n != p.info.UnencryptedContentSize {
		return fmt.Errorf("decrypted content is %d bytes but Detection.xml says %d", n.n, p.info.UnencryptedContentSize)
	}
	if !bytes.Equal(digest.Sum(nil), ei.FileDigest) {
		return errors.New("digest of the decrypted content does not match Detection.xml")
	}
	return nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// Dir extracts the .intunewin file inputFile into outputDir.
//
// Extraction is confined to outputDir: entries with absolute or parent-relative paths
// are rejected, and existing symbolic links cannot redirect writes outside of it.
func Dir(inputFile, outputDir string) error {
	in, err := os.Open(inputFile)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("input file does not exist: %s", inputFile)
		}
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return fmt.Errorf("failed to access input file: %w", err)
	}
	pkg, err := Open(in, st.Size())
	if err != nil {
		return err
	}

	// The decrypted content is as large as the package, so keep it on the output volume
	// rather than in os.TempDir. The output directory itself is only created after the
	// package has been verified.
	tmp, err := os.CreateTemp(nearestExistingDir(outputDir), ".intunewin-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()
	if err := pkg.Decrypt(tmp); err != nil {
		return err
	}
	zr, err := zip.NewReader(tmp, pkg.info.UnencryptedContentSize)
	if err != nil {
		return fmt.Errorf("failed to read decrypted content: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	root, err := os.OpenRoot(outputDir)
	if err != nil {
		return fmt.Errorf("failed to open output directory: %w", err)
	}
	defer root.Close()

	for _, f := range zr.File {
		if err := extract(root, f); err != nil {
			return err
		}
	}
	return nil
}

// nearestExistingDir returns dir or its closest existing ancestor.
func nearestExistingDir(dir string) string {
	for d := filepath.Clean(dir); ; {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

// entryPath converts a zip entry name into a local path relative to the output root.
func entryPath(name string) (p string, isDir bool, err error) {
	slashed := strings.ReplaceAll(name, `\`, "/")
	isDir = strings.HasSuffix(slashed, "/")
	trimmed := strings.TrimRight(slashed, "/")
	p = filepath.Clean(filepath.FromSlash(trimmed))
	if trimmed == "" || !filepath.IsLocal(p) {
		return "", false, fmt.Errorf("invalid file path in package: %q", name)
	}
	return p, isDir, nil
}

func extract(root *os.Root, f *zip.File) error {
	p, isDir, err := entryPath(f.Name)
	if err != nil {
		return err
	}
	mode := f.Mode()
	if isDir || mode.IsDir() {
		// Keep the directory traversable and writable by the owner.
		if err := root.MkdirAll(p, mode.Perm()|0o700); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", f.Name, err)
		}
		return nil
	}

	if dir := filepath.Dir(p); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("failed to create directory for %s: %w", f.Name, err)
		}
	}
	// An existing symbolic link is replaced rather than written through, so that it
	// cannot redirect the write to another file in the output folder. O_EXCL makes the
	// write fail if a link is recreated in between.
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if info, err := root.Lstat(p); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		if err := root.Remove(p); err != nil {
			return fmt.Errorf("failed to replace symbolic link %s: %w", f.Name, err)
		}
		flags |= os.O_EXCL
	}
	// Only permission bits are honored; setuid/setgid/sticky and file types are dropped.
	out, err := root.OpenFile(p, flags, mode.Perm()|0o600)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", f.Name, err)
	}
	rc, err := f.Open()
	if err != nil {
		_ = out.Close()
		return fmt.Errorf("failed to open %s in package: %w", f.Name, err)
	}
	// archive/zip enforces the declared size and CRC; writing large content is the purpose of extraction.
	_, copyErr := io.Copy(out, rc) //nolint:gosec // G110: see above
	_ = rc.Close()
	closeErr := out.Close()
	if copyErr != nil {
		return fmt.Errorf("failed to extract %s: %w", f.Name, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("failed to write %s: %w", f.Name, closeErr)
	}
	return nil
}
