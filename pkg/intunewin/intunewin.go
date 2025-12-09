package intunewin

import (
	"io"

	"github.com/kenchan0130/intunewin/internal/pack"
	"github.com/kenchan0130/intunewin/internal/unpack"
)

// PackReader creates an intunewin package from a zip stream.
// zipReader: io.Reader containing a zip archive of files to pack
// name: Application name for metadata
// setupFile: Setup file name within the content file
// Returns an io.Reader for the encrypted intunewin package and error if packing fails.
func PackReader(zipReader io.Reader, name, setupFile string) (io.Reader, error) {
	return pack.PackReaderFromZip(zipReader, name, setupFile)
}

// UnpackReader extracts an intunewin package and returns a zip stream.
// input: io.Reader containing the intunewin package
// Returns an io.Reader containing the decrypted zip archive and error if unpacking fails.
func UnpackReader(input io.Reader) (io.Reader, error) {
	return unpack.UnpackReaderToZip(input)
}
