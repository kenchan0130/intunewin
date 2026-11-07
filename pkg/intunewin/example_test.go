package intunewin_test

import (
	"log"
	"os"

	"github.com/kenchan0130/intunewin/pkg/intunewin"
)

// This example mirrors the README. It is compiled (not run) by go test.
func Example() {
	// Folder to file
	if err := intunewin.PackDir("./myapp", "myapp.intunewin", intunewin.PackDirOptions{
		Options: intunewin.PackOptions{SetupFile: "setup.exe"},
		Exclude: []string{".DS_Store"},
	}); err != nil {
		log.Fatal(err)
	}

	// Read Detection.xml (including the values needed for a Microsoft Graph upload)
	f, err := os.Open("myapp.intunewin")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	info, err := intunewin.ReadInfo(f, st.Size())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("name=%s setup=%s size=%d", info.Name, info.SetupFile, info.UnencryptedContentSize)

	// File to folder
	if err := intunewin.UnpackDir("myapp.intunewin", "./extracted"); err != nil {
		log.Fatal(err)
	}
}
