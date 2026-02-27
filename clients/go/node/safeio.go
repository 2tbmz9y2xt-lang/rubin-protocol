package node

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func readFileByPath(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	name := filepath.Base(path)
	return readFileFromDir(dir, name)
}

func readFileFromDir(dir, name string) ([]byte, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("invalid file name: %q", name)
	}
	return fs.ReadFile(os.DirFS(dir), name)
}
