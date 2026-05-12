//go:build !unix

package main

import (
	"errors"
	"os"
)

func openRegularFromKeyFile(_ string) (*os.File, error) {
	return nil, errors.New("from-key-file unsupported on this platform")
}
