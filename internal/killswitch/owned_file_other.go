//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package killswitch

import "os"

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY, 0)
}

func requireOwner(os.FileInfo) error { return nil }
