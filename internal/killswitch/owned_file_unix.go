//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package killswitch

import (
	"fmt"
	"os"
	"syscall"
)

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func requireOwner(st os.FileInfo) error {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid == uint32(os.Geteuid()) {
		return nil
	}
	return fmt.Errorf("invalid ownership")
}
