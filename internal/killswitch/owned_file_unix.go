//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package killswitch

import (
	"fmt"
	"os"
	"syscall"
)

func withPublishLock(dir string, fn func() error) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = syscall.Flock(int(d.Fd()), syscall.LOCK_UN) }()
	return fn()
}

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

func requireOwner(st os.FileInfo) error {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid == uint32(os.Geteuid()) {
		return nil
	}
	return fmt.Errorf("invalid ownership")
}
