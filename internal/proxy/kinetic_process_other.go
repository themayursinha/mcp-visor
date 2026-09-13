//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package proxy

import "os/exec"

func configureKineticProcess(cmd *exec.Cmd) {}

func killKineticProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
