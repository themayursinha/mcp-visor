//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package proxy

import (
	"os/exec"
	"syscall"
)

func configureKineticProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killKineticProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
}
