// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package utils

import (
	"os/exec"
	"strconv"
	"syscall"
)

func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	cmd.SysProcAttr.CreationFlags |= syscall.CREATE_NEW_PROCESS_GROUP
}

func signalProcessGroup(cmd *exec.Cmd, _ syscall.Signal) error {
	kill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))

	return kill.Run()
}
