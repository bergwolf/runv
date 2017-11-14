//
// Copyright (c) 2017 HyperHQ Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package virtcontainers

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/kr/pty"
	"github.com/opencontainers/runc/libcontainer/utils"
)

type runvShim struct{}

type RunvShimConfig struct {
	Path  string
	Debug bool
}

func sendtty(consoleSocket string, pty *os.File) error {
	// the caller of runc will handle receiving the console master
	conn, err := net.Dial("unix", consoleSocket)
	if err != nil {
		return err
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("casting to UnixConn failed")
	}
	socket, err := uc.File()
	if err != nil {
		return err
	}

	return utils.SendFd(socket, pty)
}

func (r *runvShim) start(pod Pod, params ShimParams) (int, error) {
	if pod.config == nil {
		return -1, fmt.Errorf("Pod does not have config")
	}
	config, ok := newShimConfig(*(pod.config)).(RunvShimConfig)
	if !ok {
		return -1, fmt.Errorf("Wrong shim config type, should be RunvShimConfig type")
	}

	var err error
	var ptymaster, tty *os.File
	if len(params.Console) != 0 {
		tty, err = os.OpenFile(params.Console, os.O_RDWR, 0)
		if err != nil {
			return -1, err
		}
	} else if len(params.ConsoleSocket) != 0 {
		ptymaster, tty, err = pty.Open()
		if err != nil {
			return -1, err
		}
		if err = sendtty(params.ConsoleSocket, ptymaster); err != nil {
			return -1, err
		}
		ptymaster.Close()
	}

	args := []string{"runv", "--root", params.Root}
	args = append(args, "shim", "--container", params.Container, "--process", params.Process)
	args = append(args, "--proxy-stdio", "--proxy-exit-code", "--proxy-signal")
	if params.ProxyWinsize {
		args = append(args, "--proxy-winsize")
	}
	if config.Debug {
		args = append(args, "--debug")
	}
	cmd := exec.Cmd{
		Path: config.Path,
		Args: args,
		SysProcAttr: &syscall.SysProcAttr{
			Setctty: tty != nil,
			Setsid:  tty != nil || params.Detach,
		},
	}

	if tty == nil {
		// inherit stdio/tty
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		defer tty.Close()
		cmd.Stdin = tty
		cmd.Stdout = tty
		cmd.Stderr = tty
	}

	err = cmd.Start()
	if err != nil {
		return -1, err
	}

	return cmd.Process.Pid, nil
}
