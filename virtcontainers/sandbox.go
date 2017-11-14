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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hyperhq/runv/api"
	"github.com/hyperhq/runv/factory"
	singlefactory "github.com/hyperhq/runv/factory/single"
	templatefactory "github.com/hyperhq/runv/factory/template"
	"github.com/hyperhq/runv/hyperstart/libhyperstart"
	"github.com/hyperhq/runv/hypervisor"
	templatecore "github.com/hyperhq/runv/template"
)

type HypervisorConfig struct {
	// KernelPath is the guest kernel host path.
	KernelPath string

	// InitrdPath is the guest initrd host path.
	InitrdPath string

	// ImagePath is the guest image host path.
	ImagePath string

	// FirmwarePath is the bios host path
	FirmwarePath string

	// MachineAccelerators are machine specific accelerators
	MachineAccelerators string

	// HypervisorPath is the hypervisor executable host path.
	HypervisorPath string

	// DisableBlockDeviceUse disallows a block device from being used.
	DisableBlockDeviceUse bool

	// KernelParams are additional guest kernel parameters.
	KernelParams []string

	// HypervisorParams are additional hypervisor parameters.
	HypervisorParams []string

	// HypervisorMachineType specifies the type of machine being
	// emulated.
	HypervisorMachineType string

	// Debug changes the default hypervisor and kernel parameters to
	// enable debug output where available.
	Debug bool

	// DefaultVCPUs specifies default number of vCPUs for the VM.
	// Pod configuration VMConfig.VCPUs overwrites this.
	DefaultVCPUs uint32

	// DefaultMem specifies default memory size in MiB for the VM.
	// Pod configuration VMConfig.Memory overwrites this.
	DefaultMemSz uint32

	// MemPrealloc specifies if the memory should be pre-allocated
	MemPrealloc bool

	// HugePages specifies if the memory should be pre-allocated from huge pages
	HugePages bool

	// Realtime Used to enable/disable realtime
	Realtime bool

	// Mlock is used to control memory locking when Realtime is enabled
	// Realtime=true and Mlock=false, allows for swapping out of VM memory
	// enabling higher density
	Mlock bool

	// DisableNestingChecks is used to override customizations performed
	// when running on top of another VMM.
	DisableNestingChecks bool

	// Driver is the hypervisor driver type used to create guest
	Driver string

	// EnableVsock enables vsock suport
	EnableVsock bool

	// Template is the guest vm template path
	Template string
}

func setupFactory(p *PodConfig) (factory.Factory, error) {
	kernel := p.HypervisorConfig.KernelPath
	initrd := p.HypervisorConfig.InitrdPath
	bios := p.HypervisorConfig.FirmwarePath

	driver := p.HypervisorConfig.Driver
	vsock := p.HypervisorConfig.EnableVsock
	template := p.HypervisorConfig.Template

	var tconfig *templatecore.TemplateVmConfig
	if len(template) != 0 {
		path := filepath.Join(template, "config.json")
		f, err := os.Open(path)
		if err != nil {
			err = fmt.Errorf("open template JSON configuration file failed: %v", err)
			return nil, err
		}
		if err := json.NewDecoder(f).Decode(&tconfig); err != nil {
			err = fmt.Errorf("parse template JSON configuration file failed: %v", err)
			f.Close()
			return nil, err
		}
		f.Close()

		if (driver != "" && driver != tconfig.Driver) ||
			(kernel != "" && kernel != tconfig.Config.Kernel) ||
			(initrd != "" && initrd != tconfig.Config.Initrd) ||
			(bios != "" && bios != tconfig.Config.Bios) {
			template = ""
		} else if driver == "" {
			driver = tconfig.Driver
		}
	} else if bios == "" && (kernel == "" || initrd == "") {
		err := fmt.Errorf("argument kernel+initrd or bios must be set")
		return nil, err
	}

	if len(template) != 0 {
		return singlefactory.New(templatefactory.NewFromExisted(tconfig)), nil
	}
	bootConfig := hypervisor.BootConfig{
		Kernel:      kernel,
		Initrd:      initrd,
		Bios:        bios,
		EnableVsock: vsock,
	}
	return singlefactory.Dummy(bootConfig), nil
}

func sandboxConfigFromPodconfig(p *PodConfig) *api.SandboxConfig {
	return &api.SandboxConfig{Hostname: p.Hostname}
}

func createAndLockSandBox(f factory.Factory, p *Pod) (*hypervisor.Vm, *os.File, error) {
	setupHyperstartFunc(&proxyConfig{
		path:  "runv",
		root:  p.runPath,
		debug: true})
	vm, err := f.GetVm(int(p.config.VMConfig.VCPUs), int(p.config.VMConfig.Memory))
	if err != nil {
		return nil, nil, err
	}

	r := make(chan api.Result, 1)
	go func() {
		r <- vm.WaitInit()
	}()

	sandbox := sandboxConfigFromPodconfig(p.config)
	vm.InitSandbox(sandbox)

	rsp := <-r

	if !rsp.IsSuccess() {
		vm.Kill()
		return nil, nil, fmt.Errorf("StartPod fail")
	}

	lockFile, err := lockPod(p.id)
	if err != nil {
		vm.Kill()
		return nil, nil, err
	}

	// Create sandbox dir symbol link in pod root dir
	vmRootLinkPath := filepath.Join(p.runPath, "sandbox")
	vmRootPath := sandboxPath(vm)
	if err = os.Symlink(vmRootPath, vmRootLinkPath); err != nil {
		return nil, nil, fmt.Errorf("failed to create symbol link %q: %v", vmRootLinkPath, err)
	}

	p.vm = vm

	return vm, lockFile, nil
}

func lockAndAssociateSandbox(sandboxPath string, p *Pod) (*hypervisor.Vm, *os.File, error) {
	setupHyperstartFunc(&proxyConfig{
		path:  "runv",
		root:  p.runPath,
		debug: true})
	sandboxIDPath, err := os.Readlink(sandboxPath)
	if err != nil {
		return nil, nil, err
	}

	lockFile, err := lockPod(p.id)
	if err != nil {
		return nil, nil, err
	}

	pinfoPath := filepath.Join(sandboxIDPath, "persist.json")
	data, err := ioutil.ReadFile(pinfoPath)
	if err != nil {
		unlockPod(lockFile)
		return nil, nil, err
	}
	sandboxID := filepath.Base(sandboxIDPath)
	vm, err := hypervisor.AssociateVm(sandboxID, data)
	if err != nil {
		unlockPod(lockFile)
		return nil, nil, err
	}

	p.vm = vm

	return vm, lockFile, nil
}

func destroySandbox(vm *hypervisor.Vm, lockFile *os.File) {
	result := make(chan api.Result, 1)
	go func() {
		result <- vm.Shutdown()
	}()
	select {
	case rsp, ok := <-result:
		if !ok || !rsp.IsSuccess() {
			break
		}
	case <-time.After(time.Second * 60):
	}
	vm.Kill()

	// cli refactor todo: kill the proxy if vm.Shutdown() failed.

	if lockFile != nil {
		unlockPod(lockFile)
	}
}

func releaseAndUnlockSandbox(vm *hypervisor.Vm, lockFile *os.File) error {
	data, err := vm.Dump()
	if err != nil {
		unlockPod(lockFile)
		return err
	}
	err = vm.ReleaseVm()
	if err != nil {
		unlockPod(lockFile)
		return err
	}
	pinfoPath := filepath.Join(sandboxPath(vm), "persist.json")
	err = ioutil.WriteFile(pinfoPath, data, 0644)
	if err != nil {
		unlockPod(lockFile)
		return err
	}

	unlockPod(lockFile)
	return nil
}

var getSandbox = lockAndAssociateSandbox

func putSandbox(vm *hypervisor.Vm, lockFile *os.File) {
	if len(vm.ContainerList()) > 0 {
		releaseAndUnlockSandbox(vm, lockFile)
		return
	}
	destroySandbox(vm, lockFile)
}

func sandboxPath(vm *hypervisor.Vm) string {
	return filepath.Join(hypervisor.BaseDir, vm.Id)
}

func shareDirPath(vm *hypervisor.Vm) string {
	return filepath.Join(hypervisor.BaseDir, vm.Id, hypervisor.ShareDirTag)
}

type proxyConfig struct {
	path  string
	root  string
	debug bool
}

func createProxy(config *proxyConfig, vmid, ctlSock, streamSock, grpcSock string) error {
	var cmd *exec.Cmd
	args := []string{
		"runv", "--root", config.root,
	}
	if config.debug {
		args = append(args, "--debug")
	}
	args = append(args, "proxy", "--vmid", vmid, "--hyperstart-ctl-sock", ctlSock,
		"--hyperstart-stream-sock", streamSock, "--proxy-hyperstart", grpcSock,
		"--watch-vm-console", filepath.Join(hypervisor.BaseDir, vmid, hypervisor.ConsoleSockName),
		"--watch-hyperstart")
	cmd = &exec.Cmd{
		Path: config.path,
		Args: args,
		Dir:  "/",
		SysProcAttr: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	err := cmd.Start()
	if err != nil {
		return err
	}

	return nil
}

func setupHyperstartFunc(config *proxyConfig) {
	libhyperstart.NewHyperstart = func(vmid, ctlSock, streamSock string, lastStreamSeq uint64, waitReady, paused bool) (libhyperstart.Hyperstart, error) {
		return newHyperstart(config, vmid, ctlSock, streamSock)
	}
}

func newHyperstart(config *proxyConfig, vmid, ctlSock, streamSock string) (libhyperstart.Hyperstart, error) {
	grpcSock := filepath.Join(hypervisor.BaseDir, vmid, "hyperstartgrpc.sock")

	if _, err := os.Stat(grpcSock); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("%s existed with wrong stats", grpcSock)
		}
		err = createProxy(config, vmid, ctlSock, streamSock, grpcSock)
		if err != nil {
			return nil, err
		}

		for i := 0; i < 500; i++ {
			if _, err := os.Stat(grpcSock); !os.IsNotExist(err) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	return libhyperstart.NewGrpcBasedHyperstart(grpcSock)
}
