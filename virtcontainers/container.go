//
// Copyright (c) 2016 Intel Corporation
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
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hyperhq/hyperd/utils"
	"github.com/hyperhq/runv/api"
	"github.com/hyperhq/runv/hypervisor"
	"github.com/hyperhq/runv/lib/linuxsignal"
	"github.com/sirupsen/logrus"
)

// Process gathers data related to a container process.
type Process struct {
	ID        string
	Pid       int
	StartTime time.Time
}

// ContainerStatus describes a container status.
type ContainerStatus struct {
	ID        string
	State     State
	PID       int
	StartTime time.Time
	RootFs    string

	// Annotations allow clients to store arbitrary values,
	// for example to add additional status values required
	// to support particular specifications.
	Annotations map[string]string
}

// ContainerConfig describes one container runtime configuration.
type ContainerConfig struct {
	ID string

	// RootVolume is the container workload image
	RootVolume *VolumeConfig

	// ReadOnlyRootfs indicates if the rootfs should be mounted readonly
	ReadonlyRootfs bool

	// Cmd specifies the command to run on a container
	Cmd Cmd

	// Annotations allow clients to store arbitrary values,
	// for example to add additional status values required
	// to support particular specifications.
	Annotations map[string]string

	// Device configuration for devices that must be available within the container.
	DeviceInfos []DeviceInfo

	// Ports are port-mapping configs of the container.
	// Ports []*ContainerPort

	// Volumes is a list of volumes attached and mounted inside the container.
	// The volumes must exist in pod.
	Volumes []*VolumeReference

	// Signal used to stop the container processes.
	StopSignal string
}

// valid checks that the container configuration is valid.
func (c *ContainerConfig) valid() bool {
	if c == nil {
		return false
	}

	if c.ID == "" {
		return false
	}

	return true
}

// Container is composed of a set of containers and a runtime environment.
// A Container can be created, deleted, started, stopped, listed, entered, paused and restored.
type Container struct {
	id    string
	podID string

	rootFs *PodVolume

	config *ContainerConfig

	pod *Pod

	runPath       string
	configPath    string
	containerPath string

	state State

	process Process

	volumes []*VolumeReference

	devices []Device
}

// ID returns the container identifier string.
func (c *Container) ID() string {
	return c.id
}

// Logger returns a logrus logger appropriate for logging Container messages
func (c *Container) Logger() *logrus.Entry {
	return virtLog.WithFields(logrus.Fields{
		"subsystem":    "container",
		"container-id": c.id,
		"pod-id":       c.podID,
	})
}

// Pod returns the pod handler related to this container.
func (c *Container) Pod() VCPod {
	return c.pod
}

// Process returns the container process.
func (c *Container) Process() Process {
	return c.process
}

// GetToken returns the token related to this container's process.
func (c *Container) GetToken() string {
	return c.process.ID
}

// GetPid returns the pid related to this container's process.
func (c *Container) GetPid() int {
	return c.process.Pid
}

// SetPid sets and stores the given pid as the pid of container's process.
func (c *Container) SetPid(pid int) error {
	c.process.Pid = pid

	return c.storeProcess()
}

// URL returns the URL related to the pod.
func (c *Container) URL() string {
	return c.pod.URL()
}

// GetAnnotations returns container's annotations
func (c *Container) GetAnnotations() map[string]string {
	return c.config.Annotations
}

func (c *Container) storeProcess() error {
	return c.pod.storage.storeContainerProcess(c.podID, c.id, c.process)
}

func (c *Container) fetchProcess() (Process, error) {
	return c.pod.storage.fetchContainerProcess(c.podID, c.id)
}

func (c *Container) storeDevices() error {
	return c.pod.storage.storeContainerDevices(c.podID, c.id, c.devices)
}

func (c *Container) fetchDevices() ([]Device, error) {
	return c.pod.storage.fetchContainerDevices(c.podID, c.id)
}

// fetchContainer fetches a container config from a pod ID and returns a Container.
func fetchContainer(pod *Pod, containerID string) (*Container, error) {
	if pod == nil {
		return nil, errNeedPod
	}

	if containerID == "" {
		return nil, errNeedContainerID
	}

	fs := filesystem{}
	config, err := fs.fetchContainerConfig(pod.id, containerID)
	if err != nil {
		return nil, err
	}

	pod.Logger().WithField("config", config).Debug("Container config")

	c, err := newContainer(pod, config)
	if err != nil {
		return nil, err
	}

	state, err := c.pod.storage.fetchContainerState(c.podID, c.id)
	if err == nil && state.State != "" {
		c.state.State = state.State
	}

	return c, nil
}

// storeContainer stores a container config.
func (c *Container) storeContainer() error {
	fs := filesystem{}
	err := fs.storeContainerResource(c.pod.id, c.id, configFileType, *(c.config))
	if err != nil {
		return err
	}

	return nil
}

// setContainerState sets both the in-memory and on-disk state of the
// container.
func (c *Container) setContainerState(state stateString) error {
	if state == "" {
		return errNeedState
	}

	// update in-memory state
	c.state.State = state

	// update on-disk state
	err := c.pod.storage.storeContainerResource(c.pod.id, c.id, stateFileType, c.state)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) createContainersDirs() error {
	err := os.MkdirAll(c.runPath, dirMode)
	if err != nil {
		return err
	}

	err = os.MkdirAll(c.configPath, dirMode)
	if err != nil {
		c.pod.storage.deleteContainerResources(c.podID, c.id, nil)
		return err
	}

	return nil
}

// newContainer creates a Container structure from a pod and a container configuration.
func newContainer(pod *Pod, contConfig ContainerConfig) (*Container, error) {
	if contConfig.valid() == false {
		return &Container{}, fmt.Errorf("Invalid container configuration")
	}

	c := &Container{
		id:            contConfig.ID,
		podID:         pod.id,
		rootFs:        newPodVolume(contConfig.RootVolume),
		config:        &contConfig,
		pod:           pod,
		runPath:       filepath.Join(runStoragePath, pod.id, contConfig.ID),
		configPath:    filepath.Join(configStoragePath, pod.id, contConfig.ID),
		containerPath: filepath.Join(pod.id, contConfig.ID),
		state:         State{},
		process:       Process{},
		volumes:       contConfig.Volumes,
	}

	state, err := c.pod.storage.fetchContainerState(c.podID, c.id)
	if err == nil {
		c.state = state
	}

	process, err := c.pod.storage.fetchContainerProcess(c.podID, c.id)
	if err == nil {
		c.process = process
	}

	// Devices will be found in storage after create stage has completed.
	// We fetch devices from storage at all other stages.
	storedDevices, err := c.fetchDevices()
	if err == nil {
		c.devices = storedDevices
	} else {
		// If devices were not found in storage, create Device implementations
		// from the configuration. This should happen at create.

		devices, err := newDevices(contConfig.DeviceInfos)
		if err != nil {
			return &Container{}, err
		}
		c.devices = devices
	}
	return c, nil
}

// newContainers uses newContainer to create a Container slice.
func newContainers(pod *Pod, contConfigs []ContainerConfig) ([]*Container, error) {
	if pod == nil {
		return nil, errNeedPod
	}

	var containers []*Container

	for _, contConfig := range contConfigs {
		c, err := newContainer(pod, contConfig)
		if err != nil {
			return containers, err
		}

		containers = append(containers, c)
	}

	return containers, nil
}

func getUGIFromCmd(cmd *Cmd) *api.UserGroupInfo {
	return &api.UserGroupInfo{
		User:             cmd.User,
		Group:            cmd.PrimaryGroup,
		AdditionalGroups: cmd.SupplementaryGroups,
	}
}

func getContainerDescription(c *Container) *api.ContainerDescription {
	container := &api.ContainerDescription{
		Id:         c.id,
		Name:       c.pod.config.Hostname,
		Image:      "",
		Labels:     make(map[string]string),
		Tty:        c.config.Cmd.Interactive,
		RootVolume: newPodVolume(c.config.RootVolume).toRunvDescription(),
		MountId:    "",
		RootPath:   "rootfs",
		UGI:        getUGIFromCmd(&c.config.Cmd),
		Envs:       make(map[string]string),
		Workdir:    c.config.Cmd.WorkDir,
		Path:       c.config.Cmd.Args[0],
		Args:       c.config.Cmd.Args[1:],
	}

	for _, value := range c.config.Cmd.Envs {
		container.Envs[value.Var] = value.Value
	}

	container.Sysctl["vm.overcommit_memory"] = "1"

	return container
}

func createContainers(vm *hypervisor.Vm, p *Pod) (err error) {
	for idx := range p.config.Containers {
		err = createContainer(vm, p, p.containers[idx], idx == 0)
		if err != nil {
			return err
		}
	}

	return nil
}

// createContainer creates a container inside a Pod.
func createContainer(vm *hypervisor.Vm, p *Pod, c *Container, nslistener bool) (err error) {
	desc := getContainerDescription(c)
	r := vm.AddContainer(desc)
	if !r.IsSuccess() {
		return fmt.Errorf("add container %s failed: %s", c.id, r.Message())
	}
	defer func() {
		if err != nil {
			vm.RemoveContainer(c.id)
		}
	}()

	// Prepare container state directory
	stateDir := filepath.Join(p.runPath, c.id)
	_, err = os.Stat(stateDir)
	if err == nil {
		return fmt.Errorf("Container %s exists", c.id)
	}
	err = os.MkdirAll(stateDir, 0644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(stateDir)
		}
	}()

	// create shim
	c.process, err = c.createShimProcess("root", c.config.Cmd)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			stopShim(c.process.Pid)
		}
	}()

	// If runv is launched via docker/containerd, we start netlistener to watch/collect network changes.
	// TODO: if runv is launched by cni compatible tools, the cni script can use `runv interface` cmdline to update the network.
	// Create the listener process that enters into the netns of the shim
	if nslistener {
		if err = startNsListener(c.id, c.process.Pid, vm); err != nil {
			return err
		}
	}

	return nil
}

func (c *Container) delete() error {
	state, err := c.pod.storage.fetchContainerState(c.podID, c.id)
	if err != nil {
		return err
	}

	if state.State != StateReady && state.State != StateStopped {
		return fmt.Errorf("Container not ready or stopped, impossible to delete")
	}

	if err := stopShim(c.process.Pid); err != nil {
		return err
	}

	err = c.pod.storage.deleteContainerResources(c.podID, c.id, nil)
	if err != nil {
		return err
	}

	return nil
}

// fetchState retrieves the container state.
//
// cmd specifies the operation (or verb) that the retieval is destined
// for and is only used to make the returned error as descriptive as
// possible.
func (c *Container) fetchState(cmd string) (State, error) {
	if cmd == "" {
		return State{}, fmt.Errorf("Cmd cannot be empty")
	}

	state, err := c.pod.storage.fetchPodState(c.pod.id)
	if err != nil {
		return State{}, err
	}

	if state.State != StateRunning {
		return State{}, fmt.Errorf("Pod not running, impossible to %s the container", cmd)
	}

	state, err = c.pod.storage.fetchContainerState(c.podID, c.id)
	if err != nil {
		return State{}, err
	}

	return state, nil
}

func (c *Container) doStart(vm *hypervisor.Vm) error {
	err := vm.StartContainer(c.id)
	if err != nil {
		return err
	}

	// kick off shim
	err = syscall.Kill(c.process.Pid, syscall.SIGUSR1)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) start() error {
	state, err := c.fetchState("start")
	if err != nil {
		return err
	}

	if state.State != StateReady && state.State != StateStopped {
		return fmt.Errorf("Container not ready or stopped, impossible to start")
	}

	err = state.validTransition(StateReady, StateRunning)
	if err != nil {
		err = state.validTransition(StateStopped, StateRunning)
		if err != nil {
			return err
		}
	}

	err = c.doStart(c.pod.vm)
	if err != nil {
		return err
	}

	err = c.setContainerState(StateRunning)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) stop() error {
	state, err := c.fetchState("stop")
	if err != nil {
		return err
	}

	// In case the container status has been updated implicitly because
	// the container process has terminated, it might be possible that
	// someone try to stop the container, and we don't want to issue an
	// error in that case. This should be a no-op.
	if state.State == StateStopped {
		c.Logger().Info("Container already stopped")
		return nil
	}

	if state.State != StateRunning {
		return fmt.Errorf("Container not running, impossible to stop")
	}

	err = state.validTransition(StateRunning, StateStopped)
	if err != nil {
		return err
	}

	defer func() {
		// If shim is still running something went wrong
		// Make sure we stop the shim process
		if running, _ := isShimRunning(c.process.Pid); running {
			l := c.Logger()
			l.Warn("Failed to stop container so stopping dangling shim")
			if err := stopShim(c.process.Pid); err != nil {
				l.WithError(err).Warn("failed to stop shim")
			}
		}

	}()

	// Kill and wait the container
	err = c.pod.vm.KillContainer(c.id, syscall.SIGSTOP)
	if err != nil {
		return err
	}

	result := c.pod.vm.WaitProcess(true, []string{c.id}, 60)
	if result == nil {
		return fmt.Errorf("wait container failed")
	}
	<-result

	// Wait for the end of container
	err = waitForShim(c.process.Pid)
	if err != nil {
		return err
	}

	err = c.setContainerState(StateStopped)
	if err != nil {
		return err
	}

	return nil
}

func getEnvs(envVar []EnvVar) []string {
	var envs []string
	for _, env := range envVar {
		envs = append(envs, fmt.Sprintf("%s=%s", env.Var, env.Value))
	}

	return envs
}

func (c *Container) enter(cmd Cmd) (*Process, error) {
	state, err := c.fetchState("enter")
	if err != nil {
		return nil, err
	}

	if state.State != StateRunning {
		return nil, fmt.Errorf("Container not running, impossible to enter")
	}

	id := fmt.Sprintf("exec-%s", utils.RandStr(10, "alpha"))

	p := &api.Process{
		Container:       c.id,
		Id:              id,
		Terminal:        cmd.Interactive,
		Args:            cmd.Args,
		Envs:            getEnvs(cmd.Envs),
		Workdir:         cmd.WorkDir,
		User:            cmd.User,
		Group:           cmd.PrimaryGroup,
		AdditionalGroup: cmd.SupplementaryGroups,
	}

	err = c.pod.vm.AddProcess(p, nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			c.pod.vm.SignalProcess(c.id, id, linuxsignal.SIGKILL)
		}
	}()

	var process Process
	process, err = c.createShimProcess(id, cmd)
	if err != nil {
		return nil, err
	}

	return &process, nil
}

func (c *Container) kill(signal syscall.Signal, all bool) error {
	podState, err := c.pod.storage.fetchPodState(c.pod.id)
	if err != nil {
		return err
	}

	if podState.State != StateReady && podState.State != StateRunning {
		return fmt.Errorf("Pod not ready or running, impossible to signal the container")
	}

	state, err := c.pod.storage.fetchContainerState(c.podID, c.id)
	if err != nil {
		return err
	}

	// In case our container is "ready", there is no point in trying to
	// send any signal because nothing has been started. However, this is
	// a valid case that we handle by doing nothing or by killing the shim
	// and updating the container state, according to the signal.
	if state.State == StateReady {
		if signal != syscall.SIGTERM && signal != syscall.SIGKILL {
			c.Logger().WithField("signal", signal).Info("Not sending singal as container already ready")
			return nil
		}

		// Calling into stopShim() will send a SIGKILL to the shim.
		// This signal will be forwarded to the proxy and it will be
		// handled by the proxy itself. Indeed, because there is no
		// process running inside the VM, there is no point in sending
		// this signal to our agent. Instead, the proxy will take care
		// of that signal by killing the shim (sending an exit code).
		if err := stopShim(c.process.Pid); err != nil {
			return err
		}

		return c.setContainerState(StateStopped)
	}

	if state.State != StateRunning {
		return fmt.Errorf("Container not running, impossible to signal the container")
	}

	return c.pod.vm.KillContainer(c.id, signal)
}

func (c *Container) createShimProcess(id string, cmd Cmd) (Process, error) {
	shimParams := ShimParams{
		Root:         c.pod.runPath,
		Container:    c.id,
		Process:      id,
		ProxyWinsize: cmd.Interactive,
		Console:      cmd.Console,
		Detach:       cmd.Detach,
	}

	pid, err := c.pod.shim.start(*(c.pod), shimParams)
	if err != nil {
		return Process{}, err
	}

	process := newProcess(id, pid)

	return process, nil
}

func newProcess(id string, pid int) Process {
	return Process{
		ID:        id,
		Pid:       pid,
		StartTime: time.Now().UTC(),
	}
}

func (c *Container) attachDevices() error {
	return nil
}

func (c *Container) detachDevices() error {
	return nil
}

func (c *Container) pause() error {
	return c.pod.vm.KillContainer(c.id, syscall.SIGSTOP)
}

func (c *Container) resume() error {
	return c.pod.vm.KillContainer(c.id, syscall.SIGCONT)
}

func (c *Container) addVolumes() error {
	for _, v := range c.volumes {
		if v.Details != nil {
			err := c.pod.addVolume(newPodVolume(v.Details))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
