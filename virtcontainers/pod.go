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
	"strings"
	"sync"
	"syscall"

	"github.com/hyperhq/runv/hypervisor"
	"github.com/sirupsen/logrus"
)

// controlSocket is the pod control socket.
// It is an hypervisor resource, and for example qemu's control
// socket is the QMP one.
const controlSocket = "ctrl.sock"

// monitorSocket is the pod monitoring socket.
// It is an hypervisor resource, and is a qmp socket in the qemu case.
// This is a socket that any monitoring entity will listen to in order
// to understand if the VM is still alive or not.
const monitorSocket = "monitor.sock"

// stateString is a string representing a pod state.
type stateString string

const (
	// StateReady represents a pod/container that's ready to be run
	StateReady stateString = "ready"

	// StateRunning represents a pod/container that's currently running.
	StateRunning stateString = "running"

	// StatePaused represents a pod/container that has been paused.
	StatePaused stateString = "paused"

	// StateStopped represents a pod/container that has been stopped.
	StateStopped stateString = "stopped"
)

// State is a pod state structure.
type State struct {
	State stateString `json:"state"`
}

// valid checks that the pod state is valid.
func (state *State) valid() bool {
	for _, validState := range []stateString{StateReady, StateRunning, StatePaused, StateStopped} {
		if state.State == validState {
			return true
		}
	}

	return false
}

// validTransition returns an error if we want to move to
// an unreachable state.
func (state *State) validTransition(oldState stateString, newState stateString) error {
	if state.State != oldState {
		return fmt.Errorf("Invalid state %s (Expecting %s)", state.State, oldState)
	}

	switch state.State {
	case StateReady:
		if newState == StateRunning || newState == StateStopped {
			return nil
		}

	case StateRunning:
		if newState == StatePaused || newState == StateStopped {
			return nil
		}

	case StatePaused:
		if newState == StateRunning || newState == StateStopped {
			return nil
		}

	case StateStopped:
		if newState == StateRunning {
			return nil
		}
	}

	return fmt.Errorf("Can not move from %s to %s",
		state.State, newState)
}

// Socket defines a socket to communicate between
// the host and any process inside the VM.
type Socket struct {
	DeviceID string
	ID       string
	HostPath string
	Name     string
}

// Sockets is a Socket list.
type Sockets []Socket

// Set assigns socket values from string to a Socket.
func (s *Sockets) Set(sockStr string) error {
	if sockStr == "" {
		return fmt.Errorf("sockStr cannot be empty")
	}

	sockSlice := strings.Split(sockStr, " ")
	const expectedSockCount = 4
	const sockDelimiter = ":"

	for _, sock := range sockSlice {
		sockArgs := strings.Split(sock, sockDelimiter)

		if len(sockArgs) != expectedSockCount {
			return fmt.Errorf("Wrong string format: %s, expecting only %v parameters separated with %q", sock, expectedSockCount, sockDelimiter)
		}

		for _, a := range sockArgs {
			if a == "" {
				return fmt.Errorf("Socket parameters cannot be empty")
			}
		}

		socket := Socket{
			DeviceID: sockArgs[0],
			ID:       sockArgs[1],
			HostPath: sockArgs[2],
			Name:     sockArgs[3],
		}

		*s = append(*s, socket)
	}

	return nil
}

// String converts a Socket to a string.
func (s *Sockets) String() string {
	var sockSlice []string

	for _, sock := range *s {
		sockSlice = append(sockSlice, fmt.Sprintf("%s:%s:%s:%s", sock.DeviceID, sock.ID, sock.HostPath, sock.Name))
	}

	return strings.Join(sockSlice, " ")
}

// EnvVar is a key/value structure representing a command
// environment variable.
type EnvVar struct {
	Var   string
	Value string
}

// Cmd represents a command to execute in a running container.
type Cmd struct {
	Args    []string
	Envs    []EnvVar
	WorkDir string

	User                string
	PrimaryGroup        string
	SupplementaryGroups []string

	Interactive bool
	Console     string
	Detach      bool
}

// Resources describes VM resources configuration.
type Resources struct {
	// VCPUs is the number of available virtual CPUs.
	VCPUs uint

	// Memory is the amount of available memory in MiB.
	Memory uint
}

// PodStatus describes a pod status.
type PodStatus struct {
	ID               string
	State            State
	HypervisorConfig HypervisorConfig
	Agent            AgentType
	ContainersStatus []ContainerStatus

	// Annotations allow clients to store arbitrary values,
	// for example to add additional status values required
	// to support particular specifications.
	Annotations map[string]string
}

// PodConfig is a Pod configuration.
type PodConfig struct {
	ID string

	Hostname string

	HypervisorConfig HypervisorConfig
	// Field specific to OCI specs, needed to setup all the hooks
	Hooks Hooks

	// VMConfig is the VM configuration to set for this pod.
	VMConfig Resources

	AgentType   AgentType
	AgentConfig interface{}

	ProxyType   ProxyType
	ProxyConfig interface{}

	ShimType   ShimType
	ShimConfig interface{}

	//NetworkModel  NetworkModel
	//NetworkConfig NetworkConfig

	// Volumes is a list of volumes attached to the pod.
	Volumes []VolumeConfig

	// Containers describe the list of containers within a Pod.
	// This list can be empty and populated by adding containers
	// to the Pod a posteriori.
	Containers []ContainerConfig

	// Annotations keys must be unique strings and must be name-spaced
	// with e.g. reverse domain notation (org.clearlinux.key).
	Annotations map[string]string
}

// valid checks that the pod configuration is valid.
func (podConfig *PodConfig) valid() bool {
	if podConfig.ID == "" {
		return false
	}

	return true
}

// lock locks any pod to prevent it from being accessed by other processes.
func lockPod(podID string) (*os.File, error) {
	if podID == "" {
		return nil, errNeedPodID
	}

	fs := filesystem{}
	podlockFile, _, err := fs.podURI(podID, lockFileType)
	if err != nil {
		return nil, err
	}

	lockFile, err := os.Open(podlockFile)
	if err != nil {
		return nil, err
	}

	err = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX)
	if err != nil {
		return nil, err
	}

	return lockFile, nil
}

// unlock unlocks any pod to allow it being accessed by other processes.
func unlockPod(lockFile *os.File) error {
	if lockFile == nil {
		return fmt.Errorf("lockFile cannot be empty")
	}

	err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	if err != nil {
		return err
	}

	lockFile.Close()

	return nil
}

// Pod is composed of a set of containers and a runtime environment.
// A Pod can be created, deleted, started, paused, stopped, listed, entered, and restored.
type Pod struct {
	id string

	agent   agent
	proxy   proxy
	shim    shim
	storage resourceStorage
	network network

	config *PodConfig

	volumes []*PodVolume

	containers []*Container

	runPath    string
	configPath string

	state State

	vm *hypervisor.Vm

	annotationsLock *sync.RWMutex
}

// ID returns the pod identifier string.
func (p *Pod) ID() string {
	return p.id
}

// Logger returns a logrus logger appropriate for logging Pod messages
func (p *Pod) Logger() *logrus.Entry {
	return virtLog.WithFields(logrus.Fields{
		"subsystem": "pod",
		"pod-id":    p.id,
	})
}

// Annotations returns any annotation that a user could have stored through the pod.
func (p *Pod) Annotations(key string) (string, error) {
	value, exist := p.config.Annotations[key]
	if exist == false {
		return "", fmt.Errorf("Annotations key %s does not exist", key)
	}

	return value, nil
}

// SetAnnotations sets or adds an annotations
func (p *Pod) SetAnnotations(annotations map[string]string) error {
	p.annotationsLock.Lock()
	defer p.annotationsLock.Unlock()

	for k, v := range annotations {
		p.config.Annotations[k] = v
	}

	err := p.storage.storePodResource(p.id, configFileType, *(p.config))
	if err != nil {
		return err
	}

	return nil
}

// GetAnnotations returns pod's annotations
func (p *Pod) GetAnnotations() map[string]string {
	p.annotationsLock.RLock()
	defer p.annotationsLock.RUnlock()

	return p.config.Annotations
}

// FIXME: URL returns the pod URL for any runtime to connect to the proxy.
func (p *Pod) URL() string {
	return ""
}

// GetAllContainers returns all containers.
func (p *Pod) GetAllContainers() []VCContainer {
	ifa := make([]VCContainer, len(p.containers))

	for i, v := range p.containers {
		ifa[i] = v
	}

	return ifa
}

// GetContainer returns the container named by the containerID.
func (p *Pod) GetContainer(containerID string) VCContainer {
	for _, c := range p.containers {
		if c.id == containerID {
			return c
		}
	}
	return nil
}

func (p *Pod) createSetStates() error {
	p.state.State = StateReady

	err := p.setPodState(p.state)
	if err != nil {
		return err
	}

	err = p.setContainersState(p.state.State)
	if err != nil {
		return err
	}

	return nil
}

func createPod(config *PodConfig) (*Pod, error) {
	pod, err := newPod(config)
	if err != nil {
		return nil, err
	}

	// Passthrough devices
	if err := pod.attachDevices(); err != nil {
		return nil, err
	}

	if err := pod.createSetStates(); err != nil {
		return nil, err
	}

	return pod, nil
}

// newPod (re-)construct in-memory struct of a pod from PodConfig
func newPod(podConfig *PodConfig) (*Pod, error) {
	if podConfig.valid() == false {
		return nil, fmt.Errorf("Invalid pod configuration")
	}

	shim, err := newShim(podConfig.ShimType)
	if err != nil {
		return nil, err
	}

	p := &Pod{
		id:              podConfig.ID,
		shim:            shim,
		storage:         &filesystem{},
		config:          podConfig,
		runPath:         filepath.Join(runStoragePath, podConfig.ID),
		configPath:      filepath.Join(configStoragePath, podConfig.ID),
		state:           State{},
		annotationsLock: &sync.RWMutex{},
	}

	volumes, err := newVolumes(p, podConfig.Volumes)
	if err != nil {
		return nil, err
	}

	p.volumes = volumes

	containers, err := newContainers(p, podConfig.Containers)
	if err != nil {
		return nil, err
	}

	p.containers = containers

	return p, nil
}

// storePod stores a pod config.
func (p *Pod) storePod() error {
	err := p.storage.storePodResource(p.id, configFileType, *(p.config))
	if err != nil {
		return err
	}

	for _, container := range p.containers {
		err = p.storage.storeContainerResource(p.id, container.id, configFileType, *(container.config))
		if err != nil {
			return err
		}
	}

	return nil
}

// fetchPod fetches a pod config from a pod ID and returns a pod.
func fetchPod(podID string) (pod *Pod, err error) {
	if podID == "" {
		return nil, errNeedPodID
	}

	fs := filesystem{}
	config, err := fs.fetchPodConfig(podID)
	if err != nil {
		return nil, err
	}

	pod, err = newPod(&config)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod with config %+v: %v", config, err)
	}

	state, err := pod.storage.fetchPodState(pod.id)
	if err == nil && state.State != "" {
		pod.state = state
	}

	return pod, nil
}

// delete deletes an already created pod.
// The VM in which the pod is running will be shut down.
func (p *Pod) delete() error {
	state, err := p.storage.fetchPodState(p.id)
	if err != nil {
		return err
	}

	if state.State != StateReady && state.State != StatePaused && state.State != StateStopped {
		return fmt.Errorf("Pod not ready, paused or stopped, impossible to delete")
	}

	err = p.storage.deletePodResources(p.id, nil)
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) startCheckStates() error {
	state, err := p.storage.fetchPodState(p.id)
	if err != nil {
		return err
	}

	err = state.validTransition(StateReady, StateRunning)
	if err != nil {
		err = state.validTransition(StateStopped, StateRunning)
		if err != nil {
			return err
		}
	}

	err = p.checkContainersState(StateReady)
	if err != nil {
		err = p.checkContainersState(StateStopped)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Pod) startSetState() error {
	podState := State{
		State: StateRunning,
	}

	err := p.setPodState(podState)
	if err != nil {
		return err
	}

	return nil
}

// start starts a pod. The containers that are making the pod
// will be started.
func (p *Pod) start() error {
	if err := p.startCheckStates(); err != nil {
		return err
	}

	/* FIXME:
	if _, _, err := p.proxy.connect(*p, false); err != nil {
		return err
	}
	defer p.proxy.disconnect()

	if err := p.agent.startPod(*p); err != nil {
		return err
	}
	*/

	// Pod is started
	if err := p.startSetState(); err != nil {
		return err
	}

	for _, c := range p.containers {
		if err := c.start(); err != nil {
			return err
		}
	}

	p.Logger().Info("started")

	return nil
}

// stopShims stops all remaining shims corresponfing to not started/stopped
// containers.
func (p *Pod) stopShims() error {
	shimCount := 0

	for _, c := range p.containers {
		if err := stopShim(c.process.Pid); err != nil {
			return err
		}

		shimCount++
	}

	p.Logger().WithField("shim-count", shimCount).Info("Stopped shims")

	return nil
}

func (p *Pod) pauseSetStates() error {
	state := State{
		State: StatePaused,
	}

	// XXX: When a pod is paused, all its containers are forcibly
	// paused too.

	err := p.setContainersState(state.State)
	if err != nil {
		return err
	}

	err = p.setPodState(state)
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) resumeSetStates() error {
	state := State{
		State: StateRunning,
	}

	// XXX: Resuming a paused pod puts all containers back into the
	// running state.
	err := p.setContainersState(state.State)
	if err != nil {
		return err
	}

	err = p.setPodState(state)
	if err != nil {
		return err
	}

	return nil
}

// stopVM stops the agent inside the VM and shut down the VM itself.
func (p *Pod) stopVM() error {
	p.Logger().Info("Stopping VM")

	destroySandbox(p.vm, nil)
	p.vm = nil

	return nil
}

func (p *Pod) togglePausePod(pause bool) error {
	state, err := p.storage.fetchPodState(p.id)
	if err != nil {
		return err
	}

	target := StatePaused
	if !pause {
		target = StateRunning
	}
	if state.State == target || state.State == StateReady {
		return nil
	}

	for _, c := range p.containers {
		if c.state.State == target || c.state.State == StateReady {
			continue
		}
		if pause {
			err = c.pause()
		} else {
			err = c.resume()
		}
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Pod) pause() error {
	if err := p.togglePausePod(true); err != nil {
		return err
	}

	if err := p.pauseSetStates(); err != nil {
		return err
	}

	return nil
}

func (p *Pod) resume() error {
	if err := p.togglePausePod(false); err != nil {
		return err
	}

	if err := p.resumeSetStates(); err != nil {
		return err
	}

	return nil
}

// setPodState sets both the in-memory and on-disk state of the
// pod.
func (p *Pod) setPodState(state State) error {
	// update in-memory state
	p.state = state

	// update on-disk state
	err := p.storage.storePodResource(p.id, stateFileType, state)
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) getContainer(containerID string) (*Container, error) {
	if containerID == "" {
		return &Container{}, errNeedContainerID
	}

	for _, c := range p.containers {
		if c.id == containerID {
			return c, nil
		}
	}

	return nil, fmt.Errorf("pod %v has no container with ID %v", p.ID(), containerID)
}

func (p *Pod) setContainerState(containerID string, state stateString) error {
	if containerID == "" {
		return errNeedContainerID
	}

	c := p.GetContainer(containerID)
	if c == nil {
		return fmt.Errorf("Pod %s has no container %s", p.id, containerID)
	}

	// Let container handle its state update
	cImpl := c.(*Container)
	if err := cImpl.setContainerState(state); err != nil {
		return err
	}

	return nil
}

func (p *Pod) setContainersState(state stateString) error {
	if state == "" {
		return errNeedState
	}

	for _, container := range p.config.Containers {
		err := p.setContainerState(container.ID, state)
		if err != nil {
			return err
		}
	}

	return nil
}

func (p *Pod) deleteContainerState(containerID string) error {
	if containerID == "" {
		return errNeedContainerID
	}

	err := p.storage.deleteContainerResources(p.id, containerID, []podResource{stateFileType})
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) checkContainerState(containerID string, expectedState stateString) error {
	if containerID == "" {
		return errNeedContainerID
	}

	if expectedState == "" {
		return fmt.Errorf("expectedState cannot be empty")
	}

	state, err := p.storage.fetchContainerState(p.id, containerID)
	if err != nil {
		return err
	}

	if state.State != expectedState {
		return fmt.Errorf("Container %s not %s", containerID, expectedState)
	}

	return nil
}

func (p *Pod) checkContainersState(state stateString) error {
	if state == "" {
		return errNeedState
	}

	for _, container := range p.config.Containers {
		err := p.checkContainerState(container.ID, state)
		if err != nil {
			return err
		}
	}

	return nil
}

// togglePausePod pauses a pod if pause is set to true, else it resumes
// it.
func togglePausePod(podID string, pause bool) (*Pod, error) {
	if podID == "" {
		return nil, errNeedPod
	}

	lockFile, err := lockPod(podID)
	if err != nil {
		return nil, err
	}
	defer unlockPod(lockFile)

	// Fetch the pod from storage and create it.
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	if pause {
		err = p.pause()
	} else {
		err = p.resume()
	}

	if err != nil {
		return nil, err
	}

	return p, nil
}

func (p *Pod) attachDevices() error {
	for _, container := range p.containers {
		if err := container.attachDevices(); err != nil {
			return err
		}
	}

	return nil
}

func (p *Pod) detachDevices() error {
	for _, container := range p.containers {
		if err := container.detachDevices(); err != nil {
			return err
		}
	}

	return nil
}

func (p *Pod) preparePod() error {
	err := p.prepareVolumes()
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) prepareVolumes() error {
	for _, v := range p.volumes {
		err := v.insert(p.vm)
		if err != nil {
			p.Logger().Error(err.Error())
			return err
		}
	}

	return nil
}

func (p *Pod) addVolume(vol *PodVolume) error {
	for _, v := range p.volumes {
		if v.config.ID == vol.config.ID {
			err := fmt.Errorf("Volume %s exists", v.config.ID)
			p.Logger().Error(err.Error())
			return err
		}
	}

	err := vol.insert(p.vm)
	if err != nil {
		p.Logger().Error(err.Error())
		return err
	}

	p.volumes = append(p.volumes, vol)

	return nil
}

func (p *Pod) removeVolume(vol PodVolume) error {
	index := -1
	for idx, v := range p.volumes {
		if v.config.ID == vol.config.ID {
			index = idx
		}
	}

	if index < 0 {
		err := fmt.Errorf("Volume %s does not exist", vol.config.ID)
		p.Logger().Error(err.Error())
		return err
	}

	for _, c := range p.containers {
		for _, v := range c.volumes {
			if v.ID == vol.config.ID {
				err := fmt.Errorf("Volume %s is used by container %s", v.ID, c.ID())
				p.Logger().Error(err.Error())
				return err
			}
		}
	}

	err := vol.remove(p.vm)
	if err != nil {
		p.Logger().Error(err.Error())
		return err
	}

	var vols []*PodVolume
	vols = append(p.volumes[:index], p.volumes[index+1:]...)
	p.volumes = vols

	return nil
}

func (p *Pod) validateNewContainer(config *ContainerConfig) error {
	// check container ID
	for _, c := range p.containers {
		if c.id == config.ID {
			return fmt.Errorf("invalid container config: name %s is taken", c.id)
		}
	}

	// check container volume reference
	for _, v := range config.Volumes {
		found := false
		for _, vol := range p.volumes {
			if v.ID == vol.config.ID {
				found = true
				// only voluems to add have Details
				v.Details = nil
				break
			}
		}
		if !found && v.Details == nil {
			return fmt.Errorf("invalid container config: volume %s not found", v.ID)
		}
	}

	return nil
}

func (p *Pod) addNewContainer(config *ContainerConfig) (*Container, error) {
	err := p.validateNewContainer(config)
	if err != nil {
		return nil, err
	}

	c, err := newContainer(p, *config)
	if err != nil {
		return nil, err
	}

	err = c.addVolumes()
	if err != nil {
		return nil, err
	}

	err = createContainer(p.vm, p, c, false)
	if err != nil {
		return nil, err
	}

	err = c.storeContainer()
	if err != nil {
		return nil, err
	}

	// Update and store pod config.
	p.config.Containers = append(p.config.Containers, *config)
	err = p.storage.storePodResource(p.id, configFileType, *(p.config))
	if err != nil {
		return nil, err
	}

	return c, nil
}
