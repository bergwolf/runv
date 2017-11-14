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

	"github.com/sirupsen/logrus"
)

var virtLog = logrus.FieldLogger(logrus.New())

// SetLogger sets the logger for virtcontainers package.
func SetLogger(logger logrus.FieldLogger) {
	virtLog = logger.WithField("source", "virtcontainers")
}

// CreatePod is the virtcontainers pod creation entry point.
// CreatePod creates a pod and its containers. It does not start them.
func CreatePod(podConfig PodConfig) (VCPod, error) {
	p, err := createPod(&podConfig)
	if err != nil {
		return nil, err
	}

	f, err := setupFactory(&podConfig)
	if err != nil {
		return nil, err
	}

	vm, lockFile, err := createAndLockSandBox(f, p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, lockFile)

	err = p.preparePod()
	if err != nil {
		return nil, err
	}

	err = createContainers(vm, p)
	if err != nil {
		return nil, err
	}

	err = p.storePod()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// DeletePod is the virtcontainers pod deletion entry point.
// DeletePod will stop an already running container and then delete it.
func DeletePod(podID string) (VCPod, error) {
	p, err := StopPod(podID)
	if err != nil {
		return nil, err
	}

	pod, ok := p.(*Pod)
	if !ok {
		return nil, fmt.Errorf("Internal error")
	}

	err = pod.delete()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// StartPod is the virtcontainers pod starting entry point.
// StartPod will talk to the given hypervisor to start an existing
// pod and all its containers.
// It returns the pod ID.
func StartPod(podID string) (VCPod, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, fileLock)

	if err = p.config.Hooks.preStartHooks(); err != nil {
		return nil, err
	}

	if err = p.start(); err != nil {
		return nil, err
	}

	if err = p.config.Hooks.postStartHooks(); err != nil {
		return nil, err
	}

	return p, nil
}

// StopPod is the virtcontainers pod stopping entry point.
// StopPod will talk to the given agent to stop an existing pod and destroy all containers within that pod.
func StopPod(podID string) (VCPod, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err == nil {
		destroySandbox(vm, fileLock)
	}

	err = p.stopShims()
	if err != nil {
		return nil, err
	}

	err = p.config.Hooks.postStopHooks()
	if err != nil {
		return nil, err
	}

	// Stop the VM
	err = p.stopVM()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// RunPod is the virtcontainers pod running entry point.
// RunPod creates a pod and its containers and then it starts them.
func RunPod(podConfig PodConfig) (VCPod, error) {
	_, err := CreatePod(podConfig)
	if err != nil {
		return nil, err
	}

	return StartPod(podConfig.ID)
}

// ListPod is the virtcontainers pod listing entry point.
func ListPod() ([]PodStatus, error) {
	dir, err := os.Open(configStoragePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No pod directory is not an error
			return []PodStatus{}, nil
		}
		return []PodStatus{}, err
	}

	defer dir.Close()

	podsID, err := dir.Readdirnames(0)
	if err != nil {
		return []PodStatus{}, err
	}

	var podStatusList []PodStatus

	for _, podID := range podsID {
		podStatus, err := StatusPod(podID)
		if err != nil {
			continue
		}

		podStatusList = append(podStatusList, podStatus)
	}

	return podStatusList, nil
}

// StatusPod is the virtcontainers pod status entry point.
func StatusPod(podID string) (PodStatus, error) {
	pod, err := fetchPod(podID)
	if err != nil {
		return PodStatus{}, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(pod.runPath, "sandbox"), pod)
	if err != nil {
		return PodStatus{}, err
	}
	defer putSandbox(vm, fileLock)

	var contStatusList []ContainerStatus
	for _, container := range pod.containers {
		contStatus, err := statusContainer(pod, container.id)
		if err != nil {
			return PodStatus{}, err
		}

		contStatusList = append(contStatusList, contStatus)
	}

	podStatus := PodStatus{
		ID:               pod.id,
		State:            pod.state,
		HypervisorConfig: pod.config.HypervisorConfig,
		Agent:            pod.config.AgentType,
		ContainersStatus: contStatusList,
		Annotations:      pod.config.Annotations,
	}

	return podStatus, nil
}

// CreateContainer is the virtcontainers container creation entry point.
// CreateContainer creates a container on a given pod.
func CreateContainer(podID string, containerConfig ContainerConfig) (VCPod, VCContainer, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, nil, err
	}
	defer putSandbox(vm, fileLock)

	c, err := p.addNewContainer(&containerConfig)
	if err != nil {
		return nil, nil, err
	}

	return p, c, nil
}

// DeleteContainer is the virtcontainers container deletion entry point.
// DeleteContainer deletes a Container from a Pod. If the container is running,
// it needs to be stopped first.
func DeleteContainer(podID, containerID string) (VCContainer, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, fileLock)

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Delete it.
	err = c.delete()
	if err != nil {
		return nil, err
	}

	// Update pod config
	for idx, contConfig := range p.config.Containers {
		if contConfig.ID == containerID {
			p.config.Containers = append(p.config.Containers[:idx], p.config.Containers[idx+1:]...)
			break
		}
	}
	err = p.storage.storePodResource(podID, configFileType, *(p.config))
	if err != nil {
		return nil, err
	}

	return c, nil
}

// StartContainer is the virtcontainers container starting entry point.
// StartContainer starts an already created container.
func StartContainer(podID, containerID string) (VCContainer, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, fileLock)

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Start it.
	err = c.start()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// StopContainer is the virtcontainers container stopping entry point.
// StopContainer stops an already running container.
func StopContainer(podID, containerID string) (VCContainer, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, fileLock)

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Stop it.
	err = c.stop()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// EnterContainer is the virtcontainers container command execution entry point.
// EnterContainer enters an already running container and runs a given command.
func EnterContainer(podID, containerID string, cmd Cmd) (VCPod, VCContainer, *Process, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, nil, nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, nil, nil, err
	}
	defer putSandbox(vm, fileLock)

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, nil, nil, err
	}

	// Enter it.
	process, err := c.enter(cmd)
	if err != nil {
		return nil, nil, nil, err
	}

	return p, c, process, nil
}

// StatusContainer is the virtcontainers container status entry point.
// StatusContainer returns a detailed container status.
func StatusContainer(podID, containerID string) (ContainerStatus, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return ContainerStatus{}, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return ContainerStatus{}, err
	}
	defer putSandbox(vm, fileLock)

	return statusContainer(p, containerID)
}

func statusContainer(pod *Pod, containerID string) (ContainerStatus, error) {
	for _, container := range pod.containers {
		if container.id == containerID {
			// We have to check for the process state to make sure
			// we update the status in case the process is supposed
			// to be running but has been killed or terminated.
			if (container.state.State == StateRunning ||
				container.state.State == StatePaused) &&
				container.process.Pid > 0 {
				running, err := isShimRunning(container.process.Pid)
				if err != nil {
					return ContainerStatus{}, err
				}

				if !running {
					if err := container.stop(); err != nil {
						return ContainerStatus{}, err
					}
				}
			}

			return ContainerStatus{
				ID:          container.id,
				State:       container.state,
				PID:         container.process.Pid,
				StartTime:   container.process.StartTime,
				RootFs:      container.config.RootVolume.Source,
				Annotations: container.config.Annotations,
			}, nil
		}
	}

	// No matching containers in the pod
	return ContainerStatus{}, nil
}

// KillContainer is the virtcontainers entry point to send a signal
// to a container running inside a pod. If all is true, all processes in
// the container will be sent the signal.
func KillContainer(podID, containerID string, signal syscall.Signal, all bool) error {
	p, err := fetchPod(podID)
	if err != nil {
		return err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return err
	}
	defer putSandbox(vm, fileLock)

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return err
	}

	return c.kill(signal, all)
}

// PausePod is the virtcontainers pausing entry point which pauses an
// already running pod.
func PausePod(podID string) (VCPod, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, fileLock)

	err = p.pause()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// ResumePod is the virtcontainers resuming entry point which resumes
// (or unpauses) and already paused pod.
func ResumePod(podID string) (VCPod, error) {
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	vm, fileLock, err := getSandbox(filepath.Join(p.runPath, "sandbox"), p)
	if err != nil {
		return nil, err
	}
	defer putSandbox(vm, fileLock)

	err = p.resume()
	if err != nil {
		return nil, err
	}

	return p, nil
}
